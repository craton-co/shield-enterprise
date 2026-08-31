// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_std]

//! QNX Neutrino RTOS HAL implementations for `Craton Shield`.
//!
//! On `target_os = "nto"` (QNX Neutrino), this crate provides
//! implementations that call QNX-native APIs via FFI:
//!
//! - **CAN**: `read()` / `write()` / `devctl()` on the `/dev/can*` resource manager
//! - **Timer**: `clock_gettime(CLOCK_MONOTONIC)` (microseconds) and `ClockCycles()`
//! - **Ethernet**: `io-pkt` raw sockets via BPF (`/dev/bpf*`)
//!
//! On other platforms, all I/O operations return [`VsError::NotInitialized`]
//! so the crate compiles and tests run on the development host. The
//! platform-agnostic frame parse/serialize helpers are exercised by unit
//! tests on every target.
//!
//! # Prerequisites (QNX only)
//!
//! - QNX SDP 7.1+ with `io-pkt` and `dev-can-*` drivers started
//! - Build with `cargo build --target aarch64-unknown-nto-qnx710`
//!
//! # Thread Safety
//!
//! The QNX resource-manager file descriptors cached inside
//! [`QnxCanBus`] and [`QnxEthernetPhy`] are updated lazily on the first
//! I/O operation, and the bus-off / link-up caches are updated on each
//! read or write. Neither type is `Sync`: callers must synchronise
//! access externally (e.g., via a mutex or single-owner pattern) when
//! sharing across threads. In practice these types are used from a
//! single cooperative-scheduler task per bus/PHY.
//!
//! # BPF Header Assumption
//!
//! The BSD BPF header size on QNX Neutrino 7.x is 18 bytes (aligned
//! `bpf_hdr` — timestamp + caplen + datalen + hdrlen + padding). Ports
//! to platforms where `BIOCGHDRLEN` returns a different value must
//! update [`BPF_HEADER_SIZE`] or query the header length at open time.

use vs_hal::{CanBus, EthernetPhy, RawCanFrame, RawEthFrame, Timer};
use vs_types::VsError;

// docs.rs builds with `--cfg docsrs` and `all-features = true`; skip the
// hard error there so the documentation can render the feature-gated APIs.
//
// The `qnx-link-detect` feature wires the two driver-/SDP-version-specific
// probes that are otherwise compiled out:
//   * `QnxCanBus::is_bus_off`  → `devctl(CAN_DEVCTL_GET_BUS_STATE, ...)`
//   * `QnxEthernetPhy::update_link_state` → `ioctl(SIOCGIFFLAGS, ...)`
//
// Enabling the feature requires the downstream crate to inject the
// following symbols into the `qnx_ffi` module via `build.rs` or a local
// patch (the exact numeric values are *not* portable across QNX SDP
// versions / driver vendors — extract them from the target's
// `<dev/can.h>` and `<sys/sockio.h>`):
//
//   pub const CAN_DEVCTL_GET_BUS_STATE: i32 = ...;   // <dev/can.h>
//   pub const SIOCGIFFLAGS:             i32 = ...;   // <sys/sockio.h>
//   pub const IFF_UP:                   i16 = 0x0001; // POSIX-stable, but
//   pub const IFF_RUNNING:              i16 = 0x0040; // verify on target
//
// The argument layout for `SIOCGIFFLAGS` is the POSIX-stable 32-byte
// `struct ifreq` (see [`IfReq`] below): 16-byte `ifr_name` followed by
// a 16-byte union whose first two bytes (on little-endian QNX targets)
// hold `ifr_flags`. If the target SDP ships a wider `struct ifreq`
// (e.g., 40 bytes on QNX 8.0), the downstream patch must also redefine
// [`IfReq`] to match — keeping the `static_assert!` on `size_of`
// guarantees a wire mismatch fails at compile time rather than at
// runtime via a kernel-side overwrite of the caller's stack.
#[cfg(all(feature = "qnx-link-detect", not(docsrs)))]
compile_error!(
    "qnx-link-detect requires QNX-specific ioctl/devctl command numbers \
     and matching argument layouts that are SDP- and driver-version- \
     specific. Supply the following symbols via build.rs or a local \
     patch on the qnx_ffi module: \
     `SIOCGIFFLAGS: i32` (from <sys/sockio.h>), \
     `CAN_DEVCTL_GET_BUS_STATE: i32` (from <dev/can.h>), \
     `IFF_UP: i16`, `IFF_RUNNING: i16`. \
     The POSIX-stable 32-byte `struct ifreq` layout is provided locally \
     as `IfReq`; if the target SDP differs, override it. \
     See crates/hal-qnx/README.md and docs/porting-guide.md."
);

// ---------------------------------------------------------------------------
// QNX FFI bindings (target_os = "nto" only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "nto")]
mod qnx_ffi {
    //! Minimal QNX Neutrino FFI bindings.
    //!
    //! Only the symbols actually used by this crate are declared here.
    //! A full QNX SDP provides the complete headers.

    /// Clock source — `CLOCK_MONOTONIC` on QNX.
    pub const CLOCK_MONOTONIC: i32 = 1;

    /// QNX `timespec` for `ClockTime`.
    #[repr(C)]
    pub struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }

    /// O_RDWR flag for open().
    pub const O_RDWR: i32 = 2;

    /// `O_CLOEXEC` flag for `open()` — close-on-exec.
    ///
    /// audit-LOW: every `open()` call site in this crate must pass
    /// `O_RDWR | O_CLOEXEC` so that descriptors are not inherited across
    /// QNX `posix_spawn()` boundaries. A child process inheriting an open
    /// CAN/BPF descriptor becomes a confused-deputy that can read/write
    /// the bus without ever having opened it itself. POSIX defines
    /// `O_CLOEXEC = 0o100_000` and QNX Neutrino matches that value.
    pub const O_CLOEXEC: i32 = 0o100_000;

    // ---------------------------------------------------------------------
    // CAN bus-off + Ethernet link-state ioctls
    // ---------------------------------------------------------------------
    //
    // The QNX-specific devctl/ioctl command numbers for CAN bus-state and
    // Ethernet interface flags are driver- and SDP-version-specific (see
    // `<dev/can.h>` and `<sys/sockio.h>` shipped with QNX SDP).
    //
    // Previous revisions of this file hard-coded numbers that turned out
    // to be Linux values (`SIOCGIFFLAGS = 0xC020_6911`) or otherwise
    // unverified (`CAN_DEVCTL_GET_BUS_STATE = 0x4003_6301`). Issuing a
    // Linux ioctl on a QNX fd is at best silently ignored and at worst a
    // kernel-side stack write into an undersized caller buffer.
    //
    // Until a maintainer confirms the correct command numbers against a
    // specific QNX SDP target (and also confirms the kernel-side argument
    // layout — an `ifreq` struct for `SIOCGIFFLAGS`, not a bare `i32`),
    // those two probes are compiled out entirely. The effect at runtime:
    //
    //   - `QnxCanBus::is_bus_off()` always reports `false`; the caller
    //     must not rely on it for safety-critical shutdown.
    //   - `QnxEthernetPhy::is_link_up()` always reports the value set at
    //     construction (currently `false`).
    //
    // Callers that need accurate link / bus-off status should either pass
    // the information in through a platform-specific side channel, or
    // enable the `qnx-link-detect` cargo feature after verifying and
    // supplying the correct constants in their build system.

    /// CAN bus state: bus-off (value from `<dev/can.h>` — kept for the
    /// opt-in `qnx-link-detect` feature).
    #[cfg(feature = "qnx-link-detect")]
    pub const CAN_STATE_BUS_OFF: i32 = 4;

    /// CAN bus state: error-active / normal (value from `<dev/can.h>`).
    /// Passed to `CAN_DEVCTL_SET_BUS_STATE` to request a bus-off recovery.
    /// Build-system-supplied. See the note on `CAN_DEVCTL_GET_BUS_STATE`
    /// — an incorrect value risks a kernel-side write past a 4-byte
    /// buffer.
    #[cfg(feature = "qnx-link-detect")]
    pub const CAN_STATE_ERROR_ACTIVE: i32 = 0;

    // The following CAN devctl command numbers are SDP- and driver-
    // specific. They are only referenced when `qnx-link-detect` is
    // enabled, and that feature itself fires `compile_error!` unless
    // the caller's build.rs supplies overrides — so leaving these as
    // `0` placeholders keeps unsafe paths from compiling silently.
    /// `CAN_DEVCTL_GET_INFO` — return controller info (runtime bitrate
    /// etc.). Build-system-supplied; see the feature-level note.
    #[cfg(feature = "qnx-link-detect")]
    pub const CAN_DEVCTL_GET_INFO: i32 = 0;
    /// `CAN_DEVCTL_SET_BUS_STATE` — request a bus-state transition
    /// (used by `recover_bus_off`). Build-system-supplied.
    #[cfg(feature = "qnx-link-detect")]
    pub const CAN_DEVCTL_SET_BUS_STATE: i32 = 0;

    /// Interface flag: link is administratively up. (`IFF_UP` from BSD
    /// `<net/if.h>` — POSIX-stable bit value.) Stored as `i16` so it can
    /// be `&`-tested directly against [`IfReq::flags`].
    #[cfg(feature = "qnx-link-detect")]
    pub const IFF_UP: i16 = 0x0001;
    /// Interface flag: link is operationally running.
    #[cfg(feature = "qnx-link-detect")]
    pub const IFF_RUNNING: i16 = 0x0040;

    // POSIX errno values used by the errno -> VsError mapping.
    // QNX Neutrino follows the standard POSIX numbering.
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EINTR: i32 = 4;
    pub const EIO: i32 = 5;
    pub const EAGAIN: i32 = 11;
    /// On most POSIX systems `EWOULDBLOCK == EAGAIN`. QNX is no exception,
    /// but the kernel may surface either symbol depending on the syscall.
    pub const EWOULDBLOCK: i32 = 11;
    pub const ENOMEM: i32 = 12;
    pub const EACCES: i32 = 13;
    pub const ENODEV: i32 = 19;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const ETIMEDOUT: i32 = 260; // QNX Neutrino value; differs from glibc.

    extern "C" {
        /// Read monotonic clock — `clock_gettime(CLOCK_MONOTONIC, &tp)`.
        pub fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;

        /// CPU cycle counter — `ClockCycles()` (QNX-specific).
        pub fn ClockCycles() -> u64;

        /// Open a file descriptor — `open(path, flags)`.
        pub fn open(path: *const u8, flags: i32) -> i32;

        /// Close a file descriptor.
        pub fn close(fd: i32) -> i32;

        /// Read from a file descriptor.
        pub fn read(fd: i32, buf: *mut u8, count: usize) -> isize;

        /// Write to a file descriptor.
        pub fn write(fd: i32, buf: *const u8, count: usize) -> isize;

        /// Device control — `devctl(fd, cmd, data, nbytes, info)`.
        pub fn devctl(fd: i32, cmd: i32, data: *mut u8, nbytes: usize, info: *mut i32) -> i32;

        /// Socket ioctl — `ioctl(fd, request, ...)`.
        pub fn ioctl(fd: i32, request: i32, argp: *mut u8) -> i32;

        /// QNX errno access — returns a thread-local pointer to `errno`.
        /// This is the Neutrino idiom (the `errno` C macro expands to
        /// `(*__get_errno_ptr())`). Named `__get_errno_ptr` in QNX SDP.
        #[link_name = "__get_errno_ptr"]
        fn __get_errno_ptr() -> *mut i32;
    }

    /// Safe wrapper around `*__get_errno_ptr()`. Returns 0 if the pointer
    /// is somehow null (never happens on a conforming libc but defends
    /// against a hypothetical static-link regression).
    #[inline]
    pub fn errno() -> i32 {
        // SAFETY: `__get_errno_ptr` returns a thread-local pointer that is
        // always non-null on QNX Neutrino. We additionally null-check in
        // case of a broken toolchain / static-link surprise.
        unsafe {
            let p = __get_errno_ptr();
            if p.is_null() {
                0
            } else {
                *p
            }
        }
    }
}

/// Audit fix HIGH (EAGAIN mapping). `true` if the errno indicates a
/// non-blocking operation that should be retried later — `Ok(None)` for
/// `receive()` callers, NOT a `VsError::Timeout`.
#[cfg(target_os = "nto")]
#[inline]
fn is_would_block(err: i32) -> bool {
    err == qnx_ffi::EAGAIN || err == qnx_ffi::EWOULDBLOCK
}

/// Audit fix HIGH (EINTR retry). `true` if the syscall was interrupted
/// by a signal and should be retried verbatim.
#[cfg(target_os = "nto")]
#[inline]
fn is_eintr(err: i32) -> bool {
    err == qnx_ffi::EINTR
}

/// Host-build mirror of [`is_would_block`] for unit tests, with explicit
/// constant values matching the QNX errno numbering. The cfg-gated FFI
/// helper above is the source of truth on the QNX target.
#[cfg(test)]
#[inline]
fn is_would_block_test(err: i32) -> bool {
    // QNX EAGAIN == EWOULDBLOCK == 11.
    err == 11
}

/// Host-build mirror of [`is_eintr`] for unit tests.
#[cfg(test)]
#[inline]
fn is_eintr_test(err: i32) -> bool {
    // QNX EINTR == 4.
    err == 4
}

/// Outcome of [`retry_on_eintr`] — the bounded EINTR retry loop that
/// wraps a single `read()`-style syscall. Compiled on every target so
/// the helper is unit-testable on the development host. The caller is
/// responsible for distinguishing would-block (`EAGAIN`/`EWOULDBLOCK`)
/// from genuine errors via the returned errno on `Err`.
#[allow(dead_code)] // Used on QNX target and in unit tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxOutcome {
    /// Successful read of N bytes.
    Got(isize),
    /// EINTR-retry cap was hit; the read could not complete within a
    /// bounded number of signal interruptions. Caller should map to
    /// [`VsError::Timeout`] so the bound is observable upstream.
    EintrCapHit,
    /// Any non-EINTR errno from the underlying syscall — including
    /// `EAGAIN`/`EWOULDBLOCK`, which the caller should branch on
    /// separately and turn into `Ok(None)`.
    Err(i32),
}

/// Bounded EINTR retry loop. Calls `read_once` up to
/// [`MAX_EINTR_RETRIES`] times, retrying on EINTR-class errno values
/// reported by `is_eintr_fn`. On the first non-EINTR outcome (success,
/// would-block, or other error) the result is returned to the caller.
/// If every attempt within the cap is EINTR, returns
/// [`RxOutcome::EintrCapHit`] so the caller can surface
/// [`VsError::Timeout`].
///
/// This function is the security seam for the audit-fix HIGH `DoS` bound
/// on `receive()` paths. It is intentionally generic over the syscall
/// shim (`read_once`) and over the EINTR recognizer (`is_eintr_fn`) so
/// that unit tests on the development host can drive it with a closure
/// that returns synthetic EINTRs — there is no portable way to issue
/// a real `read()` from a host test, and we MUST keep this loop covered.
///
/// Contract:
/// - `read_once` returns `Ok(n)` for `n >= 0` on success, `Err(errno)`
///   for a syscall failure (the typical `n < 0; errno = ...` pattern in
///   the POSIX `read()` shape).
/// - `is_eintr_fn` returns `true` exactly for errno values that should
///   be retried verbatim.
/// - Would-block detection (`EAGAIN` / `EWOULDBLOCK`) is NOT done here;
///   the caller must handle it on the returned `RxOutcome::Err(errno)`.
#[allow(dead_code)] // Used on QNX target and in unit tests.
#[inline]
fn retry_on_eintr<R, E>(mut read_once: R, is_eintr_fn: E) -> RxOutcome
where
    R: FnMut() -> Result<isize, i32>,
    E: Fn(i32) -> bool,
{
    let mut attempts: u8 = 0;
    loop {
        match read_once() {
            Ok(n) => return RxOutcome::Got(n),
            Err(err) if is_eintr_fn(err) => {
                attempts = attempts.saturating_add(1);
                if attempts >= MAX_EINTR_RETRIES {
                    return RxOutcome::EintrCapHit;
                }
                continue;
            }
            Err(err) => return RxOutcome::Err(err),
        }
    }
}

/// Map a POSIX errno to the closest [`VsError`] variant. Called at every
/// FFI error site on the QNX target so that the error type carries at
/// least enough information to distinguish `ENOENT` (missing device node)
/// from `EACCES` (permissions) from `EIO` (bus failure) — the original
/// code collapsed everything to `NotInitialized`, which made field
/// debugging impossible.
///
/// Callers in `receive()` paths must FIRST check [`is_would_block`] and
/// turn EAGAIN/EWOULDBLOCK into `Ok(None)` rather than letting them fall
/// through this function (which would mis-map them to `Timeout`, an
/// observably wrong error class for non-blocking I/O).
#[cfg(target_os = "nto")]
#[inline]
fn qnx_errno_to_vserror(err: i32) -> VsError {
    match err {
        qnx_ffi::ENOENT | qnx_ffi::ENODEV => VsError::NotFound,
        qnx_ffi::EPERM | qnx_ffi::EACCES => VsError::AuthenticationFailure,
        qnx_ffi::EIO => VsError::BusError,
        // EAGAIN here is a fallback only — non-blocking `receive` callers
        // should branch on `is_would_block` first. Keep the Timeout mapping
        // for any blocking callsite that has no `Ok(None)` channel.
        qnx_ffi::EAGAIN => VsError::Timeout,
        // EINTR also has no good VsError mapping. Callers should retry on
        // EINTR via the helper above; if it ever reaches this function we
        // surface it as Timeout (closest semantics: "try again").
        qnx_ffi::EINTR => VsError::Timeout,
        qnx_ffi::ENOMEM => VsError::ResourceExhausted,
        qnx_ffi::EINVAL => VsError::InvalidInput,
        qnx_ffi::ENOSPC => VsError::StorageError,
        qnx_ffi::ETIMEDOUT => VsError::Timeout,
        _ => VsError::NotInitialized,
    }
}

// ---------------------------------------------------------------------------
// close() failure observability  (audit-LOW)
// ---------------------------------------------------------------------------
//
// `Drop` impls in this crate call `close()` and intentionally ignore
// EINTR (POSIX.2008: the descriptor has already been released, retrying
// would risk closing a fd newly assigned to another thread — see the
// SAFETY comment at each Drop site). However, any *other* failure
// (EBADF, EIO) almost always signals a real bug: double-close, kernel-
// side I/O error, or a descriptor that was never opened. Such failures
// are silent at the call site because Drop has no return value.
//
// To make these failures observable, every non-EINTR close error
// increments `CLOSE_ERROR_COUNT`. Production telemetry can sample this
// counter (e.g. once per second) and alert if it grows — a growing
// counter is a strong signal of a descriptor leak or double-close
// regression. The counter is process-wide, monotonic, and never
// reset; a wraparound at u64::MAX would require ~5.8 * 10^11 years at
// one error per second so is not engineered for.
static CLOSE_ERROR_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Process-wide count of non-EINTR `close()` failures observed by this
/// crate's `Drop` impls. Monotonic, never reset.
///
/// audit-LOW: production telemetry should poll this once per second (or
/// scrape it as a counter metric) and alert on growth. A non-zero value
/// indicates either a descriptor leak (double-close on a fd that was
/// already reaped) or a kernel-side I/O error during close. Neither is
/// recoverable from user space but both are diagnostically valuable.
#[inline]
pub fn hal_qnx_close_error_count() -> u64 {
    CLOSE_ERROR_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// CAN frame layout constants
// ---------------------------------------------------------------------------

/// Standard CAN frame header: 4 bytes ID + 1 byte DLC + 3 bytes reserved.
///
/// The QNX `dev-can-*` resource manager serialises frames as
/// `id:u32_le || dlc:u8 || reserved[3] || data[dlc-bytes-per-ISO-11898-1]`.
///
/// The DLC byte on the wire is the 4-bit ISO 11898-1 DLC nibble (0..=15),
/// NOT a raw byte count. See [`dlc_to_payload_len`] for the mapping.
#[allow(dead_code)] // Used on QNX target and in unit tests.
const CAN_HEADER_SIZE: usize = 8;
/// Maximum CAN data payload (CAN FD, DLC=15).
#[allow(dead_code)]
const CAN_MAX_DATA: usize = 64;

/// Maximum legal value of the on-wire DLC nibble (4-bit field).
#[allow(dead_code)]
const CAN_MAX_DLC: u8 = 15;

/// Maximum classical-CAN DLC (also the on-wire byte count for DLCs 0..=8
/// in both classical CAN and CAN-FD).
#[allow(dead_code)]
const CAN_CLASSIC_MAX_DLC: u8 = 8;

/// ISO 11898-1 CAN-FD DLC-to-payload-length mapping.
///
/// DLC values 0..=8 map linearly to 0..=8 bytes. DLC values 9..=15 map
/// non-linearly to 12, 16, 20, 24, 32, 48, 64 bytes respectively.
///
/// This table mirrors `vs_hal::RawCanFrame`'s private `CAN_FD_DLC_TO_LEN`
/// constant. We duplicate it here because the canonical mapping in
/// `vs-hal` is exposed only as a method on a constructed `RawCanFrame`
/// (`payload_len()`); during parsing we need the length *before* the
/// frame is built, so a free function over `(dlc, is_fd)` is required.
/// Keep this table in sync with `core/hal/src/lib.rs::CAN_FD_DLC_TO_LEN`.
#[allow(dead_code)]
const CAN_FD_DLC_TO_LEN: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];

/// Convert a 4-bit DLC nibble to the on-wire payload length in bytes.
///
/// Mirrors `vs_hal::RawCanFrame::payload_len()` but as a free function
/// over `(dlc, is_fd)` so the parser can call it before constructing
/// the `RawCanFrame`.
///
/// - For classical CAN (`is_fd == false`), the length is `min(dlc, 8)`.
/// - For CAN-FD (`is_fd == true`), the ISO 11898-1 non-linear mapping
///   is applied (DLC 9→12, 10→16, 11→20, 12→24, 13→32, 14→48, 15→64).
///
/// DLC values above 15 (the 4-bit field maximum) are clamped to 15;
/// callers that reject out-of-range DLCs MUST do so before calling
/// this helper.
#[allow(dead_code)]
#[inline]
fn dlc_to_payload_len(dlc: u8, is_fd: bool) -> usize {
    if is_fd {
        let idx = (dlc as usize).min(15);
        CAN_FD_DLC_TO_LEN[idx] as usize
    } else {
        (dlc as usize).min(CAN_CLASSIC_MAX_DLC as usize)
    }
}

// ---------------------------------------------------------------------------
// BPF / Ethernet frame layout constants
// ---------------------------------------------------------------------------

/// Standard BSD BPF header size on QNX 7.x (aligned `bpf_hdr`). Verified by
/// inspecting `/usr/include/net/bpf.h` in QNX SDP 7.1.
pub const BPF_HEADER_SIZE: usize = 18;

/// Minimum Ethernet header (dst:6 || src:6 || ethertype:2).
#[allow(dead_code)]
const ETH_HEADER_MIN: usize = 14;

/// Maximum Ethernet wire length the HAL accepts from BPF and hands back
/// to the caller as a [`RawEthFrame`].
///
/// This is the **on-the-wire** size including all headers and trailers:
///
/// | Field                           | Bytes |
/// |:--------------------------------|------:|
/// | Destination MAC                 |     6 |
/// | Source MAC                      |     6 |
/// | 802.1Q VLAN tag (optional, ×1)  |     4 |
/// | `EtherType` / length            |     2 |
/// | Payload (max)                   |  1500 |
/// | Frame Check Sequence (FCS)      |     4 |
/// | **Total**                       |**1522**|
///
/// Audit fix HIGH (VLAN-truncation): the previous value of `1514`
/// silently dropped the trailing 8 bytes of every double-tagged / FCS-
/// bearing frame delivered by BPF, hiding attacker-controlled bytes
/// from downstream parsers. The value now matches
/// [`vs_hal::MAX_ETH_FRAME_LEN`] so [`RawEthFrame::data`] can hold the
/// full wire frame without truncation.
///
/// Note that BPF on QNX may or may not strip the 4-byte FCS depending
/// on the driver configuration; this constant covers the FCS-present
/// case (the worst case from the buffer-sizing perspective).
#[allow(dead_code)]
const ETH_FRAME_MAX: usize = vs_hal::MAX_ETH_FRAME_LEN;

// CLAUDE.md: fixed buffers must be <= 2048 bytes.
const _: () = assert!(BPF_HEADER_SIZE + ETH_FRAME_MAX <= 2048);
const _: () = assert!(CAN_HEADER_SIZE + CAN_MAX_DATA <= 2048);
// Audit fix HIGH (VLAN-truncation): the parser writes up to ETH_FRAME_MAX
// bytes into RawEthFrame::data, which is [u8; MAX_ETH_FRAME_LEN] in
// vs-hal. Pin the equality so a future divergence between the two
// constants becomes a compile error instead of a silent truncation.
const _: () = assert!(ETH_FRAME_MAX == vs_hal::MAX_ETH_FRAME_LEN);

// ---------------------------------------------------------------------------
// I/O retry caps
// ---------------------------------------------------------------------------

/// Maximum number of `EINTR` retries before `receive()` surfaces a
/// timeout error. POSIX guarantees forward progress per syscall but
/// does not bound the number of EINTRs; a malicious neighbour task
/// with `pthread_kill()` capability could otherwise pin the receive
/// task indefinitely. The cap converts the attack into a bounded
/// `VsError::Timeout` return that the caller can observe and act on.
///
/// Value rationale: `8` retries on a hard-RTOS context is on the order
/// of microseconds per syscall * 8 ≈ low-microsecond / millisecond
/// signal-storm tolerance. Larger values would dilute the `DoS` bound,
/// smaller values would trip on legitimate signal traffic (timer wakeups,
/// `SIGCHLD`, etc.).
#[allow(dead_code)] // Used on QNX target and in unit tests.
const MAX_EINTR_RETRIES: u8 = 8;

/// Maximum number of consecutive frames dropped by the admission filter
/// during a single `receive()` call before the HAL returns `Ok(None)`.
///
/// Audit fix (audit-M10): when the admission filter drops a frame the
/// receive path loops to fetch the next one (see [`QnxCanBus::add_id_accept`]
/// and friends). Without a per-call cap, an adversary that floods the bus
/// with rejected IDs could pin the receive task in a tight read-loop. The
/// cap bounds the loop body so a noisy bus surfaces as `Ok(None)` and the
/// scheduler regains the task; the caller may simply call `receive()`
/// again on the next tick.
#[allow(dead_code)] // Used on QNX target and in unit tests.
const MAX_FILTER_DROP_ITERATIONS: u16 = 64;

// ---------------------------------------------------------------------------
// CAN ID admission filter (audit-M10)
// ---------------------------------------------------------------------------

/// Number of admission-filter slots stored inline in [`QnxCanBus`].
///
/// 16 slots is enough for the typical safety-critical deployment that
/// needs to admit a small handful of OEM diagnostic / control IDs while
/// rejecting everything else. The fixed-size storage keeps the type
/// `#![no_std]`-friendly (no heap) and bounded at compile time.
pub const CAN_FILTER_SLOTS: usize = 16;

/// 29-bit CAN-ID mask. The CAN-FD wire format uses an 11-bit standard ID
/// or a 29-bit extended ID; the upper 3 bits of a 32-bit word are
/// reserved and any mask that sets them is rejected at construction
/// time.
#[allow(dead_code)] // Used by admission filter and unit tests.
const CAN_ID_MASK_29BIT: u32 = 0x1FFF_FFFF;

/// One admission-filter slot: an `(id, mask, accept)` triple.
///
/// The compare predicate is `(incoming_id & mask) == (slot.id & mask)`.
/// A `mask` of `0` matches every incoming frame and is therefore reserved
/// to mean "this slot is unused"; the public setters refuse to write
/// such a slot.
///
/// `accept = true`  → frames whose ID matches this slot are passed
/// through unchanged.
///
/// `accept = false` → frames whose ID matches this slot are dropped
/// (denylist semantics for one ID / range).
///
/// Slots are evaluated in order and the **first** match wins; callers
/// composing both accept and reject filters should arrange them so the
/// more-specific rejects appear before broader accepts.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CanIdFilter {
    /// Reference ID (11-bit or 29-bit, see CAN spec). Only the lower 29
    /// bits are meaningful; the upper 3 bits are reserved and any value
    /// that sets them is rejected by [`QnxCanBus::add_id_accept`] /
    /// [`QnxCanBus::add_id_reject`].
    pub id: u32,
    /// Bit-mask used in the compare predicate. `1`-bits in `mask` are
    /// compared between the incoming ID and `id`; `0`-bits are
    /// wildcards. `mask = 0` denotes an unused slot; `mask = 0x1FFF_FFFF`
    /// matches exactly `id`. Only the lower 29 bits are meaningful.
    pub mask: u32,
    /// `true` → the slot accepts the matching ID; `false` → the slot
    /// rejects (drops) the matching ID.
    pub accept: bool,
}

/// Default policy applied when no slot matches an incoming frame.
///
/// Default is [`CanAdmissionPolicy::AcceptUnmatched`] for backwards
/// compatibility: a freshly-constructed [`QnxCanBus`] with no
/// configured filters accepts every frame the kernel hands up, exactly
/// as the pre-audit-M10 implementation did.
///
/// Safety-critical deployments **must** flip this to
/// [`CanAdmissionPolicy::RejectUnmatched`] and then add explicit
/// `add_id_accept` slots for each ID they expect on the wire. Doing so
/// turns the HAL boundary into a fail-closed admission point: engine,
/// brake, and other safety-critical arbitration IDs only reach the
/// consumer when explicitly allow-listed.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanAdmissionPolicy {
    /// Frames whose ID does not match any configured slot are passed
    /// through to the caller. Backwards-compatible default.
    AcceptUnmatched = 0,
    /// Frames whose ID does not match any configured slot are dropped
    /// and the `dropped_by_filter` counter is incremented. The receive
    /// path loops up to [`MAX_FILTER_DROP_ITERATIONS`] times before
    /// returning `Ok(None)` so the caller can yield.
    RejectUnmatched = 1,
}

impl Default for CanAdmissionPolicy {
    #[inline]
    fn default() -> Self {
        Self::AcceptUnmatched
    }
}

// ---------------------------------------------------------------------------
// `struct ifreq` — argument layout for `SIOCGIFFLAGS` and friends
// ---------------------------------------------------------------------------
//
// POSIX defines `struct ifreq` (`<net/if.h>`, also reachable via the QNX
// `<sys/sockio.h>` SIOC* commands) as a 16-byte interface name followed
// by a 16-byte tagged union. The union variants include `sockaddr
// ifr_addr` (the widest at 16 bytes: `sa_family:u16 + sa_data[14]`),
// `short ifr_flags`, `int ifr_mtu`, and several others.
//
// We only ever read `ifr_flags` from this crate, so a real Rust union is
// unnecessary — a plain `[u8; 16]` payload models the kernel writeback
// faithfully and lets us pull the first two bytes as the flag word.
// Keeping the type a plain struct also avoids the `unsafe` field-access
// requirement that a real union would impose on the host-side unit
// tests (the FFI-boundary safety budget is reserved for the actual
// `ioctl` call site).
//
// `#[repr(C)]` is mandatory: the kernel writes into this buffer field
// by field at fixed offsets, so Rust's default repr (which is free to
// reorder) would be unsound.

/// Interface-name capacity, including the trailing NUL. Matches POSIX
/// `IFNAMSIZ` (and QNX `IFNAMSIZ`). Names longer than 15 bytes have no
/// room for the terminator and are rejected by [`IfReq::new`].
#[allow(dead_code)] // Used by IfReq and the qnx-link-detect feature.
pub const IFNAMSIZ: usize = 16;

/// Size of the trailing `ifr_ifru` union: 16 bytes, matching the widest
/// POSIX variant (`struct sockaddr ifr_addr`).
#[allow(dead_code)]
const IFREQ_UNION_SIZE: usize = 16;

/// Total size of POSIX `struct ifreq`: 16-byte name + 16-byte union.
#[allow(dead_code)]
pub const IFREQ_SIZE: usize = IFNAMSIZ + IFREQ_UNION_SIZE;

/// POSIX `struct ifreq` — used as the argument buffer for `SIOCGIFFLAGS`
/// and other socket ioctls on QNX Neutrino.
///
/// # Layout
///
/// ```text
///   offset 0..16 : ifr_name  — NUL-padded interface name (e.g. "en0\0...")
///   offset 16..32: ifr_ifru  — tagged union, kernel-written
/// ```
///
/// The union's first two bytes hold `ifr_flags` (`c_short`, i.e. `i16`)
/// after a successful `SIOCGIFFLAGS`. On little-endian QNX targets
/// (`aarch64`, `x86_64` — every supported SDP) this matches a direct
/// little-endian `i16` read; big-endian targets would need to flip
/// [`IfReq::flags`].
///
/// # Why a struct, not a Rust `union`
///
/// We never need to read more than one variant of the union from Rust,
/// and a real `union` would force every accessor to be `unsafe`. A
/// plain `[u8; 16]` payload captures the kernel writeback shape
/// faithfully without spending unsafe budget on a host-side
/// reinterpretation.
///
/// # Bug history
///
/// An earlier revision passed `&mut i32` (4 bytes) to `SIOCGIFFLAGS`.
/// The kernel writes a full `struct ifreq` (~32 bytes) regardless of
/// the caller's allocation; the missing 28 bytes corrupted the stack.
/// The const-asserted `size_of::<IfReq>() == IFREQ_SIZE` below makes a
/// future regression visible at compile time.
// Audit fix HIGH-U: the `IfReq::flags()` accessor below decodes the first
// two bytes of `ifr_ifru` via `i16::from_le_bytes`, baking in a hard
// little-endian assumption. Every QNX SDP target that ships today
// (`aarch64`, `x86_64`) is little-endian, but the accessor is `pub` and
// cannot be overridden by downstream crates. A hypothetical big-endian
// QNX port would silently mis-decode the kernel writeback (e.g. byte-
// swapping IFF_UP=0x0001 into 0x0100), reporting "link up" as "link
// down" and vice-versa. Convert that latent risk into an unmistakable
// build error so a future big-endian port is forced to port the
// accessor in lockstep.
#[cfg(target_endian = "big")]
compile_error!(
    "hal-qnx assumes little-endian QNX (aarch64/x86_64); big-endian \
     ports must port IfReq accessors — see IfReq::flags()."
);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Constructors/accessors used on QNX target + unit tests.
pub struct IfReq {
    /// Interface name, NUL-padded to 16 bytes. Last byte is always
    /// either NUL or part of the NUL pad — names are rejected at
    /// construction if they leave no room for the terminator.
    pub ifr_name: [u8; IFNAMSIZ],
    /// Tagged-union payload. The kernel writes the relevant variant
    /// here on a successful `SIOCG*` ioctl; we read [`Self::flags`] for
    /// `SIOCGIFFLAGS` and ignore the rest.
    pub ifr_ifru: [u8; IFREQ_UNION_SIZE],
}

// Compile-time wire-format guard. If a future QNX SDP redefines
// `struct ifreq` with a wider union, this fires before the kernel can
// overwrite our stack.
const _: () = assert!(core::mem::size_of::<IfReq>() == IFREQ_SIZE);
const _: () = assert!(core::mem::size_of::<IfReq>() == 32);

impl IfReq {
    /// Zeroed `IfReq` — `ifr_name` is empty (all NULs) and `ifr_ifru`
    /// is cleared. Suitable as a starting point before calling
    /// [`Self::set_iface_name`].
    #[inline]
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: [0; IFREQ_UNION_SIZE],
        }
    }

    /// Build an `IfReq` with `ifr_name` set to `name`, NUL-padded to
    /// 16 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if:
    /// - `name` is empty;
    /// - `name` is 16 bytes or longer (no room for the trailing NUL —
    ///   even though POSIX libcs vary on whether they tolerate a
    ///   non-terminated `ifr_name`, we reject to keep the contract
    ///   unambiguous on every SDP);
    /// - `name` contains an interior NUL (would silently truncate the
    ///   interface name when the kernel parses it as a C string).
    #[inline]
    pub fn new(name: &[u8]) -> Result<Self, VsError> {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return Err(VsError::InvalidInput);
        }
        if name.contains(&0) {
            return Err(VsError::InvalidInput);
        }
        let mut req = Self::zeroed();
        req.ifr_name[..name.len()].copy_from_slice(name);
        // Trailing bytes are already 0 from `zeroed()`.
        Ok(req)
    }

    /// Read the first two bytes of the union as `ifr_flags` (`c_short`,
    /// i.e. `i16`).
    ///
    /// # Endianness
    ///
    /// Decoded as little-endian, matching every QNX SDP target supported
    /// by this crate (`aarch64` and `x86_64` are both little-endian; QNX
    /// does not currently ship for a big-endian target). Callers on a
    /// hypothetical big-endian QNX port must override this accessor.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> i16 {
        i16::from_le_bytes([self.ifr_ifru[0], self.ifr_ifru[1]])
    }

    /// Set the union's first two bytes from a flag word, little-endian.
    /// Used by tests to seed a known writeback shape.
    #[cfg(test)]
    #[inline]
    fn set_flags(&mut self, flags: i16) {
        let bytes = flags.to_le_bytes();
        self.ifr_ifru[0] = bytes[0];
        self.ifr_ifru[1] = bytes[1];
    }
}

// ---------------------------------------------------------------------------
// Pure frame parse / serialize helpers — testable on any host
// ---------------------------------------------------------------------------

/// Parse a raw CAN frame from the on-wire buffer produced by QNX
/// `dev-can-*`. Returns the parsed [`RawCanFrame`] on success.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if `buf` is shorter than the CAN
/// header, if the advertised DLC exceeds 15 (the 4-bit field
/// maximum), if the buffer does not contain the full payload implied
/// by the ISO 11898-1 DLC mapping, or if `id` exceeds the 29-bit
/// extended-ID maximum.
///
/// The QNX `dev-can-*` 8-byte on-wire header carries `id`, `dlc`, and
/// 3 reserved bytes. The `dlc` byte is the ISO 11898-1 4-bit nibble
/// (0..=15), not a raw byte count: for CAN-FD, values 9..=15 map
/// non-linearly to 12, 16, 20, 24, 32, 48, 64 bytes (see
/// [`dlc_to_payload_len`]).
///
/// The wire format does not carry explicit "extended"/"FD" flags, so
/// we infer:
///
/// - `is_extended = id > CAN_ID_STANDARD_MAX` (any ID above 0x7FF must
///   use the 29-bit format).
/// - `is_fd = dlc > 8` (DLCs above 8 are only valid in CAN-FD).
///
/// This is a defensive derivation. If the underlying driver later
/// exposes the flags directly via devctl mode, override here.
// Visibility: `pub` under `fuzz` (so external fuzz targets can reach it),
// otherwise crate-private. Body is identical in both forms.
#[cfg(not(feature = "fuzz"))]
#[allow(dead_code)] // QNX target + unit tests
#[inline]
fn parse_can_frame(buf: &[u8]) -> Result<RawCanFrame, VsError> {
    parse_can_frame_inner(buf)
}
#[cfg(feature = "fuzz")]
#[inline]
pub fn parse_can_frame(buf: &[u8]) -> Result<RawCanFrame, VsError> {
    parse_can_frame_inner(buf)
}

#[allow(dead_code)]
#[inline]
fn parse_can_frame_inner(buf: &[u8]) -> Result<RawCanFrame, VsError> {
    if buf.len() < CAN_HEADER_SIZE {
        return Err(VsError::InvalidInput);
    }
    let id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    // Audit fix HIGH (CAN-FD wire DLC): the on-wire DLC is the ISO 11898-1
    // 4-bit nibble (0..=15), NOT a raw byte count. Reject anything that
    // overflows the nibble.
    let dlc = buf[4];
    if dlc > CAN_MAX_DLC {
        return Err(VsError::InvalidInput);
    }
    // The wire format has no FD flag; infer FD when DLC > 8 (the only
    // values that imply CAN-FD framing). Done before computing payload
    // length so the ISO mapping is applied for DLCs 9..=15.
    let is_fd = dlc > CAN_CLASSIC_MAX_DLC;
    let payload_len = dlc_to_payload_len(dlc, is_fd);
    // Audit fix HIGH (CAN-FD wire DLC): validate the kernel-supplied
    // buffer carries the FULL ISO-mapped payload, not merely `dlc`
    // bytes. A truncated DLC=15 frame (header + 16 instead of
    // header + 64) used to slip through and emit a partially-populated
    // 64-byte payload buffer downstream.
    if buf.len() < CAN_HEADER_SIZE + payload_len {
        return Err(VsError::InvalidInput);
    }
    // Audit fix HIGH (CAN ID validation): reject IDs that exceed the
    // 29-bit extended-ID maximum. A forged 32-bit ID with the upper
    // bits set could otherwise reach downstream consumers and overlap
    // safety-critical arbitration IDs after a downstream truncation.
    if id > vs_hal::CAN_ID_EXTENDED_MAX {
        return Err(VsError::InvalidInput);
    }
    let mut frame = RawCanFrame::zeroed();
    frame.id = id;
    // Store the on-wire nibble verbatim — `RawCanFrame::payload_len()`
    // performs the ISO mapping on read.
    frame.dlc = dlc;
    // Defensive derivation; see function-level docs.
    frame.is_extended = id > vs_hal::CAN_ID_STANDARD_MAX;
    frame.is_fd = is_fd;
    frame.data[..payload_len].copy_from_slice(&buf[CAN_HEADER_SIZE..CAN_HEADER_SIZE + payload_len]);
    Ok(frame)
}

/// Serialize a [`RawCanFrame`] into the on-wire format expected by
/// QNX `dev-can-*`. Writes into `buf` and returns the number of bytes
/// written. `buf` must be at least `CAN_HEADER_SIZE + payload_len` bytes,
/// where `payload_len` is derived from the ISO 11898-1 DLC mapping
/// (see [`dlc_to_payload_len`]).
///
/// `frame.dlc` is interpreted as the 4-bit ISO DLC nibble (0..=15) and
/// is written verbatim into the on-wire DLC byte. The number of payload
/// bytes copied is the ISO-mapped length, not the DLC nibble itself.
///
/// Returns [`VsError::InvalidInput`] if:
///
/// - `frame.id` exceeds the appropriate maximum for its frame format
///   (`CAN_ID_STANDARD_MAX` for classic, `CAN_ID_EXTENDED_MAX` for
///   extended), or
/// - `frame.dlc > 15` (the 4-bit on-wire DLC field cannot represent
///   higher values), or
/// - `frame.is_fd == false` and `frame.dlc > 8` (classic CAN cannot
///   carry more than 8 data bytes), or
/// - `buf` is shorter than `CAN_HEADER_SIZE + payload_len`.
#[cfg(not(feature = "fuzz"))]
#[allow(dead_code)] // QNX target + unit tests
#[inline]
fn serialize_can_frame(frame: &RawCanFrame, buf: &mut [u8]) -> Result<usize, VsError> {
    serialize_can_frame_inner(frame, buf)
}
#[cfg(feature = "fuzz")]
#[inline]
pub fn serialize_can_frame(frame: &RawCanFrame, buf: &mut [u8]) -> Result<usize, VsError> {
    serialize_can_frame_inner(frame, buf)
}

#[allow(dead_code)]
#[inline]
fn serialize_can_frame_inner(frame: &RawCanFrame, buf: &mut [u8]) -> Result<usize, VsError> {
    // Audit fix HIGH (CAN ID validation): refuse to emit a frame whose
    // ID/DLC would be invalid on the wire. Cheaper to reject here than
    // to have the controller drop it, and it stops downstream-ECU
    // fuzzing via crafted ID values.
    if !frame.is_valid_id() {
        return Err(VsError::InvalidInput);
    }
    // Audit fix HIGH (CAN-FD wire DLC): the on-wire DLC field is 4 bits
    // (0..=15). Reject anything that would overflow it before doing any
    // ISO-mapping work.
    if frame.dlc > CAN_MAX_DLC {
        return Err(VsError::InvalidInput);
    }
    // Audit fix MED (classic-CAN DLC): DLCs > 8 are only valid in CAN-FD.
    // Silently clamping classic-CAN DLC > 8 to 8 (old behaviour) hid
    // mis-built frames; reject instead.
    if !frame.is_fd && frame.dlc > CAN_CLASSIC_MAX_DLC {
        return Err(VsError::InvalidInput);
    }
    // Audit fix HIGH (CAN-FD wire DLC): translate the 4-bit DLC nibble
    // to the ISO 11898-1 payload length. The previous code treated
    // `dlc` as a raw byte count, so a CAN-FD frame with `dlc=15`
    // (meaning 64 bytes) was emitted as a 15-byte payload with `0x0F`
    // in the DLC byte — downstream ECUs would mis-decode that as a
    // 64-byte frame and read past the end of our 15-byte slice.
    let payload_len = dlc_to_payload_len(frame.dlc, frame.is_fd);
    let total = CAN_HEADER_SIZE + payload_len;
    if buf.len() < total {
        return Err(VsError::InvalidInput);
    }
    buf[..4].copy_from_slice(&frame.id.to_le_bytes());
    // Write the DLC nibble verbatim; downstream parsers apply the
    // ISO mapping on read.
    buf[4] = frame.dlc;
    buf[5..8].fill(0);
    buf[CAN_HEADER_SIZE..total].copy_from_slice(&frame.data[..payload_len]);
    Ok(total)
}

/// Parse an Ethernet frame out of a raw BPF read buffer.
///
/// The BSD BPF interface prepends an 18-byte header (`BPF_HEADER_SIZE`)
/// followed by the captured Ethernet frame. A valid frame must be at
/// least 60 bytes (audit fix: runt-frame rejection — IEEE 802.3 minimum
/// frame size pre-FCS), have a non-all-zero destination MAC, and not
/// carry the reserved ethertype `0xFFFF`.
///
/// Length-form 802.3 frames (ethertype/length field < 0x0600) are
/// accepted; only the explicit `0xFFFF` reserved value is rejected.
///
/// Audit fix HIGH (VLAN-truncation): the parser now accepts frames up
/// to [`ETH_FRAME_MAX`] (1522 bytes — the IEEE 802.1Q + FCS-bearing
/// max). Frames whose payload portion exceeds 1522 bytes are
/// **rejected** with [`VsError::InvalidInput`] rather than silently
/// truncated; previously they were clamped to 1514, which made
/// attacker-controlled trailing bytes invisible to downstream parsers.
#[cfg(not(feature = "fuzz"))]
#[allow(dead_code)] // QNX target + unit tests
#[inline]
fn parse_eth_frame(buf: &[u8]) -> Result<RawEthFrame, VsError> {
    parse_eth_frame_inner(buf)
}
#[cfg(feature = "fuzz")]
#[inline]
pub fn parse_eth_frame(buf: &[u8]) -> Result<RawEthFrame, VsError> {
    parse_eth_frame_inner(buf)
}

#[allow(dead_code)]
#[inline]
fn parse_eth_frame_inner(buf: &[u8]) -> Result<RawEthFrame, VsError> {
    if buf.len() < BPF_HEADER_SIZE + ETH_HEADER_MIN {
        return Err(VsError::InvalidInput);
    }
    let frame_len = buf.len() - BPF_HEADER_SIZE;

    // Audit fix HIGH (VLAN-truncation): reject explicitly oversized
    // frames rather than silently clamping. The previous `.min(...)`
    // hid the trailing octets of any frame larger than the constant.
    if frame_len > ETH_FRAME_MAX {
        return Err(VsError::InvalidInput);
    }

    // Audit fix: reject runt frames. IEEE 802.3 mandates a 60-byte
    // minimum payload (pre-FCS); any shorter delivery is a kernel-side
    // framing bug or a deliberately malformed packet.
    if frame_len < 60 {
        return Err(VsError::InvalidInput);
    }

    let payload = &buf[BPF_HEADER_SIZE..BPF_HEADER_SIZE + frame_len];

    // Audit fix: reject all-zero destination MAC (bytes 0..6 of the
    // Ethernet header). A genuine packet always has a real DST MAC, so
    // this catches both kernel-side delivery bugs and intentional
    // malformed packets without imposing a real allow-list.
    if payload[..6].iter().all(|&b| b == 0) {
        return Err(VsError::InvalidInput);
    }

    // Audit fix: reject the reserved ethertype 0xFFFF (Ethernet II
    // header bytes 12..14). 802.3 length-form frames (< 0x0600) and
    // all assigned EtherTypes (≥ 0x0600 except 0xFFFF) are accepted.
    let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
    if ethertype == 0xFFFF {
        return Err(VsError::InvalidInput);
    }

    let mut frame = RawEthFrame::zeroed();
    // SAFETY (LOW-2): `frame_len <= ETH_FRAME_MAX = 1522`, asserted by
    // the bound-check above (line ~885). 1522 fits in `u16::MAX` (65535)
    // with three orders of magnitude headroom, so this cast is provably
    // total. We keep `as u16` rather than `u16::try_from(...).unwrap()`
    // to preserve the no-`panic!`-in-Result-path policy in production
    // code (see CLAUDE.md "no `.unwrap()` in production code").
    #[allow(clippy::cast_possible_truncation)]
    {
        frame.len = frame_len as u16;
    }
    frame.data[..frame_len].copy_from_slice(payload);
    Ok(frame)
}

// ---------------------------------------------------------------------------
// QnxCanBus
// ---------------------------------------------------------------------------

/// Minimum interval between two `recover_bus_off` devctls in microseconds.
/// Per ISO 11898-1, the controller requires 128×11 recessive bits before
/// re-entering bus-on. At 125 kbit/s that is ~11.3 ms; the 20 ms floor
/// gives headroom and lets the firmware finish its internal recovery
/// state machine. (audit-M11)
pub const RECOVER_BUS_OFF_MIN_INTERVAL_US: u64 = 20_000;

/// Pure-function rate-limit check for [`QnxCanBus::recover_bus_off`].
///
/// Returns `Ok(())` if the call is allowed, `Err(VsError::ResourceExhausted)`
/// if the caller is hammering recovery faster than
/// [`RECOVER_BUS_OFF_MIN_INTERVAL_US`].
///
/// Two carve-outs:
///
/// - `last_recover_us == None` — the first call is always allowed so a
///   fresh bus can be recovered immediately after boot.
/// - `now_us == u64::MAX` — the monotonic clock is unavailable. Per the
///   [`Timer::now_us`] sentinel contract, this signals "clock failure".
///   We deliberately let the devctl proceed in this state: a CAN driver
///   stuck in bus-off is a safety-critical fault, and blocking recovery
///   on a missing clock would convert one fault into two. The trade-off
///   is that a hostile caller in this rare regime could still spin the
///   devctl, but a missing monotonic clock indicates the system is
///   already in a degraded state where stricter audit invariants apply.
///
/// Extracted as a free function (rather than a method) so the test
/// module can exercise it without forging a full `QnxCanBus`.
#[inline]
fn simulate_recover_bus_off_rate_limit(
    now_us: u64,
    last_recover_us: Option<u64>,
) -> Result<(), VsError> {
    // Clock-failure carve-out: never block recovery on a dead clock.
    if now_us == u64::MAX {
        return Ok(());
    }
    if let Some(prev) = last_recover_us {
        // `saturating_sub` so a non-monotonic clock excursion (now < prev)
        // does not wrap and accidentally allow a hammered call. The
        // worst case becomes "elapsed = 0 ⇒ rejected", which is
        // conservative.
        let elapsed = now_us.saturating_sub(prev);
        if elapsed < RECOVER_BUS_OFF_MIN_INTERVAL_US {
            return Err(VsError::ResourceExhausted);
        }
    }
    Ok(())
}

/// QNX Neutrino CAN bus via `/dev/can` resource manager.
///
/// On QNX, the resource manager must be started before constructing
/// this handle (`dev-can-<driver> -b<bitrate>`). The `open()` call
/// is deferred to the first I/O operation.
///
/// The device path can be customised via [`new_with_device`](Self::new_with_device)
/// for multi-bus systems (e.g., `/dev/can0`, `/dev/can1`).
///
/// **Thread safety.** This type is `Send` but **not** `Sync`. The cached
/// file descriptor and `bus_off` state are mutated by `receive()` and
/// `transmit()`, so concurrent access from multiple threads requires
/// external synchronisation (mutex or single-owner pattern).
#[repr(C)]
pub struct QnxCanBus {
    bitrate: u32,
    /// Device path, null-terminated. Default: `/dev/can0`.
    #[allow(dead_code)] // Read on QNX target only.
    device_path: [u8; 32],
    #[allow(dead_code)]
    device_path_len: usize,
    /// File descriptor for the CAN resource manager (-1 = not opened).
    #[cfg(target_os = "nto")]
    fd: i32,
    /// Cached bus-off state (updated on each I/O operation on QNX).
    ///
    /// Kept on every target (not gated on `target_os = "nto"`) so the
    /// host-side test suite can exercise the bus-off / `recover_bus_off`
    /// state machine without a live QNX kernel underneath.
    bus_off: bool,
    /// Audit fix: heuristic bus-off detector for default builds (when
    /// `qnx-link-detect` is off). Counts consecutive TX errors; flips
    /// `bus_off=true` at `MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF`, resets
    /// on any successful TX or on a call to `recover_bus_off()`.
    /// Available on every target for the same reason as `bus_off` above.
    consecutive_tx_errors: u8,
    /// Audit fix: most-recent error, populated on every I/O failure so
    /// `last_error()` can return something useful instead of the trait
    /// default `CanError::None`.
    last_error: vs_hal::CanError,
    /// Audit fix: cumulative TX/RX error counters. Updated on every I/O
    /// call (success ↦ no change to error count; failure ↦ +1).
    error_counters: vs_hal::CanErrorCounters,
    /// Audit fix (audit-M11): timestamp (microseconds, from
    /// [`QnxTimer::now_us`]) of the last successful `recover_bus_off`
    /// devctl. `None` until the first recovery attempt — see
    /// [`simulate_recover_bus_off_rate_limit`] for the rate-limit
    /// contract. Carried on every target (not gated on
    /// `target_os = "nto"`) so the host shim and the QNX path share one
    /// state-machine surface; the rate-limit window itself is moot on
    /// non-QNX hosts because [`QnxTimer::now_us`] returns the
    /// clock-failure sentinel there, which the helper interprets as
    /// "allow through".
    last_recover_us: Option<u64>,
    /// Audit fix (audit-M10): CAN ID admission filter slots. Each
    /// populated slot is an (id, mask, accept) tuple; rejected frames
    /// are silently dropped on the RX path.
    filters: [CanIdFilter; CAN_FILTER_SLOTS],
    /// Number of populated filter slots (0..=CAN_FILTER_SLOTS).
    filter_count: u8,
    /// Default policy applied when no filter slot matches. Defaults to
    /// `AcceptUnmatched` for backwards compatibility.
    default_policy: CanAdmissionPolicy,
    /// Cumulative count of frames dropped by the admission filter
    /// (saturating). Visible via [`filter_drop_count`].
    dropped_by_filter: u64,
}

impl QnxCanBus {
    /// Create a new QNX CAN bus handle on the default `/dev/can0` device.
    ///
    /// The underlying device is not opened until the first
    /// call to [`receive`](CanBus::receive) or [`transmit`](CanBus::transmit).
    pub const fn new(bitrate: u32) -> Self {
        let mut path = [0u8; 32];
        path[0] = b'/';
        path[1] = b'd';
        path[2] = b'e';
        path[3] = b'v';
        path[4] = b'/';
        path[5] = b'c';
        path[6] = b'a';
        path[7] = b'n';
        path[8] = b'0';
        path[9] = 0;
        Self {
            bitrate,
            device_path: path,
            device_path_len: 10,
            #[cfg(target_os = "nto")]
            fd: -1,
            bus_off: false,
            consecutive_tx_errors: 0,
            last_error: vs_hal::CanError::None,
            error_counters: vs_hal::CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0,
            },
            last_recover_us: None,
            filters: [CanIdFilter { id: 0, mask: 0, accept: false }; CAN_FILTER_SLOTS],
            filter_count: 0,
            default_policy: CanAdmissionPolicy::AcceptUnmatched,
            dropped_by_filter: 0,
        }
    }

    /// Create a new QNX CAN bus handle on a custom device path.
    ///
    /// `path` must be a null-terminated byte string of at most 31 bytes
    /// (plus the null terminator). The null terminator must appear
    /// exactly once, at the final byte. Returns `VsError::InvalidInput`
    /// if the path is empty, too long, not null-terminated, or contains
    /// an interior null byte that would be interpreted as end-of-string
    /// by QNX `open()`.
    pub fn new_with_device(bitrate: u32, path: &[u8]) -> Result<Self, VsError> {
        if path.is_empty() || path.len() > 32 || path[path.len() - 1] != 0 {
            return Err(VsError::InvalidInput);
        }
        // Reject interior nulls — a misplaced nul would cause QNX `open()`
        // to silently truncate the path.
        if path[..path.len() - 1].contains(&0) {
            return Err(VsError::InvalidInput);
        }
        let mut device_path = [0u8; 32];
        device_path[..path.len()].copy_from_slice(path);
        Ok(Self {
            bitrate,
            device_path,
            device_path_len: path.len(),
            #[cfg(target_os = "nto")]
            fd: -1,
            bus_off: false,
            consecutive_tx_errors: 0,
            last_error: vs_hal::CanError::None,
            error_counters: vs_hal::CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0,
            },
            last_recover_us: None,
            filters: [CanIdFilter { id: 0, mask: 0, accept: false }; CAN_FILTER_SLOTS],
            filter_count: 0,
            default_policy: CanAdmissionPolicy::AcceptUnmatched,
            dropped_by_filter: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// QnxCanBus — CAN ID admission filter (audit-M10)
// ---------------------------------------------------------------------------

impl QnxCanBus {
    /// Append an **accept** entry to the admission filter.
    ///
    /// On a successful frame parse the receive path evaluates the filter
    /// table in insertion order. A slot whose compare predicate
    /// `(incoming_id & mask) == (id & mask)` succeeds is the **first**
    /// match, and that slot's `accept` flag decides whether the frame
    /// reaches the caller (`true` — pass through) or is dropped (`false`).
    ///
    /// Returns `VsError::InvalidInput` if:
    ///
    /// - The filter table is already full (`CAN_FILTER_SLOTS` slots in
    ///   use). Call [`Self::clear_id_filters`] first to repurpose the
    ///   table.
    /// - `mask == 0`. A zero mask matches every incoming frame, which is
    ///   indistinguishable from an unused slot; callers that want to
    ///   accept everything should configure
    ///   `set_default_policy(AcceptUnmatched)` and leave the table empty.
    /// - `mask` has any bit above bit 28 set. Only the lower 29 bits of
    ///   a CAN-ID are meaningful (the upper 3 bits are reserved per ISO
    ///   11898-1), so a non-zero upper bit indicates caller confusion
    ///   between an 11-bit and a 29-bit ID.
    /// - `id` exceeds the 29-bit extended-ID maximum
    ///   ([`vs_hal::CAN_ID_EXTENDED_MAX`]).
    ///
    /// On success the new entry is the **last** in evaluation order.
    pub fn add_id_accept(&mut self, id: u32, mask: u32) -> Result<(), VsError> {
        self.add_filter_slot(id, mask, true)
    }

    /// Append a **reject** entry to the admission filter.
    ///
    /// Semantics mirror [`Self::add_id_accept`] but the slot drops
    /// matching frames instead of passing them through. The
    /// `dropped_by_filter` counter is incremented for each drop and the
    /// receive path loops to fetch the next frame (subject to
    /// [`MAX_FILTER_DROP_ITERATIONS`]).
    ///
    /// Returns `VsError::InvalidInput` on the same conditions as
    /// [`Self::add_id_accept`].
    pub fn add_id_reject(&mut self, id: u32, mask: u32) -> Result<(), VsError> {
        self.add_filter_slot(id, mask, false)
    }

    /// Empty the admission filter table.
    ///
    /// All slots are reset to `(id=0, mask=0, accept=false)` (= unused)
    /// and `filter_count` is set to `0`. The default policy and the
    /// `dropped_by_filter` counter are **not** affected; pair this with
    /// [`Self::set_default_policy`] to fully restore boot defaults, and
    /// rely on observers to interpret a continuously-incrementing
    /// `filter_drop_count` after a clear as evidence of a misconfigured
    /// downstream consumer.
    pub fn clear_id_filters(&mut self) {
        for slot in self.filters.iter_mut() {
            *slot = CanIdFilter {
                id: 0,
                mask: 0,
                accept: false,
            };
        }
        self.filter_count = 0;
    }

    /// Set the policy applied to frames whose ID matches no configured
    /// slot.
    ///
    /// Defaults to [`CanAdmissionPolicy::AcceptUnmatched`] so existing
    /// callers see no behavioural change after upgrading. Safety-
    /// critical deployments should flip this to
    /// [`CanAdmissionPolicy::RejectUnmatched`] and then explicitly
    /// `add_id_accept` the ID ranges they expect; the result is a
    /// fail-closed admission point at the HAL boundary so engine, brake,
    /// or other safety-critical arbitration IDs that the caller did not
    /// allow-list never surface above the HAL.
    pub fn set_default_policy(&mut self, policy: CanAdmissionPolicy) {
        self.default_policy = policy;
    }

    /// Cumulative count of frames dropped by the admission filter.
    ///
    /// Incremented for both explicit reject-slot matches and unmatched
    /// frames under [`CanAdmissionPolicy::RejectUnmatched`]. Saturates
    /// at `u64::MAX` rather than wrapping so a long-running task with a
    /// noisy bus cannot silently zero the counter.
    #[inline]
    pub fn filter_drop_count(&self) -> u64 {
        self.dropped_by_filter
    }

    /// Internal: append `(id, mask, accept)` to the filter table.
    /// Validation rules documented on the public setters.
    #[inline]
    fn add_filter_slot(&mut self, id: u32, mask: u32, accept: bool) -> Result<(), VsError> {
        // Table full — caller must clear before reusing.
        if (self.filter_count as usize) >= CAN_FILTER_SLOTS {
            return Err(VsError::InvalidInput);
        }
        // `mask == 0` collides with the "unused slot" sentinel and is
        // semantically meaningless (would match every ID — use
        // `set_default_policy(AcceptUnmatched)` instead).
        if mask == 0 {
            return Err(VsError::InvalidInput);
        }
        // CAN-ID is 29 bits on the wire; anything above bit 28 is
        // reserved per ISO 11898-1 and indicates caller confusion.
        if mask & !CAN_ID_MASK_29BIT != 0 {
            return Err(VsError::InvalidInput);
        }
        if id > vs_hal::CAN_ID_EXTENDED_MAX {
            return Err(VsError::InvalidInput);
        }
        let idx = self.filter_count as usize;
        self.filters[idx] = CanIdFilter { id, mask, accept };
        self.filter_count = self.filter_count.saturating_add(1);
        Ok(())
    }

    /// Audit fix (audit-M10): evaluate the admission filter against a
    /// freshly-parsed frame ID.
    ///
    /// Returns `true` when the caller should pass the frame upstream;
    /// returns `false` when the frame must be dropped. On a drop the
    /// `dropped_by_filter` counter is bumped (saturating).
    ///
    /// Evaluation order:
    ///
    /// 1. Walk `filters[..filter_count]`. The **first** slot whose
    ///    compare predicate succeeds decides the outcome (`accept`).
    /// 2. If no slot matches, apply `default_policy`.
    #[inline]
    #[allow(dead_code)] // Used on QNX target and exercised by unit tests.
    fn admit_frame(&mut self, id: u32) -> bool {
        let count = (self.filter_count as usize).min(CAN_FILTER_SLOTS);
        // Two-phase: first read the slot table (immutable view of
        // `self.filters`), then update the drop counter on `self` once
        // we know the verdict. Splitting the borrows keeps the borrow
        // checker happy without spending an `unsafe` budget here.
        let mut verdict: Option<bool> = None;
        for i in 0..count {
            let slot = self.filters[i];
            // mask == 0 cannot occur via the public setters (`add_filter_slot`
            // rejects it), but defensively skip such entries so a memory-
            // corrupted slot cannot subvert the filter into "accept all".
            if slot.mask == 0 {
                continue;
            }
            if (id & slot.mask) == (slot.id & slot.mask) {
                verdict = Some(slot.accept);
                break;
            }
        }
        match verdict {
            Some(true) => true,
            Some(false) => {
                self.dropped_by_filter = self.dropped_by_filter.saturating_add(1);
                false
            }
            None => match self.default_policy {
                CanAdmissionPolicy::AcceptUnmatched => true,
                CanAdmissionPolicy::RejectUnmatched => {
                    self.dropped_by_filter = self.dropped_by_filter.saturating_add(1);
                    false
                }
            },
        }
    }
}

impl QnxCanBus {
    #[cfg(target_os = "nto")]
    fn open_device(&mut self) -> Result<(), VsError> {
        if self.fd >= 0 {
            return Ok(());
        }
        // audit-LOW: pass `O_CLOEXEC` so the CAN descriptor is not
        // inherited across `posix_spawn()` into a child process — a
        // descriptor leak would let an unprivileged child read/write
        // the CAN bus without ever opening `/dev/can*` itself.
        // SAFETY: device_path is a valid null-terminated string;
        // `O_RDWR | O_CLOEXEC` is a valid POSIX flag combination.
        let fd = unsafe {
            qnx_ffi::open(
                self.device_path.as_ptr(),
                qnx_ffi::O_RDWR | qnx_ffi::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(qnx_errno_to_vserror(qnx_ffi::errno()));
        }
        self.fd = fd;
        Ok(())
    }

    /// Query CAN bus-off state via devctl.
    ///
    /// The CAN bus-state devctl command number is SDP-specific (declared
    /// in `<dev/can.h>` shipped with QNX SDP). Previous revisions hard-
    /// coded an unverified value; rather than risk a kernel-side stack
    /// write through a wrong ioctl, this probe is compiled out until the
    /// caller opts in via the `qnx-link-detect` cargo feature and
    /// supplies a verified constant. Without the feature `bus_off`
    /// remains at its default `false` — callers must not rely on this
    /// signal for safety-critical shutdown.
    ///
    /// # Audit fix HIGH-S (heuristic-vs-devctl ordering)
    ///
    /// The merge semantics with the in-process heuristic are **sticky-
    /// OR**: once the consecutive-TX-error heuristic latches
    /// `bus_off = true` (in `<Self as CanBus>::transmit`), a devctl
    /// reading of "not bus-off" does **not** flip the latch back to
    /// false. Previously the devctl reading unconditionally
    /// overwrote the heuristic latch, so a sequence of "16 TX errors
    /// latch heuristic → devctl returns CAN_STATE_ERROR_ACTIVE because
    /// the kernel hadn't yet observed the same TX failures →
    /// `self.bus_off` flips back to false" turned the safety-critical
    /// shutdown signal into a race-vulnerable flicker. The heuristic
    /// latch can only be cleared by [`Self::recover_bus_off`] or by a
    /// successful TX (which clears `bus_off` before this function runs
    /// in that path, so the OR below preserves the new state).
    #[cfg(all(target_os = "nto", feature = "qnx-link-detect"))]
    fn update_bus_off_state(&mut self) {
        if self.fd < 0 {
            return;
        }
        let mut state: i32 = 0;
        // SAFETY: fd is valid, state is a valid writable i32. The devctl
        // command number `CAN_DEVCTL_GET_BUS_STATE` MUST be supplied by
        // the caller's build system (e.g., a `build.rs` translating the
        // target SDP's `<dev/can.h>` into a Rust constant) before this
        // feature is enabled. An incorrect number can cause kernel-side
        // writes past the 4-byte `state` buffer.
        let ret = unsafe {
            qnx_ffi::devctl(
                self.fd,
                // Intentionally unresolved: a build-script-supplied
                // constant is required. Leaving this `0` makes the
                // feature fail loudly at link time rather than silently
                // trashing memory.
                qnx_ffi::CAN_DEVCTL_GET_BUS_STATE,
                &mut state as *mut i32 as *mut u8,
                core::mem::size_of::<i32>(),
                core::ptr::null_mut(),
            )
        };
        if ret == 0 {
            // Audit fix HIGH-S: sticky-OR. Only escalate to bus-off when
            // either source agrees; never demote a latched bus-off back
            // to healthy via a stale devctl reading. Cleared explicitly
            // by `recover_bus_off()` or implicitly on a successful TX
            // (which sets `self.bus_off = false` BEFORE calling us, so
            // the OR below correctly carries that new false through
            // when the kernel also says "not bus-off").
            let kernel_bus_off = state == qnx_ffi::CAN_STATE_BUS_OFF;
            self.bus_off = self.bus_off || kernel_bus_off;
        }
    }

    /// No-op stub when `qnx-link-detect` is disabled.
    ///
    /// `bus_off` is not refreshed here; the default-feature build relies
    /// solely on the consecutive-TX-error heuristic in
    /// [`<Self as CanBus>::transmit`], which latches `bus_off = true`
    /// once `MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF` consecutive TX
    /// errors are observed. Callers that need authoritative bus-off
    /// readings must opt into the `qnx-link-detect` feature and supply
    /// `CAN_DEVCTL_GET_BUS_STATE` via their build system.
    #[cfg(all(target_os = "nto", not(feature = "qnx-link-detect")))]
    fn update_bus_off_state(&mut self) {}

    /// Best-effort cross-check that the in-process `bitrate` matches the
    /// bitrate the `dev-can-*` resource manager is actually clocking the
    /// wire at.
    ///
    /// QNX SDP does not expose a portable devctl for this in the
    /// default headers; the most likely candidate is
    /// `CAN_DEVCTL_GET_INFO` (or an SDP-specific cousin) returning a
    /// struct with the runtime bitrate alongside other controller
    /// telemetry. This method is therefore gated behind
    /// `qnx-link-detect`, where the caller's build system supplies both
    /// the command number and the matching struct layout.
    ///
    /// Returns:
    /// - `Ok(())` if the driver reports a bitrate equal to the value
    ///   passed to [`QnxCanBus::new`].
    /// - `Err(VsError::InvalidInput)` if the values differ.
    /// - `Err(VsError::NotInitialized)` if the device fd is not yet
    ///   open.
    /// - Any other [`VsError`] surfaced from the underlying devctl.
    #[cfg(all(target_os = "nto", feature = "qnx-link-detect"))]
    pub fn validate_against_driver(&mut self) -> Result<(), VsError> {
        // Open the device lazily so the caller doesn't have to issue an
        // I/O first just to validate. The fd is reused for subsequent
        // receive/transmit calls.
        self.open_device()?;
        // Minimal struct shape: a single u32 holding the runtime bitrate
        // in bits per second. Real SDP definitions of `can_info_t` are
        // wider; the caller's build system must extend this if its
        // command number returns a larger payload.
        #[repr(C)]
        struct CanInfoBitrateOnly {
            bitrate: u32,
        }
        let mut info = CanInfoBitrateOnly { bitrate: 0 };
        // SAFETY: fd is valid (open_device() succeeded); `info` is a
        // valid writable target whose size matches the documented
        // CAN_DEVCTL_GET_INFO payload supplied by the build system. If
        // that payload is larger than 4 bytes the caller MUST extend
        // `CanInfoBitrateOnly` before enabling this feature.
        let ret = unsafe {
            qnx_ffi::devctl(
                self.fd,
                qnx_ffi::CAN_DEVCTL_GET_INFO,
                &mut info as *mut CanInfoBitrateOnly as *mut u8,
                core::mem::size_of::<CanInfoBitrateOnly>(),
                core::ptr::null_mut(),
            )
        };
        if ret != 0 {
            return Err(qnx_errno_to_vserror(qnx_ffi::errno()));
        }
        if info.bitrate == self.bitrate {
            Ok(())
        } else {
            Err(VsError::InvalidInput)
        }
    }
}

#[cfg(target_os = "nto")]
impl Drop for QnxCanBus {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd was obtained from a successful open() call and
            // has not been closed elsewhere (this is the only path that
            // closes it). Per POSIX.2008, after close() the fd is in an
            // unspecified state — it MUST NOT be reused even if close()
            // returns EINTR, because on conforming systems (including
            // QNX Neutrino) the descriptor has already been released by
            // the kernel when EINTR is signalled. We therefore ignore
            // the return value and let Drop run to completion; retrying
            // close() on EINTR would risk closing a descriptor newly
            // assigned to another thread.
            let ret = unsafe { qnx_ffi::close(self.fd) };
            // audit-LOW: surface non-EINTR close failures via a
            // process-wide counter. EINTR is benign (kernel released
            // the fd before signalling). EBADF / EIO are real bugs:
            // double-close, kernel I/O error, or descriptor accounting
            // drift. Drop has no return channel; the counter is the
            // only observability we get.
            if ret < 0 && !is_eintr(qnx_ffi::errno()) {
                CLOSE_ERROR_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

impl CanBus for QnxCanBus {
    #[cfg(target_os = "nto")]
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        self.open_device()?;
        // Audit fix (perf): use `MaybeUninit` instead of zeroing 72 bytes
        // on every RX. The kernel writes the prefix `[..n_usize]` and we
        // only read that slice back via `parse_can_frame`; bytes past
        // `n_usize` are never observed.
        const BUF_LEN: usize = CAN_HEADER_SIZE + CAN_MAX_DATA;

        // Audit fix HIGH (EINTR cap + EAGAIN→Ok(None)).
        //
        // EINTR retries are bounded by `MAX_EINTR_RETRIES`. POSIX
        // guarantees forward progress per syscall but does not bound the
        // number of EINTRs; without a cap, an adversarial neighbour task
        // with `pthread_kill()` capability can pin the receive task in an
        // unbounded retry loop and starve the scheduler. The cap converts
        // that DoS into a bounded `VsError::Timeout` that the caller can
        // observe and act on (e.g., reset the fd, raise an alert).
        //
        // EAGAIN / EWOULDBLOCK are mapped to `Ok(None)` so a non-blocking-
        // empty bus is not surfaced as a spurious Timeout error.
        //
        // Audit fix (audit-M10): wrap the read-and-parse in a bounded loop
        // so frames rejected by the admission filter are silently dropped
        // (and `dropped_by_filter` bumped) without the caller seeing them.
        // The loop is capped by `MAX_FILTER_DROP_ITERATIONS` so an
        // adversary that floods the bus with rejected IDs cannot pin this
        // task — after the cap is hit the function returns `Ok(None)` and
        // the caller may retry on the next tick.
        let fd = self.fd;
        for _ in 0..MAX_FILTER_DROP_ITERATIONS {
            let mut buf: core::mem::MaybeUninit<[u8; BUF_LEN]> =
                core::mem::MaybeUninit::uninit();
            // SAFETY: `buf` is a stack allocation of exactly BUF_LEN bytes;
            // its pointer is valid and writable for that range. The kernel
            // writes the requested `BUF_LEN` (or fewer) bytes; we treat
            // bytes past the returned count as uninit and never read them.
            let buf_ptr: *mut u8 = unsafe { (*buf.as_mut_ptr()).as_mut_ptr() };
            let outcome = retry_on_eintr(
                || {
                    // SAFETY: fd is valid (checked by open_device above);
                    // `buf_ptr` is valid and writable for `BUF_LEN` bytes
                    // (stack-owned MaybeUninit of that exact size).
                    let n = unsafe { qnx_ffi::read(fd, buf_ptr, BUF_LEN) };
                    if n >= 0 {
                        Ok(n)
                    } else {
                        Err(qnx_ffi::errno())
                    }
                },
                is_eintr,
            );
            self.update_bus_off_state();
            let n = match outcome {
                RxOutcome::Got(n) => n,
                RxOutcome::Err(err) if is_would_block(err) => return Ok(None),
                RxOutcome::EintrCapHit => {
                    self.error_counters.rx_error_count =
                        self.error_counters.rx_error_count.saturating_add(1);
                    self.last_error = vs_hal::CanError::BusError;
                    return Err(VsError::Timeout);
                }
                RxOutcome::Err(err) => {
                    self.error_counters.rx_error_count =
                        self.error_counters.rx_error_count.saturating_add(1);
                    self.last_error = vs_hal::CanError::BusError;
                    return Err(qnx_errno_to_vserror(err));
                }
            };
            if n == 0 {
                return Ok(None);
            }
            // Reject short reads that cannot contain a full CAN header:
            // the resource manager must deliver at least the 8-byte header
            // in a single read. Anything shorter is a framing-layer bug
            // and would confuse `parse_can_frame` into returning a lossy
            // InvalidInput without a useful diagnostic.
            let n_usize = n as usize;
            if n_usize < CAN_HEADER_SIZE || n_usize > BUF_LEN {
                return Err(VsError::InvalidInput);
            }
            // SAFETY: the kernel wrote `n_usize` bytes (>= CAN_HEADER_SIZE,
            // <= BUF_LEN) into the buffer; that slice is now initialized.
            // The pointer is valid for the lifetime of `buf`.
            let init_slice: &[u8] =
                unsafe { core::slice::from_raw_parts(buf_ptr, n_usize) };
            // Delegate parsing to the pure helper so the same logic is
            // exercised by unit tests on the development host.
            let frame = parse_can_frame(init_slice)?;
            // Audit fix (audit-M10): apply the admission filter at the HAL
            // boundary. Frames the filter rejects are silently dropped
            // (counter incremented) and the loop fetches the next one.
            if self.admit_frame(frame.id) {
                return Ok(Some(frame));
            }
        }
        // Hit the per-call drop cap without finding an admissible frame.
        // Surface `Ok(None)` so the caller yields and re-enters on the
        // next tick rather than seeing this as an error condition.
        Ok(None)
    }

    #[cfg(not(target_os = "nto"))]
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        // Non-QNX host build: return a clean error (no panic per CLAUDE.md).
        Err(VsError::NotInitialized)
    }

    #[cfg(target_os = "nto")]
    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        self.open_device()?;
        // `serialize_can_frame` writes exactly `CAN_HEADER_SIZE +
        // data_len` bytes, and the `write()` syscall below only consumes
        // `[..total]`, so we don't need to pre-zero the trailing bytes.
        // Zero the whole buffer anyway: `serialize_can_frame` requires
        // an `&mut [u8]` slice (initialized memory). The cost is 72
        // bytes per transmit, the same order as one cacheline; spending
        // it here keeps the helper's safe-Rust interface intact.
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        let total = serialize_can_frame(frame, &mut buf)?;

        // Audit fix: partial-write retry loop + bus-off heuristic.
        // CAN resource managers normally write a full frame in a single
        // syscall, but `write()` is allowed to return short. Retry up to
        // `MAX_PARTIAL_WRITE_RETRIES` times before declaring the device
        // unhealthy, instead of silently emitting a truncated frame.
        const MAX_PARTIAL_WRITE_RETRIES: u8 = 4;
        // Audit fix: bus-off heuristic threshold. Surface as a named
        // constant near `MAX_PARTIAL_WRITE_RETRIES` so reviewers see both
        // tunables in one grep, and so the README can reference the name
        // rather than a magic literal. Tied to the documented contract in
        // `README.md` under "is_bus_off() — safety-critical-shutdown
        // warning"; update both sites together.
        //
        // audit-LOW (saturation semantics): `consecutive_tx_errors` is a
        // saturating `u8` (see the `saturating_add` below). The bus-off
        // latch fires the first time the counter crosses
        // `MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF`. Subsequent TX errors
        // re-execute the same `>=` check and re-set `self.bus_off = true`
        // idempotently — there is no spurious "doubly-set" state and no
        // counter overflow can wrap silently past the threshold (the
        // saturating add pins at `u8::MAX = 255` once it reaches 255).
        // The latch is **only** cleared by a successful TX (the assignment
        // at the end of this function) or by an explicit caller-driven
        // `recover_bus_off()`; nothing else demotes a latched bus-off
        // back to `false`. Reviewers updating this logic should preserve
        // both clear paths.
        const MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF: u8 = 16;
        let mut written: usize = 0;
        let mut partial_attempts: u8 = 0;
        while written < total {
            // Audit fix CRIT-6 (EINTR cap on TX). Wrap the single
            // `write()` syscall in the bounded `retry_on_eintr` helper.
            // The previous implementation looped unbounded on EINTR,
            // mirroring the same signal-storm DoS that was already fixed
            // on the receive paths. The cap converts that DoS into a
            // bounded `VsError::Timeout` the caller can observe.
            let fd = self.fd;
            let buf_ptr = buf.as_ptr();
            let outcome = retry_on_eintr(
                || {
                    // SAFETY: fd is valid (open_device above);
                    // `buf_ptr.add(written)` is in-bounds for
                    // `total - written` bytes (buf is `[u8; CAN_HEADER_SIZE
                    // + CAN_MAX_DATA]`, and `total` is bounded by that
                    // size from serialize_can_frame).
                    let n =
                        unsafe { qnx_ffi::write(fd, buf_ptr.add(written), total - written) };
                    if n >= 0 {
                        Ok(n)
                    } else {
                        Err(qnx_ffi::errno())
                    }
                },
                is_eintr,
            );
            let n = match outcome {
                RxOutcome::Got(n) => n,
                RxOutcome::EintrCapHit => {
                    // Bounded-retry exhaustion: signal-storm DoS bail-out.
                    self.error_counters.tx_error_count =
                        self.error_counters.tx_error_count.saturating_add(1);
                    self.last_error = vs_hal::CanError::BusOff;
                    self.update_bus_off_state();
                    return Err(VsError::Timeout);
                }
                RxOutcome::Err(err) => {
                    // Real error path: count it, update last_error, and bump
                    // the consecutive-error heuristic for bus-off detection.
                    self.error_counters.tx_error_count =
                        self.error_counters.tx_error_count.saturating_add(1);
                    self.last_error = vs_hal::CanError::BusOff;
                    self.consecutive_tx_errors = self.consecutive_tx_errors.saturating_add(1);
                    if self.consecutive_tx_errors >= MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF {
                        self.bus_off = true;
                    }
                    self.update_bus_off_state();
                    return Err(qnx_errno_to_vserror(err));
                }
            };
            let progressed = n as usize;
            if progressed == 0 {
                // Kernel queued nothing; treat as a partial-write event.
                partial_attempts = partial_attempts.saturating_add(1);
                if partial_attempts >= MAX_PARTIAL_WRITE_RETRIES {
                    self.error_counters.tx_error_count =
                        self.error_counters.tx_error_count.saturating_add(1);
                    self.last_error = vs_hal::CanError::BusOff;
                    return Err(VsError::BusError);
                }
                continue;
            }
            written += progressed;
            if written < total {
                partial_attempts = partial_attempts.saturating_add(1);
                if partial_attempts >= MAX_PARTIAL_WRITE_RETRIES {
                    self.error_counters.tx_error_count =
                        self.error_counters.tx_error_count.saturating_add(1);
                    self.last_error = vs_hal::CanError::BusOff;
                    return Err(VsError::BusError);
                }
            }
        }
        // Success: clear the consecutive-error counter and the heuristic
        // bus-off flag. The feature-on path may still set `bus_off` from
        // a real devctl reading on the next call.
        self.consecutive_tx_errors = 0;
        if !cfg!(feature = "qnx-link-detect") {
            self.bus_off = false;
        }
        self.update_bus_off_state();
        Ok(())
    }

    #[cfg(not(target_os = "nto"))]
    fn transmit(&mut self, _frame: &RawCanFrame) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    /// Configured bitrate in bits per second.
    ///
    /// **Informational only.** The value returned here is whatever was
    /// passed to [`QnxCanBus::new`] / [`QnxCanBus::new_with_device`] at
    /// construction time; it is **not** validated against the running
    /// `dev-can-*` resource manager. The resource manager is started
    /// with `-b<rate>` at boot, and stock QNX SDP does not expose a
    /// portable `devctl` to read it back, so the HAL has no way to
    /// detect a mismatch between the value held here and the bitrate
    /// the controller is actually clocking. Callers that need an
    /// authoritative bitrate must obtain it out-of-band (e.g. by
    /// reading the same boot configuration). See
    /// [`QnxCanBus::validate_against_driver`] for an opt-in best-effort
    /// probe behind the `qnx-link-detect` feature.
    #[inline]
    fn bitrate(&self) -> u32 {
        self.bitrate
    }

    /// Returns the cached bus-off state.
    ///
    /// On QNX (default feature set) this reflects the TX-error heuristic
    /// (latched when consecutive failures reach
    /// `MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF`, cleared on a successful
    /// TX or on a call to [`Self::recover_bus_off`]). On non-QNX builds
    /// the state is settable from test code via mocks but otherwise
    /// remains `false`.
    #[inline]
    fn is_bus_off(&self) -> bool {
        self.bus_off
    }

    /// Audit fix: surface the most recent I/O error class via the
    /// `CanBus::last_error` extension point so callers can distinguish
    /// "haven't talked to the bus yet" (`None`) from "last TX/RX
    /// failed" (`BusError`). The trait default returns `None`, which
    /// silently disabled this observability surface.
    #[inline]
    fn last_error(&self) -> vs_hal::CanError {
        self.last_error
    }

    /// Audit fix: surface tallied TX/RX error counts via the
    /// `CanBus::error_counters` extension point. The trait default
    /// returns zeroed counters.
    #[inline]
    fn error_counters(&self) -> Option<vs_hal::CanErrorCounters> {
        Some(self.error_counters)
    }

    /// Clear a latched bus-off state and (when enabled) request the CAN
    /// controller to leave the bus-off condition.
    ///
    /// The trait default is `Ok(())`, which is wrong for `QnxCanBus`
    /// because the default-feature build latches `bus_off = true` after
    /// `MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF` TX failures via the
    /// heuristic in [`Self::transmit`]; without this override callers
    /// have no programmatic way to clear the flag short of dropping the
    /// handle.
    ///
    /// Behaviour:
    ///
    /// - Always: reset `consecutive_tx_errors = 0` and `bus_off = false`
    ///   (in-process state). Also clear `last_error` so observability
    ///   surfaces don't keep reporting a stale `BusError` after a
    ///   successful recovery.
    /// - With `qnx-link-detect`: additionally issue the
    ///   `CAN_DEVCTL_SET_BUS_STATE` devctl asking the controller to
    ///   transition to `CAN_STATE_ERROR_ACTIVE`. If the devctl fails,
    ///   `bus_off` is left cleared (the caller can re-detect via the
    ///   next I/O) but the function returns the underlying VsError so
    ///   the caller knows the hardware-level recovery did not complete.
    /// - Non-QNX builds: no-op `Ok(())` after the in-process reset.
    ///
    /// # Rate limit (audit-M11)
    ///
    /// Two consecutive calls within [`RECOVER_BUS_OFF_MIN_INTERVAL_US`]
    /// return [`VsError::ResourceExhausted`] **without** issuing the
    /// devctl or touching in-process state. This enforces the CAN-spec
    /// 128×11 recessive-bit recovery window (ISO 11898-1) so a
    /// misbehaving caller cannot force the controller out of bus-off
    /// before the firmware finishes its recovery state machine. The
    /// helper [`simulate_recover_bus_off_rate_limit`] documents the
    /// exact contract and is what the unit tests exercise.
    #[cfg(target_os = "nto")]
    fn recover_bus_off(&mut self) -> Result<(), VsError> {
        // audit-M11: rate-check BEFORE any state mutation. A rejected
        // call must leave both the in-process heuristic counters AND
        // the hardware state untouched; otherwise a hostile caller
        // could repeatedly clear the latched `bus_off` flag even though
        // we never reach the devctl.
        let timer = QnxTimer::new();
        let now = timer.now_us();
        simulate_recover_bus_off_rate_limit(now, self.last_recover_us)?;

        // In-process state reset runs after the rate check; even if
        // the devctl below fails, the heuristic counter has been
        // zeroed and the next successful TX will re-confirm health.
        self.consecutive_tx_errors = 0;
        self.bus_off = false;
        self.last_error = vs_hal::CanError::None;

        #[cfg(feature = "qnx-link-detect")]
        {
            if self.fd < 0 {
                // Record the attempt so the next call still respects
                // the recovery window even though we had nothing to
                // devctl. `u64::MAX` (clock failure) is recorded as
                // `None` so we don't anchor the window to a sentinel.
                if now != u64::MAX {
                    self.last_recover_us = Some(now);
                }
                return Ok(());
            }
            let mut state: i32 = qnx_ffi::CAN_STATE_ERROR_ACTIVE;
            // SAFETY: fd is valid (checked above); `state` is a valid
            // writable i32 and exactly 4 bytes match the documented
            // `CAN_DEVCTL_SET_BUS_STATE` argument size. The command
            // number itself is supplied by the caller's build system
            // (see the `qnx-link-detect` compile_error! at the top of
            // this file); an incorrect number could trigger a
            // kernel-side stack write past this buffer, so the contract
            // is documented loudly.
            let ret = unsafe {
                qnx_ffi::devctl(
                    self.fd,
                    qnx_ffi::CAN_DEVCTL_SET_BUS_STATE,
                    &mut state as *mut i32 as *mut u8,
                    core::mem::size_of::<i32>(),
                    core::ptr::null_mut(),
                )
            };
            if ret != 0 {
                return Err(qnx_errno_to_vserror(qnx_ffi::errno()));
            }
        }
        // audit-M11: only record the timestamp on a successful path so
        // a failed devctl does not extend the rate-limit window. Skip
        // the record if the clock is unavailable (`u64::MAX`); the
        // helper already treats that sentinel as "allow through", and
        // recording it would leave the next legitimate call permanently
        // anchored to the sentinel.
        if now != u64::MAX {
            self.last_recover_us = Some(now);
        }
        Ok(())
    }

    #[cfg(not(target_os = "nto"))]
    fn recover_bus_off(&mut self) -> Result<(), VsError> {
        // audit-M11: rate-check on the host shim too, for symmetry with
        // the QNX path. `QnxTimer::now_us()` returns `u64::MAX` on
        // non-QNX targets, which `simulate_recover_bus_off_rate_limit`
        // treats as "allow through" — so this preserves the existing
        // host-test behaviour while keeping one code path between the
        // shim and the production implementation.
        let timer = QnxTimer::new();
        let now = timer.now_us();
        simulate_recover_bus_off_rate_limit(now, self.last_recover_us)?;

        // Host build: still reset in-process counters/state so unit
        // tests (and any code that manually pokes the heuristic via
        // mocks) see a deterministic post-recovery state.
        self.consecutive_tx_errors = 0;
        self.bus_off = false;
        self.last_error = vs_hal::CanError::None;
        if now != u64::MAX {
            self.last_recover_us = Some(now);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// QnxTimer
// ---------------------------------------------------------------------------

/// QNX Neutrino timer via `clock_gettime(CLOCK_MONOTONIC)` / `ClockCycles()`.
///
/// Holds a private `Cell<u64>` used by
/// [`QnxTimer::cycle_count_monotonic`] to enforce strict per-instance
/// increase on top of the raw `ClockCycles()` reading. The cell is
/// interior-mutable behind `&self` so the wrapper can be called from
/// `&self` contexts (matching the surrounding `Timer` trait shape) and
/// does not require the caller to thread a `&mut QnxTimer` through nonce
/// derivation code paths.
///
/// `Cell<u64>` is `!Sync`, which matches the rest of this HAL: callers
/// must not share a `QnxTimer` across threads without external
/// synchronisation. Each task that derives nonces should hold its own
/// `QnxTimer` instance; the monotonic guarantee is per-instance.
#[repr(C)]
pub struct QnxTimer {
    /// Highest value ever returned by `cycle_count_monotonic` on this
    /// instance. Used to enforce strict increase across reads.
    /// audit-LOW: see `cycle_count_monotonic` for the rationale.
    mono_last: core::cell::Cell<u64>,
}

impl QnxTimer {
    /// Create a new QNX timer handle.
    pub const fn new() -> Self {
        Self {
            mono_last: core::cell::Cell::new(0),
        }
    }

    /// Returns a strictly-increasing within-instance counter derived from
    /// `ClockCycles()`. NOT a real cycle count once monotonic correction
    /// has been applied — suitable for nonce derivation, NOT for
    /// benchmarking. SMP migration can yield a raw cycle that is smaller
    /// than the previous read; this wrapper takes `max(raw, last + 1)`
    /// and writes the result back, so each return is strictly greater
    /// than the last on this instance.
    ///
    /// # Trade-offs
    ///
    /// - The strict-increase guarantee is **per-instance** only. Two
    ///   `QnxTimer` instances will not coordinate; nonce derivation
    ///   code paths must hold a single shared instance.
    /// - The correction is invisible until SMP migration actually
    ///   regresses the raw counter. On a stable core the return value
    ///   equals the raw `ClockCycles()` reading.
    /// - On a regression event the returned value drifts forward by
    ///   exactly 1 cycle, so this is **NOT** a wall-clock-accurate
    ///   cycle source. Do not use for benchmarking, RTT measurement,
    ///   or anything that requires the absolute count to track real
    ///   CPU cycles.
    /// - On targets where `ClockCycles()` is unavailable
    ///   (non-`target_os = "nto"`) the underlying read returns `None`
    ///   and this wrapper falls back to `last + 1` — i.e. it still
    ///   guarantees strict increase, but the values are no longer
    ///   tied to hardware time at all. Host-only tests can rely on
    ///   the strict-increase property.
    /// - Wraparound at `u64::MAX` would require ~10^11 years even at
    ///   1 GHz call rates, so saturation is not engineered for.
    #[inline]
    pub fn cycle_count_monotonic(&self) -> u64 {
        // `Timer::cycle_count` is already imported via the top-of-file
        // `use vs_hal::Timer;`. On non-QNX hosts the trait returns
        // `None`; on QNX it returns `Some(raw)`. We unwrap to 0 then
        // immediately bump past `last`, so the strict-increase
        // invariant holds on both targets.
        let raw = <Self as Timer>::cycle_count(self).unwrap_or(0);
        let last = self.mono_last.get();
        let next = core::cmp::max(raw, last.wrapping_add(1));
        self.mono_last.set(next);
        next
    }
}

impl Default for QnxTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for QnxTimer {
    #[cfg(target_os = "nto")]
    /// Read the monotonic clock in microseconds.
    ///
    /// # Audit fix — `u64::MAX` sentinel on failure
    ///
    /// `0` is a valid timestamp at boot; previously a `clock_gettime`
    /// failure was indistinguishable from a legitimate early-boot reading,
    /// which is dangerous for any caller that derives a nonce or window
    /// from `now_us()`. The function now returns `u64::MAX` on failure,
    /// on negative `tv_sec`, or on out-of-range `tv_nsec`. Callers MUST
    /// treat `u64::MAX` as "clock unavailable" and refuse to use it as
    /// nonce material.
    ///
    /// In the success path the conversion uses `checked_*` arithmetic so
    /// an implausibly large `tv_sec` does not silently saturate.
    fn now_us(&self) -> u64 {
        let mut ts = qnx_ffi::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes to a valid Timespec pointer.
        let ret = unsafe { qnx_ffi::clock_gettime(qnx_ffi::CLOCK_MONOTONIC, &mut ts) };
        if ret != 0 {
            return u64::MAX;
        }
        // Negative tv_sec or out-of-range tv_nsec is a driver bug — refuse.
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return u64::MAX;
        }
        let sec_us = match (ts.tv_sec as u64).checked_mul(1_000_000) {
            Some(v) => v,
            None => return u64::MAX,
        };
        match sec_us.checked_add((ts.tv_nsec as u64) / 1_000) {
            Some(v) => v,
            None => u64::MAX,
        }
    }

    #[cfg(not(target_os = "nto"))]
    fn now_us(&self) -> u64 {
        // Same sentinel as the QNX path so cross-platform callers can
        // branch consistently. No panic per CLAUDE.md.
        u64::MAX
    }

    #[cfg(target_os = "nto")]
    #[inline]
    fn cycle_count(&self) -> Option<u64> {
        // SAFETY: ClockCycles() is a leaf function with no side effects.
        Some(unsafe { qnx_ffi::ClockCycles() })
    }

    #[cfg(not(target_os = "nto"))]
    #[inline]
    fn cycle_count(&self) -> Option<u64> {
        None
    }
}

// ---------------------------------------------------------------------------
// QnxEthernetPhy
// ---------------------------------------------------------------------------

/// QNX Neutrino Ethernet via `io-pkt` network stack.
///
/// On QNX, raw Ethernet frames are accessed through the BPF
/// (Berkeley Packet Filter) interface. Stock QNX SDP exposes BPF
/// devices as numbered nodes (`/dev/bpf0`, `/dev/bpf1`, ...); the
/// unindexed `/dev/bpf` does not exist on a default install. The
/// `io-pkt` network stack must be started before constructing this
/// handle.
///
/// The device path can be customised via [`new_with_device`](Self::new_with_device).
///
/// **Thread safety.** Same caveat as [`QnxCanBus`]: `Send` but not
/// `Sync`. Use external synchronisation for multi-threaded access.
#[repr(C)]
pub struct QnxEthernetPhy {
    link_speed: u32,
    /// Device path, null-terminated. Default: `/dev/bpf0` (audit fix).
    #[allow(dead_code)] // Read on QNX target only.
    device_path: [u8; 32],
    #[allow(dead_code)]
    device_path_len: usize,
    /// Network interface name, NUL-padded to `IFNAMSIZ` (16) bytes, used
    /// as the `ifr_name` field of `struct ifreq` for `SIOCGIFFLAGS`.
    /// Independent from `device_path` because BPF device names
    /// (`/dev/bpf0`) and interface names (`en0`) are orthogonal on QNX:
    /// a single BPF fd can be re-bound to any interface via `BIOCSETIF`.
    /// Default: `en0` (standard QNX `io-pkt` first-Ethernet name).
    #[allow(dead_code)] // Read on QNX target with qnx-link-detect.
    iface_name: [u8; IFNAMSIZ],
    /// Length of the iface-name payload in bytes (excludes trailing
    /// NUL padding). `0 < iface_name_len < IFNAMSIZ` always.
    #[allow(dead_code)]
    iface_name_len: usize,
    /// BPF file descriptor (-1 = not opened).
    #[cfg(target_os = "nto")]
    fd: i32,
    /// Cached link-up state (updated on each I/O operation on QNX).
    #[cfg(target_os = "nto")]
    link_up: bool,
    /// Audit fix (perf): timestamp (microseconds) of the last successful
    /// link-state probe via `SIOCGIFFLAGS`. Used to rate-limit the
    /// per-TX probe to at most one syscall every
    /// `LINK_PROBE_INTERVAL_US`. Only meaningful when the
    /// `qnx-link-detect` feature is on; carried unconditionally to keep
    /// the struct layout stable across feature flips (matters for the
    /// `#[repr(C)]` concern handled by the sibling agent).
    ///
    /// Audit fix HIGH-T: `Option<u64>` (not bare `u64`). The previous
    /// `0` sentinel was ambiguous with a legitimate boot-time
    /// `CLOCK_MONOTONIC` reading of `0` µs (QNX does not guarantee a
    /// non-zero monotonic clock at process start). A genuine `now == 0`
    /// would leave `last_link_probe_us == 0`, the rate-limiter would
    /// re-treat the probe as "first call", and every subsequent TX
    /// would also bypass the rate limit — collapsing the 100 ms
    /// coalescing window into a per-TX ioctl storm. `None` disambiguates
    /// "never probed" from "last probed at t=0".
    #[cfg(target_os = "nto")]
    last_link_probe_us: Option<u64>,
}

impl QnxEthernetPhy {
    /// Create a new QNX Ethernet handle on the default `/dev/bpf0` device.
    ///
    /// (Audit fix: previously the default was `/dev/bpf`, which does
    /// not exist on a stock QNX SDP install — opening it returned
    /// `ENOENT`. Numbered BPF nodes are the canonical path.)
    pub const fn new(link_speed_mbps: u32) -> Self {
        let mut path = [0u8; 32];
        path[0] = b'/';
        path[1] = b'd';
        path[2] = b'e';
        path[3] = b'v';
        path[4] = b'/';
        path[5] = b'b';
        path[6] = b'p';
        path[7] = b'f';
        path[8] = b'0';
        path[9] = 0;
        // Default iface name "en0" — QNX `io-pkt` standard first-Ethernet
        // name. Override via `new_with_iface` when targeting a different
        // PHY (e.g. `en1`, `wm0`).
        let mut iface = [0u8; IFNAMSIZ];
        iface[0] = b'e';
        iface[1] = b'n';
        iface[2] = b'0';
        Self {
            link_speed: link_speed_mbps,
            device_path: path,
            // 9 chars + nul-terminator at index 9 → 9 bytes of payload.
            device_path_len: 9,
            iface_name: iface,
            iface_name_len: 3,
            #[cfg(target_os = "nto")]
            fd: -1,
            #[cfg(target_os = "nto")]
            link_up: false,
            #[cfg(target_os = "nto")]
            last_link_probe_us: None,
        }
    }

    /// Create a new QNX Ethernet handle on a custom device path.
    ///
    /// See [`QnxCanBus::new_with_device`] for the exact contract —
    /// in short, the path must be non-empty, ≤ 32 bytes total, null-
    /// terminated, with the nul appearing only once at the final byte.
    ///
    /// The interface name defaults to `en0`; use
    /// [`new_with_device_and_iface`](Self::new_with_device_and_iface) to
    /// override it.
    pub fn new_with_device(link_speed_mbps: u32, path: &[u8]) -> Result<Self, VsError> {
        Self::new_with_device_and_iface(link_speed_mbps, path, b"en0")
    }

    /// Create a new QNX Ethernet handle, specifying both the BPF device
    /// path and the network-interface name used for `SIOCGIFFLAGS`.
    ///
    /// `path` must satisfy the same contract as
    /// [`new_with_device`](Self::new_with_device). `iface_name` must be
    /// a non-empty byte slice shorter than [`IFNAMSIZ`] (so it can be
    /// NUL-terminated) and free of interior NULs.
    pub fn new_with_device_and_iface(
        link_speed_mbps: u32,
        path: &[u8],
        iface_name: &[u8],
    ) -> Result<Self, VsError> {
        if path.is_empty() || path.len() > 32 || path[path.len() - 1] != 0 {
            return Err(VsError::InvalidInput);
        }
        if path[..path.len() - 1].contains(&0) {
            return Err(VsError::InvalidInput);
        }
        // Validate the iface name via the same rules `IfReq::new` enforces;
        // failing here is friendlier than failing later inside the ioctl
        // call site.
        if iface_name.is_empty()
            || iface_name.len() >= IFNAMSIZ
            || iface_name.contains(&0)
        {
            return Err(VsError::InvalidInput);
        }
        let mut device_path = [0u8; 32];
        device_path[..path.len()].copy_from_slice(path);
        let mut iface = [0u8; IFNAMSIZ];
        iface[..iface_name.len()].copy_from_slice(iface_name);
        Ok(Self {
            link_speed: link_speed_mbps,
            device_path,
            device_path_len: path.len(),
            iface_name: iface,
            iface_name_len: iface_name.len(),
            #[cfg(target_os = "nto")]
            fd: -1,
            #[cfg(target_os = "nto")]
            link_up: false,
            #[cfg(target_os = "nto")]
            last_link_probe_us: None,
        })
    }
}

impl QnxEthernetPhy {
    #[cfg(target_os = "nto")]
    fn open_device(&mut self) -> Result<(), VsError> {
        if self.fd >= 0 {
            return Ok(());
        }
        // audit-LOW: pass `O_CLOEXEC` so the BPF descriptor is not
        // inherited across `posix_spawn()`. A child process inheriting
        // a raw BPF fd becomes a confused-deputy that can sniff or
        // inject arbitrary L2 frames without ever opening `/dev/bpf*`
        // itself.
        // SAFETY: device_path is a valid null-terminated string;
        // `O_RDWR | O_CLOEXEC` is a valid POSIX flag combination.
        let fd = unsafe {
            qnx_ffi::open(
                self.device_path.as_ptr(),
                qnx_ffi::O_RDWR | qnx_ffi::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(qnx_errno_to_vserror(qnx_ffi::errno()));
        }
        self.fd = fd;
        Ok(())
    }

    /// Query Ethernet link state via `ioctl(SIOCGIFFLAGS, &ifreq)`.
    ///
    /// # ABI contract
    ///
    /// `SIOCGIFFLAGS` (`<sys/sockio.h>` on QNX Neutrino, also POSIX
    /// `<net/if.h>`) writes a full `struct ifreq` back to the caller's
    /// buffer — *not* a bare integer. The kernel reads `ifr_name` (the
    /// first 16 bytes) to select the interface, then overwrites the
    /// trailing 16-byte `ifr_ifru` union with the interface flags as a
    /// `c_short` (i.e. `i16`) at offset 16.
    ///
    /// # Bug history (DO NOT regress)
    ///
    /// Before this rewrite the call site passed `&mut i32` (4 bytes) as
    /// the ioctl argument. The kernel wrote the full 32-byte `ifreq`
    /// anyway, corrupting 28 bytes of caller stack frame past the
    /// `flags` local — a HIGH-severity stack-buffer overflow. The
    /// `compile_error!` gate kept the feature off in shipping builds,
    /// but any future re-enablement without this fix would have re-
    /// armed the bug. The [`IfReq`] type plus its const-asserted size
    /// (`32 == IFREQ_SIZE`) makes a regression visible at compile time
    /// rather than as a runtime stack smash.
    ///
    /// # Layout reference
    ///
    /// POSIX.1-2017 `<net/if.h>` and QNX SDP 7.1 `<sys/sockio.h>` both
    /// define `struct ifreq` as 16-byte `ifr_name` + 16-byte
    /// `ifr_ifru` union (widest variant: `struct sockaddr ifr_addr`).
    /// Tracked locally as [`IfReq`].
    ///
    /// # Rate limiting
    ///
    /// To prevent a per-TX ioctl on a high-throughput Gigabit link
    /// (~1 syscall every 12 µs with 64-byte frames), the probe is
    /// rate-limited to once per [`LINK_PROBE_INTERVAL_US`] via the
    /// `last_link_probe_us` timestamp on this struct, sourced from the
    /// shared [`QnxTimer`]. 100 ms is chosen as the default coalescing
    /// window because:
    ///
    /// - It is one order of magnitude faster than the typical PHY link
    ///   re-negotiation time (1–3 seconds for auto-neg), so a link-down
    ///   event is detected well within a single TCP retransmit
    ///   timeout.
    /// - It is two orders of magnitude slower than the TX rate on a
    ///   saturated Gigabit link, eliminating the per-TX overhead.
    ///
    /// On the very first call (timer reading is `u64::MAX` "clock
    /// unavailable" or `last_link_probe_us == None`) the probe runs
    /// unconditionally so we don't ship the construction-time stale
    /// `link_up = false` forever.
    ///
    /// # Audit fix HIGH-T (rate-limit fail-open at boot)
    ///
    /// `last_link_probe_us` is `Option<u64>` (not bare `u64`). The
    /// previous `0` sentinel was indistinguishable from a legitimate
    /// `CLOCK_MONOTONIC` reading of `0` µs at process start — every
    /// subsequent TX would re-run the probe because the bare `0`
    /// looked like "never probed", collapsing the 100 ms coalescing
    /// window into a per-TX ioctl storm. `None` is "never probed"
    /// (bypass the rate-limit), `Some(t)` enforces the interval.
    #[cfg(all(target_os = "nto", feature = "qnx-link-detect"))]
    fn update_link_state(&mut self) {
        if self.fd < 0 {
            return;
        }
        // Rate-limit: at most one probe per LINK_PROBE_INTERVAL_US.
        let timer = QnxTimer::new();
        let now = timer.now_us();
        if let (true, Some(prev)) = (now != u64::MAX, self.last_link_probe_us) {
            let elapsed = now.saturating_sub(prev);
            if elapsed < LINK_PROBE_INTERVAL_US {
                return;
            }
        }
        // Build a fully-initialised IfReq with the configured interface
        // name (e.g. "en0"). MaybeUninit isn't strictly required for a
        // 32-byte stack buffer, but using it makes the "kernel writes
        // here" handoff explicit and pins the writeback shape.
        let mut ifr_storage: core::mem::MaybeUninit<IfReq> = core::mem::MaybeUninit::uninit();
        let iface = &self.iface_name[..self.iface_name_len];
        // Construction can only fail if the iface name violates the
        // IfReq contract; constructors already validated those invariants,
        // so on the happy path we get a populated IfReq back. On a
        // configuration regression we leave `link_up` unchanged instead
        // of issuing a syscall against a junk buffer.
        let initialised = match IfReq::new(iface) {
            Ok(req) => req,
            Err(_) => return,
        };
        // Move the initialised value into the MaybeUninit storage. After
        // this `write` the memory is fully initialised; the kernel will
        // overwrite the `ifr_ifru` half via the syscall below.
        ifr_storage.write(initialised);

        // SAFETY invariants for the `ioctl` call below:
        //   1. `self.fd` was returned by a successful `open()` on the
        //      BPF device and has not been closed (the &mut receiver
        //      provides exclusive access; Drop closes it).
        //   2. `qnx_ffi::SIOCGIFFLAGS` is supplied by the downstream
        //      build system per the `compile_error!` contract at the
        //      top of this file.
        //   3. `ifr_storage` is a fully-initialised 32-byte `IfReq`
        //      with a const-asserted layout matching POSIX `struct
        //      ifreq`. The kernel's writeback (up to 16 bytes into
        //      `ifr_ifru` at offset 16) stays strictly within the
        //      storage's bounds — this is what the historical 4-byte
        //      `i32*` buffer failed to guarantee.
        //   4. The pointer is exclusive: no other thread or signal
        //      handler can observe the buffer mid-ioctl on this fd
        //      (QnxEthernetPhy is !Sync; callers serialise access).
        //   5. Conversion to `*mut u8` is sound because `IfReq` is
        //      `#[repr(C)]` and the kernel treats the buffer as raw
        //      bytes — no alignment requirement beyond `u8`.
        let ret = unsafe {
            qnx_ffi::ioctl(
                self.fd,
                qnx_ffi::SIOCGIFFLAGS,
                ifr_storage.as_mut_ptr().cast::<u8>(),
            )
        };
        if ret != 0 {
            // Leave `link_up` at its last-known value; failed probes
            // re-attempt on the next call so a transient kernel-side
            // glitch does not lock us out for a full window. Surfacing
            // the errno here is not part of the EthernetPhy contract.
            return;
        }
        // SAFETY: a successful (`ret == 0`) `SIOCGIFFLAGS` guarantees
        // the kernel has written `ifr_ifru` — the storage was already
        // fully initialised before the call, so this `assume_init_ref`
        // is sound regardless of the success/failure path.
        let ifr: &IfReq = unsafe { ifr_storage.assume_init_ref() };
        let flags = ifr.flags();
        self.link_up = (flags & qnx_ffi::IFF_UP) != 0 && (flags & qnx_ffi::IFF_RUNNING) != 0;
        // Only update the probe timestamp on success; failed probes
        // (returned early above) re-attempt on the next call. The
        // `Some(now)` write disambiguates from the initial `None`
        // "never probed" sentinel (audit fix HIGH-T) — including the
        // legitimate boot-time `now == 0` case which would otherwise
        // permanently re-arm the rate-limiter bypass.
        if now != u64::MAX {
            self.last_link_probe_us = Some(now);
        }
    }

    /// No-op stub when `qnx-link-detect` is disabled. `link_up` keeps
    /// whatever value was set at construction; see the feature-gated
    /// implementation above for the rationale.
    #[cfg(all(target_os = "nto", not(feature = "qnx-link-detect")))]
    fn update_link_state(&mut self) {}
}

/// Minimum interval between consecutive `SIOCGIFFLAGS` link probes, in
/// microseconds. 100 ms. See [`QnxEthernetPhy::update_link_state`] for
/// the rationale.
#[cfg(all(target_os = "nto", feature = "qnx-link-detect"))]
const LINK_PROBE_INTERVAL_US: u64 = 100_000;

#[cfg(target_os = "nto")]
impl Drop for QnxEthernetPhy {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd was obtained from a successful open() call and
            // has not been closed elsewhere. Per POSIX.2008, after
            // close() the fd is in an unspecified state — it MUST NOT
            // be reused even if close() returns EINTR, because QNX
            // Neutrino releases the descriptor before signalling
            // EINTR. Retrying would risk closing a descriptor newly
            // assigned to another thread; we ignore the return value.
            let ret = unsafe { qnx_ffi::close(self.fd) };
            // audit-LOW: count non-EINTR close failures. See the matching
            // CAN-bus Drop and the `CLOSE_ERROR_COUNT` doc-comment near
            // the top of this module for the rationale.
            if ret < 0 && !is_eintr(qnx_ffi::errno()) {
                CLOSE_ERROR_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

impl EthernetPhy for QnxEthernetPhy {
    #[cfg(target_os = "nto")]
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError> {
        self.open_device()?;
        // Audit fix (perf): avoid zeroing the full
        // `BPF_HEADER_SIZE + ETH_FRAME_MAX` = 1540 byte buffer on every
        // RX. `read()` writes the prefix and we only ever read back
        // `[..n_usize]`; bytes past `n_usize` stay uninitialized and
        // are never observed.
        //
        // PERF: TODO — eliminate the second memcpy (stack buf → RawEthFrame::data)
        // inside `parse_eth_frame`. A single-copy design would read
        // directly into a wrapper struct containing the BPF header
        // followed by the RawEthFrame, but `RawEthFrame` is `#[repr(C)]`
        // and may have alignment padding between `[u8; BPF_HEADER_SIZE]`
        // and itself, breaking the kernel's byte-offset contract.
        // Solving this safely requires either a `#[repr(C, packed)]`
        // wrapper (UB-prone) or a `vs-hal` trait extension that lets
        // the HAL hand the kernel a `RawEthFrame` slot directly.
        // Tracked as an invasive change for a separate PR.
        const BUF_LEN: usize = BPF_HEADER_SIZE + ETH_FRAME_MAX;
        let mut buf: core::mem::MaybeUninit<[u8; BUF_LEN]> = core::mem::MaybeUninit::uninit();
        // SAFETY: `buf` is a stack allocation of exactly BUF_LEN bytes;
        // its pointer is valid and writable for that range. Uninit
        // bytes past the kernel's returned length are never read.
        let buf_ptr: *mut u8 = unsafe { (*buf.as_mut_ptr()).as_mut_ptr() };
        // Audit fix HIGH (EINTR cap + EAGAIN→Ok(None)). Identical pattern
        // to `QnxCanBus::receive` — see that function's comment and
        // [`retry_on_eintr`] for the DoS bound rationale. An adversarial
        // neighbour task with `pthread_kill()` capability could otherwise
        // pin this receive task indefinitely via repeated EINTRs; the cap
        // converts the attack into a bounded `VsError::Timeout`.
        let fd = self.fd;
        let outcome = retry_on_eintr(
            || {
                // SAFETY: fd is valid (checked by open_device above);
                // `buf_ptr` is valid and writable for `BUF_LEN` bytes
                // (stack-owned MaybeUninit of that exact size).
                let n = unsafe { qnx_ffi::read(fd, buf_ptr, BUF_LEN) };
                if n >= 0 {
                    Ok(n)
                } else {
                    Err(qnx_ffi::errno())
                }
            },
            is_eintr,
        );
        self.update_link_state();
        let n = match outcome {
            RxOutcome::Got(n) => n,
            RxOutcome::Err(err) if is_would_block(err) => return Ok(None),
            RxOutcome::EintrCapHit => return Err(VsError::Timeout),
            RxOutcome::Err(err) => return Err(qnx_errno_to_vserror(err)),
        };
        if n == 0 {
            return Ok(None);
        }
        // Must carry at least a full BPF header + minimum Ethernet header.
        // A shorter delivery is a kernel-side framing bug and `parse_eth_frame`
        // would otherwise collapse it into a generic InvalidInput.
        let n_usize = n as usize;
        if n_usize < BPF_HEADER_SIZE + ETH_HEADER_MIN || n_usize > BUF_LEN {
            return Err(VsError::InvalidInput);
        }
        // SAFETY: kernel wrote `n_usize` bytes (>= BPF_HEADER_SIZE +
        // ETH_HEADER_MIN, <= BUF_LEN) into the buffer; that slice is
        // initialized. The pointer lives as long as `buf`.
        let init_slice: &[u8] = unsafe { core::slice::from_raw_parts(buf_ptr, n_usize) };
        parse_eth_frame(init_slice).map(Some)
    }

    #[cfg(not(target_os = "nto"))]
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError> {
        Err(VsError::NotInitialized)
    }

    #[cfg(target_os = "nto")]
    fn transmit(&mut self, data: &[u8]) -> Result<(), VsError> {
        self.open_device()?;
        if data.len() > ETH_FRAME_MAX {
            return Err(VsError::InvalidInput);
        }
        // Audit fix CRIT-6 (EINTR cap on Ethernet TX): wrap the
        // `write()` syscall in the bounded `retry_on_eintr` helper so a
        // signal storm cannot pin the TX path forever.
        //
        // Audit fix HIGH-R (partial-write retry): port the same
        // bounded partial-write loop the CAN TX path uses. The previous
        // code issued one `write()` and surfaced `(n != data.len())` as
        // an immediate `BusError`, even though a stock io-pkt BPF write
        // is allowed to return short (e.g. when the kernel TX ring
        // briefly fills under load). Without retry, a routine partial
        // becomes a noisy spurious bus-error AND a truncated frame
        // sitting on the wire. Bound the retries to
        // `MAX_PARTIAL_WRITE_RETRIES` so this stays DoS-safe: an
        // adversary cannot force unbounded write() spinning.
        const MAX_PARTIAL_WRITE_RETRIES: u8 = 4;
        let fd = self.fd;
        let data_ptr = data.as_ptr();
        let total = data.len();
        let mut written: usize = 0;
        let mut partial_attempts: u8 = 0;
        while written < total {
            let outcome = retry_on_eintr(
                || {
                    // SAFETY: fd is valid (open_device above);
                    // `data_ptr.add(written)` is in-bounds for
                    // `total - written` bytes (the caller's slice
                    // outlives this closure and `written <= total`).
                    let n = unsafe {
                        qnx_ffi::write(fd, data_ptr.add(written), total - written)
                    };
                    if n >= 0 {
                        Ok(n)
                    } else {
                        Err(qnx_ffi::errno())
                    }
                },
                is_eintr,
            );
            let n = match outcome {
                RxOutcome::Got(n) => n,
                RxOutcome::EintrCapHit => {
                    // Signal-storm DoS bail-out — refresh link cache so
                    // observers see a fresh reading after a stalled TX.
                    self.update_link_state();
                    return Err(VsError::Timeout);
                }
                RxOutcome::Err(err) => {
                    self.update_link_state();
                    return Err(qnx_errno_to_vserror(err));
                }
            };
            let progressed = n as usize;
            if progressed == 0 {
                // Kernel queued nothing this iteration — treat as a
                // partial-write event and back off via the bounded
                // counter rather than spinning forever.
                partial_attempts = partial_attempts.saturating_add(1);
                if partial_attempts >= MAX_PARTIAL_WRITE_RETRIES {
                    self.update_link_state();
                    return Err(VsError::BusError);
                }
                continue;
            }
            written += progressed;
            if written < total {
                partial_attempts = partial_attempts.saturating_add(1);
                if partial_attempts >= MAX_PARTIAL_WRITE_RETRIES {
                    self.update_link_state();
                    return Err(VsError::BusError);
                }
            }
        }
        self.update_link_state();
        Ok(())
    }

    #[cfg(not(target_os = "nto"))]
    fn transmit(&mut self, _data: &[u8]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    /// Configured link speed in Mbit/s.
    ///
    /// **Informational only.** This returns the value passed to
    /// [`QnxEthernetPhy::new`] / [`QnxEthernetPhy::new_with_device`]; it
    /// is **not** validated against the running `io-pkt` stack or the
    /// underlying PHY. QNX BPF does not expose a portable ioctl for the
    /// negotiated wire speed in stock SDP headers, and `SIOCGIFFLAGS`
    /// only reports up/down (not speed). Callers that need the actual
    /// negotiated speed must obtain it out-of-band.
    #[inline]
    fn link_speed_mbps(&self) -> u32 {
        self.link_speed
    }

    #[cfg(target_os = "nto")]
    #[inline]
    fn link_is_up(&self) -> bool {
        self.link_up
    }

    #[cfg(not(target_os = "nto"))]
    #[inline]
    fn link_is_up(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Test-only allow (LOW-2): test fixtures generate wire-format byte
    // payloads via `usize as u8` and `u8::wrapping_add`. The index `i`
    // is bounded by the buffer length (≤ 2048 bytes per
    // CLAUDE.md "Fixed-size buffers only"), and the resulting truncation
    // / wrap to a `u8` is *intentional* — it is how the tests synthesise
    // deterministic-but-non-trivial wire bytes. The casts have no
    // semantic content beyond "low byte of `i`". Using `u8::try_from(i)`
    // here would either panic in long fixtures (no semantic improvement)
    // or force `?` plumbing into `#[test] fn` signatures that don't
    // return `Result`. Confined to `#[cfg(test)]`: no production code
    // path inherits this allow.
    #![allow(clippy::cast_possible_truncation)]

    use super::*;

    // -- QnxCanBus (non-QNX host) --

    #[test]
    fn qnx_can_stub_receive_returns_not_initialized() {
        let mut can = QnxCanBus::new(500_000);
        assert_eq!(can.receive(), Err(VsError::NotInitialized));
    }

    #[test]
    fn qnx_can_stub_transmit_returns_not_initialized() {
        let mut can = QnxCanBus::new(500_000);
        let frame = RawCanFrame::zeroed();
        assert_eq!(can.transmit(&frame), Err(VsError::NotInitialized));
    }

    #[test]
    fn qnx_can_stub_bitrate() {
        let can = QnxCanBus::new(1_000_000);
        assert_eq!(can.bitrate(), 1_000_000);
    }

    #[test]
    fn qnx_can_stub_is_not_bus_off() {
        let can = QnxCanBus::new(500_000);
        assert!(!can.is_bus_off());
    }

    #[test]
    fn qnx_can_zero_bitrate() {
        let can = QnxCanBus::new(0);
        assert_eq!(can.bitrate(), 0);
    }

    #[test]
    fn qnx_can_custom_device_path() {
        let can = QnxCanBus::new_with_device(500_000, b"/dev/can1\0").unwrap();
        assert_eq!(can.bitrate(), 500_000);
        assert_eq!(&can.device_path[..10], b"/dev/can1\0");
    }

    #[test]
    fn qnx_can_custom_device_rejects_empty() {
        assert!(QnxCanBus::new_with_device(500_000, b"").is_err());
    }

    #[test]
    fn qnx_can_custom_device_rejects_no_null() {
        assert!(QnxCanBus::new_with_device(500_000, b"/dev/can1").is_err());
    }

    #[test]
    fn qnx_can_custom_device_rejects_too_long() {
        let long_path = [b'x'; 33];
        assert!(QnxCanBus::new_with_device(500_000, &long_path).is_err());
    }

    #[test]
    fn qnx_can_custom_device_rejects_interior_null() {
        // Valid trailing nul but an embedded nul partway through would
        // silently truncate the path when passed to QNX `open()`.
        assert!(QnxCanBus::new_with_device(500_000, b"/dev/\0can0\0").is_err());
    }

    #[test]
    fn qnx_ethernet_custom_device_rejects_interior_null() {
        assert!(QnxEthernetPhy::new_with_device(100, b"/dev/\0bpf\0").is_err());
    }

    // -- QnxTimer (non-QNX host) --

    #[test]
    fn qnx_timer_stub_returns_unavailable_sentinel() {
        // Audit fix: non-QNX `now_us()` returns `u64::MAX` (the
        // "clock unavailable" sentinel) instead of `0` (a valid timestamp).
        let timer = QnxTimer::new();
        assert_eq!(timer.now_us(), u64::MAX);
    }

    #[test]
    fn qnx_timer_stub_no_cycle_count() {
        let timer = QnxTimer::new();
        assert!(timer.cycle_count().is_none());
    }

    #[test]
    fn qnx_timer_default_trait() {
        // Audit fix: same sentinel as the explicit constructor.
        let timer = QnxTimer::default();
        assert_eq!(timer.now_us(), u64::MAX);
    }

    // -- audit-LOW: O_CLOEXEC bit pattern --

    /// audit-LOW: every `open()` call in this crate must pass
    /// `O_RDWR | O_CLOEXEC` so the descriptor is not inherited across a
    /// QNX `posix_spawn()` boundary. This is a pure-constant test that
    /// pins the bit pattern; mocking `open()` itself would require an
    /// FFI shim layer this crate intentionally does not have. The two
    /// real call sites pass exactly `qnx_ffi::O_RDWR | qnx_ffi::O_CLOEXEC`
    /// — grep proves it, this test pins the value.
    #[cfg(target_os = "nto")]
    #[test]
    fn open_passes_o_cloexec() {
        // POSIX-stable: O_RDWR == 2, O_CLOEXEC == 0o100_000.
        // The OR of those two bits is what the QNX kernel sees.
        assert_eq!(qnx_ffi::O_RDWR, 2);
        assert_eq!(qnx_ffi::O_CLOEXEC, 0o100_000);
        assert_eq!(qnx_ffi::O_RDWR | qnx_ffi::O_CLOEXEC, 0o100_002);
    }

    // -- audit-LOW: monotonic cycle wrapper --

    #[test]
    fn cycle_count_monotonic_strictly_increases() {
        // Build a single timer and call the wrapper many times. Every
        // return must be strictly greater than the previous one,
        // regardless of whether the underlying `cycle_count()` returned
        // `None` (host build) or a raw cycle that regressed (SMP
        // migration). On the host the raw read is `None` so the
        // wrapper falls back to `last + 1`; we still observe strict
        // increase from the bump path.
        let timer = QnxTimer::new();
        let mut prev = timer.cycle_count_monotonic();
        for _ in 0..1000 {
            let cur = timer.cycle_count_monotonic();
            assert!(
                cur > prev,
                "cycle_count_monotonic regressed: {} -> {}",
                prev,
                cur,
            );
            prev = cur;
        }
    }

    #[test]
    fn cycle_count_monotonic_independent_instances() {
        // Negative path: the strict-increase guarantee is documented as
        // **per-instance**. Two separate `QnxTimer` instances do NOT
        // coordinate; their cells are independent. Both must
        // individually be strictly increasing, but they may report
        // overlapping values across instances. This test pins that
        // contract so a future refactor that turned the cell into a
        // shared `AtomicU64` would have to update the docs in lockstep.
        let a = QnxTimer::new();
        let b = QnxTimer::new();
        let a1 = a.cycle_count_monotonic();
        let b1 = b.cycle_count_monotonic();
        let a2 = a.cycle_count_monotonic();
        let b2 = b.cycle_count_monotonic();
        assert!(a2 > a1);
        assert!(b2 > b1);
    }

    // -- audit-LOW: close-error observability counter --

    #[test]
    fn close_error_count_increments() {
        // White-box test: we cannot exercise the real Drop path on the
        // host (QNX `close()` is only compiled in under
        // `target_os = "nto"`), so we exercise the counter directly.
        // This pins the public reader (`hal_qnx_close_error_count`)
        // against the underlying static and proves that telemetry can
        // observe forward progress.
        //
        // The counter is process-wide; record the baseline so other
        // tests that ever fault into the increment path do not flake
        // this one.
        let baseline = hal_qnx_close_error_count();
        CLOSE_ERROR_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(hal_qnx_close_error_count(), baseline + 1);
        CLOSE_ERROR_COUNT.fetch_add(2, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(hal_qnx_close_error_count(), baseline + 3);
    }

    #[test]
    fn close_error_count_starts_at_or_above_zero() {
        // Negative path: the public reader must be safely callable at
        // any time and never panic. A monotonic counter cannot be
        // less than zero (it's a u64), but we pin the type explicitly
        // so a future change to a signed type would have to update
        // this test.
        let v: u64 = hal_qnx_close_error_count();
        // `v >= 0` is tautological on u64 and triggers a clippy lint;
        // touching the value is enough to exercise the read path.
        let _ = v;
    }

    // -- QnxEthernetPhy (non-QNX host) --

    #[test]
    fn qnx_ethernet_stub_receive_returns_not_initialized() {
        let mut eth = QnxEthernetPhy::new(1000);
        assert!(matches!(eth.receive(), Err(VsError::NotInitialized)));
    }

    #[test]
    fn qnx_ethernet_stub_transmit_returns_not_initialized() {
        let mut eth = QnxEthernetPhy::new(1000);
        assert_eq!(eth.transmit(&[0u8; 64]), Err(VsError::NotInitialized));
    }

    #[test]
    fn qnx_ethernet_link_speed() {
        let eth = QnxEthernetPhy::new(100);
        assert_eq!(eth.link_speed_mbps(), 100);
    }

    #[test]
    fn qnx_ethernet_link_down_on_non_qnx() {
        let eth = QnxEthernetPhy::new(1000);
        assert!(!eth.link_is_up());
    }

    #[test]
    fn qnx_ethernet_gigabit_speed() {
        let eth = QnxEthernetPhy::new(1000);
        assert_eq!(eth.link_speed_mbps(), 1000);
    }

    #[test]
    fn qnx_ethernet_custom_device_path() {
        let eth = QnxEthernetPhy::new_with_device(100, b"/dev/bpf1\0").unwrap();
        assert_eq!(eth.link_speed_mbps(), 100);
        assert_eq!(&eth.device_path[..10], b"/dev/bpf1\0");
    }

    #[test]
    fn qnx_ethernet_custom_device_rejects_empty() {
        assert!(QnxEthernetPhy::new_with_device(100, b"").is_err());
    }

    #[test]
    fn qnx_ethernet_custom_device_rejects_no_null() {
        assert!(QnxEthernetPhy::new_with_device(100, b"/dev/bpf").is_err());
    }

    #[test]
    fn qnx_can_custom_device_max_length_accepted() {
        // 32 bytes total (31 chars + null) is the maximum allowed.
        let mut path = [b'x'; 32];
        path[31] = 0;
        assert!(QnxCanBus::new_with_device(500_000, &path).is_ok());
    }

    #[test]
    fn qnx_ethernet_custom_device_max_length_accepted() {
        let mut path = [b'y'; 32];
        path[31] = 0;
        assert!(QnxEthernetPhy::new_with_device(100, &path).is_ok());
    }

    #[test]
    fn qnx_ethernet_custom_device_rejects_too_long() {
        let long_path = [b'x'; 33];
        assert!(QnxEthernetPhy::new_with_device(100, &long_path).is_err());
    }

    #[test]
    fn qnx_can_default_device_path_is_correct() {
        let can = QnxCanBus::new(500_000);
        assert_eq!(&can.device_path[..10], b"/dev/can0\0");
        assert_eq!(can.device_path_len, 10);
    }

    #[test]
    fn qnx_ethernet_default_device_path_is_correct() {
        // Audit fix: default path is `/dev/bpf0` (numbered BPF node)
        // because the un-indexed `/dev/bpf` does not exist on stock QNX.
        let eth = QnxEthernetPhy::new(1000);
        assert_eq!(&eth.device_path[..10], b"/dev/bpf0\0");
        assert_eq!(eth.device_path_len, 9);
    }

    #[test]
    fn qnx_can_max_u32_bitrate() {
        let can = QnxCanBus::new(u32::MAX);
        assert_eq!(can.bitrate(), u32::MAX);
    }

    #[test]
    fn qnx_ethernet_zero_speed() {
        let eth = QnxEthernetPhy::new(0);
        assert_eq!(eth.link_speed_mbps(), 0);
    }

    // -----------------------------------------------------------------------
    // Frame parser / serializer tests — exercised on every target
    // -----------------------------------------------------------------------

    #[test]
    fn parse_can_frame_happy_path() {
        // id=0x123, dlc=3, data=[0xAA,0xBB,0xCC]
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&0x123u32.to_le_bytes());
        buf[4] = 3;
        buf[8] = 0xAA;
        buf[9] = 0xBB;
        buf[10] = 0xCC;
        let frame = parse_can_frame(&buf[..11]).unwrap();
        assert_eq!(frame.id, 0x123);
        assert_eq!(frame.dlc, 3);
        assert_eq!(&frame.data[..3], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_can_frame_rejects_short_header() {
        assert_eq!(parse_can_frame(&[0u8; 7]), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_can_frame_rejects_dlc_over_maximum() {
        // Audit fix HIGH (CAN-FD wire DLC): the on-wire DLC is a 4-bit
        // nibble (0..=15). Anything above 15 is malformed.
        let mut buf = [0u8; 16];
        buf[4] = 16; // > CAN_MAX_DLC (15)
        assert_eq!(parse_can_frame(&buf[..8]), Err(VsError::InvalidInput));
        buf[4] = 255;
        assert_eq!(parse_can_frame(&buf[..8]), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_can_frame_rejects_truncated_payload() {
        let mut buf = [0u8; 16];
        buf[4] = 4; // dlc=4 but only 2 payload bytes present
        assert_eq!(parse_can_frame(&buf[..10]), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_can_frame_canfd_max_payload() {
        // CAN-FD: DLC=15 on the wire means 64 payload bytes per ISO 11898-1.
        // Audit fix HIGH (CAN-FD wire DLC): rewritten — previously this
        // test wrote `buf[4] = 64` which is illegal on the wire (DLC is
        // a 4-bit field). The correct on-wire DLC for a 64-byte payload
        // is 15.
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        buf[4] = 15;
        for (i, b) in buf[CAN_HEADER_SIZE..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let frame = parse_can_frame(&buf).unwrap();
        assert_eq!(frame.dlc, 15);
        assert!(frame.is_fd);
        assert_eq!(frame.payload_len(), 64);
        // Every payload byte must round-trip through the parser.
        for (i, b) in frame.data.iter().enumerate() {
            assert_eq!(*b, i as u8);
        }
    }

    #[test]
    fn serialize_can_frame_roundtrips_through_parse() {
        let mut orig = RawCanFrame::zeroed();
        orig.id = 0x0EAD_BEEF; // 28-bit, valid extended ID (≤ 0x1FFF_FFFF)
        orig.is_extended = true; // required for IDs above 0x7FF after audit fix
        orig.dlc = 5;
        orig.data[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        let n = serialize_can_frame(&orig, &mut buf).unwrap();
        let parsed = parse_can_frame(&buf[..n]).unwrap();
        assert_eq!(parsed.id, 0x0EAD_BEEF);
        assert_eq!(parsed.dlc, 5);
        // Audit fix: parser now infers `is_extended` from the ID range.
        assert!(parsed.is_extended);
        assert_eq!(&parsed.data[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn serialize_can_frame_rejects_short_buffer() {
        let mut orig = RawCanFrame::zeroed();
        orig.dlc = 4;
        let mut buf = [0u8; CAN_HEADER_SIZE + 2]; // too small for 4-byte payload
        assert_eq!(
            serialize_can_frame(&orig, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn serialize_can_frame_rejects_dlc_above_nibble_max() {
        // Audit fix HIGH (CAN-FD wire DLC): rewritten. Previously this
        // test asserted that a u8::MAX DLC was silently clamped to 64
        // bytes — but DLC is a 4-bit on-wire field, and the only legal
        // values are 0..=15. Anything else is a caller bug and must be
        // rejected, not clamped (clamping would either truncate data
        // or write a garbage `0xFF` in the DLC byte that downstream
        // ECUs would mis-decode).
        let mut orig = RawCanFrame::zeroed();
        orig.is_fd = true;
        orig.dlc = u8::MAX;
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        assert_eq!(
            serialize_can_frame(&orig, &mut buf),
            Err(VsError::InvalidInput)
        );

        orig.dlc = 16; // one above the nibble max
        assert_eq!(
            serialize_can_frame(&orig, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn parse_eth_frame_rejects_short_buffer() {
        // Needs at least BPF_HEADER_SIZE + 14 bytes for a minimum Ethernet frame.
        let buf = [0u8; BPF_HEADER_SIZE + 13];
        assert_eq!(parse_eth_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_eth_frame_happy_path() {
        let mut buf = [0u8; BPF_HEADER_SIZE + 64];
        // Fill a simple Ethernet frame: 14-byte header + 50-byte payload.
        // Bytes are 1..64 — non-zero DST MAC, ethertype = 0x0D0E (not 0xFFFF).
        for (i, b) in buf[BPF_HEADER_SIZE..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        let frame = parse_eth_frame(&buf).unwrap();
        assert_eq!(frame.len as usize, 64);
    }

    #[test]
    fn parse_eth_frame_rejects_oversized_frame() {
        // Audit fix HIGH (VLAN-truncation): feeding in more than
        // ETH_FRAME_MAX payload is now an explicit rejection rather
        // than a silent clamp. Previously this test asserted clamping
        // to 1514, which hid the trailing 8 bytes of every double-
        // tagged frame.
        let mut buf = [0u8; BPF_HEADER_SIZE + ETH_FRAME_MAX + 128];
        buf[BPF_HEADER_SIZE] = 0x01; // non-zero DST MAC
        buf[BPF_HEADER_SIZE + 12] = 0x08; // ethertype 0x0800 = IPv4
        assert_eq!(parse_eth_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_eth_frame_accepts_exactly_max_frame_size() {
        // The 1522-byte ceiling (header + 1500 payload + 4 VLAN + 4 FCS)
        // must be accepted in full — the entire range up to and
        // including byte 1521 of the eth frame is now visible to
        // downstream parsers via RawEthFrame::payload().
        let mut buf = [0u8; BPF_HEADER_SIZE + ETH_FRAME_MAX];
        buf[BPF_HEADER_SIZE] = 0x01;
        buf[BPF_HEADER_SIZE + 12] = 0x08;
        let frame = parse_eth_frame(&buf).unwrap();
        assert_eq!(frame.len as usize, ETH_FRAME_MAX);
    }

    #[test]
    fn parse_eth_frame_minimum_size_rejected_for_runt() {
        // Audit fix: runt frames (< 60 bytes) are now rejected even if
        // the BPF buffer is technically long enough.
        let buf = [0u8; BPF_HEADER_SIZE + 14];
        assert_eq!(parse_eth_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_eth_frame_60_byte_with_valid_header_accepted() {
        // 60 bytes is the audit-mandated minimum; a real DST MAC and a
        // non-reserved ethertype are also required.
        let mut buf = [0u8; BPF_HEADER_SIZE + 60];
        buf[BPF_HEADER_SIZE] = 0x01;
        buf[BPF_HEADER_SIZE + 12] = 0x08;
        let frame = parse_eth_frame(&buf).unwrap();
        assert_eq!(frame.len as usize, 60);
    }

    #[test]
    fn parse_eth_frame_rejects_all_zero_dst_mac() {
        let mut buf = [0u8; BPF_HEADER_SIZE + 60];
        // DST MAC left all zero on purpose.
        buf[BPF_HEADER_SIZE + 12] = 0x08;
        assert_eq!(parse_eth_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_eth_frame_rejects_reserved_ethertype_ffff() {
        let mut buf = [0u8; BPF_HEADER_SIZE + 60];
        buf[BPF_HEADER_SIZE] = 0x01;
        buf[BPF_HEADER_SIZE + 12] = 0xFF;
        buf[BPF_HEADER_SIZE + 13] = 0xFF;
        assert_eq!(parse_eth_frame(&buf), Err(VsError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // Audit fix HIGH: CAN ID range validation
    // -----------------------------------------------------------------------

    #[test]
    fn parse_can_frame_rejects_id_above_extended_max() {
        // Build a frame whose first 4 bytes encode an ID = 0x2000_0000 — one
        // bit above the 29-bit max. Must be rejected outright; previously
        // the high bits would silently survive into RawCanFrame and could
        // alias a safety-critical arbitration ID after downstream truncation.
        let mut buf = [0u8; CAN_HEADER_SIZE + 4];
        let bad_id: u32 = 0x2000_0000;
        buf[..4].copy_from_slice(&bad_id.to_le_bytes());
        buf[4] = 4; // dlc
        assert_eq!(parse_can_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_can_frame_infers_extended_flag() {
        // ID > 0x7FF must come back marked is_extended.
        let mut buf = [0u8; CAN_HEADER_SIZE];
        let id: u32 = 0x800;
        buf[..4].copy_from_slice(&id.to_le_bytes());
        let f = parse_can_frame(&buf).unwrap();
        assert!(f.is_extended);
        assert_eq!(f.id, 0x800);
    }

    #[test]
    fn parse_can_frame_standard_id_is_not_extended() {
        let mut buf = [0u8; CAN_HEADER_SIZE];
        let id: u32 = 0x7FF;
        buf[..4].copy_from_slice(&id.to_le_bytes());
        let f = parse_can_frame(&buf).unwrap();
        assert!(!f.is_extended);
    }

    #[test]
    fn parse_can_frame_infers_fd_flag_for_long_dlc() {
        // Audit fix HIGH (CAN-FD wire DLC): DLC=12 on the wire maps to
        // 24 payload bytes per ISO 11898-1 (not 12). The buffer must
        // be sized accordingly.
        let mut buf = [0u8; CAN_HEADER_SIZE + 24];
        buf[4] = 12;
        let f = parse_can_frame(&buf).unwrap();
        assert!(f.is_fd);
        assert_eq!(f.payload_len(), 24);
    }

    #[test]
    fn serialize_can_frame_rejects_invalid_standard_id() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x800; // exceeds standard max
                          // is_extended left false → invalid combination
        let mut buf = [0u8; CAN_HEADER_SIZE + 8];
        assert_eq!(
            serialize_can_frame(&frame, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn serialize_can_frame_rejects_invalid_extended_id() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x2000_0000;
        frame.is_extended = true;
        let mut buf = [0u8; CAN_HEADER_SIZE + 8];
        assert_eq!(
            serialize_can_frame(&frame, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn serialize_can_frame_rejects_classic_dlc_above_8() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x100;
        frame.is_fd = false;
        frame.dlc = 9;
        let mut buf = [0u8; CAN_HEADER_SIZE + 16];
        assert_eq!(
            serialize_can_frame(&frame, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn serialize_can_frame_accepts_classic_dlc_8() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x100;
        frame.is_fd = false;
        frame.dlc = 8;
        let mut buf = [0u8; CAN_HEADER_SIZE + 8];
        assert!(serialize_can_frame(&frame, &mut buf).is_ok());
    }

    #[test]
    fn serialize_can_frame_accepts_fd_dlc_15_for_64_byte_payload() {
        // Audit fix HIGH (CAN-FD wire DLC): rewritten. Previously this
        // test set `frame.dlc = 64`, which is illegal on the wire (DLC
        // is a 4-bit field). The correct way to request a 64-byte FD
        // payload is `dlc = 15`.
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x100;
        frame.is_fd = true;
        frame.dlc = 15;
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        let n = serialize_can_frame(&frame, &mut buf).unwrap();
        assert_eq!(n, CAN_HEADER_SIZE + 64);
        assert_eq!(buf[4], 15);
    }

    // -----------------------------------------------------------------------
    // Audit fix HIGH: ISO 11898-1 CAN-FD DLC wire-format mapping
    // -----------------------------------------------------------------------
    //
    // The 4-bit on-wire DLC nibble maps non-linearly to payload bytes for
    // CAN-FD:
    //
    //    DLC | bytes
    //   -----+------
    //    0-8 | 0-8       (classical CAN / CAN-FD linear range)
    //      9 | 12
    //     10 | 16
    //     11 | 20
    //     12 | 24
    //     13 | 32
    //     14 | 48
    //     15 | 64
    //
    // Round-trip coverage below pins both the serializer (raw nibble in
    // the DLC byte, ISO-mapped payload) and the parser (length validation
    // against ISO-mapped payload, DLC stored as nibble) for every legal
    // DLC value, plus the negative paths required by CLAUDE.md.

    /// Helper: build a `RawCanFrame` with sequential payload bytes for
    /// the ISO-mapped length implied by `(dlc, is_fd)`.
    fn make_frame(dlc: u8, is_fd: bool) -> RawCanFrame {
        let mut f = RawCanFrame::zeroed();
        f.id = 0x123;
        f.dlc = dlc;
        f.is_fd = is_fd;
        let n = dlc_to_payload_len(dlc, is_fd);
        for (i, b) in f.data[..n].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x40);
        }
        f
    }

    #[test]
    fn dlc_to_payload_len_classical_table() {
        for dlc in 0..=8u8 {
            assert_eq!(dlc_to_payload_len(dlc, false), dlc as usize);
            assert_eq!(dlc_to_payload_len(dlc, true), dlc as usize);
        }
        // Classical CAN clamps anything above 8.
        for dlc in 9..=15u8 {
            assert_eq!(dlc_to_payload_len(dlc, false), 8);
        }
    }

    #[test]
    fn dlc_to_payload_len_canfd_iso_table() {
        // The non-linear FD section.
        for &(dlc, len) in &[
            (9u8, 12usize),
            (10, 16),
            (11, 20),
            (12, 24),
            (13, 32),
            (14, 48),
            (15, 64),
        ] {
            assert_eq!(dlc_to_payload_len(dlc, true), len, "DLC {dlc}");
        }
    }

    #[test]
    fn serialize_parse_roundtrip_classical_can_all_dlcs() {
        for dlc in 0..=8u8 {
            let orig = make_frame(dlc, false);
            let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
            let n = serialize_can_frame(&orig, &mut buf).unwrap();
            let expected_len = dlc as usize;
            assert_eq!(n, CAN_HEADER_SIZE + expected_len, "classical dlc={dlc}");
            // On-wire DLC byte must equal the nibble verbatim.
            assert_eq!(buf[4], dlc, "wire DLC byte classical dlc={dlc}");
            let parsed = parse_can_frame(&buf[..n]).unwrap();
            assert_eq!(parsed.dlc, dlc);
            assert_eq!(parsed.payload_len(), expected_len);
            assert_eq!(&parsed.data[..expected_len], &orig.data[..expected_len]);
        }
    }

    #[test]
    fn serialize_parse_roundtrip_canfd_linear_dlcs() {
        // DLC 0..=8 in FD mode behaves identically to classical CAN.
        for dlc in 0..=8u8 {
            let orig = make_frame(dlc, true);
            let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
            let n = serialize_can_frame(&orig, &mut buf).unwrap();
            let expected_len = dlc as usize;
            assert_eq!(n, CAN_HEADER_SIZE + expected_len, "fd-linear dlc={dlc}");
            assert_eq!(buf[4], dlc, "wire DLC byte fd-linear dlc={dlc}");
            let parsed = parse_can_frame(&buf[..n]).unwrap();
            assert_eq!(parsed.dlc, dlc);
            assert_eq!(parsed.payload_len(), expected_len);
            assert_eq!(&parsed.data[..expected_len], &orig.data[..expected_len]);
        }
    }

    #[test]
    fn serialize_parse_roundtrip_canfd_nonlinear_dlcs() {
        // The seven non-linear FD DLCs, each with its ISO-mapped length.
        let cases: [(u8, usize); 7] = [
            (9, 12),
            (10, 16),
            (11, 20),
            (12, 24),
            (13, 32),
            (14, 48),
            (15, 64),
        ];
        for &(dlc, expected_len) in &cases {
            let orig = make_frame(dlc, true);
            let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
            let n = serialize_can_frame(&orig, &mut buf).unwrap();
            assert_eq!(
                n,
                CAN_HEADER_SIZE + expected_len,
                "fd-nonlinear dlc={dlc}: expected {expected_len} payload bytes"
            );
            assert_eq!(buf[4], dlc, "wire DLC byte fd-nonlinear dlc={dlc}");
            let parsed = parse_can_frame(&buf[..n]).unwrap();
            assert_eq!(parsed.dlc, dlc, "parsed dlc nibble fd-nonlinear dlc={dlc}");
            assert!(parsed.is_fd, "parser must infer is_fd for dlc={dlc}");
            assert_eq!(
                parsed.payload_len(),
                expected_len,
                "parsed payload_len fd-nonlinear dlc={dlc}"
            );
            assert_eq!(
                &parsed.data[..expected_len],
                &orig.data[..expected_len],
                "payload contents fd-nonlinear dlc={dlc}"
            );
        }
    }

    #[test]
    fn serialize_canfd_dlc_15_wire_format_anchor() {
        // Wire-format anchor: a CAN-FD frame with DLC=15 must be emitted
        // as `header (8) || data (64)` with the DLC byte at offset 4
        // holding exactly 0x0F. This is the very bit the audit fix
        // restored from the broken 15-byte-payload behaviour.
        let mut orig = RawCanFrame::zeroed();
        orig.id = 0x1AB;
        orig.is_fd = true;
        orig.dlc = 15;
        for (i, b) in orig.data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        let n = serialize_can_frame(&orig, &mut buf).unwrap();
        assert_eq!(n, CAN_HEADER_SIZE + 64, "DLC=15 must serialise 64 bytes");
        assert_eq!(buf[4], 0x0F, "DLC byte must hold the nibble verbatim");
        // Reserved bytes 5..8 must be zero.
        assert_eq!(&buf[5..8], &[0u8; 3]);
        // All 64 payload bytes are present in order.
        for (i, b) in buf[CAN_HEADER_SIZE..CAN_HEADER_SIZE + 64]
            .iter()
            .enumerate()
        {
            assert_eq!(*b, i as u8, "wire payload byte {i}");
        }
    }

    #[test]
    fn serialize_rejects_dlc_16() {
        // DLC is a 4-bit field; 16 overflows it.
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x100;
        frame.is_fd = true;
        frame.dlc = 16;
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        assert_eq!(
            serialize_can_frame(&frame, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn serialize_rejects_dlc_255() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x100;
        frame.is_fd = true;
        frame.dlc = u8::MAX;
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        assert_eq!(
            serialize_can_frame(&frame, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn serialize_rejects_classical_with_dlc_9() {
        // Classical CAN tops out at DLC=8. DLC=9 is only meaningful in
        // CAN-FD (where it maps to 12 bytes); on a classical frame it
        // must be rejected outright.
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x100;
        frame.is_fd = false;
        frame.dlc = 9;
        let mut buf = [0u8; CAN_HEADER_SIZE + CAN_MAX_DATA];
        assert_eq!(
            serialize_can_frame(&frame, &mut buf),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn parse_rejects_truncated_canfd_dlc_15_buffer() {
        // The on-wire DLC byte says 15 (→ 64 payload bytes) but the
        // kernel buffer only carries `header + 16` bytes. The parser
        // must reject this — silently truncating would emit a 64-byte
        // RawCanFrame.data slice with 48 stale bytes downstream.
        let mut buf = [0u8; CAN_HEADER_SIZE + 16];
        let id: u32 = 0x123;
        buf[..4].copy_from_slice(&id.to_le_bytes());
        buf[4] = 15;
        assert_eq!(parse_can_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_rejects_truncated_canfd_dlc_9_buffer() {
        // DLC=9 means 12 payload bytes; a buffer with only 8 must be
        // rejected. Pins the boundary between "would have passed under
        // the old raw-byte-count semantics" (8 bytes <= 9 raw bytes is
        // not enough either, but the old code would error for a
        // different reason — the new logic errors on ISO-mapped length).
        let mut buf = [0u8; CAN_HEADER_SIZE + 8];
        buf[4] = 9;
        assert_eq!(parse_can_frame(&buf), Err(VsError::InvalidInput));
    }

    #[test]
    fn parse_accepts_canfd_dlc_9_with_12_byte_buffer() {
        // Mirrors the negative test above: the same DLC with a full
        // 12-byte payload must parse cleanly.
        let mut buf = [0u8; CAN_HEADER_SIZE + 12];
        buf[4] = 9;
        for (i, b) in buf[CAN_HEADER_SIZE..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x80);
        }
        let f = parse_can_frame(&buf).unwrap();
        assert_eq!(f.dlc, 9);
        assert!(f.is_fd);
        assert_eq!(f.payload_len(), 12);
        for (i, b) in f.data[..12].iter().enumerate() {
            assert_eq!(*b, (i as u8).wrapping_add(0x80));
        }
    }

    // -----------------------------------------------------------------------
    // Audit fix HIGH: EAGAIN / EWOULDBLOCK / EINTR helpers (host build)
    // -----------------------------------------------------------------------

    #[test]
    fn would_block_helper_recognises_eagain() {
        // QNX EAGAIN == 11 (also == EWOULDBLOCK).
        assert!(is_would_block_test(11));
        // EINTR (4), EBADF (9), generic errors must NOT count as would-block.
        assert!(!is_would_block_test(4));
        assert!(!is_would_block_test(9));
        assert!(!is_would_block_test(0));
    }

    #[test]
    fn eintr_helper_recognises_only_eintr() {
        assert!(is_eintr_test(4));
        assert!(!is_eintr_test(11));
        assert!(!is_eintr_test(0));
    }

    // -----------------------------------------------------------------------
    // Audit fix HIGH: bounded EINTR retry loop (retry_on_eintr)
    //
    // The seam under test is the security boundary for the DoS bound on
    // `receive()` paths. The closure passed to `retry_on_eintr` stands in
    // for the real `read()` syscall — we drive it with synthetic EINTRs
    // so the cap can be exercised without a live QNX kernel.
    // -----------------------------------------------------------------------

    /// Convenience: a closure source that yields EINTR `n` times then
    /// returns `Ok(success_value)` on the (n+1)-th call. Counts calls in
    /// a `Cell` so the closure stays `FnMut` without external state.
    fn eintr_then_ok(eintr_count: u8, success_value: isize) -> impl FnMut() -> Result<isize, i32> {
        let mut calls: u8 = 0;
        move || {
            if calls < eintr_count {
                calls += 1;
                Err(4) // QNX EINTR
            } else {
                Ok(success_value)
            }
        }
    }

    #[test]
    fn retry_on_eintr_succeeds_immediately() {
        // Zero EINTRs: the helper returns the first Ok unchanged.
        let mut calls: u8 = 0;
        let out = retry_on_eintr(
            || {
                calls += 1;
                Ok(42)
            },
            is_eintr_test,
        );
        assert_eq!(out, RxOutcome::Got(42));
        assert_eq!(calls, 1);
    }

    #[test]
    fn retry_on_eintr_succeeds_after_one_retry() {
        let out = retry_on_eintr(eintr_then_ok(1, 16), is_eintr_test);
        assert_eq!(out, RxOutcome::Got(16));
    }

    #[test]
    fn retry_on_eintr_succeeds_after_two_retries() {
        let out = retry_on_eintr(eintr_then_ok(2, 24), is_eintr_test);
        assert_eq!(out, RxOutcome::Got(24));
    }

    #[test]
    fn retry_on_eintr_succeeds_after_seven_retries() {
        // 7 EINTRs is one fewer than the cap; the 8th call returns Ok.
        let out = retry_on_eintr(eintr_then_ok(7, 100), is_eintr_test);
        assert_eq!(out, RxOutcome::Got(100));
    }

    #[test]
    fn retry_on_eintr_boundary_succeeds_on_last_allowed_retry() {
        // Pin the boundary precisely. The cap is MAX_EINTR_RETRIES (8);
        // after MAX_EINTR_RETRIES - 1 = 7 EINTRs the helper has used
        // 7 of its 8 attempts and the next call may still succeed.
        // (After MAX_EINTR_RETRIES consecutive EINTRs it must bail.)
        assert_eq!(MAX_EINTR_RETRIES, 8);
        let out = retry_on_eintr(eintr_then_ok(MAX_EINTR_RETRIES - 1, 7), is_eintr_test);
        assert_eq!(out, RxOutcome::Got(7));
    }

    #[test]
    fn retry_on_eintr_caps_at_max_retries_and_returns_eintr_cap_hit() {
        // MAX_EINTR_RETRIES consecutive EINTRs (no success ever) must
        // surface as EintrCapHit so the caller can return VsError::Timeout.
        // We construct a closure that always returns EINTR.
        let mut calls: u32 = 0;
        let out = retry_on_eintr(
            || {
                calls += 1;
                Err(4) // EINTR forever
            },
            is_eintr_test,
        );
        assert_eq!(out, RxOutcome::EintrCapHit);
        // Saturating counter: the helper makes exactly MAX_EINTR_RETRIES
        // attempts before bailing. (The first EINTR is attempt #1; the
        // helper bails when `attempts >= MAX_EINTR_RETRIES` after
        // incrementing, i.e. on the MAX_EINTR_RETRIES-th call.)
        assert_eq!(calls, u32::from(MAX_EINTR_RETRIES));
    }

    #[test]
    fn retry_on_eintr_propagates_non_eintr_errors_verbatim() {
        // EAGAIN must not be retried — the helper surfaces it as
        // `Err(11)` and the receive callers translate it to `Ok(None)`.
        let out = retry_on_eintr(|| Err(11), is_eintr_test);
        assert_eq!(out, RxOutcome::Err(11));
    }

    #[test]
    fn retry_on_eintr_propagates_eio_after_eintr_burst() {
        // A burst of EINTRs followed by a real error (EIO = 5) must
        // surface the real error, NOT the cap-hit sentinel.
        let mut calls: u8 = 0;
        let out = retry_on_eintr(
            || {
                calls += 1;
                if calls <= 3 {
                    Err(4) // EINTR
                } else {
                    Err(5) // EIO
                }
            },
            is_eintr_test,
        );
        assert_eq!(out, RxOutcome::Err(5));
    }

    #[test]
    fn retry_on_eintr_zero_byte_read_is_ok_not_retried() {
        // POSIX `read()` returning 0 means EOF — the helper must surface
        // it as `Got(0)` rather than retrying. (The receive callers then
        // map `Got(0)` to `Ok(None)`.)
        let out = retry_on_eintr(|| Ok(0), is_eintr_test);
        assert_eq!(out, RxOutcome::Got(0));
    }

    #[test]
    fn max_eintr_retries_constant_matches_documented_value() {
        // Pin the constant. If a future change relaxes the bound, this
        // test forces an explicit acknowledgement.
        assert_eq!(MAX_EINTR_RETRIES, 8);
    }

    // -----------------------------------------------------------------------
    // Audit fix: error counters / last_error / now_us sentinel surfaces
    // -----------------------------------------------------------------------

    #[test]
    fn fresh_can_bus_reports_no_error() {
        // A freshly-constructed bus has not exercised the wire yet, so
        // both observability surfaces must be at their initial state.
        use vs_hal::CanBus;
        let bus = QnxCanBus::new(500_000);
        assert_eq!(bus.last_error(), vs_hal::CanError::None);
        let c = bus.error_counters().expect("error_counters returns Some on QnxCanBus");
        assert_eq!(c.tx_error_count, 0);
        assert_eq!(c.rx_error_count, 0);
    }

    #[test]
    fn now_us_sentinel_returned_on_non_qnx_target() {
        use vs_hal::Timer;
        // On host (non-NTO) builds the implementation returns the
        // "clock unavailable" sentinel. Pin that contract here.
        let timer = QnxTimer::new();
        assert_eq!(timer.now_us(), u64::MAX);
    }

    #[test]
    fn ethernet_default_path_is_bpf0() {
        // Pinning the audit-fixed default. `/dev/bpf` does not exist on
        // stock QNX SDP installs; numbered nodes are canonical.
        let eth = QnxEthernetPhy::new(1000);
        assert_eq!(&eth.device_path[..10], b"/dev/bpf0\0");
    }

    // -----------------------------------------------------------------------
    // Audit fix HIGH: VLAN frame parsing (1518 / 1522 / 1523-byte ceilings)
    // -----------------------------------------------------------------------
    //
    // Single-tagged 802.1Q frames are 1518 bytes on the wire. Frames
    // delivered by BPF with the FCS still attached are 1522 bytes. Both
    // sizes must now make it through `parse_eth_frame` undamaged; one
    // byte more (1523) must be explicitly rejected, not silently
    // clamped.

    #[test]
    fn parse_eth_frame_single_vlan_frame_1518_bytes_round_trips() {
        // Build a single-tagged frame: 14 header + 4 VLAN + 1500 payload.
        const ETH_LEN: usize = 1518;
        let mut buf = [0u8; BPF_HEADER_SIZE + ETH_LEN];
        // Non-zero DST MAC.
        buf[BPF_HEADER_SIZE] = 0x02;
        // EtherType = 0x8100 (VLAN), then VLAN tag, then inner EtherType.
        buf[BPF_HEADER_SIZE + 12] = 0x81;
        buf[BPF_HEADER_SIZE + 13] = 0x00;
        buf[BPF_HEADER_SIZE + 14] = 0x00; // PCP / DEI / VID hi
        buf[BPF_HEADER_SIZE + 15] = 0x64; // VID = 100
        buf[BPF_HEADER_SIZE + 16] = 0x08; // inner EtherType 0x0800 = IPv4
        buf[BPF_HEADER_SIZE + 17] = 0x00;
        // Stamp the last byte so we can prove the trailing octet
        // survives the parse — previously this was lost to the 1514
        // cap. ETH_LEN-1 = 1517.
        buf[BPF_HEADER_SIZE + ETH_LEN - 1] = 0xCA;
        let frame = parse_eth_frame(&buf).unwrap();
        assert_eq!(frame.len as usize, ETH_LEN);
        assert_eq!(frame.payload().len(), ETH_LEN);
        assert_eq!(frame.payload()[ETH_LEN - 1], 0xCA);
    }

    #[test]
    fn parse_eth_frame_1522_bytes_with_fcs_round_trips() {
        // 1518 (single-tag) + 4 FCS bytes — the worst case BPF can hand
        // up when the driver does not strip the FCS. We stamp the bytes
        // at positions 1514..1521 so the test directly proves the
        // VLAN-truncation fix: those bytes were INVISIBLE on the
        // previous `ETH_FRAME_MAX = 1514` setting.
        const ETH_LEN: usize = ETH_FRAME_MAX; // 1522
        let mut buf = [0u8; BPF_HEADER_SIZE + ETH_LEN];
        buf[BPF_HEADER_SIZE] = 0x02; // non-zero DST MAC
        buf[BPF_HEADER_SIZE + 12] = 0x81; // 0x8100 VLAN
        buf[BPF_HEADER_SIZE + 13] = 0x00;
        // Stamp the last 8 octets with a recognisable pattern so the
        // assertion documents which bytes were previously lost.
        for (i, off) in (1514..1522).enumerate() {
            buf[BPF_HEADER_SIZE + off] = 0xA0 + i as u8;
        }
        let frame = parse_eth_frame(&buf).unwrap();
        assert_eq!(frame.len as usize, ETH_LEN);
        let payload = frame.payload();
        // Verify each of the 8 previously-invisible bytes survives.
        for (i, off) in (1514..1522).enumerate() {
            assert_eq!(
                payload[off],
                0xA0 + i as u8,
                "byte at offset {off} (within {ETH_LEN}-byte frame) was lost"
            );
        }
    }

    #[test]
    fn parse_eth_frame_1523_bytes_rejected() {
        // One byte above the 1522 ceiling must be a hard rejection, not
        // a silent clamp. This was the security hole: any frame above
        // ETH_FRAME_MAX previously delivered a truncated body to the
        // caller with no signal that data had been dropped.
        const ETH_LEN: usize = ETH_FRAME_MAX + 1; // 1523
        let mut buf = [0u8; BPF_HEADER_SIZE + ETH_LEN];
        buf[BPF_HEADER_SIZE] = 0x02;
        buf[BPF_HEADER_SIZE + 12] = 0x08;
        assert_eq!(parse_eth_frame(&buf), Err(VsError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // Audit fix: recover_bus_off() clears the heuristic bus-off state
    // -----------------------------------------------------------------------

    #[test]
    fn recover_bus_off_clears_latched_state() {
        use vs_hal::CanBus;
        let mut bus = QnxCanBus::new(500_000);
        // The latching codepath only runs inside the QNX-specific
        // `transmit()` body, which is not exercised on the host build.
        // Simulate a latched bus-off by writing the same in-process
        // state the heuristic would produce after
        // MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF (=16) consecutive TX
        // failures, then assert `recover_bus_off()` clears both pieces
        // of state.
        bus.consecutive_tx_errors = 16;
        bus.bus_off = true;
        bus.last_error = vs_hal::CanError::BusOff;
        assert!(bus.is_bus_off());
        bus.recover_bus_off().unwrap();
        assert!(!bus.is_bus_off());
        assert_eq!(bus.consecutive_tx_errors, 0);
        assert_eq!(bus.last_error(), vs_hal::CanError::None);
    }

    #[test]
    fn recover_bus_off_is_idempotent_on_clean_bus() {
        // Negative path: calling recover on a healthy bus must not flip
        // any state into a worse condition.
        use vs_hal::CanBus;
        let mut bus = QnxCanBus::new(500_000);
        assert!(!bus.is_bus_off());
        assert_eq!(bus.consecutive_tx_errors, 0);
        bus.recover_bus_off().unwrap();
        assert!(!bus.is_bus_off());
        assert_eq!(bus.consecutive_tx_errors, 0);
        assert_eq!(bus.last_error(), vs_hal::CanError::None);
    }

    // -----------------------------------------------------------------------
    // audit-M11: recover_bus_off() rate-limit (CAN-spec 128×11 recessive bits)
    // -----------------------------------------------------------------------
    //
    // The on-target devctl is QNX-only, so we exercise the rate-limit
    // contract via the pure `simulate_recover_bus_off_rate_limit`
    // helper. The QNX `recover_bus_off` calls the same helper, so a
    // drift between the two paths will surface here.

    #[test]
    fn recover_bus_off_rate_limit_first_call_allowed() {
        // Positive: the first call has no prior timestamp, so the
        // helper must allow it through. This matches the "fresh bus
        // recovers immediately after boot" requirement.
        let result = simulate_recover_bus_off_rate_limit(1_000_000, None);
        assert!(result.is_ok());
    }

    #[test]
    fn recover_bus_off_rate_limit_second_call_after_window_allowed() {
        // Positive: the second call lands at `now + 21_000` µs, which
        // is > RECOVER_BUS_OFF_MIN_INTERVAL_US (20_000 µs) past the
        // previous recovery. Must be allowed.
        let first = 1_000_000u64;
        let second = first + 21_000;
        let result = simulate_recover_bus_off_rate_limit(second, Some(first));
        assert!(result.is_ok());
    }

    #[test]
    fn recover_bus_off_rate_limit_second_call_well_inside_window_rejected() {
        // Negative: a second call only 5_000 µs after the previous
        // recovery is well inside the 20 ms window and must be
        // rejected with ResourceExhausted.
        let first = 1_000_000u64;
        let second = first + 5_000;
        let result = simulate_recover_bus_off_rate_limit(second, Some(first));
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn recover_bus_off_rate_limit_one_us_inside_window_rejected() {
        // Negative: boundary check — a call landing exactly one
        // microsecond before the window closes (now + 20_000 - 1 =
        // now + 19_999 µs) must still be rejected. The window is
        // half-open `[prev, prev + RECOVER_BUS_OFF_MIN_INTERVAL_US)`.
        let first = 1_000_000u64;
        let second = first + RECOVER_BUS_OFF_MIN_INTERVAL_US - 1;
        let result = simulate_recover_bus_off_rate_limit(second, Some(first));
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn recover_bus_off_rate_limit_clock_failure_sentinel_allows_call() {
        // Positive: a `now_us == u64::MAX` clock-failure sentinel must
        // pass through unconditionally. A bus-off recovery is safety-
        // critical; blocking it on a dead clock would convert one
        // fault into two. See the helper's doc-comment for the trade-
        // off discussion.
        let first = 1_000_000u64;
        let result = simulate_recover_bus_off_rate_limit(u64::MAX, Some(first));
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Audit fix: partial-write retry path (MAX_PARTIAL_WRITE_RETRIES)
    // -----------------------------------------------------------------------
    //
    // The retry loop itself lives inside the QNX-specific `transmit()`
    // body, so we exercise the contract via a pure helper on the host
    // build. The helper mirrors the loop's accounting so a future drift
    // between the two will surface as a test failure.

    /// Pure-Rust mirror of the partial-write retry loop in
    /// `QnxCanBus::transmit`. Returns `Ok(bytes_written)` once the
    /// frame is fully written or `Err` after
    /// `MAX_PARTIAL_WRITE_RETRIES_TEST` partial events.
    ///
    /// `writer(remaining)` mimics the kernel `write()` syscall: it
    /// returns the number of bytes the kernel queued this iteration
    /// (0 = nothing queued, partial; < remaining = partial; ==
    /// remaining = done).
    fn simulate_partial_write_loop<F: FnMut(usize) -> usize>(
        total: usize,
        mut writer: F,
    ) -> Result<usize, VsError> {
        const MAX_PARTIAL_WRITE_RETRIES_TEST: u8 = 4;
        let mut written = 0usize;
        let mut partial_attempts: u8 = 0;
        while written < total {
            let progressed = writer(total - written);
            if progressed == 0 {
                partial_attempts = partial_attempts.saturating_add(1);
                if partial_attempts >= MAX_PARTIAL_WRITE_RETRIES_TEST {
                    return Err(VsError::BusError);
                }
                continue;
            }
            written += progressed;
            if written < total {
                partial_attempts = partial_attempts.saturating_add(1);
                if partial_attempts >= MAX_PARTIAL_WRITE_RETRIES_TEST {
                    return Err(VsError::BusError);
                }
            }
        }
        Ok(written)
    }

    #[test]
    fn partial_write_loop_byte_by_byte_succeeds_when_few_iterations() {
        // 3 byte frame, write 1 byte at a time — completes in 3 calls
        // with 2 partial events. MAX = 4 so this must succeed.
        let mut calls = 0u32;
        let result = simulate_partial_write_loop(3, |_remaining| {
            calls += 1;
            1
        });
        assert_eq!(result, Ok(3));
        assert_eq!(calls, 3);
    }

    #[test]
    fn partial_write_loop_byte_by_byte_fails_after_4_partials() {
        // 8 byte frame, write 1 byte at a time — 7 partial events
        // before completion. MAX = 4 so this must error.
        let result = simulate_partial_write_loop(8, |_remaining| 1);
        assert_eq!(result, Err(VsError::BusError));
    }

    #[test]
    fn partial_write_loop_zero_queued_fails_after_4_retries() {
        // Kernel keeps returning 0 (queue full) — must error after 4
        // attempts rather than spinning forever.
        let mut calls = 0u32;
        let result = simulate_partial_write_loop(8, |_remaining| {
            calls += 1;
            0
        });
        assert_eq!(result, Err(VsError::BusError));
        assert_eq!(calls, 4);
    }

    #[test]
    fn partial_write_loop_full_write_succeeds_first_try() {
        // Positive control: a kernel that queues everything in one call
        // completes with no partials and no errors.
        let mut calls = 0u32;
        let result = simulate_partial_write_loop(8, |remaining| {
            calls += 1;
            remaining
        });
        assert_eq!(result, Ok(8));
        assert_eq!(calls, 1);
    }

    // -----------------------------------------------------------------------
    // Audit fix CRIT-6: EINTR cap on TX paths (CAN + Ethernet)
    // -----------------------------------------------------------------------
    //
    // The transmit() bodies wrap their single `write()` syscall in
    // `retry_on_eintr`, the same helper used by the receive paths. We
    // cannot exercise the real syscall on the host, but we can pin the
    // contract by driving `retry_on_eintr` with the exact same EINTR
    // recognizer used at the TX callsites (`is_eintr_test` mirrors the
    // QNX `is_eintr` errno test) and the same `RxOutcome` mapping the
    // TX bodies branch on. Drift between the helper and the callsites
    // surfaces here as a test failure.

    /// Pure-Rust mirror of the `RxOutcome` → `VsError` mapping used by
    /// the audit-fixed CAN/Ethernet TX paths. Returns the same error
    /// variants the production code surfaces:
    ///   - cap-hit → `VsError::Timeout` (signal-storm `DoS` bail-out)
    ///   - non-EINTR errno → `qnx_errno_to_vserror`-equivalent (here we
    ///     pin the EAGAIN→Timeout / EIO→BusError mappings since those
    ///     are the host-observable equivalents).
    fn simulate_tx_eintr_wrap<F>(write_once: F) -> Result<isize, VsError>
    where
        F: FnMut() -> Result<isize, i32>,
    {
        match retry_on_eintr(write_once, is_eintr_test) {
            RxOutcome::Got(n) => Ok(n),
            // 11 = EAGAIN, 5 = EIO — match the QNX errno mapping the
            // production code uses via `qnx_errno_to_vserror`. Cap-hit
            // (signal-storm bail-out) maps to the same `Timeout` variant
            // as EAGAIN so callers see a unified "retry exhausted" signal.
            RxOutcome::EintrCapHit | RxOutcome::Err(11) => Err(VsError::Timeout),
            RxOutcome::Err(5) => Err(VsError::BusError),
            RxOutcome::Err(_) => Err(VsError::NotInitialized),
        }
    }

    #[test]
    fn tx_eintr_wrap_succeeds_on_first_attempt() {
        // Positive path: a `write()` that succeeds immediately returns
        // `Ok(n)` with no retries. This mirrors the common case in both
        // CAN and Ethernet transmit() — no signal interruption, kernel
        // queues the frame on the first call.
        let mut calls = 0u32;
        let result = simulate_tx_eintr_wrap(|| {
            calls += 1;
            Ok(64) // kernel reports 64 bytes queued
        });
        assert_eq!(result, Ok(64));
        assert_eq!(calls, 1);
    }

    #[test]
    fn tx_eintr_wrap_succeeds_after_a_few_eintrs() {
        // Mid-range positive path: a couple of EINTRs followed by
        // success — the bounded helper transparently retries and the
        // caller never sees the interruptions.
        let result = simulate_tx_eintr_wrap(eintr_then_ok(3, 128));
        assert_eq!(result, Ok(128));
    }

    #[test]
    fn tx_eintr_wrap_caps_at_max_retries_returns_timeout() {
        // Negative path (the actual security seam): an adversarial
        // signal storm that keeps EINTR'ing the `write()` syscall must
        // be bounded. After MAX_EINTR_RETRIES consecutive EINTRs the
        // helper bails with EintrCapHit and the TX body surfaces it as
        // `VsError::Timeout`, NOT an unbounded spin.
        let mut calls: u32 = 0;
        let result = simulate_tx_eintr_wrap(|| {
            calls += 1;
            Err(4) // EINTR forever
        });
        assert_eq!(result, Err(VsError::Timeout));
        // Verify the bound itself: the helper made exactly
        // MAX_EINTR_RETRIES attempts before giving up.
        assert_eq!(calls, u32::from(MAX_EINTR_RETRIES));
    }

    #[test]
    fn tx_eintr_wrap_propagates_eio_through_burst() {
        // A burst of EINTRs followed by EIO must surface the real
        // error (BusError) and NOT the cap-hit sentinel — pinning that
        // EINTR retries don't mask genuine bus failures on TX.
        let mut calls: u8 = 0;
        let result = simulate_tx_eintr_wrap(|| {
            calls += 1;
            if calls <= 2 {
                Err(4) // EINTR
            } else {
                Err(5) // EIO
            }
        });
        assert_eq!(result, Err(VsError::BusError));
    }

    // Audit fix HIGH: `IfReq` marshalling for SIOCGIFFLAGS
    //
    // These tests exercise the host-side marshalling logic for the
    // `struct ifreq` buffer used by `update_link_state` on QNX. The
    // syscall itself can only be exercised on the QNX target, but the
    // pre-syscall buffer layout (name padding, flag offset, total size)
    // must be wire-correct on every host, since a layout mismatch is
    // exactly the regression that produced the original stack-overflow.
    // -----------------------------------------------------------------------

    #[test]
    fn ifreq_layout_is_32_bytes() {
        // Compile-time guard (`const _: () = assert!(...)`) already
        // pins this; mirror it as a runtime test so the failure is
        // visible in test output rather than as a confusing build break
        // on a future SDP bump.
        assert_eq!(core::mem::size_of::<IfReq>(), 32);
        assert_eq!(core::mem::size_of::<IfReq>(), IFREQ_SIZE);
        assert_eq!(IFNAMSIZ, 16);
    }

    #[test]
    fn ifreq_marshals_short_iface_name() {
        // "en0" → 3 bytes payload + 13 bytes NUL padding.
        let req = IfReq::new(b"en0").expect("3-byte name fits in IFNAMSIZ");
        assert_eq!(&req.ifr_name[..3], b"en0");
        // Everything past the payload must be NUL — the kernel parses
        // ifr_name as a C string and a stray non-NUL would either
        // select the wrong interface or fail ENXIO.
        for &b in &req.ifr_name[3..] {
            assert_eq!(b, 0, "ifr_name not NUL-padded past payload");
        }
        // ifr_ifru is zeroed before the kernel writes to it.
        assert_eq!(req.ifr_ifru, [0u8; 16]);
    }

    #[test]
    fn ifreq_marshals_15_char_iface_name() {
        // Exactly IFNAMSIZ-1 = 15 chars + the one NUL byte at index 15.
        let name = b"abcdefghijklmno"; // 15 bytes
        let req = IfReq::new(name).expect("15-byte name leaves room for NUL");
        assert_eq!(&req.ifr_name[..15], name);
        assert_eq!(req.ifr_name[15], 0, "trailing byte must be NUL");
    }

    #[test]
    fn ifreq_rejects_16_char_iface_name() {
        // 16 bytes fills the entire ifr_name without a terminator. Some
        // libcs tolerate non-NUL-terminated names; we reject for safety
        // because the contract becomes ambiguous on a mixed-SDP fleet.
        let name = b"abcdefghijklmnop"; // 16 bytes
        assert_eq!(IfReq::new(name), Err(VsError::InvalidInput));
    }

    #[test]
    fn ifreq_rejects_empty_iface_name() {
        // Empty name would select interface "" which is meaningless and
        // returns ENXIO from any conforming SIOCGIFFLAGS. Reject at the
        // marshalling boundary so the error surfaces before the syscall.
        assert_eq!(IfReq::new(b""), Err(VsError::InvalidInput));
    }

    #[test]
    fn ifreq_rejects_interior_nul_iface_name() {
        // Interior NUL would silently truncate the C-string parse on
        // the kernel side and possibly select an unintended interface.
        let name = b"en\x000"; // "en\0" + extra byte
        assert_eq!(IfReq::new(name), Err(VsError::InvalidInput));
    }

    #[test]
    fn ifreq_flags_reads_little_endian_i16() {
        // Stage a known writeback shape: ifr_ifru bytes [0x41, 0x00, ..]
        // must decode as i16 0x0041 (= IFF_UP | IFF_RUNNING) on every
        // little-endian QNX target.
        let mut req = IfReq::new(b"en0").expect("valid name");
        req.set_flags(0x0041); // IFF_UP (0x01) | IFF_RUNNING (0x40)
        assert_eq!(req.ifr_ifru[0], 0x41, "LSB at union offset 0");
        assert_eq!(req.ifr_ifru[1], 0x00, "MSB at union offset 1");
        assert_eq!(req.flags(), 0x0041);
    }

    #[test]
    fn ifreq_flags_reads_zero_for_zeroed_union() {
        // Negative path: a freshly-constructed IfReq has a zeroed union,
        // so flags() must read 0 — important for the update_link_state
        // path that calls flags() unconditionally after a successful
        // ioctl; a zeroed buffer must not register as link-up.
        let req = IfReq::new(b"en0").expect("valid name");
        assert_eq!(req.flags(), 0);
    }

    #[test]
    fn ifreq_flags_handles_negative_i16() {
        // ifr_flags is a *signed* short on POSIX. The MSB being set
        // must round-trip as a negative i16, not wrap into u16
        // arbitration. Negative path proving the signed decode.
        let mut req = IfReq::new(b"en0").expect("valid name");
        req.set_flags(-1);
        assert_eq!(req.ifr_ifru[0], 0xFF);
        assert_eq!(req.ifr_ifru[1], 0xFF);
        assert_eq!(req.flags(), -1);
    }

    #[test]
    fn ifreq_zeroed_constructor_produces_empty_name() {
        let req = IfReq::zeroed();
        assert_eq!(req.ifr_name, [0u8; 16]);
        assert_eq!(req.ifr_ifru, [0u8; 16]);
    }

    #[test]
    fn ethernet_default_iface_name_is_en0() {
        let eth = QnxEthernetPhy::new(1000);
        assert_eq!(&eth.iface_name[..3], b"en0");
        assert_eq!(eth.iface_name_len, 3);
        // Padding past the payload must be NUL so the name is a valid
        // C string for the kernel-side `ifr_name` parse.
        for &b in &eth.iface_name[3..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn ethernet_custom_iface_name_is_stored() {
        let eth = QnxEthernetPhy::new_with_device_and_iface(1000, b"/dev/bpf0\0", b"wm1")
            .expect("valid iface name");
        assert_eq!(&eth.iface_name[..3], b"wm1");
        assert_eq!(eth.iface_name_len, 3);
    }

    #[test]
    fn ethernet_custom_iface_rejects_overlong_name() {
        let too_long = [b'x'; 16];
        let r = QnxEthernetPhy::new_with_device_and_iface(1000, b"/dev/bpf0\0", &too_long);
        assert_eq!(r.err(), Some(VsError::InvalidInput));
    }

    #[test]
    fn ethernet_custom_iface_rejects_empty_name() {
        let r = QnxEthernetPhy::new_with_device_and_iface(1000, b"/dev/bpf0\0", b"");
        assert_eq!(r.err(), Some(VsError::InvalidInput));
    }

    #[test]
    fn ethernet_custom_iface_rejects_interior_nul() {
        let r = QnxEthernetPhy::new_with_device_and_iface(1000, b"/dev/bpf0\0", b"en\x000");
        assert_eq!(r.err(), Some(VsError::InvalidInput));
    }

    // ------------------------------------------------------------------
    // Audit fix (audit-M10): CAN ID admission filter
    // ------------------------------------------------------------------

    /// Iterate the admission filter over a fixed list of IDs and return
    /// how many of them would have been passed through. Mirrors the
    /// loop body inside `<QnxCanBus as CanBus>::receive` on QNX so the
    /// host-side test suite can exercise the filter logic without a
    /// live kernel underneath.
    fn admit_count(can: &mut QnxCanBus, ids: &[u32]) -> usize {
        let mut passed = 0usize;
        for &id in ids {
            if can.admit_frame(id) {
                passed += 1;
            }
        }
        passed
    }

    #[test]
    fn can_filter_default_accepts_every_id() {
        // Positive: a freshly-constructed bus has no filters and uses
        // AcceptUnmatched by default → every frame passes through and
        // the drop counter stays at zero.
        let mut can = QnxCanBus::new(500_000);
        assert_eq!(can.filter_drop_count(), 0);
        let ids = [0x000, 0x100, 0x123, 0x7E0, 0x7FF, 0x1FFF_FFFF];
        let passed = admit_count(&mut can, &ids);
        assert_eq!(passed, ids.len());
        assert_eq!(can.filter_drop_count(), 0);
    }

    #[test]
    fn can_filter_accept_unmatched_with_one_reject_drops_only_that_id() {
        // Positive: AcceptUnmatched + a single reject filter on 0x123.
        // Frames with ID 0x123 are dropped, every other ID passes
        // through, and the drop counter matches the count of dropped
        // frames exactly.
        let mut can = QnxCanBus::new(500_000);
        can.set_default_policy(CanAdmissionPolicy::AcceptUnmatched);
        can.add_id_reject(0x123, CAN_ID_MASK_29BIT)
            .expect("valid reject slot");

        // Three 0x123 frames interleaved with three other IDs.
        let ids = [0x123, 0x100, 0x123, 0x200, 0x300, 0x123];
        let passed = admit_count(&mut can, &ids);
        assert_eq!(passed, 3, "three non-0x123 frames pass");
        assert_eq!(can.filter_drop_count(), 3, "three 0x123 frames dropped");
    }

    #[test]
    fn can_filter_reject_unmatched_with_accept_range_passes_only_range() {
        // Positive: RejectUnmatched + one accept filter for the OBD-II
        // diagnostic range 0x7E0..=0x7EF (mask 0x7F0 → matches any ID
        // whose top 11-4 bits equal 0x7E_). Only frames in that range
        // pass through; everything else is dropped and counted.
        let mut can = QnxCanBus::new(500_000);
        can.set_default_policy(CanAdmissionPolicy::RejectUnmatched);
        can.add_id_accept(0x7E0, 0x7F0).expect("valid accept slot");

        // 4 in-range IDs + 3 out-of-range IDs.
        let ids = [
            0x7E0, // in
            0x7E1, // in
            0x7EF, // in
            0x7E8, // in
            0x000, // out
            0x100, // out
            0x7F0, // out (next nibble)
        ];
        let passed = admit_count(&mut can, &ids);
        assert_eq!(passed, 4, "four in-range frames pass");
        assert_eq!(can.filter_drop_count(), 3, "three out-of-range dropped");
    }

    #[test]
    fn can_filter_first_match_wins_with_reject_before_accept() {
        // Sanity check on insertion-order evaluation: a specific reject
        // for 0x123 placed BEFORE a broad accept-all (0x000 / mask 0x1)
        // must still drop 0x123. (`0x000 / 0x1` matches any even ID.)
        let mut can = QnxCanBus::new(500_000);
        can.set_default_policy(CanAdmissionPolicy::RejectUnmatched);
        can.add_id_reject(0x122, CAN_ID_MASK_29BIT)
            .expect("specific reject");
        can.add_id_accept(0x000, 0x1).expect("broad accept-even");

        // 0x122 hits the reject slot first → dropped.
        // 0x100 is even → accepted via the broad slot.
        // 0x101 is odd, doesn't match accept slot, and the default is
        // RejectUnmatched → dropped.
        assert!(!can.admit_frame(0x122));
        assert!(can.admit_frame(0x100));
        assert!(!can.admit_frame(0x101));
        assert_eq!(can.filter_drop_count(), 2);
    }

    #[test]
    fn can_filter_clear_resets_table_but_not_counter() {
        let mut can = QnxCanBus::new(500_000);
        can.add_id_reject(0x123, CAN_ID_MASK_29BIT).unwrap();
        assert!(!can.admit_frame(0x123));
        assert_eq!(can.filter_drop_count(), 1);

        can.clear_id_filters();
        // Slot is gone → 0x123 now passes (default policy is still
        // AcceptUnmatched). Drop counter is preserved across clear so a
        // long-running observer doesn't see the history evaporate.
        assert!(can.admit_frame(0x123));
        assert_eq!(can.filter_drop_count(), 1);
    }

    #[test]
    fn can_filter_add_accept_returns_invalid_input_when_table_full() {
        // Negative: fill the table to CAN_FILTER_SLOTS and confirm the
        // next add_id_accept call returns InvalidInput.
        let mut can = QnxCanBus::new(500_000);
        for i in 0..CAN_FILTER_SLOTS as u32 {
            can.add_id_accept(i, CAN_ID_MASK_29BIT)
                .expect("slot must fit");
        }
        // Table is now full.
        let r = can.add_id_accept(0x100, CAN_ID_MASK_29BIT);
        assert_eq!(r, Err(VsError::InvalidInput));
        // add_id_reject must also refuse when the table is full.
        let r = can.add_id_reject(0x200, CAN_ID_MASK_29BIT);
        assert_eq!(r, Err(VsError::InvalidInput));
    }

    #[test]
    fn can_filter_add_accept_rejects_mask_with_reserved_bits_set() {
        // Negative: mask 0x8000_0000 sets bit 31 (well above the 29-bit
        // CAN-ID space). This usually indicates the caller confused an
        // 11-bit / 29-bit ID with a 32-bit integer mask; reject loudly.
        let mut can = QnxCanBus::new(500_000);
        let r = can.add_id_accept(0x123, 0x8000_0000);
        assert_eq!(r, Err(VsError::InvalidInput));
        // The boundary at bit 29 is the lowest reserved bit; cover it
        // explicitly so a future loosening of the check is visible.
        let r = can.add_id_accept(0x123, 0x2000_0000);
        assert_eq!(r, Err(VsError::InvalidInput));
        // Mask == 0 collides with the "unused slot" sentinel.
        let r = can.add_id_accept(0x123, 0x0000_0000);
        assert_eq!(r, Err(VsError::InvalidInput));
        // ID above the 29-bit max is also rejected.
        let r = can.add_id_accept(0x2000_0000, CAN_ID_MASK_29BIT);
        assert_eq!(r, Err(VsError::InvalidInput));
        // Same negative-path checks for add_id_reject (the underlying
        // helper is shared, but lock the contract in tests).
        let r = can.add_id_reject(0x123, 0x8000_0000);
        assert_eq!(r, Err(VsError::InvalidInput));
        let r = can.add_id_reject(0x123, 0x0000_0000);
        assert_eq!(r, Err(VsError::InvalidInput));
    }

    #[test]
    fn can_filter_drop_counter_saturates_rather_than_wraps() {
        // Defence-in-depth: a long-running task on a hostile bus must
        // not silently zero its drop counter via u64 wraparound. The
        // counter saturates at u64::MAX, so once we plant that value
        // directly, further drops must leave it pinned.
        let mut can = QnxCanBus::new(500_000);
        can.dropped_by_filter = u64::MAX;
        can.set_default_policy(CanAdmissionPolicy::RejectUnmatched);
        assert!(!can.admit_frame(0x100));
        assert!(!can.admit_frame(0x200));
        assert_eq!(can.filter_drop_count(), u64::MAX);
    }

    #[test]
    fn can_admission_policy_default_is_accept_unmatched() {
        // Lock the default-policy contract: changing this would alter
        // the backwards-compatibility story documented in CLAUDE.md.
        assert_eq!(
            CanAdmissionPolicy::default(),
            CanAdmissionPolicy::AcceptUnmatched
        );
    }
}

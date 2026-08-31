// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! `Craton Shield` VSOC telemetry uplink.
//!
//! Provides [`TelemetryConfig`], [`TelemetryEntry`], and [`TelemetryUplink`]
//! for buffering, encrypting, and forwarding security telemetry to a Vehicle Security
//! Operations Centre (VSOC) backend.
//!
//! # Nonce-Reuse Hazard (read before wiring)
//!
//! Every AES-GCM nonce produced by `flush()` contains the persistent
//! `flush_counter` field. If this counter ever repeats under the same
//! encryption key the ciphertexts become trivially recoverable and
//! forgeries become trivial (GCM's catastrophic-nonce-reuse failure mode).
//!
//! The provider makes two hard requirements on callers:
//!
//! 1. **Per-device keys are mandatory.** The nonce layout places the first
//!    4 bytes of `device_id` directly into the nonce as deterministic
//!    per-device separation. That bounds cross-device collisions to
//!    devices that share all of `device_id[0..4]`, but is still *not*
//!    sufficient uniqueness on its own — two devices must never share the
//!    encryption-key slot.
//! 2. **`flush_counter` must be persisted across reboots.** Use
//!    [`PersistedFlushCounter::restore`] as the *only* way to construct
//!    an uplink in production, passing the last value returned by
//!    [`TelemetryUplink::flush_counter`]. The unconditional
//!    [`TelemetryUplink::new`] constructor is documented as test-only /
//!    stateless-device-only; using it on a device that has already
//!    flushed a batch will reuse nonces.
//!
//! Callers must also supply **monotonically non-decreasing** timestamps
//! to [`TelemetryUplink::flush`]. A clock regression would reset the
//! rate-limit window and allow unbounded uplink traffic.

#![no_std]
// SAFETY: this crate is otherwise `unsafe`-free. The only exception is a
// small number of `core::ptr::write_volatile` calls used to defeat dead-store
// elimination when wiping transient plaintext buffers. Every such block
// carries a `// SAFETY:` comment at the call site.
#![allow(unsafe_code)]

// TODO(follow-up): once the workspace-root `Cargo.toml` dev-dep on
// `vs-vsoc-telemetry` adds the `test-only` feature alongside
// `unauthenticated-restore`, the workspace integration tests in
// `src/lib.rs` (which call `flush_no_persist`, `NoOpPersistence`, and
// `PersistedFlushCounter::restore(u64)`) will compile again. The
// `fuzz/Cargo.toml` dev-dep needs the same change for the
// `telemetry_flush` target. The workspace `Cargo.toml` is being edited
// by a parallel agent so this crate cannot land that change atomically.
// See the `test-only` feature definition in `crates/vsoc-telemetry/Cargo.toml`
// for the rationale (footguns must be cfg-gated, `#[deprecated]` is not
// a safety boundary).

// audit-H3: hard compile-fail guard against the `test-only` and
// `unauthenticated-restore` feature flags reaching a release build via
// Cargo feature unification. Both flags ungate the unauthenticated
// `PersistedFlushCounter::restore(u64)` rollback shim and/or the
// `flush_no_persist` wrapper that bypasses the write-ahead counter
// persistence contract. If either survives into a release-profile build
// the AES-GCM nonce-uniqueness invariant collapses (a rolled-back counter
// reuses a nonce under the same key, which is catastrophic).
//
// `debug_assertions` is true in the `dev` and `test` cargo profiles and
// false in `release` and any profile that inherits from `release` (see
// the Cargo Book, "Profiles" chapter). The `test` cfg covers `cargo
// test`. The deliberate escape hatch
// `deliberately-unsafe-release-acknowledged` exists ONLY so a security
// engineer running a hand-audited release with these features active for
// a forensic experiment can opt in; it must never be enabled in a
// shipping artefact.
#[cfg(all(
    any(feature = "test-only", feature = "unauthenticated-restore"),
    not(any(
        test,
        debug_assertions,
        feature = "deliberately-unsafe-release-acknowledged"
    ))
))]
compile_error!(
    "`test-only` and `unauthenticated-restore` features must not be active in release builds. \
     These features expose unauthenticated rollback paths that defeat AES-GCM nonce uniqueness. \
     If you reached this error via cargo feature unification, find the dependency that pulled \
     them in and remove the activation. The only escape hatch is the \
     `deliberately-unsafe-release-acknowledged` feature, which must NEVER be enabled in a \
     shipping artefact. See crates/vsoc-telemetry/README.md (audit-H3 section) and SECURITY.md."
);

use vs_crypto::{CryptoProvider, KeyId};
use vs_types::{AlertSeverity, VsError};

pub mod rollback;

pub use rollback::AssertedExternallyRollbackResistant;

/// Sealed-trait module for [`RollbackResistantStorage`]. Downstream crates
/// cannot name `Sealed`, so only types defined in this crate can implement
/// the marker trait. This prevents a downstream caller from declaring
/// `impl RollbackResistantStorage for MyPlainFsBlob {}` and silently
/// re-introducing the rollback vulnerability (audit-H2).
mod sealed {
    /// Private super-trait of [`super::RollbackResistantStorage`]. Cannot be
    /// implemented outside this crate.
    pub trait Sealed {}
}

/// Marker trait advertising that the wrapped storage backend is durable
/// against rollback: a previously-valid counter blob cannot be replayed
/// after the device has advanced past it.
///
/// # Why this trait exists (audit-H2)
///
/// [`PersistedFlushCounter::restore_authenticated`] verifies an HMAC tag
/// over a 40-byte blob, but the HMAC alone has no notion of *freshness*.
/// An attacker who can snapshot a valid blob at counter value `N` and
/// later overwrite the storage with that blob — after the device has
/// flushed to `N + k` — will succeed in re-installing `N`, causing
/// AES-GCM nonce reuse under the same encryption key. The HMAC-only
/// scheme cannot enforce this property on its own; it has to be supplied
/// by the storage layer.
///
/// Examples of rollback-resistant backends (these are properties of the
/// hardware / firmware, NOT the in-process Rust code):
///
/// - A TPM NV index with `TPMA_NV_WRITE_STCLEAR` set, so the index is
///   write-locked for the remainder of the boot cycle after the first
///   write — a same-boot attacker cannot stomp on it.
/// - A monotonic eFuse counter that physically cannot decrement.
/// - An RPMB (Replay-Protected Memory Block) partition on eMMC.
/// - A bank of fuses, OTP cells, or a secure-element counter.
///
/// # Sealing
///
/// The trait is sealed via [`sealed::Sealed`]. The crate ships exactly
/// one blessed implementation —
/// [`AssertedExternallyRollbackResistant`](rollback::AssertedExternallyRollbackResistant)
/// — which delegates `CounterStorage` to an inner backend and lets the
/// caller assert that the wrapper sits in front of a rollback-resistant
/// medium. Plain `impl CounterStorage for MyFsBlob {}` cannot satisfy
/// the bound on [`PersistedFlushCounter::restore_authenticated_from_storage`]
/// because the caller cannot also write
/// `impl RollbackResistantStorage for MyFsBlob {}` — the `Sealed`
/// super-trait is private.
pub trait RollbackResistantStorage: sealed::Sealed {
    /// Human-readable tag describing what makes the storage backend
    /// resistant to rollback. Surfaces in audit logs and in panic
    /// messages produced by defensive callers.
    ///
    /// Suggested values:
    ///
    /// - `"tpm-nv-write-stclear"` — TPM 2.0 NV index with
    ///   `TPMA_NV_WRITE_STCLEAR` set.
    /// - `"efuse-counter"` — write-once-per-bit eFuse monotonic counter.
    /// - `"rpmb"` — eMMC Replay-Protected Memory Block.
    /// - `"caller-asserted"` — caller used
    ///   [`AssertedExternallyRollbackResistant`](rollback::AssertedExternallyRollbackResistant)
    ///   to commit to an out-of-band guarantee.
    const STORAGE_KIND: &'static str;
}

/// A persistent-storage backend that yields the 40-byte
/// HMAC-authenticated counter blob written by
/// [`PersistedFlushCounter::to_blob`].
///
/// # Why this is a separate trait from [`CounterPersistence`]
///
/// [`CounterPersistence`] is the *write-ahead* sink used during a flush
/// (audit fix CRIT-1). [`CounterStorage`] is the *load* path used at
/// boot to seed `flush_counter` from whatever survived the last power
/// cycle. They typically wrap the same physical medium (a TPM NV
/// index, an RPMB partition, an HMAC-authenticated file) but expose
/// different operations so the boot-time and runtime call sites do not
/// have to share an over-broad trait.
///
/// # Implementations and audit-H2
///
/// A bare `impl CounterStorage for MyType` is *not* sufficient to call
/// [`PersistedFlushCounter::restore_authenticated_from_storage`] —
/// that method additionally requires
/// [`RollbackResistantStorage`], which is sealed. Implementers MUST
/// wire their storage to a rollback-resistant medium and wrap it in
/// [`AssertedExternallyRollbackResistant`](rollback::AssertedExternallyRollbackResistant)
/// at the call site.
/// Sink for durably persisting the monotonic `flush_counter` *before* any
/// encryption happens (audit fix CRIT-1: write-ahead counter).
///
/// # Preferred trait
///
/// New code should implement [`CounterStorage`] instead, which combines
/// the symmetric `load_authenticated` + `persist` halves of the durability
/// contract into a single trait. `CounterPersistence` is the legacy
/// write-only half retained for backwards compatibility, and any type
/// that implements `CounterStorage` automatically implements
/// `CounterPersistence` via a blanket impl below.
///
/// # Contract
///
/// Implementations MUST NOT return `Ok(())` until the new counter value has
/// been written to durable, rollback-resistant storage (e.g., a TPM NV
/// index, an HMAC-authenticated file on an eMMC partition). If the persist
/// call succeeds but the device loses power before a subsequent encrypt,
/// the counter is still "burned" — the next boot sees the new value and
/// the old nonce is never reused. This is the core property that prevents
/// AES-GCM nonce repetition.
///
/// On any failure to persist, return an error. [`TelemetryUplink`] will
/// NOT advance its in-memory counter, so the caller may retry after
/// resolving the underlying storage fault.
///
/// # Idempotency
///
/// Implementations MUST accept a re-write of an already-persisted value:
/// calling `persist(N)` after a previous `persist(N)` returned `Ok` must
/// also return `Ok`. The `flush_with_persistence` jump-over invariant
/// relies on this — after an encrypt-failure-following-persist a retry
/// may legitimately re-attempt the same counter value, and an idempotent
/// rejection here would deadlock the uplink.
pub trait CounterPersistence {
    /// Persist `new_counter` to durable storage. Returns only after the
    /// write is committed.
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError>;
}

/// Unified durability sink for the monotonic `flush_counter`.
///
/// Combines the symmetric `load_authenticated` + `persist` halves of the
/// counter-durability contract into a single trait, so that a single
/// concrete type owns the whole on-disk / NV-index lifecycle. Before this
/// trait existed the load half was implemented out-of-band as
/// [`PersistedFlushCounter::restore_authenticated`] while the persist
/// half went through the unrelated [`CounterPersistence`] trait — making
/// it easy to wire a load implementation against one storage backend and
/// a persist implementation against another, with predictably catastrophic
/// nonce-reuse consequences.
///
/// # Contract (durability, atomicity, monotonicity, authenticator binding)
///
/// Every implementation MUST guarantee:
///
/// - **Durability.** `persist` must not return `Ok(())` until the new
///   counter value is written to rollback-resistant storage. If the
///   device loses power between this method returning and the next boot,
///   `load_authenticated` on the next boot MUST observe the persisted
///   value (or an error — never an older value).
/// - **Atomicity.** A torn write that leaves storage in a half-updated
///   state MUST cause `load_authenticated` on the next boot to return
///   `Err`, NOT a partial/inconsistent counter. Implementations typically
///   achieve this with a journal / two-slot rotation / TPM-NV write that
///   the platform guarantees is atomic.
///   counter, NOT a stale one.
/// - **Idempotency.** `persist(N)` after a previous successful
///   `persist(N)` must also return `Ok` so the
///   [`TelemetryUplink::flush_with_persistence`] retry path can re-attempt
///   the same value without deadlocking.
/// - **Monotonicity.** Implementations SHOULD reject a regression
///   (`persist(N)` after `persist(N+k)`, `k > 0`) — the uplink only ever
///   advances forward, so a regression indicates a logic bug or rollback
///   attack and the implementation has the best vantage point to detect
///   it.
/// - **Authenticator binding.** `load_authenticated` MUST verify the
///   persisted blob against `mac_key_id` and reject any blob whose
///   authenticator does not check out — see
///   [`PersistedFlushCounter::restore_authenticated`] for the canonical
///   tag-verification routine. This is what blocks a rollback attacker
///   from re-presenting an older signed counter and a tamperer from
///   patching the raw counter bytes.
///
/// # Symmetry with `restore_authenticated`
///
/// `load_authenticated` is the natural pair of
/// [`PersistedFlushCounter::to_blob`] +
/// [`PersistedFlushCounter::restore_authenticated`]: an implementation
/// typically reads its 40-byte blob from durable storage and forwards it
/// straight to `restore_authenticated`. The
/// [`TelemetryUplink::from_storage`] convenience constructor consumes a
/// `CounterStorage` end-to-end so callers never have to wire load +
/// `try_restore` + persist as three separate hops.
pub trait CounterStorage {
    /// Load the previously-persisted counter blob and verify its
    /// authenticator. Returns a [`PersistedFlushCounter`] only when the
    /// MAC tag verifies under `mac_key_id`.
    ///
    /// On a factory-fresh device (no prior persisted blob) implementations
    /// MAY return [`PersistedFlushCounter::fresh_device`] — but only if
    /// they can distinguish "no blob" from "blob missing because someone
    /// deleted it" with a separate authenticated channel (e.g. a sealed
    /// fresh-device marker in the same NV index). If they cannot make
    /// that distinction they MUST return an error so the caller cannot
    /// silently roll the counter back to zero.
    fn load_authenticated<C: CryptoProvider>(
        &self,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<PersistedFlushCounter, VsError>;

    /// Persist the next counter value (write-ahead). Same contract as
    /// [`CounterPersistence::persist`]: durable, atomic, idempotent,
    /// monotonic.
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError>;
}

/// Blanket impl so every [`CounterStorage`] also satisfies the legacy
/// [`CounterPersistence`] trait. Existing call sites that take a
/// `&mut impl CounterPersistence` (notably
/// [`TelemetryUplink::flush_with_persistence`] and
/// [`TelemetryUplink::flush_outcome`]) accept `CounterStorage`
/// implementations unchanged — there is no need to maintain two parallel
/// persist implementations during the migration.
impl<T: CounterStorage + ?Sized> CounterPersistence for T {
    #[inline]
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError> {
        <T as CounterStorage>::persist(self, new_counter)
    }
}

/// No-op persistence for test and stateless-device scenarios.
///
/// **Hazard:** every use on a device whose encryption key survives a
/// reboot leaks nonce reuse — only use on factory-fresh / single-boot
/// test rigs.
///
/// # Availability
///
/// This API is only available in `cfg(test)` or with the `test-only`
/// Cargo feature. `#[deprecated]` alone is a *warning*, not an
/// enforcement boundary, so this footgun is confined to test surface
/// to prevent production callers from reaching it through autocomplete
/// or copy-paste. Production code MUST implement [`CounterPersistence`]
/// against durable, rollback-resistant storage.
#[cfg(any(test, feature = "test-only"))]
#[repr(C)]
pub struct NoOpPersistence;

#[cfg(any(test, feature = "test-only"))]
impl CounterPersistence for NoOpPersistence {
    #[inline]
    fn persist(&mut self, _new_counter: u64) -> Result<(), VsError> {
        Ok(())
    }
}

/// Upper bound on acceptable `ts_us` values supplied to `flush()`.
///
/// Blocks the `ts_us = u64::MAX` denial-of-service where a single call at the upper
/// boundary would lock out all future flushes via the monotonic-clock
/// check (audit fix MED-1). 2^63 microseconds is ~292,000 years, well
/// beyond any realistic vehicle deployment lifetime.
const MAX_REASONABLE_TS_US: u64 = 1u64 << 63;

/// Volatile-zero every byte of `buf`.
///
/// Prevents the compiler from dead-store-eliminating the wipe of transient
/// plaintext buffers on drop, since the trailing store is observable via
/// `write_volatile` even if the value is never read again.
///
/// `#[inline]` is required so the volatile store is emitted at the call
/// site — moving the loop behind a non-inlined function call would defeat
/// the wipe if the function itself is optimised away.
#[inline]
fn volatile_wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid writable reference into a stack-allocated
        // array. `write_volatile` with a u8 is always sound.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    // audit-LOW: `write_volatile` alone defeats DSE of the wipe stores
    // themselves, but it does NOT prevent the compiler (or a speculative
    // CPU pipeline) from reordering surrounding *non-volatile* loads/stores
    // across the wipe. A neighbouring read of `buf` that LLVM hoists above
    // this loop would observe pre-wipe plaintext. The `SeqCst` compiler
    // fence forbids that reordering in both directions and is the standard
    // hygiene for secure-wipe primitives. The fence is a compile-time-only
    // barrier (no runtime instruction emitted on most ISAs), so cost is
    // negligible. Speculative-execution resistance is the rationale here.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Maximum valid payload length for a [`TelemetryEntry`].
const MAX_PAYLOAD_LEN: u8 = 64;

/// One minute in microseconds, used for rate-limit windowing.
const MICROS_PER_MINUTE: u64 = 60_000_000;

/// Serialized size of a single entry for rate-limit accounting:
/// 8 (sequence) + 8 (timestamp) + 1 (`event_type`) + 1 (severity) + 1 (`payload_len`) + 64 (payload).
const ENTRY_SERIAL_SIZE: usize = 83;

/// Batch header size for rate-limit accounting:
/// 32 (`device_id`) + 8 (`flush_counter`) + 8 (timestamp).
const BATCH_HEADER_SIZE: usize = 48;

/// AAD binds every non-secret value the receiver must trust:
/// `device_id` (32) || `flush_counter` (8) || `entry_count` (8) || `ts_us` (8) ||
/// `dropped_count` (8) || `severity_dist` (8) || `dropped_per_severity` (8) ||
/// `dropped_other` (2) || `histogram_saturated` (1) || `_reserved` (1).
///
/// Adding `dropped_count` (audit fix) lets the receiver detect eviction
/// floods — an attacker who silently overflows the ring buffer to evict
/// genuine alerts now perturbs the AAD on the next flush and the
/// receiver's monotonic-check on `dropped_count` will fire.
///
/// Adding `severity_dist` (audit fix MED-vsoc-AAD-sev) binds a
/// fixed-layout `[u16; 4]` little-endian histogram of the flushed
/// batch's alert severities (Critical, High, Medium, Low — `Info` is
/// excluded because it is not an alert). A targeted "drop all Critical,
/// retain Info" rewrite against the ring buffer would otherwise be
/// detectable only by the absence of expected alerts; binding the
/// histogram into the AAD makes any silent severity-distribution
/// rewrite fail AES-GCM authentication end-to-end.
///
/// Adding `dropped_per_severity` (audit fix INFO-1) binds the parallel
/// `[u16; 4]` little-endian histogram of *dropped* entries
/// (Critical, High, Medium, Low — `Info` excluded for the same reason).
/// `dropped_count` alone tells the receiver "how many" but not "which
/// tier was suppressed"; binding the tier-resolved histogram lets the
/// receiver distinguish "attacker flooded Info events and the ring
/// evicted Critical alerts" from "caller emitted too many Info events
/// of their own". The receiver SHOULD validate each slot is
/// monotonically non-decreasing across flushes from the same device,
/// and that `sum(dropped_per_severity[0..4]) + dropped_other
/// <= dropped_count` (Info drops are excluded from the histogram so the
/// inequality is strict when Info drops are present).
///
/// Adding `dropped_other` and `histogram_saturated` (audit fixes
/// audit-M13 and audit-M14) closes two observability gaps:
///
///   * audit-M13 (`dropped_other`, `u16` little-endian at AAD[80..82]):
///     `AlertSeverity` is `#[non_exhaustive]`. If a future variant
///     (e.g. `Catastrophic`) lands without an explicit histogram slot,
///     the old wildcard arm would silently swallow drops of that
///     variant — `dropped_count` would still climb but no per-slot
///     would, breaking the receiver's
///     `sum(dropped_per_severity) + dropped_other <= dropped_count`
///     invariant. Binding an explicit "unknown variant" bucket
///     preserves the invariant across `#[non_exhaustive]` extensions
///     until the new variant is promoted to its own slot.
///
///   * audit-M14 (`histogram_saturated`, `u8` at AAD[82], 0 or 1):
///     `dropped_count` saturates at `u64::MAX` while every
///     `dropped_per_severity` slot (and `dropped_other`) saturates at
///     `u16::MAX`. Once any per-slot pins at 65_535 and the scalar
///     keeps climbing, the receiver's
///     `sum(per_severity) + dropped_other <= dropped_count`
///     cross-check and per-slot monotonicity both become uninformative
///     — a tier-targeted suppression flood is no longer distinguishable
///     from baseline saturation. Binding a one-shot saturation flag
///     lets the receiver flip into "drop count unknown" mode for all
///     subsequent frames from the device. Once
///     `histogram_saturated == 1`, BOTH `dropped_count` AND every
///     `dropped_per_severity[*]` (and `dropped_other`) are frozen at
///     their last value, so the per-slot saturation pin and the scalar
///     stay in lock-step rather than drifting apart.
///
/// The trailing reserved byte (AAD[83]) is zero today; a future audit
/// fix that needs to bind a second flag (or a tier widening) can
/// allocate it without bumping `AAD_SIZE` again.
const AAD_SIZE: usize = 32 + 8 + 8 + 8 + 8 + 8 + 8 + 4;

/// Byte length of the severity-distribution histogram embedded in the
/// AAD: `[u16; 4]` covering Critical, High, Medium, Low (Info excluded).
/// `u16` is sufficient because `UPLINK_BUFFER_CAPACITY = 64` bounds the
/// per-flush count well below `u16::MAX = 65_535`.
const SEVERITY_DIST_BYTES: usize = 8;

/// Byte length of the per-severity *dropped* histogram embedded in the
/// AAD: `[u16; 4]` covering Critical, High, Medium, Low (Info excluded).
/// `u16` is intentional — the histogram is saturating per-bump so a
/// pathologically long-running deployment hitting `u16::MAX` simply
/// pins at the ceiling rather than wrapping. Once the
/// `histogram_saturated` flag is set (audit-M14), both this array and
/// `dropped_count` freeze at their last values so the receiver's
/// `<= dropped_count` cross-check stays in lock-step.
const DROPPED_PER_SEV_BYTES: usize = 8;

/// Byte length of the trailing audit-M13/M14 trailer:
/// `dropped_other` (2) || `histogram_saturated` (1) || `_reserved` (1).
///
/// `dropped_other` (audit-M13) is the catch-all bucket for
/// `AlertSeverity` variants that do not yet have a dedicated histogram
/// slot — e.g. a future `#[non_exhaustive]` `AlertSeverity::Catastrophic`
/// would land here until the histogram layout is widened. The receiver's
/// invariant becomes
/// `sum(dropped_per_severity) + dropped_other <= dropped_count` (Info
/// drops are still excluded from the histogram, so the inequality is
/// strict when Info drops are present).
///
/// `histogram_saturated` (audit-M14) is a one-shot saturation marker:
/// once it flips to 1, BOTH `dropped_count` and every per-slot value
/// (including `dropped_other`) are frozen at their last-observed value
/// for the lifetime of the uplink. Receivers MUST treat subsequent
/// frames as "drop count unknown" and stop relying on monotonic
/// non-decrease for per-slot values past the saturation point.
const DROPPED_OTHER_AND_FLAGS_BYTES: usize = 4;

// Compile-time pinning: if `AAD_SIZE` and any field footprint ever
// drift apart, fail to build instead of silently misaligning the AAD
// writer in `flush_with_persistence`. Receivers parse the AAD by fixed
// offsets, so any silent drift here is a wire-format break.
const _: () = assert!(
    AAD_SIZE
        == 32 + 8
            + 8
            + 8
            + 8
            + SEVERITY_DIST_BYTES
            + DROPPED_PER_SEV_BYTES
            + DROPPED_OTHER_AND_FLAGS_BYTES
);
const _: () = assert!(AAD_SIZE == 84);

/// Maximum representable flush counter given the 6-byte counter slot in the
/// AES-GCM nonce. `2^48 ≈ 2.8 × 10¹⁴` flushes — at one flush per millisecond
/// that is ~8900 years, so the limit is practical but is enforced to prevent
/// silent truncation into the nonce.
const MAX_FLUSH_COUNTER: u64 = (1u64 << 48) - 1;

/// Upper bound on `KeyId` slot indices accepted by [`TelemetryConfig`].
///
/// Mirrors the `MAX_KEY_SLOTS = 64` invariant enforced inside the
/// PKCS#11 and TPM providers (`crypto-pkcs11`, `crypto-tpm`). A
/// `TelemetryConfig` whose `encryption_key_id` or `signing_key_id`
/// would later be rejected by the provider with `VsError::InvalidInput`
/// is instead caught at config-validation time so the failure is
/// observed before the uplink is wired (audit fix LOW-vsoc-cleanup).
const MAX_KEY_SLOTS: u32 = 64;

// -----------------------------------------------------------------------
// Persistence-blob version tags (audit fix audit-H4)
// -----------------------------------------------------------------------
//
// `PersistedFlushCounter` blobs are HMAC-SHA-256 authenticated. The
// MAC originally covered only `(counter_le)` bound implicitly to a
// `mac_key_id` (the HMAC key). Audit-H4 observed that this leaves a
// nonce-reuse window during an AES-encryption-key rotation under a
// stable MAC key: an old counter blob still authenticates under the
// MAC key, but the encryption key the receiver expects is the new one,
// so the AES-GCM nonce derived from the loaded counter collides with
// the one already used under the new encryption key.
//
// The fix binds `encryption_key_id` into the HMAC input as well. The
// blob carries a 1-byte version tag at the front so the loader can
// distinguish:
//
//   V1 (legacy, 40 bytes) -- `counter_le(8) || tag(32)`, HMAC input is
//                            `counter_le(8)`; older devices that
//                            haven't been re-persisted yet sit here
//                            during the upgrade window.
//   V2 (current, 45 bytes) -- `0x02 || counter_le(8) ||
//                              encryption_key_id_le(4) || tag(32)`,
//                              HMAC input is
//                              `0x02 || counter_le(8) ||
//                               encryption_key_id_le(4)`. The
//                              `mac_key_id` remains implicit (it IS
//                              the HMAC key).
//
// On load both versions verify; on persist the device always writes V2.
// A V1 blob loaded once will be re-persisted as V2 by the next
// `flush_with_persistence` call (one-way upgrade — see
// `restore_authenticated_versioned` / `to_blob` docs).
//
// V1 implicitly had version=0x01 (no tag byte was written), so an
// attacker who tries to forge a V2 blob with version=0x01 plus 4 bytes
// of attacker-controlled tail will fail HMAC verification because the
// new V2 verifier always includes the version byte in the MAC input.

/// Legacy persistence blob version. Implicitly assumed by pre-audit-H4
/// devices that wrote 40-byte blobs without a leading version tag.
pub const PERSIST_BLOB_VERSION_V1: u8 = 0x01;

/// Current persistence blob version. V2 blobs carry an explicit version
/// byte and bind `encryption_key_id` into the HMAC input so an
/// AES-key-rotation under a stable MAC key cannot replay an older
/// counter under the new AES key (audit fix audit-H4).
pub const PERSIST_BLOB_VERSION_V2: u8 = 0x02;

/// Wire length of a V1 (legacy) persistence blob: `counter_le(8) ||
/// tag(32) = 40 bytes`. Retained as the documented constant so
/// integrators with V1 NV partitions can size their reads correctly
/// during the V1->V2 upgrade window.
pub const PERSIST_BLOB_LEN_V1: usize = 40;

/// Wire length of a V2 persistence blob: `version(1) || counter_le(8)
/// || encryption_key_id_le(4) || tag(32) = 45 bytes`. New persistence
/// backends should size their storage to V2 from the start; the
/// legacy [`PersistedFlushCounter::to_blob`] entry point still emits
/// V1 for backwards-compat callers, but the new
/// [`PersistedFlushCounter::to_blob_v2`] entry point emits V2 and is
/// the preferred path.
pub const PERSIST_BLOB_LEN_V2: usize = 45;

// Sanity assertions: keep the constants and the on-disk layout
// arithmetic in lock-step so a future schema bump doesn't silently
// desync the verifier.
const _: () = assert!(PERSIST_BLOB_LEN_V1 == 8 + 32);
const _: () = assert!(PERSIST_BLOB_LEN_V2 == 1 + 8 + 4 + 32);
const _: () = assert!(PERSIST_BLOB_VERSION_V1 != PERSIST_BLOB_VERSION_V2);

/// Configuration for the VSOC telemetry uplink.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TelemetryConfig {
    /// Maximum bytes per minute allowed on the uplink channel.
    pub max_bytes_per_minute: u32,
    /// Number of entries to accumulate before flushing a batch.
    pub batch_size: u8,
    /// Key slot used for encrypting batches before transmission.
    pub encryption_key_id: KeyId,
    /// Key slot used for signing batches before transmission.
    pub signing_key_id: KeyId,
    /// Device identifier included in every telemetry batch header.
    pub device_id: [u8; 32],
    /// Number of ring-buffer slots reserved for `Critical`/`High` severity
    /// entries when the buffer is otherwise full (audit fix MED-2).
    ///
    /// When occupancy is at or above `(UPLINK_BUFFER_CAPACITY -
    /// reserved_critical_slots)`, only `Critical` and `High` severities
    /// are accepted into the buffer; lower-severity entries are dropped
    /// (`dropped_count += 1`). Defaults to 8 if you construct
    /// `TelemetryConfig` via field-literals; this prevents an attacker
    /// from flooding `Info` events to evict genuine `Critical` alerts.
    pub reserved_critical_slots: u8,
    /// Relax the strict per-entry monotonicity check on
    /// `submit_entry` (audit fix HIGH-Y).
    ///
    /// When `false` (the strict default), `submit_entry` rejects an
    /// entry whose `sequence` is less than or equal to the previously
    /// admitted entry's sequence, and whose `timestamp_us` is strictly
    /// less than the previously admitted entry's timestamp. The
    /// `MAX_REASONABLE_TS_US` upper-bound check is enforced regardless
    /// of this flag.
    ///
    /// When `true`, those sequence/timestamp ordering checks are
    /// skipped. Some integrators legitimately interleave entries from
    /// multiple producers and cannot guarantee global ordering at the
    /// uplink ingress; they may opt in to this relaxed mode and rely
    /// on the receiver for ordering. The upper-bound timestamp check
    /// (against `MAX_REASONABLE_TS_US`) is still enforced.
    pub allow_out_of_order_entries: bool,
}

impl TelemetryConfig {
    /// Validate that the configuration is internally consistent.
    ///
    /// Audit fix MED-4: rejects `batch_size == 0` (would silently silence
    /// every flush) and `max_bytes_per_minute == 0` (would silently fail
    /// every rate-limit check). Both used to be silently accepted.
    ///
    /// Audit fix LOW-vsoc-cleanup: also rejects `encryption_key_id` /
    /// `signing_key_id` whose raw slot index is `>= MAX_KEY_SLOTS`.
    /// The provider would otherwise reject the very first
    /// `aes_gcm_encrypt` / `sign_p256` call with `VsError::InvalidInput`,
    /// after the uplink had already advanced `flush_counter` and
    /// persisted it — wasting a nonce slot on every retry. Failing here
    /// catches the misconfiguration at construction time instead.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if any field is out of range.
    pub fn validate(&self) -> Result<(), VsError> {
        if self.batch_size == 0 {
            return Err(VsError::InvalidInput);
        }
        if self.max_bytes_per_minute == 0 {
            return Err(VsError::InvalidInput);
        }
        if self.reserved_critical_slots as usize > UPLINK_BUFFER_CAPACITY {
            return Err(VsError::InvalidInput);
        }
        if self.encryption_key_id.get() >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        if self.signing_key_id.get() >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        Ok(())
    }
}

/// A single telemetry observation ready for uplink.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TelemetryEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Microsecond timestamp of the originating event.
    pub timestamp_us: u64,
    /// Numeric event-type discriminant (mirrors `EventType as u8`).
    pub event_type: u8,
    /// Alert severity level.
    pub severity: AlertSeverity,
    /// Raw serialised event payload (up to 64 bytes).
    pub payload: [u8; 64],
    /// Number of valid bytes in `payload`.
    pub payload_len: u8,
}

impl TelemetryEntry {
    /// Create a new telemetry entry, validating that `payload` fits within
    /// the 64-byte buffer.
    ///
    /// # Errors
    ///
    /// Returns `VsError::ResourceExhausted` if `payload.len() > 64`.
    pub fn new(
        sequence: u64,
        timestamp_us: u64,
        event_type: u8,
        severity: AlertSeverity,
        payload: &[u8],
    ) -> Result<Self, VsError> {
        if payload.len() > MAX_PAYLOAD_LEN as usize {
            return Err(VsError::ResourceExhausted);
        }
        let mut buf = [0u8; 64];
        buf[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            sequence,
            timestamp_us,
            event_type,
            severity,
            payload: buf,
            payload_len: payload.len() as u8,
        })
    }

    /// Sequence number accessor.
    #[inline]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Microsecond timestamp accessor.
    #[inline]
    pub fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }

    /// Event-type discriminant accessor.
    #[inline]
    pub fn event_type(&self) -> u8 {
        self.event_type
    }

    /// Severity accessor.
    #[inline]
    pub fn severity(&self) -> AlertSeverity {
        self.severity
    }

    /// Number of valid bytes in [`Self::raw_payload`].
    #[inline]
    pub fn payload_len(&self) -> u8 {
        self.payload_len
    }

    /// Validated payload slice — `&self.payload[..self.payload_len]`.
    /// Use this in preference to [`Self::raw_payload`].
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let n = (self.payload_len as usize).min(self.payload.len());
        &self.payload[..n]
    }

    /// Full 64-byte payload buffer including zero padding. Most callers
    /// should prefer [`Self::payload`].
    #[inline]
    pub fn raw_payload(&self) -> &[u8; 64] {
        &self.payload
    }

    /// Serialize this entry into `out[offset..]` using the fixed-size
    /// `ENTRY_SERIAL_SIZE` (83 bytes) format. The payload is zero-padded to
    /// the full 64 bytes so that every entry produces a constant-length
    /// serialization, consistent with rate-limit accounting.
    ///
    /// # Errors
    ///
    /// Returns `VsError::InvalidInput` if `out` is too small to hold
    /// `offset + ENTRY_SERIAL_SIZE` bytes, or if `offset` overflows, or
    /// if `payload_len` exceeds `MAX_PAYLOAD_LEN` (audit fix MED-3 —
    /// defends against a hand-mutated `TelemetryEntry`).
    fn serialize_into(&self, out: &mut [u8], offset: usize) -> Result<usize, VsError> {
        let end = offset
            .checked_add(ENTRY_SERIAL_SIZE)
            .ok_or(VsError::InvalidInput)?;
        if out.len() < end {
            return Err(VsError::InvalidInput);
        }
        // Audit fix MED-3: even though `TelemetryEntry::new` validates
        // `payload_len`, the public fields could be hand-mutated. Reject
        // an oversized `payload_len` here instead of silently clamping
        // (which would publish a truncated wire encoding).
        if self.payload_len > MAX_PAYLOAD_LEN {
            return Err(VsError::InvalidInput);
        }
        let plen = self.payload_len as usize;
        let start = offset;
        out[start..start + 8].copy_from_slice(&self.sequence.to_le_bytes());
        out[start + 8..start + 16].copy_from_slice(&self.timestamp_us.to_le_bytes());
        out[start + 16] = self.event_type;
        out[start + 17] = self.severity as u8;
        out[start + 18] = self.payload_len;
        // Copy the valid payload bytes.
        out[start + 19..start + 19 + plen].copy_from_slice(&self.payload[..plen]);
        // Zero-pad remaining payload to ensure fixed-size serialization.
        if plen < MAX_PAYLOAD_LEN as usize {
            out[start + 19 + plen..start + ENTRY_SERIAL_SIZE].fill(0);
        }
        Ok(ENTRY_SERIAL_SIZE)
    }
}

/// Maximum entries held in the in-memory ring buffer before flush.
const UPLINK_BUFFER_CAPACITY: usize = 64;

/// Compile-time assertion that `UPLINK_BUFFER_CAPACITY` is the power-of-two
/// constant the bit-mask code below depends on.
const _: () = {
    assert!(UPLINK_BUFFER_CAPACITY.is_power_of_two());
    assert!(UPLINK_BUFFER_CAPACITY == 64);
};

/// Bit-mask form of the buffer capacity used in place of `% UPLINK_BUFFER_CAPACITY`
/// (audit perf item).
const UPLINK_BUFFER_MASK: usize = UPLINK_BUFFER_CAPACITY - 1;

/// Domain-separating label for the per-device nonce-prefix derivation
/// (audit fix HIGH-1). Always padded to 32 bytes by the caller before
/// being concatenated with the `device_id`.
const NONCE_PREFIX_LABEL: &[u8] = b"vsoc-telemetry/nonce-prefix/v1";

const _: () = assert!(NONCE_PREFIX_LABEL.len() <= 32);

/// Result of a successful batch flush, containing the digest commitment,
/// authentication tag, and ECDSA signature ready for transmission.
///
/// # What this crate does NOT encrypt (audit fix HIGH-3)
///
/// The 32-byte AES-GCM-encrypted blob in [`Self::digest_commitment`] is a
/// commitment over the SHA-256 chain of `(header, entries...)` — it
/// authenticates the batch contents but does NOT carry the plaintext
/// entries themselves. Callers must transmit the raw entries via a
/// separate confidential channel if they need plaintext confidentiality.
/// The previous field name (`encrypted_digest`) implied otherwise and is
/// retained as a deprecated accessor.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct FlushResult {
    /// AES-GCM ciphertext over the SHA-256 batch digest (32 bytes). This
    /// is a *commitment* to the batch contents; entries themselves are
    /// not encrypted by this crate.
    pub digest_commitment: [u8; 32],
    /// AES-GCM authentication tag (16 bytes).
    pub tag: [u8; 16],
    /// ECDSA P-256 signature over the plaintext digest (64 bytes).
    pub signature: [u8; 64],
    /// Number of entries included in this batch.
    pub entry_count: usize,
    /// Flush counter value for this batch (for replay detection).
    pub flush_counter: u64,
}

impl FlushResult {
    /// Backward-compatibility accessor for the renamed field. New code
    /// should read [`Self::digest_commitment`] directly.
    #[deprecated(
        since = "0.7.3",
        note = "Renamed to `digest_commitment` to reflect that entries are NOT encrypted by this crate"
    )]
    #[inline]
    pub fn encrypted_digest(&self) -> &[u8; 32] {
        &self.digest_commitment
    }
}

/// Distinct outcomes of a [`TelemetryUplink::flush`] call (audit fix —
/// `FlushOutcome` enum). Replaces the previous `Result<Option<FlushResult>>`
/// shape which conflated "empty" with "rate-limited" with
/// "counter-exhausted" — all three returned `Ok(None)` and the caller
/// had no way to distinguish.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum FlushOutcome {
    /// A batch was successfully flushed.
    Sent(FlushResult),
    /// No entries were queued; nothing to flush.
    Empty,
    /// Flush was inhibited by the rate limiter. `retry_after_us` is the
    /// caller-relative microsecond delay until the next budget window.
    RateLimited { retry_after_us: u64 },
    /// `flush_counter` reached `MAX_FLUSH_COUNTER` and the key must be
    /// rotated before any further flush. This is a terminal state
    /// — re-attempting will continue to return this variant.
    CounterExhausted,
}

/// Encrypted, signed telemetry uplink to a VSOC backend.
///
/// Entries are queued in a fixed-size ring buffer and flushed in batches.
/// The type parameter `C` provides the cryptographic operations required for
/// encryption and signing of outgoing batches.
#[repr(C)]
pub struct TelemetryUplink<C: CryptoProvider> {
    config: TelemetryConfig,
    buffer: [Option<TelemetryEntry>; UPLINK_BUFFER_CAPACITY],
    head: usize,
    count: usize,
    /// Number of entries silently dropped due to buffer overflow.
    ///
    /// Bound into the AES-GCM AAD on every flush so the receiver can
    /// detect eviction floods (an attacker who overflows the ring buffer
    /// to evict genuine alerts will perturb this counter, which is then
    /// observable end-to-end via the authenticated AAD frame). The
    /// receiver MUST validate monotonic non-decrease across flushes from
    /// the same device.
    dropped_count: u64,
    /// Per-severity histogram of dropped entries (audit fix INFO-1),
    /// indexed `[Critical, High, Medium, Low]`. Info-tier drops are
    /// uninteresting (caller-induced floods are a feature, not an attack
    /// against high-priority events) and are not tracked here.
    ///
    /// Bound into the AES-GCM AAD on every flush so the receiver can
    /// detect a tier-targeted suppression attack (e.g. "drop all
    /// Critical, retain Info") — without this binding, the only
    /// observable change would be `dropped_count`, which cannot
    /// distinguish whether the evicted entries were trivia or genuine
    /// safety-critical alerts. Saturating semantics on bump prevent
    /// silent wrap-around at `u16::MAX`; the receiver MUST also validate
    /// `sum(dropped_per_severity[0..4]) + dropped_other <= dropped_count`
    /// (Info-tier drops are excluded from this histogram, so the
    /// inequality is strict when Info drops are present).
    ///
    /// Once [`Self::histogram_saturated`] is `true`, this array is
    /// frozen — see the field docs for the saturation contract.
    dropped_per_severity: [u16; 4],
    /// Catch-all histogram slot for `AlertSeverity` variants that have
    /// no dedicated bucket in `dropped_per_severity` (audit fix
    /// audit-M13). `AlertSeverity` is `#[non_exhaustive]`, so a future
    /// variant (e.g. `Catastrophic`) lands here until the histogram
    /// layout is widened.
    ///
    /// Bound into the AES-GCM AAD on every flush. The receiver's
    /// cross-check generalises to
    /// `sum(dropped_per_severity[0..4]) + dropped_other <= dropped_count`
    /// — without this slot the wildcard `_` arm in
    /// [`Self::account_drop`] would silently swallow drops of
    /// new variants, breaking the invariant on the wire.
    ///
    /// `u16` matches the per-severity slot width so the saturation
    /// contract carries uniformly: when this slot would exceed
    /// `u16::MAX` the [`Self::histogram_saturated`] flag flips on and
    /// every counter freezes at its last value.
    dropped_other: u16,
    /// One-shot saturation marker (audit fix audit-M14).
    ///
    /// Flips from `false` to `true` the first time any drop accounting
    /// step would push a `u16` histogram slot (`dropped_per_severity[*]`
    /// or `dropped_other`) past `u16::MAX`. Once set, every subsequent
    /// drop is observed by this flag but does NOT bump `dropped_count`,
    /// `dropped_per_severity[*]`, or `dropped_other` — all five counters
    /// freeze at their last value so the receiver's invariants
    /// (`sum(per_severity) + dropped_other <= dropped_count`,
    /// per-slot monotonicity) stay in lock-step rather than the scalar
    /// drifting past the saturated histogram.
    ///
    /// Bound into the AES-GCM AAD on every flush. Receivers MUST treat
    /// frames with `histogram_saturated == 1` as "drop count unknown"
    /// from that point on; the device has lost the ability to
    /// distinguish further tier-targeted suppression activity until the
    /// uplink is reconstructed (typically via key rotation).
    histogram_saturated: bool,
    /// Monotonic flush counter, used as nonce material and replay protection.
    flush_counter: u64,
    /// Bytes accounted in the current rate-limit window.
    bytes_this_window: u32,
    /// Microsecond timestamp marking the start of the current rate-limit window.
    window_start_us: u64,
    /// Microsecond timestamp of the most recent successful (or empty) flush.
    /// Enforces caller monotonicity across `flush()` invocations so a clock
    /// regression cannot reset the rate-limit window.
    last_flush_us: u64,
    // audit-LOW: previously this struct held a cached `nonce_prefix:
    // [u8; 6]` plus a `nonce_prefix_initialized: bool` flag that gated
    // the lazy derivation. That branch produced a timing oracle: the
    // first flush spent one extra SHA-256 (visible) compared to every
    // subsequent flush. The oracle is low-impact (the only secret it
    // could leak about is "is this device's first flush after boot?",
    // which is also recoverable from the wire `flush_counter` field
    // itself) but easy to remove — we now recompute the prefix into a
    // local variable on every flush, paying one SHA-256 per call.
    // Fields removed; cf. `flush_with_persistence` for the recompute.
    /// Cached copy of `config.device_id` — the first 32 bytes of both
    /// the batch header and the AAD frame. `device_id` never changes
    /// for the lifetime of an uplink, so we materialise the slice once
    /// at construction and `copy_from_slice` it into the per-flush
    /// buffers instead of paying the read-from-config indirection on
    /// every flush. Saves 64 bytes of redundant stack copying per
    /// flush (32 for the header, 32 for the AAD).
    device_id_cache: [u8; 32],
    /// Sequence number of the most recently admitted entry (audit fix
    /// HIGH-Y). `None` until the first successful `submit_entry`.
    ///
    /// Used by `submit_entry` to reject an incoming entry whose
    /// `sequence` is less than or equal to this value, catching buggy
    /// callers at ingress instead of letting the violation propagate
    /// through encryption to the receiver. Bypassed when
    /// `config.allow_out_of_order_entries` is `true`.
    last_entry_sequence: Option<u64>,
    /// Microsecond timestamp of the most recently admitted entry
    /// (audit fix HIGH-Y). `None` until the first successful
    /// `submit_entry`.
    ///
    /// Used by `submit_entry` to reject an incoming entry whose
    /// `timestamp_us` is strictly less than this value. Bypassed when
    /// `config.allow_out_of_order_entries` is `true`. The upper-bound
    /// `MAX_REASONABLE_TS_US` check is enforced regardless of the flag.
    last_entry_timestamp_us: Option<u64>,
    _phantom: core::marker::PhantomData<C>,
}

/// A `flush_counter` value that has been read from authenticated persistent
/// storage.
///
/// This newtype exists to make nonce-reuse accidents harder: constructing
/// it requires the caller to commit to a specific source of the counter
/// (loaded from disk, NV storage, etc.). [`TelemetryUplink::restore`]
/// accepts only a `PersistedFlushCounter`, not a raw `u64`.
///
/// On a fresh device with no prior state, use
/// [`PersistedFlushCounter::fresh_device`], which enforces that the
/// counter has never been used before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PersistedFlushCounter(u64);

impl PersistedFlushCounter {
    /// Restore a counter loaded from persistent storage.
    ///
    /// # Contract
    ///
    /// `value` **must** be at least as large as every `flush_counter`
    /// previously returned by a [`TelemetryUplink::flush`] call against
    /// the same encryption key. Passing a smaller value causes AES-GCM
    /// nonce reuse, which is catastrophic.
    ///
    /// # Availability
    ///
    /// This API is only available in `cfg(test)` or with the `test-only`
    /// Cargo feature. It is additionally gated on
    /// `cfg(any(test, feature = "unauthenticated-restore"))` and disabled
    /// when the `strict-nonce` feature is on. `#[deprecated]` alone is a
    /// warning, not an enforcement boundary; the cfg gate is what keeps
    /// production builds from reaching this footgun. A caller who
    /// restores `0` after dropping the on-disk file would silently roll
    /// the counter back, causing AES-GCM nonce reuse — catastrophic.
    /// Neither `test-only` nor `unauthenticated-restore` may be enabled
    /// in production.
    #[cfg(any(test, feature = "test-only"))]
    #[cfg(any(test, feature = "unauthenticated-restore"))]
    #[cfg(not(feature = "strict-nonce"))]
    #[deprecated(
        since = "0.7.3",
        note = "Use `PersistedFlushCounter::restore_authenticated` for rollback protection"
    )]
    #[inline]
    pub fn restore(value: u64) -> Self {
        Self(value)
    }

    /// Assert that this device has never flushed a batch before.
    ///
    /// Use only on factory-fresh hardware or on devices whose encryption
    /// key has just been rotated. Any prior flush invalidates this
    /// assertion — use [`restore`](Self::restore) instead.
    #[inline]
    pub fn fresh_device() -> Self {
        Self(0)
    }

    /// Return the wrapped counter value.
    #[inline]
    pub fn value(self) -> u64 {
        self.0
    }

    /// Serialise this counter as a legacy V1 HMAC-SHA-256-authenticated
    /// blob (audit fix HIGH-2). Format:
    ///
    /// ```text
    ///   counter_le(8B) || tag(32B) = 40 bytes total = PERSIST_BLOB_LEN_V1
    /// ```
    ///
    /// The tag is `HMAC-SHA-256(mac_key_id, counter_le)`. Persistent
    /// storage MUST store the full 40-byte blob; round-tripping through
    /// [`Self::restore_authenticated`] verifies the tag in constant time
    /// and rejects rollback / tamper attempts.
    ///
    /// # Audit-H4 caveat
    ///
    /// V1 binds the counter to `mac_key_id` only. Under an AES-encryption-key
    /// rotation with a stable MAC key, an old V1 blob still verifies and
    /// the loaded counter would be used to derive an AES-GCM nonce under
    /// the *new* AES key — risking nonce reuse. Production code SHOULD
    /// emit V2 blobs via [`Self::to_blob_v2`] instead; V1 is retained for
    /// backwards-compat during the transition window only. See
    /// [`PERSIST_BLOB_VERSION_V2`] for the rationale.
    pub fn to_blob<C: CryptoProvider>(
        &self,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<[u8; PERSIST_BLOB_LEN_V1], VsError> {
        let mut blob = [0u8; PERSIST_BLOB_LEN_V1];
        blob[..8].copy_from_slice(&self.0.to_le_bytes());
        let mut tag = [0u8; 32];
        crypto.hmac_sha256(mac_key_id, &blob[..8], &mut tag)?;
        blob[8..].copy_from_slice(&tag);
        Ok(blob)
    }

    /// Serialise this counter as a V2 HMAC-SHA-256-authenticated blob
    /// that binds both `mac_key_id` (implicitly, as the HMAC key) AND
    /// `encryption_key_id` (explicitly, in the MAC input) — audit fix
    /// audit-H4. Format:
    ///
    /// ```text
    ///   version(1)=0x02 || counter_le(8) || encryption_key_id_le(4)
    ///       || tag(32) = 45 bytes total = PERSIST_BLOB_LEN_V2
    /// ```
    ///
    /// The tag is
    /// `HMAC-SHA-256(mac_key_id, version || counter_le || encryption_key_id_le)`.
    /// The `mac_key_id` stays implicit (it IS the HMAC key), and
    /// `encryption_key_id` is placed AFTER it in the MAC input as a
    /// fixed-width 4-byte little-endian field matching `KeyId`'s
    /// `#[repr(transparent)] pub u32` wire encoding used elsewhere in
    /// the workspace.
    ///
    /// # Why the version byte is first
    ///
    /// The leading 0x02 lets [`Self::restore_authenticated_versioned`]
    /// distinguish V1 (no version tag) from V2 without ambiguity. The
    /// V1 verifier feeds only `counter_le` into HMAC; the V2 verifier
    /// feeds `0x02 || counter_le || encryption_key_id_le`, so an
    /// attacker who copies an old V1 counter into a forged V2 envelope
    /// cannot make the tag match without knowing the MAC key.
    ///
    /// # Why `encryption_key_id` goes after `mac_key_id`
    ///
    /// `mac_key_id` is already the HMAC key (no need to duplicate it
    /// in the data input — it is implicit). Adding `encryption_key_id`
    /// to the MAC input binds the counter to *both* the MAC key (key
    /// identity) and the AES key the counter will be used under
    /// (nonce-uniqueness scope). A counter blob that authenticates
    /// under the MAC key but was originally produced for a different
    /// `encryption_key_id` will fail tag verification on load,
    /// blocking the audit-H4 cross-key-rotation nonce-reuse hazard.
    pub fn to_blob_v2<C: CryptoProvider>(
        &self,
        crypto: &C,
        mac_key_id: KeyId,
        encryption_key_id: KeyId,
    ) -> Result<[u8; PERSIST_BLOB_LEN_V2], VsError> {
        let mut blob = [0u8; PERSIST_BLOB_LEN_V2];
        blob[0] = PERSIST_BLOB_VERSION_V2;
        blob[1..9].copy_from_slice(&self.0.to_le_bytes());
        // `KeyId` is `#[repr(transparent)] pub u32` (see vs-types) — match
        // the workspace-wide 4-byte little-endian wire encoding.
        blob[9..13].copy_from_slice(&encryption_key_id.get().to_le_bytes());
        let mut tag = [0u8; 32];
        // MAC input is the first 13 bytes:
        //   version(1) || counter_le(8) || encryption_key_id_le(4).
        crypto.hmac_sha256(mac_key_id, &blob[..13], &mut tag)?;
        blob[13..].copy_from_slice(&tag);
        Ok(blob)
    }

    /// Restore a counter from a legacy V1 HMAC-authenticated blob
    /// (audit fix HIGH-2). The tag is verified with constant-time
    /// comparison before the counter is returned. V1 blobs are bound
    /// to `mac_key_id` only; `encryption_key_id` binding was added in
    /// V2 — see [`Self::restore_authenticated_v2`] (audit-H4: the
    /// encryption_key_id binding has been included in V2 since version
    /// 0.7.x).
    ///
    /// # What this method guarantees
    ///
    /// **AUTHENTICITY** — proves the 40-byte blob was produced by a
    /// holder of `mac_key_id`. A blob whose counter half or tag half
    /// was modified, or a blob forged without knowledge of the MAC key,
    /// is rejected with [`VsError::CryptoError`].
    ///
    /// # What this method does NOT guarantee (audit AUDIT-INFO-2 / audit-H2)
    ///
    /// **FRESHNESS** — the method has no way to know whether the blob
    /// it just verified is the *current* persisted counter or a stale
    /// snapshot captured from earlier in the device's lifetime. A blob
    /// that was validly produced at counter=42 will always re-verify at
    /// counter=42, even after the live device has advanced to
    /// counter=1000. An attacker with read/write access to the
    /// persistence layer who captures an old blob can therefore replay
    /// it to force AES-GCM nonce reuse — the integrity check covers the
    /// counter *value*, not its *recency*.
    ///
    /// This is a known and documented limitation, not a bug. The MAC
    /// alone cannot distinguish "valid old" from "valid current"
    /// because both are, in fact, valid. Prefer
    /// [`Self::restore_authenticated_from_storage`] (audit-H2), which
    /// requires the caller to commit — in the type system — to a
    /// rollback-resistant storage backend.
    ///
    /// # Required caller mitigation
    ///
    /// Callers MUST store the 40-byte blob in **rollback-resistant
    /// storage**. Acceptable options are:
    ///
    /// 1. A TPM 2.0 NV index with the `TPMA_NV_WRITTEN` /
    ///    `TPMA_NV_WRITE_STCLEAR` / monotonic-counter attributes so the
    ///    blob cannot be silently replaced with an older copy.
    /// 2. A signed monotonic counter on a secure element (e.g., the
    ///    PKCS#11 `CKM_*_MONOTONIC_COUNTER` mechanism) whose freshness
    ///    proof is cross-checked at boot.
    /// 3. A vendor-specific anti-replay primitive (eFuse-backed
    ///    monotonic counter, secure-boot-managed RPMB partition).
    ///
    /// Plain filesystem persistence — even on an authenticated
    /// filesystem — is **not** sufficient: the attacker model includes
    /// an adversary who can snapshot and restore the storage volume.
    ///
    /// See `docs/threat-model.md` (T2 / D1) and the operational-security
    /// playbook for the production provisioning checklist.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::CryptoError`] if the MAC does not verify —
    /// this indicates a tamper attempt (or, if the storage layer is
    /// rollback-resistant, also a rollback attempt) and the caller MUST
    /// treat the persisted counter as untrusted.
    pub fn restore_authenticated<C: CryptoProvider>(
        blob: &[u8; PERSIST_BLOB_LEN_V1],
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<Self, VsError> {
        let mut expected = [0u8; 32];
        crypto.hmac_sha256(mac_key_id, &blob[..8], &mut expected)?;
        // Constant-time comparison: collect the XOR-OR of every byte
        // pair into a single byte; only `acc == 0` means the tags match.
        // Both sides are walked unconditionally so a timing oracle
        // cannot leak which prefix matched.
        let mut acc: u8 = 0;
        for i in 0..32 {
            acc |= expected[i] ^ blob[8 + i];
        }
        // Side-channel-resistant zero check.
        let zero = (acc as u32).wrapping_sub(1) >> 31;
        if zero == 1 {
            let mut counter_bytes = [0u8; 8];
            counter_bytes.copy_from_slice(&blob[..8]);
            Ok(Self(u64::from_le_bytes(counter_bytes)))
        } else {
            Err(VsError::CryptoError)
        }
    }

    /// Restore the counter from a [`CounterStorage`] backend that has
    /// been certified, via the sealed [`RollbackResistantStorage`]
    /// marker, to resist rollback (audit-H2).
    ///
    /// This is the rollback-aware companion to
    /// [`Self::restore_authenticated`]. The HMAC layer here is
    /// identical — what differs is the type-system constraint on the
    /// storage parameter: a plain `impl CounterStorage` cannot be
    /// passed in without first being wrapped in
    /// [`AssertedExternallyRollbackResistant`](rollback::AssertedExternallyRollbackResistant)
    /// (or an in-crate type that the crate ships as
    /// rollback-resistant). That wrapper forces the caller to read its
    /// doc-comment and decide whether the underlying medium really is
    /// rollback-resistant.
    ///
    /// # Errors
    ///
    /// - [`VsError::CryptoError`] if the HMAC tag does not verify.
    /// - Any error returned by the storage backend's `load` call.
    pub fn restore_authenticated_from_storage<C, R>(
        storage: &R,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<Self, VsError>
    where
        C: CryptoProvider,
        R: CounterStorage + RollbackResistantStorage,
    {
        storage.load_authenticated(crypto, mac_key_id)
    }

    /// Restore a counter from a V2 HMAC-authenticated blob whose tag
    /// covers `encryption_key_id` (audit fix audit-H4). The tag is
    /// verified with constant-time comparison and the version byte is
    /// checked before any HMAC work.
    ///
    /// # Why V2 forbids `encryption_key_id` substitution
    ///
    /// V1 bound the persisted counter to `mac_key_id` only. Under an
    /// AES-encryption-key rotation with a stable MAC key, an old V1
    /// blob still verifies and the loaded counter would be reused to
    /// derive an AES-GCM nonce under the *new* AES key — catastrophic
    /// nonce reuse. V2 puts `encryption_key_id` into the HMAC input so
    /// the loader's `encryption_key_id` (from the live config) must
    /// match the value the persist-time caller committed to, or the
    /// tag fails to verify and the load is rejected with
    /// [`VsError::CryptoError`].
    ///
    /// # Errors
    ///
    /// - [`VsError::CryptoError`] if the leading version byte is not
    ///   [`PERSIST_BLOB_VERSION_V2`].
    /// - [`VsError::CryptoError`] if the MAC tag fails to verify under
    ///   `(mac_key_id, encryption_key_id)`.
    pub fn restore_authenticated_v2<C: CryptoProvider>(
        blob: &[u8; PERSIST_BLOB_LEN_V2],
        crypto: &C,
        mac_key_id: KeyId,
        encryption_key_id: KeyId,
    ) -> Result<Self, VsError> {
        // Version check first. We treat an unknown version byte as a
        // CryptoError rather than an InvalidInput because the verifier
        // is the trust boundary; raising the same error class for
        // "wrong version" and "bad tag" means a downstream caller
        // cannot use version-byte-only feedback to oracle-probe the
        // storage layout.
        if blob[0] != PERSIST_BLOB_VERSION_V2 {
            return Err(VsError::CryptoError);
        }
        // Bind `encryption_key_id` into the HMAC input. The MAC input is
        //   version(1) || counter_le(8) || encryption_key_id_le(4) = 13B.
        // We re-derive the expected encryption_key_id bytes locally
        // instead of trusting `blob[9..13]`, then compare them
        // byte-for-byte in constant time *alongside* the tag check.
        // Trusting the blob's own bytes would mean an attacker who
        // flipped the encryption_key_id bytes in the blob would still
        // be matched against the same bytes on the recompute side.
        let mut mac_input = [0u8; 13];
        mac_input[0] = PERSIST_BLOB_VERSION_V2;
        mac_input[1..9].copy_from_slice(&blob[1..9]);
        mac_input[9..13].copy_from_slice(&encryption_key_id.get().to_le_bytes());

        let mut expected_tag = [0u8; 32];
        crypto.hmac_sha256(mac_key_id, &mac_input, &mut expected_tag)?;

        // Constant-time comparison over the tag bytes. We also XOR the
        // 4 `encryption_key_id` bytes that live in the blob against
        // the bytes we just put into `mac_input` — a mismatch here
        // means the blob carries a different `encryption_key_id` than
        // the caller passed, even if (somehow) the tag still matched.
        // In practice the MAC will already reject that case; the
        // explicit check is belt-and-braces against a future MAC-input
        // refactor that accidentally drops the encryption_key_id field.
        let mut acc: u8 = 0;
        for i in 0..32 {
            acc |= expected_tag[i] ^ blob[13 + i];
        }
        for i in 0..4 {
            acc |= mac_input[9 + i] ^ blob[9 + i];
        }
        let zero = (acc as u32).wrapping_sub(1) >> 31;
        if zero == 1 {
            let mut counter_bytes = [0u8; 8];
            counter_bytes.copy_from_slice(&blob[1..9]);
            Ok(Self(u64::from_le_bytes(counter_bytes)))
        } else {
            Err(VsError::CryptoError)
        }
    }

    /// Unified, length-and-version-dispatched loader for V1 / V2
    /// persistence blobs (audit fix audit-H4 — backwards-compat upgrade
    /// path).
    ///
    /// Accepts a slice rather than a fixed-size array so the caller can
    /// hand the raw bytes read from durable storage straight in without
    /// having to know the version up front. Dispatch is by length AND
    /// leading byte:
    ///
    /// - `blob.len() == PERSIST_BLOB_LEN_V1` (40 bytes) ->
    ///   [`Self::restore_authenticated`] (V1 verifier, ignores
    ///   `encryption_key_id`). A V1 blob is the legacy format; the
    ///   loader returns it unchanged so the next
    ///   [`TelemetryUplink::flush_with_persistence`] call writes V2
    ///   back through the storage layer (one-way upgrade — storage
    ///   impls MUST `to_blob_v2` on persist).
    /// - `blob.len() == PERSIST_BLOB_LEN_V2` (45 bytes) AND
    ///   `blob[0] == PERSIST_BLOB_VERSION_V2` ->
    ///   [`Self::restore_authenticated_v2`].
    /// - Any other length, or a 45-byte blob with an unknown version
    ///   tag, is rejected with [`VsError::CryptoError`].
    ///
    /// # Errors
    ///
    /// Returns [`VsError::CryptoError`] for length mismatch, unknown
    /// version tag, or HMAC verify failure. The caller cannot
    /// distinguish those classes — that is intentional (see the
    /// `restore_authenticated_v2` rationale above).
    pub fn restore_authenticated_versioned<C: CryptoProvider>(
        blob: &[u8],
        crypto: &C,
        mac_key_id: KeyId,
        encryption_key_id: KeyId,
    ) -> Result<Self, VsError> {
        match blob.len() {
            PERSIST_BLOB_LEN_V1 => {
                // V1: legacy format. `encryption_key_id` is intentionally
                // ignored here — V1 didn't bind it. The caller-driven
                // upgrade path immediately re-persists as V2 on the
                // next flush so we close the audit-H4 window after at
                // most one boot.
                let mut fixed = [0u8; PERSIST_BLOB_LEN_V1];
                fixed.copy_from_slice(blob);
                Self::restore_authenticated(&fixed, crypto, mac_key_id)
            }
            PERSIST_BLOB_LEN_V2 => {
                // V2: must carry the explicit version tag. We check
                // before copying so a length-only collision (e.g. a
                // future V3 format that reuses 45 bytes) doesn't pass
                // through the V2 verifier by accident.
                if blob[0] != PERSIST_BLOB_VERSION_V2 {
                    return Err(VsError::CryptoError);
                }
                let mut fixed = [0u8; PERSIST_BLOB_LEN_V2];
                fixed.copy_from_slice(blob);
                Self::restore_authenticated_v2(&fixed, crypto, mac_key_id, encryption_key_id)
            }
            _ => Err(VsError::CryptoError),
        }
    }
}

impl<C: CryptoProvider> TelemetryUplink<C> {
    /// Create a new uplink channel assuming a zero flush counter.
    ///
    /// **Deprecated.** Prefer [`try_restore`](Self::try_restore), which
    /// validates the config and fails loudly on out-of-range fields
    /// instead of silently clamping them. See [`try_restore`](Self::try_restore)
    /// for the documented constructor.
    ///
    /// **Hazard:** using this constructor on a device that has already
    /// flushed a batch under the same encryption key will reuse AES-GCM
    /// nonces.
    ///
    /// This convenience constructor is disabled when the `strict-nonce`
    /// feature is enabled.
    ///
    /// `batch_size` is clamped to `UPLINK_BUFFER_CAPACITY` if it exceeds
    /// the ring buffer size.
    #[cfg(not(feature = "strict-nonce"))]
    #[deprecated(note = "use try_restore for fail-loud validation")]
    pub fn new(config: TelemetryConfig) -> Self {
        #[allow(deprecated)]
        Self::restore(config, PersistedFlushCounter::fresh_device())
    }

    /// Create a new uplink channel, restoring `flush_counter` from
    /// authenticated persistent storage.
    ///
    /// **Deprecated.** Prefer [`try_restore`](Self::try_restore), which
    /// validates the config and fails loudly on out-of-range fields
    /// instead of silently clamping them. `restore` is retained for
    /// back-compat and will continue to clamp.
    #[deprecated(note = "use try_restore for fail-loud validation")]
    pub fn restore(mut config: TelemetryConfig, counter: PersistedFlushCounter) -> Self {
        if (config.batch_size as usize) > UPLINK_BUFFER_CAPACITY {
            config.batch_size = UPLINK_BUFFER_CAPACITY as u8;
        }
        // Audit fix MED-4: clamp out-of-range fields to a safe default so
        // an accidentally-zeroed config doesn't silently disable the
        // uplink. `try_restore` is the strict version that returns an
        // error instead.
        if config.batch_size == 0 {
            config.batch_size = 1;
        }
        if config.max_bytes_per_minute == 0 {
            config.max_bytes_per_minute = 1;
        }
        if config.reserved_critical_slots as usize > UPLINK_BUFFER_CAPACITY {
            config.reserved_critical_slots = UPLINK_BUFFER_CAPACITY as u8;
        }
        let device_id_cache = config.device_id;
        Self {
            config,
            buffer: [None; UPLINK_BUFFER_CAPACITY],
            head: 0,
            count: 0,
            dropped_count: 0,
            dropped_per_severity: [0u16; 4],
            dropped_other: 0,
            histogram_saturated: false,
            flush_counter: counter.value(),
            bytes_this_window: 0,
            window_start_us: 0,
            last_flush_us: 0,
            device_id_cache,
            last_entry_sequence: None,
            last_entry_timestamp_us: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Construct an uplink directly from a [`CounterStorage`] backend.
    ///
    /// Performs the full boot-time sequence in one shot:
    ///
    /// 1. [`CounterStorage::load_authenticated`] reads and verifies the
    ///    last persisted counter blob.
    /// 2. [`Self::try_restore`] validates `config` and constructs the
    ///    uplink seeded with the loaded counter.
    ///
    /// This replaces the previous out-of-band pattern where callers had
    /// to read a blob, hand it to
    /// [`PersistedFlushCounter::restore_authenticated`], then forward the
    /// result to `try_restore` — three steps with three opportunities to
    /// wire the wrong storage backend into the wrong slot. The unified
    /// [`CounterStorage`] trait keeps load + persist on the same object.
    ///
    /// The `storage` is borrowed mutably so the caller can subsequently
    /// pass it to [`Self::flush_with_persistence`] /
    /// [`Self::flush_outcome`] — `CounterStorage` automatically satisfies
    /// the legacy [`CounterPersistence`] bound via the blanket impl.
    ///
    /// # Errors
    ///
    /// Returns whatever error `load_authenticated` produces (typically
    /// [`VsError::CryptoError`] on tag-verify failure indicating tamper /
    /// rollback), or [`VsError::InvalidInput`] if `config` fails
    /// validation.
    pub fn from_storage<S: CounterStorage>(
        config: TelemetryConfig,
        storage: &mut S,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<Self, VsError> {
        let counter = storage.load_authenticated(crypto, mac_key_id)?;
        Self::try_restore(config, counter)
    }

    /// Documented constructor — returns an error when the supplied config
    /// fails [`TelemetryConfig::validate`] instead of silently clamping
    /// (audit fix MED-4). Prefer this over the deprecated
    /// [`new`](Self::new) and [`restore`](Self::restore) shims.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `batch_size == 0`,
    /// `max_bytes_per_minute == 0`, or `reserved_critical_slots`
    /// exceeds the ring-buffer capacity.
    pub fn try_restore(
        mut config: TelemetryConfig,
        counter: PersistedFlushCounter,
    ) -> Result<Self, VsError> {
        config.validate()?;
        if (config.batch_size as usize) > UPLINK_BUFFER_CAPACITY {
            config.batch_size = UPLINK_BUFFER_CAPACITY as u8;
        }
        let device_id_cache = config.device_id;
        Ok(Self {
            config,
            buffer: [None; UPLINK_BUFFER_CAPACITY],
            head: 0,
            count: 0,
            dropped_count: 0,
            dropped_per_severity: [0u16; 4],
            dropped_other: 0,
            histogram_saturated: false,
            flush_counter: counter.value(),
            bytes_this_window: 0,
            window_start_us: 0,
            last_flush_us: 0,
            device_id_cache,
            last_entry_sequence: None,
            last_entry_timestamp_us: None,
            _phantom: core::marker::PhantomData,
        })
    }

    /// **Deprecated.** Use [`restore`](Self::restore) with a
    /// [`PersistedFlushCounter`] instead.
    ///
    /// # Availability
    ///
    /// This API is only available in `cfg(test)` or with the `test-only`
    /// Cargo feature. The internal call to
    /// `PersistedFlushCounter::restore(u64)` is the unauthenticated
    /// rollback path, so it is additionally gated on
    /// `cfg(any(test, feature = "unauthenticated-restore"))` and
    /// disabled under `strict-nonce`. All three gates are additive: a
    /// downstream caller must enable both `test-only` and
    /// `unauthenticated-restore` (and NOT `strict-nonce`) for this
    /// constructor to be visible. Neither feature may be enabled in
    /// production.
    #[cfg(any(test, feature = "test-only"))]
    #[cfg(any(test, feature = "unauthenticated-restore"))]
    #[cfg(not(feature = "strict-nonce"))]
    #[deprecated(
        since = "0.7.2",
        note = "Use `TelemetryUplink::restore(cfg, PersistedFlushCounter::restore(counter))` \
                so the caller commits to a nonce-safe counter source."
    )]
    pub fn new_with_counter(config: TelemetryConfig, initial_counter: u64) -> Self {
        // Deprecation warning is intentional and the caller has already
        // opted into the unauthenticated path by calling this deprecated
        // constructor; suppress it on the internal forward.
        #[allow(deprecated)]
        let counter = PersistedFlushCounter::restore(initial_counter);
        #[allow(deprecated)]
        Self::restore(config, counter)
    }

    /// Pin the monotonic-clock floor (`last_flush_us`) to a trusted
    /// boot-time time anchor (audit-LOW).
    ///
    /// On a freshly constructed uplink the internal floor starts at
    /// `0`, which means the first call to
    /// [`flush_with_persistence`](Self::flush_with_persistence) will
    /// accept any `ts_us >= 0` (bounded above by
    /// [`MAX_REASONABLE_TS_US`]). Callers that have a higher-confidence
    /// time source available at boot — for example a GPS lock or a
    /// monotonic-RTC value sealed against rollback — should call this
    /// method **before** the first `submit_entry` / `flush*` to close
    /// the first-flush window: subsequent flushes must then carry a
    /// `ts_us >= floor`.
    ///
    /// # Hazard
    ///
    /// Passing a `floor` value that is **higher** than every legitimate
    /// `ts_us` the caller will subsequently produce permanently locks
    /// out flushes from this uplink (every flush returns
    /// [`VsError::InvalidInput`]) until the uplink is reconstructed.
    /// This is the same trap the first-flush window has — made
    /// explicit here so the caller pays attention. Treat `floor` as a
    /// commit: only pin it if you trust the source.
    ///
    /// `floor > MAX_REASONABLE_TS_US` is rejected to preserve the
    /// invariant that no internal state can climb past the implausible
    /// timestamp ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `floor > MAX_REASONABLE_TS_US`.
    pub fn set_initial_ts_floor(&mut self, floor: u64) -> Result<(), VsError> {
        if floor > MAX_REASONABLE_TS_US {
            return Err(VsError::InvalidInput);
        }
        // Monotonic by construction: only advance the floor, never
        // regress it. (If the floor were lowered, an attacker who got
        // one well-timed call in could undo a legitimate later pin.)
        if floor > self.last_flush_us {
            self.last_flush_us = floor;
        }
        Ok(())
    }

    /// Add a single entry to the internal ring buffer.
    ///
    /// If `payload_len` exceeds 64, returns `VsError::PolicyViolation`.
    ///
    /// If the buffer is full the oldest entry is overwritten (head advances)
    /// and `dropped_count` is incremented.
    ///
    /// # Per-entry sequence and timestamp validation (audit fix HIGH-Y)
    ///
    /// `TelemetryEntry` carries caller-supplied `sequence` and
    /// `timestamp_us` fields. A buggy or malicious producer could
    /// otherwise submit `sequence = 0` repeatedly, submit a backwards
    /// timestamp, or submit `timestamp_us = u64::MAX`; the receiver
    /// would notice the chain inconsistency only after decryption,
    /// which is too late. To catch this at ingress we enforce three
    /// rules before admitting the entry:
    ///
    /// 1. `entry.timestamp_us <= MAX_REASONABLE_TS_US` — always
    ///    enforced; rejects the `u64::MAX` `DoS` shape regardless of the
    ///    relaxed-ordering flag.
    /// 2. If [`TelemetryConfig::allow_out_of_order_entries`] is `false`
    ///    (the default) and at least one entry has previously been
    ///    admitted, the incoming `sequence` must be strictly greater
    ///    than the previous entry's `sequence`.
    /// 3. Under the same default, the incoming `timestamp_us` must be
    ///    greater than or equal to the previous entry's `timestamp_us`.
    ///
    /// Violations return [`VsError::InvalidInput`] and DO NOT enqueue
    /// the entry. `last_entry_sequence` / `last_entry_timestamp_us` are
    /// updated only on successful admission to the ring buffer (the
    /// reserved-critical-slots drop path does NOT update them, since
    /// the entry never reaches the wire).
    ///
    /// # Reserved-critical-slots policy (audit fix MED-2)
    ///
    /// When ring-buffer occupancy is at or above
    /// `(UPLINK_BUFFER_CAPACITY - reserved_critical_slots)`, only entries
    /// of severity [`AlertSeverity::Critical`] or [`AlertSeverity::High`]
    /// are admitted. Lower-severity entries are dropped (counted in
    /// `dropped_count`) without disturbing the queue. This blocks the
    /// "flood Info events to evict Critical alerts" attack.
    ///
    /// # Errors
    ///
    /// - [`VsError::PolicyViolation`] if `payload_len > MAX_PAYLOAD_LEN`.
    /// - [`VsError::InvalidInput`] if any of the per-entry validations
    ///   above fail.
    pub fn submit_entry(&mut self, entry: TelemetryEntry) -> Result<(), VsError> {
        if entry.payload_len > MAX_PAYLOAD_LEN {
            return Err(VsError::PolicyViolation);
        }

        // --- Per-entry timestamp upper bound (audit fix HIGH-Y) ---
        // Always enforced, even in relaxed-ordering mode: a caller
        // supplying `u64::MAX` would otherwise pin the `last_entry_*`
        // floors so high that every subsequent monotonic check fails.
        if entry.timestamp_us > MAX_REASONABLE_TS_US {
            return Err(VsError::InvalidInput);
        }

        // --- Strict monotonicity gate (audit fix HIGH-Y) ---
        // Skipped when the integrator has opted in to out-of-order
        // entries (legitimate use case: multiple producers feeding one
        // uplink without a global sequence source).
        if !self.config.allow_out_of_order_entries {
            if let Some(last_seq) = self.last_entry_sequence {
                if entry.sequence <= last_seq {
                    return Err(VsError::InvalidInput);
                }
            }
            if let Some(last_ts) = self.last_entry_timestamp_us {
                if entry.timestamp_us < last_ts {
                    return Err(VsError::InvalidInput);
                }
            }
        }

        // Reserved-critical-slots gate (audit MED-2).
        let reserved = self.config.reserved_critical_slots as usize;
        let high_water = UPLINK_BUFFER_CAPACITY.saturating_sub(reserved);
        if self.count >= high_water {
            let is_high_priority = matches!(
                entry.severity,
                AlertSeverity::Critical | AlertSeverity::High
            );
            if !is_high_priority {
                // Audit fixes INFO-1 / audit-M13 / audit-M14:
                // `account_drop` atomically bumps both the
                // per-severity histogram slot AND `dropped_count`,
                // honouring the saturation contract — once any per-slot
                // would exceed `u16::MAX`, the saturation flag flips on
                // and BOTH counters freeze together. Reserved-slots
                // drops are self-induced (the caller submitted a
                // low-priority entry while the buffer was reserved for
                // Critical / High), so the dropped tier matches
                // `entry.severity`.
                self.account_drop(entry.severity);
                // Intentionally do NOT update `last_entry_*` here: the
                // entry was rejected, never reaches the wire, and must
                // not advance the monotonic floor for future entries.
                return Ok(());
            }
        }

        let slot = (self.head + self.count) & (UPLINK_BUFFER_CAPACITY - 1);
        if self.count == UPLINK_BUFFER_CAPACITY {
            // Audit fix INFO-1: ring overflow — the *evicted* entry is
            // what got dropped, not the newly-submitted one. Capture
            // the head-slot severity BEFORE we overwrite it so the
            // per-severity histogram reflects the tier of the alert
            // that was actually suppressed (an attacker who floods Info
            // events to evict a Critical alert must perturb the
            // Critical histogram slot, not the Info slot, for the
            // receiver to see the tier-targeted suppression).
            let evicted_severity = self.buffer[self.head].map(|e| e.severity);
            self.head = (self.head + 1) & (UPLINK_BUFFER_CAPACITY - 1);
            // Audit fixes INFO-1 / audit-M13 / audit-M14: route both
            // the scalar bump and the per-severity bump through
            // `account_drop` so the saturation contract is applied in
            // lock-step. If the head slot is empty (shouldn't happen
            // when `count == UPLINK_BUFFER_CAPACITY`, but defensively
            // handle the `None`), fall through to `account_drop_other`
            // — the drop still happened and must remain countable.
            match evicted_severity {
                Some(sev) => self.account_drop(sev),
                None => {
                    debug_assert!(
                        false,
                        "ring buffer reported full but head slot was None — \
                         drop accounting invariant violated"
                    );
                    self.account_drop_other();
                }
            }
        } else {
            self.count += 1;
        }
        self.buffer[slot] = Some(entry);

        // --- Update monotonic floors on successful admission ---
        // We update unconditionally (even under
        // `allow_out_of_order_entries`) so that flipping the flag back
        // to strict mode later does not let a stale ordering slip
        // through: the floor reflects the highest sequence/timestamp
        // actually admitted so far.
        self.last_entry_sequence = Some(match self.last_entry_sequence {
            Some(prev) if prev > entry.sequence => prev,
            _ => entry.sequence,
        });
        self.last_entry_timestamp_us = Some(match self.last_entry_timestamp_us {
            Some(prev) if prev > entry.timestamp_us => prev,
            _ => entry.timestamp_us,
        });
        Ok(())
    }

    /// Atomic drop-accounting step (audit fixes INFO-1 / audit-M13 /
    /// audit-M14). Bumps BOTH `dropped_count` AND the appropriate
    /// per-severity histogram slot, honouring the one-shot saturation
    /// contract so the two counters never drift out of lock-step.
    ///
    /// # Saturation contract (audit-M14)
    ///
    /// Once any per-`u16` histogram slot
    /// (`dropped_per_severity[*]` or `dropped_other`) would exceed
    /// `u16::MAX`, the [`Self::histogram_saturated`] flag flips on and
    /// EVERY further call to this method (or
    /// [`Self::account_drop_other`]) is a no-op: `dropped_count`,
    /// every `dropped_per_severity[*]`, and `dropped_other` all freeze
    /// at their last-observed value. This keeps the receiver's
    /// `sum(per_severity) + dropped_other <= dropped_count` invariant
    /// stable past the saturation point — without the flag, a `u16`
    /// per-slot would pin at 65_535 while `dropped_count` continued to
    /// climb toward `u64::MAX`, turning the cross-check into noise and
    /// blinding the receiver to tier-targeted suppression.
    ///
    /// # Forward-compat contract (audit-M13)
    ///
    /// `Info`-tier drops are intentionally untracked at the per-slot
    /// level — Info-tier floods are caller-induced, not a suppression
    /// attack, and `dropped_count` alone already answers "how many".
    /// Variants WITHOUT a dedicated slot (a future `#[non_exhaustive]`
    /// `AlertSeverity::Catastrophic`, etc.) are routed to the
    /// `dropped_other` catch-all so the receiver's
    /// `sum(per_severity) + dropped_other <= dropped_count` invariant
    /// remains satisfied across enum extensions. A `debug_assert!`
    /// fires in test builds so an unmapped variant is caught early —
    /// release builds silently accumulate into `dropped_other` rather
    /// than corrupt the histogram.
    #[inline]
    fn account_drop(&mut self, severity: AlertSeverity) {
        // Saturated: every counter is frozen. Do nothing — observability
        // is now via the `histogram_saturated` AAD flag, not further
        // increments to either counter.
        if self.histogram_saturated {
            return;
        }
        // Layout matches AAD encoding: [Critical, High, Medium, Low].
        match severity {
            AlertSeverity::Critical => self.bump_slot_with_saturation_check(0),
            AlertSeverity::High => self.bump_slot_with_saturation_check(1),
            AlertSeverity::Medium => self.bump_slot_with_saturation_check(2),
            AlertSeverity::Low => self.bump_slot_with_saturation_check(3),
            AlertSeverity::Info => {
                // Info-tier: per-spec, only bump the scalar. No
                // histogram slot is allocated for Info.
                self.dropped_count = self.dropped_count.saturating_add(1);
            }
            _unknown => {
                // Audit-M13: a future `#[non_exhaustive]` variant landed
                // without an explicit slot in this match. Catch it in
                // test builds so the histogram layout is widened
                // before release; in production, route to the
                // `dropped_other` catch-all so the receiver's
                // `sum(per_severity) + dropped_other <= dropped_count`
                // invariant still holds.
                debug_assert!(
                    false,
                    "unmapped AlertSeverity variant — re-check severity histogram \
                     (audit-M13: widen dropped_per_severity / dropped_other layout)"
                );
                self.bump_other_with_saturation_check();
            }
        }
    }

    /// Drop-accounting step for a drop whose severity cannot be
    /// recovered (e.g. defensive `None` from `buffer[head]` when the
    /// occupancy counter says the slot must be populated). Routes the
    /// scalar bump and the `dropped_other` catch-all bump through the
    /// shared saturation contract.
    ///
    /// This is paired with `debug_assert!(false, ...)` at the only
    /// call site so the underlying invariant violation surfaces in
    /// tests rather than silently corrupting the histogram. Kept
    /// separate from `account_drop(AlertSeverity)` so callers cannot
    /// reach the `dropped_other` slot via the wildcard arm without
    /// the audit-M13 debug-assert tripping first.
    #[inline]
    fn account_drop_other(&mut self) {
        if self.histogram_saturated {
            return;
        }
        self.bump_other_with_saturation_check();
    }

    /// Bump `dropped_per_severity[idx]` and `dropped_count` together.
    /// If the per-slot is already at `u16::MAX` the saturation flag
    /// flips on and both counters freeze at their current value.
    ///
    /// Audit-M14: the freeze-on-saturation behaviour is the wire
    /// contract — once `histogram_saturated == true` the receiver
    /// MUST treat further frames as "drop count unknown".
    #[inline]
    fn bump_slot_with_saturation_check(&mut self, idx: usize) {
        debug_assert!(idx < 4, "bump_slot idx out of range");
        if self.dropped_per_severity[idx] == u16::MAX {
            // Saturation: freeze BOTH counters together so the
            // receiver's `sum(per_severity) + dropped_other
            // <= dropped_count` invariant stays satisfied past this
            // point. Set the flag so the next AAD frame signals the
            // freeze to the receiver.
            self.histogram_saturated = true;
            return;
        }
        // Pre-checked above, so the `+ 1` cannot overflow. Using
        // `saturating_add` defensively in case the precondition is
        // ever violated by a future refactor — the saturation flag
        // would also be set, so the receiver still observes the
        // freeze.
        self.dropped_per_severity[idx] = self.dropped_per_severity[idx].saturating_add(1);
        self.dropped_count = self.dropped_count.saturating_add(1);
    }

    /// Bump `dropped_other` and `dropped_count` together. Same
    /// saturation semantics as
    /// [`Self::bump_slot_with_saturation_check`].
    #[inline]
    fn bump_other_with_saturation_check(&mut self) {
        if self.dropped_other == u16::MAX {
            self.histogram_saturated = true;
            return;
        }
        self.dropped_other = self.dropped_other.saturating_add(1);
        self.dropped_count = self.dropped_count.saturating_add(1);
    }

    /// Test-only hook (audit-M13 / audit-M14): drive the
    /// `account_drop` accounting path with a raw `u8` severity tag so
    /// tests can exercise the unknown-variant routing without needing
    /// to mutate the upstream `#[non_exhaustive]` `AlertSeverity`
    /// enum. Tags `0..=4` route through the documented `AlertSeverity`
    /// variants; tags outside that range route through
    /// [`Self::account_drop_other`], which mirrors what the production
    /// wildcard arm in `account_drop` does for a future
    /// `#[non_exhaustive]` variant (modulo the `debug_assert!` — the
    /// test hook is the *only* sanctioned way to reach
    /// `account_drop_other` without tripping that assert).
    ///
    /// The hook is `pub(crate)` and gated on `cfg(test)` so it cannot
    /// leak into production callers.
    #[cfg(test)]
    pub(crate) fn test_account_drop_by_tag(&mut self, severity_tag: u8) {
        match severity_tag {
            0 => self.account_drop(AlertSeverity::Info),
            1 => self.account_drop(AlertSeverity::Low),
            2 => self.account_drop(AlertSeverity::Medium),
            3 => self.account_drop(AlertSeverity::High),
            4 => self.account_drop(AlertSeverity::Critical),
            // Synthetic "unknown" tag: route through the same
            // accounting path the production wildcard arm uses. This
            // keeps the test honest — if a future variant lands and
            // the production match is updated, this branch needs to
            // be updated too, and the audit-M13 debug_assert! in
            // `account_drop` will trip in the meantime.
            _ => {
                self.account_drop_other();
            }
        }
    }

    /// Test-only accessor: returns the saturation flag so tests can
    /// pin the audit-M14 freeze behaviour without exposing internal
    /// state through the public API. Always returns `false` on a
    /// fresh uplink; flips to `true` on the increment that first
    /// pushes any `u16` slot past its ceiling.
    #[cfg(test)]
    pub(crate) fn histogram_saturated(&self) -> bool {
        self.histogram_saturated
    }

    /// Test-only accessor: returns the `dropped_other` catch-all
    /// histogram slot (audit-M13). Used by tests to confirm
    /// unknown-variant drops accumulate into the dedicated bucket
    /// instead of being silently swallowed.
    #[cfg(test)]
    pub(crate) fn dropped_other(&self) -> u16 {
        self.dropped_other
    }

    /// Test-only accessor: returns the per-severity dropped histogram
    /// (audit-M13 negative-path tests verify known variants land in
    /// their own slots; M14 saturation tests assert the slot freezes
    /// at the documented ceiling).
    #[cfg(test)]
    pub(crate) fn dropped_per_severity(&self) -> [u16; 4] {
        self.dropped_per_severity
    }

    /// **Deprecated alias for [`flush_with_persistence`] with a
    /// no-op persistence backend** — the name `flush` hid the fact that
    /// this variant skips the write-ahead counter persistence contract
    /// and is therefore unsafe to use on any device whose AES-GCM key
    /// survives a reboot.
    ///
    /// Concretely, this method forwards to
    /// [`flush_with_persistence`](Self::flush_with_persistence) with a
    /// [`NoOpPersistence`] backend. If the device loses power between
    /// the in-memory counter advancing and the next boot, the
    /// `flush_counter` is lost and the next flush after reboot reuses a
    /// nonce — catastrophic for AES-GCM.
    ///
    /// Use [`flush_with_persistence`](Self::flush_with_persistence) (or
    /// the richer [`flush_outcome`](Self::flush_outcome) shape) instead.
    /// This method is retained only for test fixtures and ephemeral
    /// devices where nonce reuse across reboots is impossible by
    /// construction (e.g. fresh-keys-per-boot architectures).
    ///
    /// # Availability
    ///
    /// This API is only available in `cfg(test)` or with the `test-only`
    /// Cargo feature. `#[deprecated]` alone is a warning, not an
    /// enforcement boundary; the cfg gate confines this footgun to the
    /// test surface so production callers cannot reach it through
    /// autocomplete or copy-paste. Additionally disabled when the
    /// `strict-nonce` feature is on, because the `NoOpPersistence`
    /// backing store cannot guarantee that the advanced counter survives
    /// a reboot — a power loss after the encrypt would leak nonce reuse
    /// on the next boot. Strict-nonce callers must use
    /// [`flush_with_persistence`](Self::flush_with_persistence) or
    /// [`flush_outcome`](Self::flush_outcome).
    ///
    /// # Error discrimination
    ///
    /// This method conflates rate-limit exhaustion and flush-counter
    /// exhaustion under a single `Err(VsError::ResourceExhausted)`, which
    /// turns retry-on-error callers into busy-loops at end-of-life. New
    /// code should prefer [`flush_outcome`](Self::flush_outcome), which
    /// returns a discriminated [`FlushOutcome`] enum carrying
    /// `RateLimited { retry_after_us }` vs `CounterExhausted`.
    ///
    /// # Errors
    ///
    /// - `VsError::CryptoError` if any cryptographic operation fails.
    /// - `VsError::ResourceExhausted` if the batch would exceed the
    ///   configured `max_bytes_per_minute` rate limit, or if the
    ///   `flush_counter` has saturated.
    #[cfg(any(test, feature = "test-only"))]
    #[cfg(not(feature = "strict-nonce"))]
    #[allow(clippy::too_many_lines)] // Splitting flush_no_persist() into helpers would
                                     // duplicate the volatile-wipe scaffolding across multiple frames.
    #[deprecated(
        note = "Use flush_with_persistence or flush_outcome — flush_no_persist bypasses the counter-persistence contract and can cause AES-GCM nonce reuse after reboot."
    )]
    pub fn flush_no_persist(
        &mut self,
        crypto: &C,
        ts_us: u64,
    ) -> Result<Option<FlushResult>, VsError> {
        self.flush_with_persistence(crypto, ts_us, &mut NoOpPersistence)
    }

    /// Strict variant returning a [`FlushOutcome`] that distinguishes
    /// `Sent`, `Empty`, `RateLimited`, and `CounterExhausted` — replaces
    /// the legacy `Result<Option<FlushResult>>` shape. New code should
    /// prefer this method.
    ///
    /// # Errors
    ///
    /// Returns an error only for cryptographic / IO failures. The
    /// "no batch was sent because of capacity / rate-limit / counter"
    /// cases are non-error variants of [`FlushOutcome`].
    pub fn flush_outcome<P: CounterPersistence>(
        &mut self,
        crypto: &C,
        ts_us: u64,
        persistence: &mut P,
    ) -> Result<FlushOutcome, VsError> {
        match self.flush_with_persistence(crypto, ts_us, persistence) {
            Ok(Some(r)) => Ok(FlushOutcome::Sent(r)),
            Ok(None) => Ok(FlushOutcome::Empty),
            Err(VsError::ResourceExhausted) => {
                // The legacy method conflates "rate-limited" and
                // "counter exhausted" under ResourceExhausted. Discriminate
                // by inspecting state.
                if self.flush_counter >= MAX_FLUSH_COUNTER {
                    Ok(FlushOutcome::CounterExhausted)
                } else {
                    let elapsed = ts_us.saturating_sub(self.window_start_us);
                    let retry_after_us = MICROS_PER_MINUTE.saturating_sub(elapsed);
                    Ok(FlushOutcome::RateLimited { retry_after_us })
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Flush buffered entries, persisting the advanced `flush_counter` via
    /// `persistence` **before** any encryption runs.
    ///
    /// This is the nonce-safe variant of [`flush`](Self::flush) and is the
    /// only correct choice for any device where the encryption key survives
    /// a reboot. See [`CounterPersistence`] for the contract persist
    /// implementations must uphold.
    ///
    /// # Write-ahead ordering (audit fix CRIT-1) + jump-over invariant
    ///
    /// 1. Validate inputs and compute `next_counter = self.flush_counter + 1`.
    /// 2. Call `persistence.persist(next_counter)` and propagate any error.
    /// 3. **Immediately** commit `self.flush_counter = next_counter` so the
    ///    in-memory state matches the durable store. Any subsequent
    ///    encrypt/sign failure therefore "jumps over" `next_counter` rather
    ///    than reusing it.
    /// 4. Derive nonce/AAD from `next_counter` and run AES-GCM encrypt +
    ///    P-256 sign.
    ///
    /// **Invariant:** once `persistence.persist(N+1)` returns `Ok`, the
    /// in-memory counter equals `N+1` regardless of whether the subsequent
    /// crypto operations succeed. This keeps in-memory and durable state in
    /// lock-step and prevents the persistence backend from rejecting an
    /// idempotent re-write deadlock on retry. If step 4 fails the counter
    /// value is "burned" — persistent storage and in-memory state both
    /// hold `N+1` but no ciphertext was published, and the next flush
    /// advances to `N+2`.
    #[allow(clippy::too_many_lines)]
    pub fn flush_with_persistence<P: CounterPersistence>(
        &mut self,
        crypto: &C,
        ts_us: u64,
        persistence: &mut P,
    ) -> Result<Option<FlushResult>, VsError> {
        // --- Reject implausibly large timestamps (audit fix MED-1) ---
        // A caller-supplied `u64::MAX` (or anywhere near it) would pin the
        // monotonic-clock floor so high that every subsequent flush fails
        // the check at the top of this function — a one-shot DoS. Bound
        // well below `u64::MAX` so the `last_flush_us` invariant stays
        // useful.
        if ts_us > MAX_REASONABLE_TS_US {
            return Err(VsError::InvalidInput);
        }

        // --- Monotonic-clock check (applies even to empty flushes, so that
        // a regression is noisy regardless of ring-buffer occupancy) ---
        //
        // audit-LOW: on the very first call after construction
        // `last_flush_us == 0`, so any `ts_us >= 0` passes this check.
        // This leaves a one-shot window where an untrusted caller could
        // pin the floor near `MAX_REASONABLE_TS_US` on first flush and
        // permanently lock out every legitimate timestamp below that
        // value. The window is open by design — no prior anchor exists
        // to compare against on a fresh boot — and the load-bearing
        // mitigation is the `MAX_REASONABLE_TS_US` ceiling enforced
        // above, which bounds the maximum damage to "lock out the
        // lower half of the u64 range" rather than "lock out everything
        // up to u64::MAX". Callers that have a trusted boot-time time
        // anchor (GPS, RTC) should call
        // [`Self::set_initial_ts_floor`] before the first submit to
        // close this window explicitly.
        if ts_us < self.last_flush_us {
            return Err(VsError::InvalidInput);
        }

        let to_flush = self.count.min(self.config.batch_size as usize);
        if to_flush == 0 {
            // Empty-flush still advances `last_flush_us` so the monotonic
            // guard stays consistent with the caller's reported clock. The
            // earlier ts_us bound (`MAX_REASONABLE_TS_US`) prevents the
            // u64::MAX DoS path that this update previously enabled.
            self.last_flush_us = ts_us;
            return Ok(None);
        }

        // --- Flush counter overflow guard ---
        // A wrapped flush_counter would cause nonce reuse in AES-GCM, which is
        // catastrophic. The nonce encoding uses a 6-byte counter slot, so we
        // must reject well before u64::MAX to prevent silent truncation into
        // the nonce.
        let next_counter = match self.flush_counter.checked_add(1) {
            Some(v) if v <= MAX_FLUSH_COUNTER => v,
            _ => return Err(VsError::ResourceExhausted),
        };

        // --- Write-ahead counter persistence (audit fix CRIT-1) ---
        // Persist the ADVANCED counter BEFORE any encrypt/sign happens.
        // If the device loses power between this persist and the encrypt
        // below, the next boot sees `next_counter` and therefore never
        // reuses the current nonce. If persist itself fails we leave
        // `self.flush_counter` untouched so the caller may retry cleanly.
        persistence.persist(next_counter)?;

        // Jump-over invariant: advance in-memory counter immediately after
        // a successful persist, BEFORE encrypt/sign runs. If encrypt fails
        // the counter is still burned in both stores, so the next flush
        // moves to `next_counter + 1` without ever reusing this nonce.
        self.flush_counter = next_counter;

        // --- Rate limiting ---
        if ts_us.saturating_sub(self.window_start_us) >= MICROS_PER_MINUTE {
            self.bytes_this_window = 0;
            self.window_start_us = ts_us;
        }
        // Cast-free conversion: with to_flush ≤ 64 and ENTRY_SERIAL_SIZE = 83,
        // the product fits comfortably in u32, but use `try_from` to be
        // future-proof against configuration changes.
        let batch_usize = BATCH_HEADER_SIZE
            .checked_add(
                to_flush
                    .checked_mul(ENTRY_SERIAL_SIZE)
                    .ok_or(VsError::InvalidInput)?,
            )
            .ok_or(VsError::InvalidInput)?;
        let batch_bytes = u32::try_from(batch_usize).map_err(|_| VsError::InvalidInput)?;
        if self.bytes_this_window.saturating_add(batch_bytes) > self.config.max_bytes_per_minute {
            return Err(VsError::ResourceExhausted);
        }

        // --- Build digest over actual entry data ---
        // Hash the batch header: device_id (32) + flush_counter (8) + timestamp (8).
        // NB: we encode `next_counter` (the write-ahead-persisted value), NOT
        // `self.flush_counter`, so the header/nonce/AAD all agree on the
        // counter the VSOC backend will observe.
        //
        // Hoist `next_counter.to_le_bytes()` into a local so the three sites
        // that need it (header, nonce, AAD) share one materialised buffer
        // instead of three `to_le_bytes` calls.
        let counter_le_bytes = next_counter.to_le_bytes();
        let mut header = [0u8; BATCH_HEADER_SIZE];
        // `device_id_cache` is the immutable 32-byte device_id captured at
        // construction (audit perf item): avoids re-reading `self.config`
        // for the first 32 bytes of every header.
        header[..32].copy_from_slice(&self.device_id_cache);
        header[32..40].copy_from_slice(&counter_le_bytes);
        header[40..48].copy_from_slice(&ts_us.to_le_bytes());

        let mut digest = [0u8; 32];
        crypto.sha256(&header, &mut digest)?;

        // Chain each entry: digest = SHA-256(prev_digest || serialized_entry).
        // Buffer: 32 (prev hash) + 83 (fixed serialized entry) = 115 bytes.
        //
        // `chain` transiently holds serialised plaintext entry bytes (sequence
        // numbers, severities, raw payloads). Wipe it before the buffer drops
        // so the plaintext doesn't linger on the stack for the lifetime of
        // the caller's frame.
        let mut chain = [0u8; 32 + ENTRY_SERIAL_SIZE];
        let mut idx = self.head;
        let mut hash_result: Result<(), VsError> = Ok(());
        // Severity histogram bound into the AAD (audit fix
        // MED-vsoc-AAD-sev). Layout: `[Critical, High, Medium, Low]` —
        // Info is intentionally excluded because it is not an alert,
        // and counting it would let a noisy producer (or attacker)
        // drown the commitment in benign events. `UPLINK_BUFFER_CAPACITY
        // = 64` bounds each bucket well below `u16::MAX`, so the
        // per-flush accumulator cannot overflow.
        let mut severity_dist: [u16; 4] = [0; 4];
        for _ in 0..to_flush {
            if let Some(ref entry) = self.buffer[idx] {
                // Tally severity BEFORE the (fallible) hash step so the
                // distribution we would bind into AAD always matches
                // the entries we just walked. On the error path the
                // AAD build is short-circuited by `hash_result?` below,
                // so `severity_dist` is simply discarded.
                match entry.severity() {
                    AlertSeverity::Critical => {
                        severity_dist[0] = severity_dist[0].saturating_add(1);
                    }
                    AlertSeverity::High => {
                        severity_dist[1] = severity_dist[1].saturating_add(1);
                    }
                    AlertSeverity::Medium => {
                        severity_dist[2] = severity_dist[2].saturating_add(1);
                    }
                    AlertSeverity::Low => {
                        severity_dist[3] = severity_dist[3].saturating_add(1);
                    }
                    // Info is intentionally not counted; see comment above.
                    AlertSeverity::Info => {}
                    // Audit-M13: any future `#[non_exhaustive]`
                    // additions to `AlertSeverity` route through this
                    // explicit arm rather than a bare wildcard. The
                    // `debug_assert!` fires in test builds so the
                    // missing slot is caught before release — the
                    // admitted-severity histogram (unlike the
                    // dropped-severity one) has no catch-all slot of
                    // its own because it is bounded by
                    // `UPLINK_BUFFER_CAPACITY` and is fully recoverable
                    // by adding the variant explicitly. In release the
                    // arm is a no-op, preserving the previous behaviour
                    // (the receiver pins the layout too, so silent
                    // miscounting for unknown variants is the only
                    // forward-compatible choice).
                    _unknown => {
                        debug_assert!(
                            false,
                            "unmapped AlertSeverity variant in admitted severity_dist tally — \
                             audit-M13: widen severity_dist layout for the new variant"
                        );
                    }
                }
                chain[..32].copy_from_slice(&digest);
                match entry.serialize_into(&mut chain, 32) {
                    Ok(written) => {
                        if let Err(e) = crypto.sha256(&chain[..32 + written], &mut digest) {
                            hash_result = Err(e);
                            break;
                        }
                    }
                    Err(e) => {
                        hash_result = Err(e);
                        break;
                    }
                }
            }
            idx = (idx + 1) & UPLINK_BUFFER_MASK;
        }
        // Always wipe the transient plaintext buffer, including on error.
        // `volatile_wipe` defeats dead-store elimination: `chain` is about to
        // go out of scope and LLVM could otherwise drop the zeroing stores,
        // leaving serialised plaintext (sequences, severities, payloads) on
        // the stack for subsequent frames to observe.
        volatile_wipe(&mut chain);
        hash_result?;

        // --- Derive per-device nonce prefix (audit fix HIGH-1) ---
        // The previous nonce layout placed only `device_id[0..4]` into the
        // nonce, so two devices sharing those 4 bytes plus the same key
        // produced colliding nonces. Now we hash the full 32-byte
        // `device_id` and use the first 6 bytes as a per-device prefix.
        //
        // audit-LOW: branch-free derivation. We used to cache the prefix
        // on first flush and gate the recompute behind a `bool`. That
        // produced a one-shot timing delta between "first flush after
        // construction" and every other flush. The derivation is purely
        // deterministic over `device_id` (which never changes for the
        // lifetime of an uplink), so recomputing it every call yields the
        // same bytes — and removes the timing oracle entirely. Cost: one
        // SHA-256 per flush. The 64-byte input buffer layout is unchanged
        // so the resulting prefix is bit-identical to the previously-cached
        // value.
        let mut nonce_prefix_digest = [0u8; 32];
        let mut nonce_prefix_input = [0u8; 64];
        nonce_prefix_input[..NONCE_PREFIX_LABEL.len()].copy_from_slice(NONCE_PREFIX_LABEL);
        nonce_prefix_input[32..].copy_from_slice(&self.config.device_id);
        crypto.sha256(&nonce_prefix_input, &mut nonce_prefix_digest)?;

        // --- Encrypt the digest using AES-GCM ---
        // Nonce layout (12 bytes, deterministic, collision-free by construction):
        //   [0..6]  = HKDF-like derivation from full device_id
        //   [6..12] = flush_counter (6 bytes little-endian, 2^48 range)
        // The prefix now spans 6 bytes derived from all 32 device-id
        // bytes, so cross-device collisions require a SHA-256 collision
        // (negligible) rather than a 4-byte device_id-prefix overlap.
        // `counter_le_bytes` reuses the hoisted local from the header
        // step above (audit perf item: one `to_le_bytes` per flush, not
        // three).
        let mut nonce = [0u8; 12];
        nonce[..6].copy_from_slice(&nonce_prefix_digest[..6]);
        nonce[6..12].copy_from_slice(&counter_le_bytes[..6]);

        // AAD binds every non-secret value the receiver must trust:
        //   device_id (32) || flush_counter (8) || entry_count (8)
        //       || ts_us (8) || dropped_count (8) || severity_dist (8)
        //       || dropped_per_severity (8)
        //       || dropped_other (2) || histogram_saturated (1) || _reserved (1)
        //
        // Binding `dropped_count` (audit fix): otherwise an attacker who
        // floods low-severity events to evict genuine alerts perturbs only
        // `self.dropped_count`, which is never observed by the receiver.
        // The receiver MUST validate that the decoded `dropped_count` is
        // monotonically non-decreasing across flushes from the same
        // device; a regression indicates rollback or tamper.
        //
        // Binding `severity_dist` (audit fix MED-vsoc-AAD-sev): a
        // targeted rewrite that drops every Critical entry and pads
        // with Info entries would otherwise only be detectable by the
        // absence of expected alerts. The little-endian `[u16; 4]`
        // histogram of (Critical, High, Medium, Low) covers the batch
        // we just hashed, so any silent severity-distribution rewrite
        // (in the ring buffer, in transit, or via a tampered
        // `serialize_into`) fails AES-GCM authentication end-to-end.
        // Info is excluded — see the comment above the in-loop tally.
        //
        // Binding `dropped_per_severity` (audit fix INFO-1):
        // `dropped_count` alone cannot distinguish "attacker flooded
        // Info events and the ring evicted Critical alerts" from
        // "caller emitted too many Info events of their own". Binding
        // the per-tier histogram lets the receiver detect a
        // tier-targeted suppression attack — a perturbation in the
        // Critical/High slots is operationally distinguishable from
        // baseline Low/Medium chatter. The receiver SHOULD validate
        // each slot is monotonically non-decreasing across flushes
        // from the same device, and that
        // `sum(dropped_per_severity[0..4]) + dropped_other
        // <= dropped_count` (Info-tier drops are excluded from the
        // histogram so the inequality is strict when Info drops are
        // present).
        //
        // Binding `dropped_other` (audit-M13): catch-all bucket for
        // `AlertSeverity` variants that have no dedicated histogram
        // slot today. `AlertSeverity` is `#[non_exhaustive]`, so this
        // slot absorbs drops of future variants (e.g.
        // `AlertSeverity::Catastrophic`) until the layout is widened.
        // Without this slot, a wildcard `_` arm in the drop accounting
        // path would let `dropped_count` climb while every per-slot
        // stayed pinned — silently breaking the receiver's
        // sum-inequality cross-check.
        //
        // Binding `histogram_saturated` (audit-M14): one-shot
        // saturation marker. Once any `u16` per-slot would exceed its
        // ceiling, this flag flips to 1 and BOTH `dropped_count` AND
        // every `dropped_per_severity[*]` (and `dropped_other`) are
        // frozen at their last value. The receiver MUST treat
        // subsequent frames as "drop count unknown" — without this
        // signal, `dropped_count` would saturate at `u64::MAX` while
        // every per-slot saturated at `u16::MAX`, blinding the
        // receiver to further tier-targeted suppression activity.
        //
        // The first 32 bytes mirror the device_id header and are sourced
        // from `device_id_cache` (audit perf item) so we don't re-read
        // `self.config` for material that never changes.
        let mut aad = [0u8; AAD_SIZE];
        aad[..32].copy_from_slice(&self.device_id_cache);
        aad[32..40].copy_from_slice(&counter_le_bytes);
        // Cast guard (audit fix LOW-vsoc-cleanup): `to_flush` is bounded
        // by `batch_size: u8 <= UPLINK_BUFFER_CAPACITY <= 64` on every
        // supported platform, so the `usize -> u64` cast is currently
        // lossless. The debug assert documents and enforces the
        // invariant so a future configuration change that lifts the
        // bound cannot silently truncate into the AAD.
        debug_assert!(u64::try_from(to_flush).is_ok());
        aad[40..48].copy_from_slice(&(to_flush as u64).to_le_bytes());
        aad[48..56].copy_from_slice(&ts_us.to_le_bytes());
        aad[56..64].copy_from_slice(&self.dropped_count.to_le_bytes());
        // severity_dist: 4 × u16 little-endian, totalling
        // SEVERITY_DIST_BYTES (= 8). Materialise into a fixed-size
        // byte buffer so the field width is tied to
        // SEVERITY_DIST_BYTES and `copy_from_slice` does a single
        // bounds-checked copy rather than eight indexed stores.
        let mut sev_bytes = [0u8; SEVERITY_DIST_BYTES];
        sev_bytes[0..2].copy_from_slice(&severity_dist[0].to_le_bytes());
        sev_bytes[2..4].copy_from_slice(&severity_dist[1].to_le_bytes());
        sev_bytes[4..6].copy_from_slice(&severity_dist[2].to_le_bytes());
        sev_bytes[6..8].copy_from_slice(&severity_dist[3].to_le_bytes());
        aad[64..64 + SEVERITY_DIST_BYTES].copy_from_slice(&sev_bytes);
        // dropped_per_severity: 4 × u16 little-endian into bytes
        // 72..80. Same fixed-size buffer approach as severity_dist for
        // the same single-copy reason.
        let mut dropped_sev_bytes = [0u8; DROPPED_PER_SEV_BYTES];
        dropped_sev_bytes[0..2].copy_from_slice(&self.dropped_per_severity[0].to_le_bytes());
        dropped_sev_bytes[2..4].copy_from_slice(&self.dropped_per_severity[1].to_le_bytes());
        dropped_sev_bytes[4..6].copy_from_slice(&self.dropped_per_severity[2].to_le_bytes());
        dropped_sev_bytes[6..8].copy_from_slice(&self.dropped_per_severity[3].to_le_bytes());
        aad[72..72 + DROPPED_PER_SEV_BYTES].copy_from_slice(&dropped_sev_bytes);
        // Audit-M13 / audit-M14 trailer (DROPPED_OTHER_AND_FLAGS_BYTES = 4):
        //   AAD[80..82] = dropped_other     (u16 LE)
        //   AAD[82]     = histogram_saturated (u8, 0 or 1)
        //   AAD[83]     = _reserved          (u8, always 0)
        //
        // Binding `dropped_other` (audit-M13) preserves the receiver's
        // `sum(dropped_per_severity) + dropped_other <= dropped_count`
        // invariant across `#[non_exhaustive]` extensions to
        // `AlertSeverity`. Without it, a future variant landing in
        // production code would have its drops bump `dropped_count`
        // (via the wildcard-shaped accounting path) while silently
        // bypassing every per-slot — the cross-check would degrade
        // from "tight equality (modulo Info)" to "vacuous inequality".
        //
        // Binding `histogram_saturated` (audit-M14) is a one-shot
        // signal that the per-slot `u16` ceiling has been hit. Once
        // set, the AAD-bound `dropped_count` and every
        // `dropped_per_severity[*]` (and `dropped_other`) are frozen
        // at their last value — the receiver MUST treat further frames
        // as "drop count unknown" rather than relying on
        // `dropped_count` continuing to climb past the saturation
        // ceiling. Tying the freeze to a single flag (rather than
        // letting `dropped_count` overshoot a saturated histogram)
        // keeps the invariant
        // `sum(per_severity) + dropped_other <= dropped_count`
        // honest past the saturation point.
        //
        // The reserved trailing byte is zero today; a future audit fix
        // that needs to bind a second flag (or a tier widening) can
        // allocate it without bumping AAD_SIZE again.
        let mut trailer = [0u8; DROPPED_OTHER_AND_FLAGS_BYTES];
        trailer[0..2].copy_from_slice(&self.dropped_other.to_le_bytes());
        trailer[2] = u8::from(self.histogram_saturated);
        trailer[3] = 0; // explicit zero for the reserved byte.
        aad[80..80 + DROPPED_OTHER_AND_FLAGS_BYTES].copy_from_slice(&trailer);

        let mut encrypted_digest = [0u8; 32];
        let mut tag = [0u8; 16];
        let enc_res = crypto.aes_gcm_encrypt(
            self.config.encryption_key_id,
            &nonce,
            &digest,
            &aad,
            &mut encrypted_digest,
            &mut tag,
        );
        // --- Wipe philosophy (audit perf item) ---
        // Only wipe what is *plaintext-secret*. `header`, `nonce`, `aad`,
        // `encrypted_digest`, `sig`, and the local `counter_le_bytes` carry
        // only non-secret material:
        //   - header / nonce / aad: device_id, counters, timestamps, entry
        //     counts — all observable on the wire and recoverable from
        //     `FlushResult`/network capture.
        //   - encrypted_digest: ciphertext, public by definition.
        //   - sig: ECDSA signature, public by definition.
        //   - counter_le_bytes: the flush counter, published in
        //     `FlushResult::flush_counter`.
        // Volatile-wiping these buffers blocks autovectorisation of the
        // surrounding `copy_from_slice` calls without any confidentiality
        // benefit. The wipes that REMAIN cover `digest` and `chain`, which
        // do hold plaintext-secret material (the SHA-256 chain over the raw
        // entry sequences/severities/payloads).
        if let Err(e) = enc_res {
            volatile_wipe(&mut digest);
            return Err(e);
        }

        // --- Sign the digest ---
        let mut sig = [0u8; 64];
        let sign_res = crypto.sign_p256(self.config.signing_key_id, &digest, &mut sig);
        // Digest is the plaintext we just encrypted. Wipe it before return
        // regardless of sign outcome, so it does not linger on the stack.
        // (`sig` itself is public ECDSA output and is intentionally not wiped.)
        volatile_wipe(&mut digest);
        sign_res?;

        // --- Update accounting ---
        // `self.flush_counter` already equals `next_counter` (advanced
        // immediately after the successful persist above). Only rate-limit
        // bookkeeping and `last_flush_us` remain.
        self.bytes_this_window = self.bytes_this_window.saturating_add(batch_bytes);
        self.last_flush_us = ts_us;

        // Consume the flushed entries. Audit perf item: replace the
        // per-iteration `count -= 1` with a single saturating subtraction
        // outside the loop, and use the bit-mask form of the modulus.
        for _ in 0..to_flush {
            self.buffer[self.head] = None;
            self.head = (self.head + 1) & UPLINK_BUFFER_MASK;
        }
        self.count = self.count.saturating_sub(to_flush);

        Ok(Some(FlushResult {
            digest_commitment: encrypted_digest,
            tag,
            signature: sig,
            entry_count: to_flush,
            // `next_counter` was used for nonce/AAD/header of this batch.
            // Receivers use it to dedupe and to detect replay, so report
            // exactly the value that was encoded on the wire.
            flush_counter: next_counter,
        }))
    }

    /// Returns the number of entries currently queued.
    #[inline]
    pub fn queued(&self) -> usize {
        self.count
    }

    /// Returns the number of entries dropped due to buffer overflow.
    #[inline]
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    /// Returns the monotonic flush counter.
    ///
    /// # Post-advance semantics (audit fix LOW-vsoc-cleanup)
    ///
    /// The returned value is the **post-advance** counter — i.e., it
    /// reflects the value that was already written to durable storage
    /// by [`CounterPersistence::persist`] inside
    /// [`flush_with_persistence`](Self::flush_with_persistence) /
    /// [`flush_outcome`](Self::flush_outcome). Concretely, that means a
    /// caller that observes this value between a successful persist
    /// and a subsequent encrypt-failure will see the counter for a
    /// batch that was **never transmitted on the wire**. This is by
    /// design and is the core of the jump-over invariant: the receiver
    /// will simply see a one-batch gap in `flush_counter`, and the
    /// nonce that would have been used is permanently retired in both
    /// stores so it can never be reused.
    ///
    /// Callers that need the "last successfully transmitted" counter
    /// for backend reconciliation should track it themselves from the
    /// [`FlushResult`] returned by `flush_outcome`, not from this
    /// getter.
    #[inline]
    pub fn flush_counter(&self) -> u64 {
        self.flush_counter
    }
}

// Legacy test module exercises the deprecated/insecure entry points
// (`flush_no_persist`, `PersistedFlushCounter::restore(u64)`, etc.) which
// the `strict-nonce` feature gates out of the public API. Gate the whole
// module on `not(strict-nonce)` so `cargo test --features strict-nonce`
// exercises only the strict-API surface in `strict_nonce_api_surface`.
#[cfg(all(test, not(feature = "strict-nonce")))]
mod tests;

/// Strict-nonce-mode API-surface smoke test. Compiles only under
/// `--features strict-nonce`; verifies that the strict subset
/// (`try_restore` + `flush_outcome`/`flush_with_persistence`) is reachable.
#[cfg(all(test, feature = "strict-nonce"))]
mod strict_nonce_api_surface;

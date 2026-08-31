// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_std]
#![allow(unsafe_code)] // Required: all unsafe blocks target the PKCS#11 C ABI.

//! PKCS#11 HSM-backed implementation of [`CryptoProvider`].
//!
//! # Overview
//!
//! [`Pkcs11CryptoProvider`] implements the `vs-crypto` [`CryptoProvider`]
//! trait by forwarding every operation to a PKCS#11 v2.40 / v3.0 token via
//! caller-supplied function pointers ([`Pkcs11FunctionList`]).
//!
//! Targets: **`SoftHSM2`** (development), **Thales Luna**, **Utimaco**,
//! **Microchip ATECC**, and any PKCS#11-compliant HSM.
//!
//! # Design
//!
//! The crate is `#![no_std]` with zero heap allocations. All buffers are
//! stack-allocated. The caller resolves the PKCS#11 function pointers
//! (e.g., via `dlopen` on Linux, or static linking on embedded targets) and
//! provides them as a [`Pkcs11FunctionList`] at construction time.
//!
//! Key identity is managed via a slot array of 64 [`CkObjectHandle`] values,
//! indexed by the [`KeyId`] used throughout the `craton-shield` platform.
//! Call [`register_key_handle`] to map a `KeyId` to its PKCS#11 handle after
//! opening a session and locating the key object.
//!
//! # AES-GCM tag handling
//!
//! PKCS#11 appends the authentication tag to the ciphertext output of
//! `C_Encrypt`. This provider splits the combined buffer into separate
//! ciphertext and tag slices as required by the [`CryptoProvider`] interface.
//!
//! # Safety
//!
//! All `unsafe` blocks in this file invoke C function pointers supplied by
//! the caller. Each call site documents the invariants the caller must uphold.
//!
//! # Nonce Management
//!
//! AES-GCM is catastrophically broken if a nonce is ever reused with the
//! same key. This provider accepts caller-supplied nonces and does **not**
//! track or enforce uniqueness. The caller **must** guarantee that every
//! `(key_id, nonce)` pair is used at most once. Recommended strategies:
//!
//! - Use a monotonic counter (e.g., `flush_counter` in `vs-vsoc-telemetry`).
//! - Use a 96-bit random nonce from the HSM's TRNG (collision probability
//!   is negligible below 2^32 messages per key).
//!
//! As defense-in-depth, this provider tracks the last nonce used per
//! `KeyId` and rejects verbatim repeats with `VsError::CryptoError`. This
//! does **not** substitute for caller discipline — it only catches the
//! degenerate "same nonce twice in a row" bug.
//!
//! # Write-Ahead Nonce Persistence (audit fix CRIT-2)
//!
//! The in-memory `last_nonce` cache above is reset to all-zero on
//! [`Pkcs11CryptoProvider::new`], so a process restart silently re-enables
//! AES-GCM nonce reuse against any token-persisted key. The
//! [`aes_gcm_encrypt_with_persistence`](Pkcs11CryptoProvider::aes_gcm_encrypt_with_persistence)
//! method takes a caller-supplied [`NoncePersistence`] sink that durably
//! records the next counter value **before** the encryption happens
//! (mirrors `vsoc_telemetry::CounterPersistence`). The derived 12-byte
//! nonce is `device_prefix[0..6] || counter_le[0..6]`, which guarantees
//! uniqueness across reboots as long as the persistence implementation
//! survives power loss.
//!
//! The legacy [`aes_gcm_encrypt`](CryptoProvider::aes_gcm_encrypt) entry
//! point (caller supplies the nonce) remains available but is deprecated;
//! new code must use the persistence variant.

// audit-M5: `unsafe-fuzz-trng` disables the `random_bytes` sentinel check
// so a fuzzer can drive the provider with an in-process generator. It
// must never reach a production binary — refuse to compile any release
// build (no `debug_assertions`, not `cfg(test)`) that has the feature
// enabled, even if activated transitively via Cargo feature unification.
#[cfg(all(feature = "unsafe-fuzz-trng", not(any(test, debug_assertions))))]
compile_error!(
    "`unsafe-fuzz-trng` disables the random_bytes sentinel check and must NEVER be enabled in release builds. \
     See audit-M5. If you reached this error via Cargo feature unification, find the activator and remove it."
);

mod error;
pub mod ffi;
mod types;

use subtle::ConstantTimeEq;

use error::{check_rv, rv_to_err};
use ffi::Pkcs11FunctionList;
use types::{
    CkAesGcmParams, CkAttribute, CkEcdh1DeriveParams, CkMechanism, CkObjectClass, CkObjectHandle,
    CkRv, CkSessionHandle, CkTokenInfo, CkUlong, CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_TOKEN,
    CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_AES_GCM,
    CKM_ECDH1_DERIVE, CKM_ECDSA, CKM_SHA256, CKM_SHA256_HMAC, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
    CKU_USER, CK_FALSE, CK_INVALID_HANDLE, CK_TRUE,
};
use vs_crypto::{CryptoProvider, KeyId, KeyType};
use vs_types::VsError;

/// Maximum number of key slots (matches `vs-key-manager` `MAX_KEYS`).
const MAX_KEY_SLOTS: usize = 64;

/// AES-GCM authentication tag length in bytes.
const GCM_TAG_LEN: usize = 16;

/// AES-GCM tag length in bits (128).
const GCM_TAG_BITS: CkUlong = 128;

/// SHA-256 output length in bytes.
const SHA256_LEN: usize = 32;

/// ECDSA P-256 signature length in bytes (r || s, unpadded).
const ECDSA_SIG_LEN: usize = 64;

/// ECDH P-256 shared secret length (x-coordinate only).
const ECDH_SHARED_LEN: usize = 32;

/// Maximum AES-GCM plaintext / ciphertext length in bytes (audit fix HIGH-Q).
///
/// PKCS#11 `C_Encrypt` writes `ciphertext || tag` into a single buffer
/// of `MAX_PT + GCM_TAG_LEN`. CLAUDE.md caps every per-call stack buffer
/// at 2048 B, so `MAX_PT = 2048 - GCM_TAG_LEN = 2032` is the largest
/// plaintext that still fits the budget exactly. Callers passing more
/// must chunk their payload themselves.
const MAX_PT: usize = 2048 - GCM_TAG_LEN;

/// Maximum AES-GCM AAD length in bytes (audit fix HIGH-P).
///
/// AES-GCM itself permits up to 2^61 bytes of AAD, but every buffer in
/// this crate is capped at the CLAUDE.md per-call 2048 B ceiling. The
/// historical 256 B cap was arbitrary and rejected legal AAD; raising
/// it to `MAX_AAD = 2048` matches the plaintext-side ceiling without
/// growing the per-call stack frame (AAD is borrowed from the caller's
/// slice, not copied into a local buffer).
const MAX_AAD: usize = 2048;

// Compile-time invariant: the combined `ciphertext || tag` buffer fits
// the 2048 B per-call cap exactly.
const _: () = assert!(MAX_PT + GCM_TAG_LEN == 2048);

/// Length of the `EC_POINT` (uncompressed P-256 public key): `0x04 || X || Y`.
const EC_POINT_LEN: usize = 65;

/// Derived-key attribute for ECDH: extract the raw 32-byte shared secret.
const ECDH_DERIVED_KEY_ATTRS: usize = 2;

/// Master switch for the `random_bytes` pre-fill sentinel check (audit-M5).
///
/// The sentinel pre-fills the caller's buffer with a per-byte variable
/// pattern, calls the token's `C_GenerateRandom`, and rejects the result
/// if every byte still matches the pre-fill — catching a token that
/// returns `CKR_OK` without writing, or no-ops on a non-zero buffer.
///
/// The check is active whenever `strict-rng` is on OR `unsafe-fuzz-trng`
/// is off. Equivalently: the only way to disable it is to BOTH clear
/// `strict-rng` from `default-features` AND explicitly opt into
/// `unsafe-fuzz-trng`. A compile-time guard at the top of this file
/// further refuses to build any release artifact with `unsafe-fuzz-trng`.
///
/// Centralising this as a single `const bool` instead of `cfg!`-ing the
/// call site directly gives auditors one place to verify the policy.
const RANDOM_SENTINEL_ENABLED: bool =
    cfg!(any(feature = "strict-rng", not(feature = "unsafe-fuzz-trng")));

// Compile-time invariant: the 16-byte GCM tag matches `ul_tag_bits = 128`.
// Changing these values in lock-step is required by the PKCS#11 AES-GCM spec.
const _: () = assert!(GCM_TAG_LEN * 8 == GCM_TAG_BITS as usize);

const _: () = assert!(EC_POINT_LEN == 65);

// ---------------------------------------------------------------------------
// P-256 software on-curve validation (audit fix).
//
// The validation logic — including U256 limb arithmetic and the curve
// equation y² ≡ x³ − 3x + b (mod p) for `secp256r1` — lives in the
// shared `vs-p256-validate` crate. It uses Solinas (FIPS 186-4 §D.2.3)
// fast reduction instead of bit-serial long division, so each P-256
// modular multiply is O(1) reduction steps instead of O(512).
//
// `crypto-tpm` re-exports the same routine. Centralising the
// implementation keeps the two providers' on-curve checks bit-for-bit
// identical and removes a maintenance hazard where one copy could
// silently drift from the other.
// ---------------------------------------------------------------------------

use vs_p256_validate::validate_p256_point_on_curve;

// Compile-time agreement on the uncompressed P-256 point length.
const _: () = assert!(EC_POINT_LEN == vs_p256_validate::EC_POINT_LEN);

/// Convert a buffer length to `CkUlong` without silent truncation.
///
/// PKCS#11 `CK_ULONG` is platform-dependent (`unsigned long`): 32-bit on
/// some embedded ILP32 targets, 64-bit elsewhere. A naïve `as CkUlong`
/// cast would silently truncate on 32-bit platforms for lengths above
/// 4 GiB. Use this helper on every `usize → CkUlong` conversion that
/// feeds a PKCS#11 argument so an attacker-sized buffer cannot wrap.
#[inline]
fn to_ck_ulong(len: usize) -> Result<CkUlong, VsError> {
    // audit-LOW: clamp at the 31-bit ceiling (0x7FFF_FFFF) for portability.
    // The PKCS#11 v2.40 / v3.0 specs define `CK_ULONG` as an
    // `unsigned long` whose width varies across platforms (32-bit on
    // ILP32 embedded targets, 64-bit on LP64). A handful of historical
    // tokens treat the high bit of `CK_ULONG` as reserved (for vendor
    // error-code encoding); writing a length above `0x7FFF_FFFF` is
    // therefore portably unsafe even when the platform `CkUlong` would
    // hold the value. Our per-call buffer cap upstream (2 KiB) makes a
    // real overflow impossible on the in-tree call sites, but the bare
    // `try_from` previously accepted `usize::MAX` on 64-bit hosts —
    // collapse the ceiling explicitly so a future caller plumbing a
    // larger buffer cannot bypass the portability bound.
    if len > 0x7FFF_FFFF {
        return Err(VsError::InvalidInput);
    }
    CkUlong::try_from(len).map_err(|_| VsError::InvalidInput)
}

/// Volatile-zero every byte of `buf`.
///
/// Prevents the compiler from dead-store-eliminating the wipe of
/// short-lived key-adjacent material on the stack.
#[inline]
fn volatile_wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid writable reference into caller-owned memory;
        // `write_volatile<u8>` is always sound.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Fixed-size stack buffer used by `find_object_by_label` to hold a
/// mutable copy of the caller's label (PKCS#11's `CK_ATTRIBUTE.pValue`
/// is `*mut`, so the bytes cannot be borrowed directly).
///
/// Extracted as a `pub(crate)` helper so the test suite can build the
/// exact same buffer and observe the pre-/post-wipe contents without
/// dipping into the live `find_object_by_label` call path.
#[inline]
pub(crate) fn build_label_buffer(label: &[u8]) -> [u8; 256] {
    let mut out = [0u8; 256];
    // Callers in this crate validate `label.len() <= 256` *before*
    // invoking the helper; clamp defensively here so the helper itself
    // is panic-free even under direct test invocation.
    let n = if label.len() > out.len() {
        out.len()
    } else {
        label.len()
    };
    out[..n].copy_from_slice(&label[..n]);
    out
}

// ---------------------------------------------------------------------------
// Audit fix HIGH-O: surface `C_DestroyObject` return values for diagnostics.
//
// `ecdh_derive_shared` and `verify_p256` both create transient session
// objects that hold key/public-key material. If the token reports a
// non-`CKR_OK` from `C_DestroyObject`, that material lingers on the
// token. The provider now escalates the destroy failure to
// `VsError::CryptoError` (overall API impact), AND stores the raw
// `CkRv` value here so tests and operational tooling can observe the
// exact reason the destroy failed.
//
// The atomic is process-global by design: it carries diagnostic value
// only and is overwritten by every destroy call. `CKR_OK == 0` is the
// reset value, so an unread atomic is indistinguishable from a clean
// destroy — that is the intended semantics.
// ---------------------------------------------------------------------------

/// Most recent `C_DestroyObject` return value observed by any
/// `Pkcs11CryptoProvider` operation. Reads / writes are `SeqCst` because
/// the value is consumed by tests that may run after the operation.
pub static LAST_DESTROY_ERROR: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[inline]
fn record_destroy_rv(rv: CkRv) {
    // `CkRv` is `CkUlong`, which is platform-dependent (`unsigned long`).
    // Cast through `usize` so the atomic width matches without truncation
    // on either ILP32 or LP64 targets.
    LAST_DESTROY_ERROR.store(rv as usize, core::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// PinBuffer: zeroizing PIN holder
// ---------------------------------------------------------------------------

/// Maximum PKCS#11 PIN length supported by this crate (bytes).
///
/// Matches the upper bound in most tokens' `C_InitToken` documentation and
/// is wide enough for the longest real-world HSM admin/user PINs.
pub const MAX_PIN_LEN: usize = 64;

/// Fixed-size PIN buffer that volatile-wipes itself on drop.
///
/// The `no_std` surface of this crate cannot use `Vec<u8>` or the
/// `zeroize` crate's `Zeroizing<Vec<u8>>`. `PinBuffer` provides an
/// equivalent facility: callers copy their PIN bytes in, pass the buffer
/// to [`Pkcs11CryptoProvider::new`] / [`Pkcs11CryptoProvider::try_clone`],
/// and either `Drop::drop` or an explicit [`PinBuffer::wipe`] call ensures
/// the PIN is scrubbed from the stack as soon as it is no longer needed.
#[repr(C)]
pub struct PinBuffer {
    bytes: [u8; MAX_PIN_LEN],
    len: usize,
}

impl PinBuffer {
    /// Copy `pin` into a fresh `PinBuffer`. Fails if the PIN is empty or
    /// exceeds [`MAX_PIN_LEN`] bytes.
    pub fn new(pin: &[u8]) -> Result<Self, VsError> {
        if pin.is_empty() || pin.len() > MAX_PIN_LEN {
            return Err(VsError::InvalidInput);
        }
        let mut bytes = [0u8; MAX_PIN_LEN];
        bytes[..pin.len()].copy_from_slice(pin);
        Ok(Self {
            bytes,
            len: pin.len(),
        })
    }

    /// Return the PIN as a slice for use in PKCS#11 calls.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Volatile-wipe the PIN immediately. Called automatically by `Drop`.
    #[inline]
    pub fn wipe(&mut self) {
        volatile_wipe(&mut self.bytes);
        self.len = 0;
    }
}

impl Drop for PinBuffer {
    fn drop(&mut self) {
        self.wipe();
    }
}

// ---------------------------------------------------------------------------
// NoncePersistence trait (audit fix CRIT-2)
// ---------------------------------------------------------------------------

/// Maximum counter value representable in the 6-byte counter slot used by
/// the derived nonce (`device_prefix[0..6] || counter_le[0..6]`).
///
/// `2^48 - 1 ≈ 2.8 × 10¹⁴` encryptions per key — at one encryption per
/// millisecond that is ~8900 years, so the limit is practical but enforced
/// to prevent silent truncation into the nonce.
pub const MAX_NONCE_COUNTER: u64 = (1u64 << 48) - 1;

/// Length of the per-provider device prefix prepended to every derived
/// AES-GCM nonce (in bytes).
pub const NONCE_DEVICE_PREFIX_LEN: usize = 6;

/// Length of the little-endian counter slot in every derived AES-GCM
/// nonce (in bytes).
pub const NONCE_COUNTER_LEN: usize = 6;

// Compile-time invariant: derived nonce is exactly 12 bytes.
const _: () = assert!(NONCE_DEVICE_PREFIX_LEN + NONCE_COUNTER_LEN == 12);

/// Sink for durably persisting the per-`KeyId` monotonic nonce counter
/// **before** any encryption happens (audit fix CRIT-2: write-ahead
/// counter).
///
/// Mirrors `vsoc_telemetry::CounterPersistence` — same write-ahead and
/// jump-over invariant.
///
/// # Contract
///
/// Implementations MUST NOT return `Ok(())` until `next_counter` has been
/// written to durable, rollback-resistant storage (e.g., a TPM NV index,
/// an HMAC-authenticated file on an eMMC partition). If the persist call
/// succeeds but the device loses power before a subsequent encrypt, the
/// counter is still "burned" — the next boot sees the new value and the
/// old nonce is never reused. This is the core property that prevents
/// AES-GCM nonce repetition across reboots.
///
/// On any failure to persist, return an error.
/// [`Pkcs11CryptoProvider::aes_gcm_encrypt_with_persistence`] will NOT
/// advance its in-memory counter, so the caller may retry after resolving
/// the underlying storage fault.
///
/// # Atomicity
///
/// `persist` must be atomic: a partial write that loses power must leave
/// the persisted counter either at its previous value or at `next_counter`,
/// never at an intermediate value.
///
/// # Monotonicity
///
/// Implementations MUST enforce that `next_counter` is strictly greater
/// than any previously persisted value for the same `key_id`. A persist
/// that would regress the counter must return an error so a rollback
/// attack cannot rewind the nonce counter.
///
/// # Idempotency
///
/// Implementations MUST accept a re-write of an already-persisted value:
/// calling `persist(N)` after a previous `persist(N)` returned `Ok` must
/// also return `Ok`. The jump-over invariant relies on this — after an
/// encrypt-failure-following-persist a retry may legitimately re-attempt
/// the same counter value, and a non-idempotent rejection here would
/// deadlock the caller.
pub trait NoncePersistence {
    /// Persist `next_counter` for `key_id` to durable storage. Returns
    /// only after the write is committed.
    fn persist(&mut self, key_id: KeyId, next_counter: u64) -> Result<(), VsError>;

    /// Load the last persisted counter for `key_id`. Returns `0` if no
    /// prior counter has been persisted for this key.
    fn load(&self, key_id: KeyId) -> Result<u64, VsError>;
}

/// No-op nonce persistence for test and stateless-device scenarios.
///
/// **Hazard:** every use on a device whose encryption key survives a
/// reboot leaks nonce reuse — only use on factory-fresh / single-boot
/// test rigs.
#[cfg(any(test, feature = "test-only"))]
#[repr(C)]
pub struct NoOpNoncePersistence;

#[cfg(any(test, feature = "test-only"))]
impl NoncePersistence for NoOpNoncePersistence {
    #[inline]
    fn persist(&mut self, _key_id: KeyId, _next_counter: u64) -> Result<(), VsError> {
        Ok(())
    }

    #[inline]
    fn load(&self, _key_id: KeyId) -> Result<u64, VsError> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Provider struct
// ---------------------------------------------------------------------------

/// PKCS#11 HSM-backed [`CryptoProvider`].
///
/// Holds a live PKCS#11 session and a map from [`KeyId`] to
/// `CK_OBJECT_HANDLE`. Use [`new`](Self::new) to open a session and log in,
/// then call [`register_key_handle`](Self::register_key_handle) for each key
/// the platform will use.
///
/// # Thread Safety
///
/// PKCS#11 sessions are **not** thread-safe by specification. This type
/// must only be used from a single thread. The `PhantomData<*mut ()>` marker
/// prevents auto-derivation of `Send` and `Sync`.
#[repr(C)]
pub struct Pkcs11CryptoProvider {
    /// PKCS#11 function pointer table (provided by caller).
    fn_list: Pkcs11FunctionList,
    /// Open session handle.
    session: CkSessionHandle,
    /// Key-slot map: `key_map[key_id.0 as usize]` → `CK_OBJECT_HANDLE`.
    ///
    /// `CK_INVALID_HANDLE` (0) means the slot is not populated.
    key_map: [CkObjectHandle; MAX_KEY_SLOTS],
    /// Per-`KeyId` cache of the last AES-GCM nonce used for `encrypt`.
    ///
    /// Defence-in-depth against the catastrophic GCM-nonce-reuse bug
    /// (audit fix HIGH). Interior mutability is required because the
    /// `CryptoProvider::aes_gcm_encrypt` signature takes `&self`. The
    /// `_not_send_sync` marker below ensures the cell is never observed
    /// from another thread.
    last_nonce: [core::cell::Cell<[u8; 12]>; MAX_KEY_SLOTS],
    /// Bitmask of slots whose `last_nonce[i]` cell is populated. Bit `i`
    /// set means at least one encrypt has been recorded for `KeyId(i)`.
    last_nonce_set: core::cell::Cell<u64>,
    /// Set to `true` on the first successful `aes_gcm_encrypt`. Used by
    /// [`Pkcs11CryptoProvider::try_clone`] to refuse cloning once any GCM
    /// encryption has occurred, because the cloned provider would start
    /// with an empty `last_nonce` cache and could re-issue a nonce that
    /// was already used by the parent — silently breaking GCM's
    /// nonce-misuse defence-in-depth.
    has_encrypted: core::cell::Cell<bool>,
    /// Per-provider 6-byte prefix prepended to every derived AES-GCM
    /// nonce (audit fix CRIT-2). Derived once at construction time from
    /// the token's TRNG via `C_GenerateRandom`, so two providers that
    /// somehow share the same persistent counter still produce disjoint
    /// nonces with overwhelming probability. The prefix is **not**
    /// secret; it only needs to be unique per provider instance.
    nonce_device_prefix: [u8; NONCE_DEVICE_PREFIX_LEN],
    /// In-memory cache of the last persisted counter per `KeyId`, used by
    /// [`Pkcs11CryptoProvider::aes_gcm_encrypt_with_persistence`] to
    /// avoid a `load` call on every encrypt. `0` means "no counter
    /// loaded yet for this slot" — the next encrypt will call
    /// `persistence.load(key_id)` before incrementing.
    nonce_counter: [core::cell::Cell<u64>; MAX_KEY_SLOTS],
    /// Bitmask of slots whose `nonce_counter[i]` has been populated from
    /// the persistence layer at least once. Bit `i` set means the cache
    /// is authoritative for `KeyId(i)`; bit clear means the next encrypt
    /// must `load` from persistence first.
    nonce_counter_loaded: core::cell::Cell<u64>,
    /// Prevent `Send` and `Sync` — PKCS#11 sessions are not thread-safe.
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

impl Pkcs11CryptoProvider {
    /// Open a PKCS#11 session with the given slot and log in as the normal user.
    ///
    /// # Parameters
    ///
    /// - `fn_list`: Fully populated [`Pkcs11FunctionList`]. All function
    ///   pointer fields must be non-null and valid.
    /// - `pin`: User PIN bytes. The slice is never stored; it is only passed
    ///   to `C_Login` and then forgotten. The caller should zeroize the PIN
    ///   buffer after this call returns (e.g., via the `zeroize` crate) to
    ///   prevent the PIN from lingering in memory.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::NotInitialized`] if `C_Initialize`, `C_OpenSession`,
    /// or `C_Login` fails. If `fn_list.library_pre_initialized` is non-zero,
    /// `C_Initialize` is skipped.
    pub fn new(fn_list: Pkcs11FunctionList, pin: &[u8]) -> Result<Self, VsError> {
        // Wrap the caller's PIN in a zeroizing buffer so that the local copy
        // is always scrubbed on return (success or error). Callers should
        // also wipe their own source buffer after this returns.
        let mut pin_buf = PinBuffer::new(pin)?;
        let result = Self::new_with_pin_buffer(fn_list, &pin_buf);
        pin_buf.wipe();
        result
    }

    /// Constructor variant that takes an already-owned [`PinBuffer`].
    ///
    /// Prefer this constructor in deployments that obtain the PIN from a
    /// TPM-protected wrap or secure-element secure-channel read, so that the
    /// PIN never traverses the caller's own stack as a plain `&[u8]`.
    pub fn new_with_pin_buffer(
        fn_list: Pkcs11FunctionList,
        pin: &PinBuffer,
    ) -> Result<Self, VsError> {
        // Initialise the library unless the caller already did.
        if fn_list.library_pre_initialized == 0 {
            // SAFETY: `C_Initialize` may be called at most once per process.
            // The caller asserts the function pointer is valid and that
            // library initialisation has not yet been performed by any
            // other code in this process.
            let rv = unsafe { (fn_list.c_initialize)(core::ptr::null_mut()) };
            check_rv(rv)?;
        }

        // Open a read-write serial session on the caller's slot.
        let mut session: CkSessionHandle = 0;
        // SAFETY: `session` is a local variable whose address is valid for
        // the duration of this call. `fn_list.slot_id` is set by the caller.
        let rv = unsafe {
            (fn_list.c_open_session)(
                fn_list.slot_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                core::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        check_rv(rv)?;

        let pin_slice = pin.as_slice();
        let pin_len_u = match to_ck_ulong(pin_slice.len()) {
            Ok(v) => v,
            Err(e) => {
                // Audit fix HIGH (session leak): the open session must be
                // closed before propagating the error.
                // SAFETY: `session` is a valid handle returned by
                // `C_OpenSession` above; close on the same fn_list.
                unsafe { (fn_list.c_close_session)(session) };
                return Err(e);
            }
        };
        // Log in as the normal user.
        // SAFETY: `pin_slice` is valid for the duration of this call; its
        // length has been checked to fit `CkUlong`.
        let rv = unsafe { (fn_list.c_login)(session, CKU_USER, pin_slice.as_ptr(), pin_len_u) };
        if let Err(e) = check_rv(rv) {
            // Audit fix HIGH (session leak on PIN failure): `C_Login` failed
            // (CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_USER_ALREADY_LOGGED_IN,
            // ...). The session opened above is still active and counts
            // against the token's session table. Repeated PIN-failure paths
            // would exhaust the token's session table — a real DoS surface.
            // Best-effort close; ignore the close return value because we are
            // already on an error path.
            // SAFETY: `session` is the live handle returned by
            // `C_OpenSession`; it has not been closed yet on this path.
            unsafe { (fn_list.c_close_session)(session) };
            return Err(e);
        }

        // Derive a per-provider 6-byte nonce prefix from the token's TRNG.
        // If the TRNG fails, close the session and surface the error: a
        // zero prefix would silently weaken nonce uniqueness across
        // co-existing providers.
        let mut nonce_device_prefix = [0u8; NONCE_DEVICE_PREFIX_LEN];
        // SAFETY: `nonce_device_prefix` is a valid 6-byte stack buffer.
        let rv = unsafe {
            (fn_list.c_generate_random)(
                session,
                nonce_device_prefix.as_mut_ptr(),
                NONCE_DEVICE_PREFIX_LEN as CkUlong,
            )
        };
        if let Err(e) = check_rv(rv) {
            // SAFETY: session is still live; logout + close before bailing
            // to match the failure paths above.
            unsafe { (fn_list.c_logout)(session) };
            unsafe { (fn_list.c_close_session)(session) };
            return Err(e);
        }

        Ok(Self {
            fn_list,
            session,
            key_map: [CK_INVALID_HANDLE; MAX_KEY_SLOTS],
            last_nonce: [const { core::cell::Cell::new([0u8; 12]) }; MAX_KEY_SLOTS],
            last_nonce_set: core::cell::Cell::new(0),
            has_encrypted: core::cell::Cell::new(false),
            nonce_device_prefix,
            nonce_counter: [const { core::cell::Cell::new(0u64) }; MAX_KEY_SLOTS],
            nonce_counter_loaded: core::cell::Cell::new(0),
            _not_send_sync: core::marker::PhantomData,
        })
    }

    /// Map a [`KeyId`] to a PKCS#11 `CK_OBJECT_HANDLE`.
    ///
    /// The handle is typically obtained by searching for token objects with
    /// `C_FindObjects` using a label template (`"vs-key-XX"`).
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `key_id` ≥ `MAX_KEY_SLOTS`.
    pub fn register_key_handle(
        &mut self,
        key_id: KeyId,
        handle: CkObjectHandle,
    ) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        self.key_map[idx] = handle;
        // Audit fix CRIT-2: registering a (possibly different) handle in
        // this slot must invalidate the in-memory nonce-counter cache,
        // because the cache is keyed by `KeyId` but its semantic
        // ownership is the underlying key material. The next encrypt
        // re-loads from persistence so that a slot-reuse cannot
        // resurrect a stale counter value.
        let bit = 1u64 << idx;
        self.nonce_counter[idx].set(0);
        self.nonce_counter_loaded
            .set(self.nonce_counter_loaded.get() & !bit);
        // Also invalidate the legacy last-nonce repeat-detection cache —
        // the new handle may key a different cryptographic identity.
        self.last_nonce[idx].set([0u8; 12]);
        self.last_nonce_set.set(self.last_nonce_set.get() & !bit);
        Ok(())
    }

    /// Find a token object by its `CKA_LABEL` **and** `CKA_CLASS` attributes
    /// (audit fix).
    ///
    /// Wires `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`
    /// — previously declared in [`Pkcs11FunctionList`] but unused. The
    /// helper is the canonical path for recovering a key handle on
    /// startup ("look up `vs-key-XX` and then call
    /// [`register_key_handle`](Self::register_key_handle)").
    ///
    /// `Init` and `Final` are paired strictly: if `Init` succeeds the
    /// helper always calls `Final`, even on subsequent errors. If `Init`
    /// fails, `Final` is NOT called (no session to close out).
    ///
    /// # Why both attributes are required
    ///
    /// PKCS#11 labels are not unique across object classes — a public-key
    /// and the corresponding private-key object commonly share the same
    /// `CKA_LABEL` (e.g., both labelled `vs-key-00`). Filtering on
    /// `CKA_LABEL` alone would return whichever object the token enumerates
    /// first, leading to subtle wrong-key bugs (encrypt-with-public-key,
    /// or import-public-as-secret). The caller must specify the class
    /// they actually intend, e.g. [`CKO_PRIVATE_KEY`](types::CKO_PRIVATE_KEY),
    /// [`CKO_SECRET_KEY`](types::CKO_SECRET_KEY), or
    /// [`CKO_PUBLIC_KEY`](types::CKO_PUBLIC_KEY).
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidInput`] if `label.len() > 256`.
    /// - Propagates the PKCS#11 error class for any failed call.
    pub fn find_object_by_label(
        &self,
        label: &[u8],
        class: CkObjectClass,
    ) -> Result<Option<CkObjectHandle>, VsError> {
        use types::CKA_LABEL;
        const MAX_LABEL_LEN: usize = 256;

        if label.len() > MAX_LABEL_LEN {
            return Err(VsError::InvalidInput);
        }

        // The PKCS#11 ABI defines `CK_ATTRIBUTE.pValue` as `*mut`, so we
        // copy the caller-supplied label into a local mutable buffer.
        // `MAX_LABEL_LEN` upper-bounds the stack allocation.
        let mut label_local = build_label_buffer(label);
        // Local mutable copy of the class for the same `*mut` ABI reason.
        let mut class_local: CkObjectClass = class;

        // audit-LOW: labels are operational metadata, not secrets, but we
        // mirror the `volatile_wipe` discipline applied to PIN / key
        // material elsewhere in this crate. The local stack copy holds
        // the caller's label until the function returns; explicitly
        // scrub it on every exit path so a stale frame cannot leak the
        // label into an adjacent allocation.
        let label_len_u = match to_ck_ulong(label.len()) {
            Ok(v) => v,
            Err(e) => {
                volatile_wipe(&mut label_local);
                return Err(e);
            }
        };

        let template = [
            CkAttribute {
                attribute_type: CKA_CLASS,
                p_value: &mut class_local as *mut CkObjectClass as *mut core::ffi::c_void,
                ul_value_len: core::mem::size_of::<CkObjectClass>() as CkUlong,
            },
            CkAttribute {
                attribute_type: CKA_LABEL,
                p_value: label_local.as_mut_ptr().cast::<core::ffi::c_void>(),
                ul_value_len: label_len_u,
            },
        ];

        let template_len_u = match to_ck_ulong(template.len()) {
            Ok(v) => v,
            Err(e) => {
                volatile_wipe(&mut label_local);
                return Err(e);
            }
        };

        // SAFETY: `template` is a valid stack-allocated single-element
        // array; `self.session` is a live PKCS#11 session.
        let rv = unsafe {
            (self.fn_list.c_find_objects_init)(self.session, template.as_ptr(), template_len_u)
        };
        if let Err(e) = check_rv(rv) {
            volatile_wipe(&mut label_local);
            return Err(e);
        }

        // From here on, every exit path must call `C_FindObjectsFinal`.
        //
        // Audit fix HIGH-N: ask for up to 2 matches so we can detect a
        // label collision (e.g. an admin accidentally creating two objects
        // with the same `vs-key-NN` label and class). Previously we asked
        // for `ul_max_object_count = 1`, which silently returned whichever
        // object the token enumerated first — a wrong-key bug waiting to
        // happen. The buffer is sized for 2; if the token reports `count > 1`
        // we refuse the lookup and force the operator to deduplicate.
        let mut found = [CK_INVALID_HANDLE; 2];
        let mut count: CkUlong = 0;
        // SAFETY: `found` is a valid 2-element stack array and `count` is a
        // valid stack local; we explicitly request up to 2 matches.
        let rv_find = unsafe {
            (self.fn_list.c_find_objects)(self.session, found.as_mut_ptr(), 2, &mut count)
        };

        // SAFETY: `Init` succeeded, so the session is in a find-objects
        // operation that must be terminated by `Final`. Best-effort:
        // ignore the close return code (we only care about the inner
        // `rv_find` to decide what to surface).
        let rv_final = unsafe { (self.fn_list.c_find_objects_final)(self.session) };

        // Surface the inner failure first. If `Init` and `Find`
        // succeeded but `Final` failed, surface that.
        if let Err(e) = check_rv(rv_find) {
            volatile_wipe(&mut label_local);
            return Err(e);
        }
        if let Err(e) = check_rv(rv_final) {
            volatile_wipe(&mut label_local);
            return Err(e);
        }

        // audit-LOW: scrub the label copy on the success path too.
        volatile_wipe(&mut label_local);
        if count == 0 {
            Ok(None)
        } else if count > 1 {
            // Label collision: refuse to guess. The caller must rename or
            // delete one of the colliding objects (or pass a tighter
            // class) before this lookup can succeed.
            Err(VsError::CryptoError)
        } else {
            Ok(Some(found[0]))
        }
    }

    /// Forget the local PKCS#11 handle for `key_id` **without** contacting
    /// the token.
    ///
    /// This is the canonical "local-forget" method — it clears the
    /// `key_id` slot in the provider's in-memory handle map and resets the
    /// per-slot nonce-cache state, then returns. It does **NOT** invoke
    /// `C_DestroyObject`; the underlying key material remains on the HSM
    /// and any caller that re-binds the same `CKA_ID` / `CKA_LABEL` via
    /// [`register_key_handle`](Self::register_key_handle) can resume using
    /// the same token-side key.
    ///
    /// Callers that genuinely need the key destroyed on the token must use
    /// the HSM's administration tooling (e.g., `pkcs11-tool
    /// --delete-object`, the vendor's KMS UI) so the destruction goes
    /// through the HSM's dual-control / audit ceremony. The
    /// `policy-allow-token-destroy` feature additionally enables an
    /// in-band destruction path via the `CryptoProvider::delete_key` trait
    /// method — see the crate-level docs and audit-M4.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `key_id.0 >= MAX_KEY_SLOTS`.
    /// Cannot fail for any token-side reason because the token is never
    /// contacted.
    pub fn forget_local_handle(&mut self, key_id: KeyId) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        self.key_map[idx] = CK_INVALID_HANDLE;
        // Audit fix CRIT-2 + audit-M4: clear the in-memory nonce counter
        // and the per-slot last-nonce cache so a subsequent
        // `register_key_handle` for a different handle cannot inherit
        // stale GCM nonce-repeat-detection state from the previous
        // cryptographic identity. The persistence layer (if any) retains
        // the durable counter — that is the source of truth on the next
        // encrypt — so this is a cache-clear only.
        let bit = 1u64 << idx;
        self.nonce_counter[idx].set(0);
        self.nonce_counter_loaded
            .set(self.nonce_counter_loaded.get() & !bit);
        self.last_nonce[idx].set([0u8; 12]);
        self.last_nonce_set.set(self.last_nonce_set.get() & !bit);
        Ok(())
    }

    /// Look up the PKCS#11 handle for `key_id`.
    #[inline]
    fn handle_for(&self, key_id: KeyId) -> Result<CkObjectHandle, VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        let h = self.key_map[idx];
        if h == CK_INVALID_HANDLE {
            Err(VsError::InvalidInput)
        } else {
            Ok(h)
        }
    }
}

impl Drop for Pkcs11CryptoProvider {
    fn drop(&mut self) {
        // Best-effort: ignore errors during teardown.
        // SAFETY: session handle was obtained from C_OpenSession and has not
        // been closed yet; C_Logout clears token-side auth state before the
        // session is closed.
        unsafe { (self.fn_list.c_logout)(self.session) };
        // SAFETY: session handle was obtained from C_OpenSession and has not
        // been closed yet (we close it only here).
        unsafe { (self.fn_list.c_close_session)(self.session) };
        if self.fn_list.library_pre_initialized == 0 {
            // SAFETY: we called C_Initialize in new(); it is safe to finalize.
            unsafe { (self.fn_list.c_finalize)(core::ptr::null_mut()) };
        }
    }
}

/// Fallible clone — opens a new PKCS#11 session on the same token and
/// re-authenticates using the provided PIN.
///
/// Unlike `Clone::clone`, this method propagates errors instead of
/// silently sharing the session handle (which would cause double-close
/// in `Drop`).
///
/// # Parameters
///
/// - `pin`: User PIN for re-authentication on the new session. The caller
///   should zeroize the PIN buffer after this call returns.
///
/// # Errors
///
/// Returns [`VsError::NotInitialized`] if `C_OpenSession` or `C_Login` fails.
///
/// # Key-handle inheritance (audit-M6)
///
/// Cloned providers start with **no registered key handles**. Callers
/// must call [`register_key_handle`](Pkcs11CryptoProvider::register_key_handle)
/// on the clone for any `KeyId` they intend to use. See
/// [`try_clone_with_pin_buffer`](Pkcs11CryptoProvider::try_clone_with_pin_buffer)
/// for the rationale.
impl Pkcs11CryptoProvider {
    pub fn try_clone(&self, pin: &[u8]) -> Result<Self, VsError> {
        let mut pin_buf = PinBuffer::new(pin)?;
        let result = self.try_clone_with_pin_buffer(&pin_buf);
        pin_buf.wipe();
        result
    }

    /// Clone variant that takes an already-owned [`PinBuffer`].
    ///
    /// # Security
    ///
    /// Refuses to clone once any AES-GCM encrypt has occurred on this
    /// provider. The per-`KeyId` `last_nonce` cache is intentionally
    /// non-shareable: a cloned provider with an empty cache could re-issue
    /// a nonce that the parent already used with the same key, silently
    /// breaking GCM's nonce-misuse defence-in-depth. Open the clone
    /// **before** performing any encryptions, or use a fresh provider
    /// instance instead.
    ///
    /// # Key-handle inheritance (audit-M6)
    ///
    /// Cloned providers start with **no registered key handles**. Callers
    /// must call [`register_key_handle`](Self::register_key_handle) on the
    /// clone for any `KeyId` they intend to use. This prevents
    /// (a) two providers writing to the same persistence row under
    /// different in-memory `nonce_device_prefix` values, which would
    /// silently fail monotonicity checks, and (b) two providers issuing
    /// different cryptographic operations under the same `KeyId` against
    /// an HSM that does not coordinate them. Forcing the caller to
    /// re-register each handle makes the inheritance explicit and prevents
    /// silent aliasing between parent and clone. See audit-M6.
    pub fn try_clone_with_pin_buffer(&self, pin: &PinBuffer) -> Result<Self, VsError> {
        if self.has_encrypted.get() {
            return Err(VsError::PolicyViolation);
        }
        let mut session: CkSessionHandle = 0;
        // SAFETY: same safety argument as in new().
        let rv = unsafe {
            (self.fn_list.c_open_session)(
                self.fn_list.slot_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                core::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        check_rv(rv)?;

        let pin_slice = pin.as_slice();
        let pin_len_u = to_ck_ulong(pin_slice.len())?;
        // Re-authenticate on the new session.
        // SAFETY: `pin_slice` is valid for the duration of this call.
        let rv =
            unsafe { (self.fn_list.c_login)(session, CKU_USER, pin_slice.as_ptr(), pin_len_u) };
        if rv != types::CKR_OK {
            // audit-LOW: mirror the `new_with_pin_buffer` cleanup discipline.
            // A failed `C_Login` may still leave the token in a partial-auth
            // state (e.g. some tokens count a `CKR_PIN_INCORRECT` as an
            // attempted login that needs to be cleared); issue `C_Logout`
            // before `C_Close_Session` so the token-side auth state is
            // explicitly torn down on every error exit. Both calls are
            // best-effort: we already have an error to surface and ignore
            // their return codes.
            // SAFETY: session was obtained from a successful C_OpenSession;
            // C_Logout / C_Close_Session accept any live session handle.
            unsafe { (self.fn_list.c_logout)(session) };
            // SAFETY: session was obtained from a successful C_OpenSession.
            unsafe { (self.fn_list.c_close_session)(session) };
            check_rv(rv)?;
        }

        // Derive a fresh device prefix for the clone — distinct from the
        // parent so that even if the persistence layer is somehow shared
        // the derived nonces are disjoint between provider instances.
        let mut nonce_device_prefix = [0u8; NONCE_DEVICE_PREFIX_LEN];
        // SAFETY: `nonce_device_prefix` is a valid 6-byte stack buffer.
        let rv = unsafe {
            (self.fn_list.c_generate_random)(
                session,
                nonce_device_prefix.as_mut_ptr(),
                NONCE_DEVICE_PREFIX_LEN as CkUlong,
            )
        };
        if let Err(e) = check_rv(rv) {
            // SAFETY: session is still live; close before bailing.
            unsafe { (self.fn_list.c_logout)(session) };
            unsafe { (self.fn_list.c_close_session)(session) };
            return Err(e);
        }

        // Audit fix HIGH-L: prevent double-`C_Finalize` on cloned providers.
        // The parent's `Drop` will run `C_Finalize` if its
        // `library_pre_initialized == 0`. The clone copies `fn_list`
        // verbatim, so without intervention BOTH parent and clone would
        // call `C_Finalize` — undefined behaviour per PKCS#11
        // v2.40 §5.4 (`C_Finalize` may be called at most once per process).
        //
        // Mark the clone's view of the library as pre-initialised so only
        // the parent (the actual caller of `C_Initialize`) ever calls
        // `C_Finalize`. The clone still uses the same function pointer
        // table; only its drop behaviour changes.
        let mut clone_fn_list = self.fn_list;
        clone_fn_list.library_pre_initialized = 1;

        Ok(Self {
            fn_list: clone_fn_list,
            session,
            // audit-M6: do NOT inherit the parent's key_map. A clone that
            // silently shared the `KeyId → CK_OBJECT_HANDLE` mapping could
            // (a) collide with the parent on a persistence backend keyed
            // solely by `KeyId` (each provider has its own
            // `nonce_device_prefix`, so the second `persist` would be
            // rejected by the monotonicity check — silent operational
            // hazard), and (b) issue divergent cryptographic operations
            // under the same logical `KeyId` against an HSM that does not
            // coordinate them. Forcing the caller to re-register handles
            // on the clone makes inheritance explicit. See rustdoc above.
            key_map: [CK_INVALID_HANDLE; MAX_KEY_SLOTS],
            // Safe to start with an empty cache: try_clone refuses if any
            // encrypt has occurred (see the doc comment above).
            last_nonce: [const { core::cell::Cell::new([0u8; 12]) }; MAX_KEY_SLOTS],
            last_nonce_set: core::cell::Cell::new(0),
            has_encrypted: core::cell::Cell::new(false),
            nonce_device_prefix,
            nonce_counter: [const { core::cell::Cell::new(0u64) }; MAX_KEY_SLOTS],
            nonce_counter_loaded: core::cell::Cell::new(0),
            _not_send_sync: core::marker::PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider implementation
// ---------------------------------------------------------------------------

impl CryptoProvider for Pkcs11CryptoProvider {
    /// AES-256-GCM authenticated encryption with **caller-supplied nonce**.
    ///
    /// PKCS#11 appends the tag to the ciphertext output. This method passes a
    /// combined scratch buffer to `C_Encrypt` and then splits it.
    ///
    /// # Deprecated (audit fix CRIT-2)
    ///
    /// The in-memory `last_nonce` cache only catches the "same nonce twice in
    /// a row" bug, and is reset to all-zero on
    /// [`Pkcs11CryptoProvider::new`] — a process restart silently re-enables
    /// AES-GCM nonce reuse against any token-persisted key. Prefer
    /// [`Pkcs11CryptoProvider::aes_gcm_encrypt_with_persistence`], which
    /// derives nonces from a durably-persisted monotonic counter that
    /// survives reboots.
    // `#[deprecated]` on a trait *impl* method emits clippy's
    // `useless_deprecated` (the attribute can only meaningfully sit on the
    // trait declaration itself, which is owned by the upstream `vs-crypto`
    // crate). We intentionally place a deprecation note here as a
    // documentation/IDE hint to migrate to `aes_gcm_encrypt_with_persistence`,
    // so silence the lint locally.
    #[allow(useless_deprecated)]
    #[deprecated(
        note = "use aes_gcm_encrypt_with_persistence(...) instead — the caller-supplied-nonce path \
                cannot survive process restarts safely (audit fix CRIT-2)"
    )]
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; GCM_TAG_LEN],
    ) -> Result<(), VsError> {
        // PERF/STACK (audit fix HIGH-Q): `combined` is `MAX_PT + GCM_TAG_LEN`
        // = 2032 + 16 = 2048 B, exactly at the CLAUDE.md per-call ceiling.
        // The previous `MAX_PT = 2048` overran the cap by 16 B because the
        // PKCS#11 `C_Encrypt` API writes `ciphertext || tag` into one
        // buffer; reducing `MAX_PT` to `2048 - GCM_TAG_LEN` re-establishes
        // the invariant exactly. AAD is borrowed from the caller's slice
        // (not copied) so its `MAX_AAD = 2048` cap (audit fix HIGH-P) does
        // not contribute to the stack frame.
        if plaintext.len() != ciphertext_out.len() {
            return Err(VsError::InvalidInput);
        }
        let h_key = self.handle_for(key_id)?;

        // Audit fix HIGH (defence-in-depth nonce repeat check).
        // GCM is catastrophically broken on nonce reuse with the same key.
        // We track the last nonce seen per `KeyId` and reject a verbatim
        // repeat. This does NOT replace caller discipline (it only catches
        // the degenerate "same nonce twice in a row" bug, not earlier
        // repeats), but it converts what was a silent crypto break into
        // a loud `VsError::CryptoError`.
        let slot = key_id.0 as usize;
        let bit = 1u64 << slot;
        if (self.last_nonce_set.get() & bit) != 0 {
            let prev = self.last_nonce[slot].get();
            // Constant-time equality to avoid leaking nonce bytes via a
            // data-dependent compare timing oracle.
            if bool::from(prev.ct_eq(nonce)) {
                return Err(VsError::CryptoError);
            }
        }

        if plaintext.len() > MAX_PT {
            return Err(VsError::InvalidInput);
        }
        // PERF P1: the previous implementation zero-initialised the full
        // 2064-byte `combined` array on every encrypt call (a ~2 KiB
        // `memset` on the hot path). PKCS#11 `C_Encrypt` overwrites the
        // bytes it writes, so the pre-zero is wasted work. Use
        // `MaybeUninit` storage and only treat the FFI-written prefix as
        // initialised. The unwritten tail is never read.
        let mut combined: [core::mem::MaybeUninit<u8>; MAX_PT + GCM_TAG_LEN] =
            [core::mem::MaybeUninit::uninit(); MAX_PT + GCM_TAG_LEN];
        let combined_len = plaintext.len() + GCM_TAG_LEN;
        let combined_ptr = combined.as_mut_ptr() as *mut u8;

        if aad.len() > MAX_AAD {
            return Err(VsError::InvalidInput);
        }
        // PKCS#11 v2.40 defines `CK_GCM_PARAMS.p_iv` / `.p_aad` as
        // `CK_BYTE_PTR` (i.e. `*mut`), but the AES-GCM spec contract is
        // strictly read-only for both: the token consumes IV and AAD when
        // generating the tag, never modifies them in place. We therefore
        // hand the const slice pointers directly to the token cast to
        // `*mut`, saving up to 2 KiB of AAD memcpy per call. Note that we
        // can NOT skip the nonce-cache `*nonce` read above — that copy is
        // for our own bookkeeping, not for the token.
        //
        // SAFETY: passing the caller's `nonce` / `aad` slice pointers
        // through a `*mut u8` cast does not violate aliasing as long as
        // the token treats them as read-only (PKCS#11 v2.40 §2.15.3 / RFC
        // 5116 §5.1). Both pointers remain valid for the duration of the
        // `C_Encrypt` call: `nonce` is borrowed `&[u8; 12]` and `aad` is
        // borrowed `&[u8]`, both of which the Rust borrow checker keeps
        // live across the FFI calls below.
        let nonce_ptr = nonce.as_ptr() as *mut u8;
        let aad_ptr = if aad.is_empty() {
            core::ptr::null_mut()
        } else {
            aad.as_ptr() as *mut u8
        };

        let mut gcm_params = CkAesGcmParams {
            p_iv: nonce_ptr,
            ul_iv_len: 12,
            ul_iv_bits: 96,
            p_aad: aad_ptr,
            ul_aad_len: to_ck_ulong(aad.len())?,
            ul_tag_bits: GCM_TAG_BITS,
        };
        let mut mechanism = CkMechanism {
            mechanism: CKM_AES_GCM,
            p_parameter: &mut gcm_params as *mut CkAesGcmParams as *mut core::ffi::c_void,
            ul_parameter_len: core::mem::size_of::<CkAesGcmParams>() as CkUlong,
        };

        // SAFETY: session and h_key were obtained from successful PKCS#11
        // calls. mechanism and its parameters point to valid stack data.
        let rv = unsafe { (self.fn_list.c_encrypt_init)(self.session, &mechanism, h_key) };
        check_rv(rv)?;

        let mut out_len = to_ck_ulong(combined_len)?;
        let pt_len_u = to_ck_ulong(plaintext.len())?;
        // SAFETY: plaintext slice is valid for `plaintext.len()` bytes;
        // `combined_ptr` is valid for `MAX_PT + GCM_TAG_LEN` bytes (the
        // full `MaybeUninit` array), which is ≥ `combined_len`. PKCS#11
        // `C_Encrypt` writes exactly `out_len` bytes on success.
        let rv = unsafe {
            (self.fn_list.c_encrypt)(
                self.session,
                plaintext.as_ptr(),
                pt_len_u,
                combined_ptr,
                &mut out_len,
            )
        };
        check_rv(rv)?;

        // Validate out_len before any arithmetic: a misbehaving token could
        // report a size larger than the buffer we provided. Reject that rather
        // than underflowing (total - GCM_TAG_LEN) or reading past the buffer.
        let total = out_len as usize;
        if total > combined_len || total < GCM_TAG_LEN || total - GCM_TAG_LEN != plaintext.len() {
            return Err(VsError::CryptoError);
        }
        // SAFETY (PERF P1): `C_Encrypt` returned CKR_OK and reported it
        // wrote `total` bytes. We bounds-checked `total ≤ combined_len ≤
        // MAX_PT + GCM_TAG_LEN`, so the first `total` bytes of the
        // `MaybeUninit` storage are initialised. View only that prefix as
        // a `&mut [u8]`; the uninitialised tail is never read.
        let combined_init: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(combined_ptr, total) };
        let ct_len = total - GCM_TAG_LEN;
        ciphertext_out.copy_from_slice(&combined_init[..ct_len]);
        tag_out.copy_from_slice(&combined_init[ct_len..ct_len + GCM_TAG_LEN]);
        // PERF + SAFETY (P2): scope the wipe to the bytes `C_Encrypt`
        // actually wrote (`ct_len + GCM_TAG_LEN == total`). After P1 the
        // tail of the `MaybeUninit` array is still uninitialised and
        // therefore cannot hold residual key material — wiping it would
        // be wasted work (and reading it as `&mut [u8]` would be UB).
        // Using the `volatile_wipe` helper keeps the compiler from
        // dead-store-eliminating the zeroing.
        volatile_wipe(&mut combined_init[..total]);
        // Drop mechanism borrow before returning (gcm_params goes out of scope).
        let _ = &mut mechanism;

        // Audit fix HIGH (defence-in-depth nonce tracking):
        // Record the nonce only on a fully successful encrypt so that an
        // error path does not pollute the cache. We mark the slot bit
        // before storing the nonce; readers always read the bit then the
        // nonce, so the order is consistent.
        self.last_nonce[slot].set(*nonce);
        self.last_nonce_set.set(self.last_nonce_set.get() | bit);
        self.has_encrypted.set(true);

        Ok(())
    }

    /// AES-256-GCM authenticated decryption.
    fn aes_gcm_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; GCM_TAG_LEN],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        // PERF/STACK (audit fix HIGH-Q): see `aes_gcm_encrypt`.
        // `MAX_CT = MAX_PT = 2032`, so `combined` (ciphertext || tag) is
        // exactly the 2048 B per-call ceiling. `MAX_AAD = 2048` (audit
        // fix HIGH-P) caps the borrowed AAD slice; it is not copied
        // into a local buffer, so it does not affect the stack frame.
        const MAX_CT: usize = MAX_PT;
        if ciphertext.len() != plaintext_out.len() {
            return Err(VsError::InvalidInput);
        }
        let h_key = self.handle_for(key_id)?;

        if ciphertext.len() > MAX_CT {
            return Err(VsError::InvalidInput);
        }

        // Build `ciphertext || tag` in a combined buffer. Use checked
        // arithmetic so that an adversarial ciphertext length close to
        // `usize::MAX` cannot wrap the `+ GCM_TAG_LEN` addition.
        //
        // PERF P1: skip the 2 KiB zero-init by using `MaybeUninit` storage
        // and initialising only the `total_in`-byte prefix we actually
        // populate from `ciphertext || tag`. The unwritten tail is never
        // read by `C_Decrypt` (we pass `total_in` as the input length) or
        // by us.
        let mut combined: [core::mem::MaybeUninit<u8>; MAX_CT + GCM_TAG_LEN] =
            [core::mem::MaybeUninit::uninit(); MAX_CT + GCM_TAG_LEN];
        let total_in = ciphertext
            .len()
            .checked_add(GCM_TAG_LEN)
            .ok_or(VsError::InvalidInput)?;
        if total_in > combined.len() {
            return Err(VsError::InvalidInput);
        }
        let combined_ptr = combined.as_mut_ptr() as *mut u8;
        // SAFETY (PERF P1): `combined_ptr` is valid for `MAX_CT +
        // GCM_TAG_LEN` bytes and we just bounds-checked `total_in ≤
        // combined.len()`. We write the full `total_in`-byte prefix on
        // the next two lines, so the slice is fully initialised before
        // any reader sees it.
        let combined_init: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(combined_ptr, total_in) };
        combined_init[..ciphertext.len()].copy_from_slice(ciphertext);
        combined_init[ciphertext.len()..total_in].copy_from_slice(tag);

        if aad.len() > MAX_AAD {
            return Err(VsError::InvalidInput);
        }
        // SAFETY: identical contract to `aes_gcm_encrypt` — PKCS#11
        // v2.40 §2.15.3 declares the IV / AAD as inputs (read-only) to
        // `CKM_AES_GCM`, so casting the caller's `&` slice pointers to
        // `*mut` is sound. Both pointers are valid for the FFI call
        // because the borrow checker keeps `nonce` and `aad` live.
        let nonce_ptr = nonce.as_ptr() as *mut u8;
        let aad_ptr = if aad.is_empty() {
            core::ptr::null_mut()
        } else {
            aad.as_ptr() as *mut u8
        };

        let mut gcm_params = CkAesGcmParams {
            p_iv: nonce_ptr,
            ul_iv_len: 12,
            ul_iv_bits: 96,
            p_aad: aad_ptr,
            ul_aad_len: to_ck_ulong(aad.len())?,
            ul_tag_bits: GCM_TAG_BITS,
        };
        let mut mechanism = CkMechanism {
            mechanism: CKM_AES_GCM,
            p_parameter: &mut gcm_params as *mut CkAesGcmParams as *mut core::ffi::c_void,
            ul_parameter_len: core::mem::size_of::<CkAesGcmParams>() as CkUlong,
        };

        // SAFETY: same as encrypt_init above.
        let rv = unsafe { (self.fn_list.c_decrypt_init)(self.session, &mechanism, h_key) };
        check_rv(rv)?;

        let mut out_len = to_ck_ulong(plaintext_out.len())?;
        let total_in_u = to_ck_ulong(total_in)?;
        // SAFETY: combined_init is a fully-initialised slice of `total_in`
        // bytes; plaintext_out is a valid `&mut [u8]` from the caller.
        let rv = unsafe {
            (self.fn_list.c_decrypt)(
                self.session,
                combined_init.as_ptr(),
                total_in_u,
                plaintext_out.as_mut_ptr(),
                &mut out_len,
            )
        };
        // PERF + SAFETY (P2): wipe only the `total_in`-byte
        // ciphertext||tag prefix we actually wrote. After P1 the
        // `MaybeUninit` tail is untouched and never held key-adjacent
        // data, so scrubbing it would be wasted work (and accessing it
        // as `&mut [u8]` would be UB). The explicit slice expression
        // makes the bound visible at the wipe call site.
        volatile_wipe(&mut combined_init[..total_in]);
        let _ = &mut mechanism;

        // Audit fix HIGH (plaintext_out wipe on decrypt failure): if the
        // token reports any error from `C_Decrypt`, it may already have
        // written partial plaintext into `plaintext_out` before noticing
        // the GCM tag mismatch. A caller that ignores the error code and
        // reads the buffer would observe a plaintext oracle on auth
        // failure. Always wipe the full output buffer on any decrypt
        // error path before propagating.
        if check_rv(rv).is_err() {
            volatile_wipe(plaintext_out);
            return Err(rv_to_err(rv));
        }
        // Defend against a misbehaving token reporting an out_len that does
        // not match the expected plaintext length. Wipe the full output
        // buffer regardless of the reported length — that covers both a
        // short-write (scrub the partial plaintext) and a claim that the
        // token wrote past our buffer (we can only reach what we own;
        // any overflow past the caller-supplied slice is a token-side
        // memory-safety violation and not ours to remediate).
        if (out_len as usize) != plaintext_out.len() {
            volatile_wipe(plaintext_out);
            return Err(VsError::CryptoError);
        }
        Ok(())
    }

    /// SHA-256 hash (no key needed — passes `CK_INVALID_HANDLE` to the digest API).
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; SHA256_LEN]) -> Result<(), VsError> {
        let mechanism = CkMechanism {
            mechanism: CKM_SHA256,
            p_parameter: core::ptr::null_mut(),
            ul_parameter_len: 0,
        };
        // SAFETY: mechanism has no parameter pointer; data is valid.
        let rv = unsafe { (self.fn_list.c_digest_init)(self.session, &mechanism) };
        check_rv(rv)?;

        // Pre-fill the output with a position-varying sentinel pattern so we
        // can detect a misbehaving token that reports CKR_OK but never
        // actually writes the digest (audit fix HIGH-M). A constant sentinel
        // only caught the all-untouched case; a token that writes only the
        // first few bytes would leave the tail equal to the sentinel and
        // sneak past `all(== SENTINEL)`. With `SENTINEL ^ i`, every byte has
        // a position-unique pre-fill so the check catches partial writes too.
        #[allow(clippy::items_after_statements)]
        const SENTINEL: u8 = 0xA5;
        for (i, b) in hash_out.iter_mut().enumerate() {
            *b = SENTINEL ^ (i as u8);
        }
        let mut digest_len = SHA256_LEN as CkUlong;
        let data_len_u = to_ck_ulong(data.len())?;
        // SAFETY: data and hash_out are valid for this call.
        let rv = unsafe {
            (self.fn_list.c_digest)(
                self.session,
                data.as_ptr(),
                data_len_u,
                hash_out.as_mut_ptr(),
                &mut digest_len,
            )
        };
        check_rv(rv)?;
        if digest_len as usize != SHA256_LEN
            || hash_out
                .iter()
                .enumerate()
                .any(|(i, &b)| b == SENTINEL ^ (i as u8))
        {
            volatile_wipe(hash_out);
            return Err(VsError::CryptoError);
        }
        Ok(())
    }

    /// HMAC-SHA-256 message authentication.
    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; SHA256_LEN],
    ) -> Result<(), VsError> {
        let h_key = self.handle_for(key_id)?;
        let mechanism = CkMechanism {
            mechanism: CKM_SHA256_HMAC,
            p_parameter: core::ptr::null_mut(),
            ul_parameter_len: 0,
        };
        // SAFETY: mechanism and h_key are valid for this session.
        let rv = unsafe { (self.fn_list.c_sign_init)(self.session, &mechanism, h_key) };
        check_rv(rv)?;

        // Pre-fill with a position-varying sentinel (audit fix HIGH-M);
        // a constant sentinel only catches the all-untouched case, while
        // `SENTINEL ^ i` makes every byte's pre-fill position-unique so a
        // token that writes only a prefix of the MAC is also caught.
        #[allow(clippy::items_after_statements)]
        const SENTINEL: u8 = 0x5A;
        for (i, b) in mac_out.iter_mut().enumerate() {
            *b = SENTINEL ^ (i as u8);
        }
        let mut mac_len = SHA256_LEN as CkUlong;
        let data_len_u = to_ck_ulong(data.len())?;
        // SAFETY: data and mac_out are valid for this call.
        let rv = unsafe {
            (self.fn_list.c_sign)(
                self.session,
                data.as_ptr(),
                data_len_u,
                mac_out.as_mut_ptr(),
                &mut mac_len,
            )
        };
        check_rv(rv)?;
        if mac_len as usize != SHA256_LEN
            || mac_out
                .iter()
                .enumerate()
                .any(|(i, &b)| b == SENTINEL ^ (i as u8))
        {
            // Zeroize potentially partial MAC to prevent forgeries succeeding
            // against a weakened output length.
            volatile_wipe(mac_out);
            return Err(VsError::CryptoError);
        }
        Ok(())
    }

    /// ECDH P-256 shared-secret derivation.
    ///
    /// Uses `CKM_ECDH1_DERIVE` with KDF=null; the x-coordinate of the
    /// resulting shared EC point is extracted via `CKA_VALUE` on a transient
    /// AES key object.
    fn ecdh_derive_shared(
        &self,
        private_key_id: KeyId,
        peer_public: &[u8; EC_POINT_LEN],
        shared_out: &mut [u8; ECDH_SHARED_LEN],
    ) -> Result<(), VsError> {
        // Audit fix: full on-curve validation BEFORE any FFI call.
        // Defends against invalid-curve attacks on tokens (notably older
        // SoftHSM builds) that don't strictly validate points themselves.
        if let Err(e) = validate_p256_point_on_curve(peer_public) {
            shared_out.fill(0);
            return Err(e);
        }

        let h_base = self.handle_for(private_key_id)?;

        // Local mutable copy — see `aes_gcm_encrypt` for const-to-mut rationale.
        let mut peer_public_local = *peer_public;

        let mut params = CkEcdh1DeriveParams {
            kdf: 0, // CKD_NULL — no KDF, raw x-coordinate
            ul_shared_data_len: 0,
            p_shared_data: core::ptr::null_mut(),
            ul_public_data_len: to_ck_ulong(peer_public_local.len())?,
            p_public_data: peer_public_local.as_mut_ptr(),
        };
        let mut mechanism = CkMechanism {
            mechanism: CKM_ECDH1_DERIVE,
            p_parameter: &mut params as *mut CkEcdh1DeriveParams as *mut core::ffi::c_void,
            ul_parameter_len: core::mem::size_of::<CkEcdh1DeriveParams>() as CkUlong,
        };

        // Template for the derived transient key: 32-byte AES key, not on token.
        let mut key_len_val: CkUlong = ECDH_SHARED_LEN as CkUlong;
        let mut class_val: CkUlong = CKO_SECRET_KEY;
        let template: [CkAttribute; ECDH_DERIVED_KEY_ATTRS] = [
            CkAttribute {
                attribute_type: CKA_CLASS,
                p_value: &mut class_val as *mut CkUlong as *mut core::ffi::c_void,
                ul_value_len: core::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attribute_type: CKA_VALUE_LEN,
                p_value: &mut key_len_val as *mut CkUlong as *mut core::ffi::c_void,
                ul_value_len: core::mem::size_of::<CkUlong>() as CkUlong,
            },
        ];
        let mut h_derived: CkObjectHandle = CK_INVALID_HANDLE;
        // SAFETY: mechanism, template, and h_base are all valid. h_derived
        // receives the new transient key handle.
        let rv = unsafe {
            (self.fn_list.c_derive_key)(
                self.session,
                &mechanism,
                h_base,
                template.as_ptr(),
                template.len() as CkUlong,
                &mut h_derived,
            )
        };
        let _ = &mut mechanism;
        check_rv(rv)?;

        // Extract the raw shared secret from the derived key object.
        let mut attr = CkAttribute {
            attribute_type: CKA_VALUE,
            p_value: shared_out.as_mut_ptr() as *mut core::ffi::c_void,
            ul_value_len: ECDH_SHARED_LEN as CkUlong,
        };
        // SAFETY: h_derived is a valid session object; attr points to shared_out.
        let rv =
            unsafe { (self.fn_list.c_get_attribute_value)(self.session, h_derived, &mut attr, 1) };
        // Always destroy the transient key, even if attribute read fails.
        // Guard against a token leaving `h_derived` unset on error paths.
        //
        // Audit fix HIGH-O: capture the destroy return value rather than
        // discarding it. A failed destroy means the transient session-key
        // object still holds the shared-secret bytes on the token (it
        // disappears only when the session ends, which may be much later
        // for a long-lived provider). We escalate any non-CKR_OK destroy
        // to `VsError::CryptoError` so callers see the residue risk and
        // also record it in `LAST_DESTROY_ERROR` for tests / diagnostics.
        let destroy_rv: CkRv = if h_derived == CK_INVALID_HANDLE {
            types::CKR_OK
        } else {
            // SAFETY: h_derived is a valid session object.
            unsafe { (self.fn_list.c_destroy_object)(self.session, h_derived) }
        };
        record_destroy_rv(destroy_rv);
        // Zeroize the peer-public-key copy on the stack. Public keys are not
        // strictly secret, but leaving them on the stack would widen the
        // residual-data surface visible to later callers' own stack frames.
        volatile_wipe(&mut peer_public_local);
        check_rv(rv)?;
        // PKCS#11 tokens report the actual attribute length written. Any
        // value != 32 means the buffer may be partially uninitialised (short)
        // or the token misbehaved (long) — reject both and zero the buffer.
        // CkUlong is `u32` on Windows / `u64` elsewhere; compare in CkUlong
        // space (not `usize`) to keep the test independent of host width.
        if attr.ul_value_len != ECDH_SHARED_LEN as CkUlong {
            volatile_wipe(shared_out);
            return Err(VsError::CryptoError);
        }
        // Audit fix HIGH-O: the derivation itself succeeded and the
        // attribute read returned the expected 32 bytes — but if the
        // transient key could not be destroyed, the shared-secret bytes
        // are still resident on the token. Wipe the shared_out (it's
        // already been observed by us, so the caller may have a copy,
        // but at least scrub our own view) and escalate.
        if destroy_rv != types::CKR_OK {
            volatile_wipe(shared_out);
            return Err(VsError::CryptoError);
        }
        Ok(())
    }

    /// ECDSA P-256 signing (caller pre-hashes; `digest` is 32 bytes).
    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; SHA256_LEN],
        sig_out: &mut [u8; ECDSA_SIG_LEN],
    ) -> Result<(), VsError> {
        let h_key = self.handle_for(key_id)?;
        let mechanism = CkMechanism {
            mechanism: CKM_ECDSA,
            p_parameter: core::ptr::null_mut(),
            ul_parameter_len: 0,
        };
        // SAFETY: mechanism and h_key are valid.
        let rv = unsafe { (self.fn_list.c_sign_init)(self.session, &mechanism, h_key) };
        check_rv(rv)?;

        // Pre-fill with a position-varying sentinel (audit fix HIGH-M).
        // See `sha256` / `hmac_sha256` for rationale: the per-byte
        // `SENTINEL ^ i` pattern catches partial writes the original
        // constant-fill missed.
        #[allow(clippy::items_after_statements)]
        const SENTINEL: u8 = 0x3C;
        for (i, b) in sig_out.iter_mut().enumerate() {
            *b = SENTINEL ^ (i as u8);
        }
        let mut sig_len = ECDSA_SIG_LEN as CkUlong;
        let digest_len_u = to_ck_ulong(digest.len())?;
        // SAFETY: digest (32 bytes) and sig_out (64 bytes) are valid.
        let rv = unsafe {
            (self.fn_list.c_sign)(
                self.session,
                digest.as_ptr(),
                digest_len_u,
                sig_out.as_mut_ptr(),
                &mut sig_len,
            )
        };
        check_rv(rv)?;
        if sig_len as usize != ECDSA_SIG_LEN
            || sig_out
                .iter()
                .enumerate()
                .any(|(i, &b)| b == SENTINEL ^ (i as u8))
        {
            volatile_wipe(sig_out);
            return Err(VsError::CryptoError);
        }
        Ok(())
    }

    /// ECDSA P-256 verification using a raw uncompressed public key.
    ///
    /// The public key is imported as a transient session object, used to
    /// verify, then destroyed.
    ///
    /// # Public Key Validation
    ///
    /// This method validates the uncompressed point format (`0x04` prefix)
    /// and rejects the point at infinity. Full on-curve validation is
    /// additionally delegated to the PKCS#11 token via `C_CreateObject`,
    /// which MUST reject invalid points per PKCS#11 v2.40 Section 6.9.1.
    fn verify_p256(
        &self,
        pub_key: &[u8; EC_POINT_LEN],
        digest: &[u8; SHA256_LEN],
        sig: &[u8; ECDSA_SIG_LEN],
    ) -> Result<bool, VsError> {
        // Audit fix: full on-curve validation BEFORE the token sees the
        // point. Catches invalid-curve attacks against tokens (notably
        // SoftHSM) that don't strictly validate themselves.
        validate_p256_point_on_curve(pub_key)?;

        // Import the raw public key as a transient EC public key object.
        // We need a DER-encoded EC point for CKA_EC_POINT, but many tokens
        // also accept the raw uncompressed key wrapped in an OCTET STRING.
        // Build: 0x04 (OCTET STRING) || 0x41 (65 bytes) || raw_key.
        #[allow(clippy::items_after_statements)]
        const EC_POINT_DER_LEN: usize = 2 + EC_POINT_LEN; // tag + len + key
        let mut ec_point_der = [0u8; EC_POINT_DER_LEN];
        ec_point_der[0] = 0x04; // DER OCTET STRING tag
        ec_point_der[1] = EC_POINT_LEN as u8;
        ec_point_der[2..].copy_from_slice(pub_key);

        /// Named curve OID for P-256 (1.2.840.10045.3.1.7).
        /// DER encoding: `06 08 2a 86 48 ce 3d 03 01 07`.
        #[allow(clippy::items_after_statements)]
        const P256_OID_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut ec_params_der = P256_OID_DER;
        let mut class_val: CkUlong = CKO_PUBLIC_KEY;
        let mut token_val: u8 = CK_FALSE;
        let mut verify_val: u8 = CK_TRUE;

        let template = [
            CkAttribute {
                attribute_type: CKA_CLASS,
                p_value: &mut class_val as *mut CkUlong as *mut core::ffi::c_void,
                ul_value_len: core::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attribute_type: CKA_TOKEN,
                p_value: &mut token_val as *mut u8 as *mut core::ffi::c_void,
                ul_value_len: 1,
            },
            CkAttribute {
                attribute_type: CKA_VERIFY,
                p_value: &mut verify_val as *mut u8 as *mut core::ffi::c_void,
                ul_value_len: 1,
            },
            CkAttribute {
                attribute_type: CKA_EC_PARAMS,
                p_value: ec_params_der.as_mut_ptr() as *mut core::ffi::c_void,
                ul_value_len: ec_params_der.len() as CkUlong,
            },
            CkAttribute {
                attribute_type: CKA_EC_POINT,
                p_value: ec_point_der.as_mut_ptr() as *mut core::ffi::c_void,
                ul_value_len: EC_POINT_DER_LEN as CkUlong,
            },
        ];

        let mut h_pub: CkObjectHandle = CK_INVALID_HANDLE;
        // SAFETY: template entries point to valid stack variables.
        let rv = unsafe {
            (self.fn_list.c_create_object)(
                self.session,
                template.as_ptr(),
                template.len() as CkUlong,
                &mut h_pub,
            )
        };
        check_rv(rv)?;

        let mechanism = CkMechanism {
            mechanism: CKM_ECDSA,
            p_parameter: core::ptr::null_mut(),
            ul_parameter_len: 0,
        };
        // SAFETY: h_pub is a valid session object.
        let rv_init = unsafe { (self.fn_list.c_verify_init)(self.session, &mechanism, h_pub) };
        let result = if rv_init == 0 {
            // digest and sig are fixed-size arrays (32 and 64 bytes), so
            // the constants below cannot wrap `CkUlong`.
            //
            // Constant-time note: the ECDSA signature comparison happens
            // *inside* the HSM token. The result returned over the PKCS#11
            // API is a single rv code — `CKR_OK` vs `CKR_SIGNATURE_INVALID`
            // — which carries no timing information about where the
            // mismatch occurred. Any future "fast path" that compares the
            // signature bytes locally MUST use `subtle::ConstantTimeEq`.
            //
            // SAFETY: digest and sig are valid fixed-size arrays.
            let rv_verify = unsafe {
                (self.fn_list.c_verify)(
                    self.session,
                    digest.as_ptr(),
                    SHA256_LEN as CkUlong,
                    sig.as_ptr(),
                    ECDSA_SIG_LEN as CkUlong,
                )
            };
            match rv_verify {
                0 => Ok(true),
                s if s == types::CKR_SIGNATURE_INVALID => Ok(false),
                err => Err(rv_to_err(err)),
            }
        } else {
            Err(rv_to_err(rv_init))
        };

        // Always destroy the transient public key object (guard against a
        // misbehaving token that returned CKR_OK without writing h_pub).
        //
        // Audit fix HIGH-O: capture the destroy return value. The transient
        // EC public-key object holds the caller-supplied public point; a
        // failed destroy means that point lingers on the token (visible to
        // any later session that enumerates session objects on the same
        // slot). Record it and, if the verify itself succeeded, escalate
        // the leftover-object condition to `VsError::CryptoError` so the
        // caller can react.
        let destroy_rv: CkRv = if h_pub == CK_INVALID_HANDLE {
            types::CKR_OK
        } else {
            // SAFETY: h_pub is a valid session object.
            unsafe { (self.fn_list.c_destroy_object)(self.session, h_pub) }
        };
        record_destroy_rv(destroy_rv);
        match (result, destroy_rv) {
            // Verify failed first → propagate the verify error and don't
            // mask it with the destroy condition (the destroy error has
            // already been recorded via `record_destroy_rv`).
            (Err(e), _) => Err(e),
            // Verify succeeded and destroy succeeded.
            (Ok(b), rv) if rv == types::CKR_OK => Ok(b),
            // Verify succeeded but destroy left key material behind →
            // surface a hard error so callers must react.
            (Ok(_), _) => Err(VsError::CryptoError),
        }
    }

    /// Delete a key.
    ///
    /// # SECURITY (audit-M4)
    ///
    /// The `CryptoProvider` trait contract implies that `delete_key`
    /// destroys the underlying key material — software providers in the
    /// same trait family genuinely zeroize / drop the key on return.
    /// Earlier revisions of this PKCS#11 provider silently violated that
    /// contract: `delete_key` only cleared the in-memory `key_id` slot
    /// and left the token-side key intact, so a caller that called
    /// `delete_key` and then later called
    /// [`register_key_handle`](Pkcs11CryptoProvider::register_key_handle)
    /// for the same `CKA_ID` / `CKA_LABEL` could resume using the same
    /// cryptographic identity — defeating any forward-secrecy assumption
    /// the consumer derived from "delete" semantics.
    ///
    /// Rather than silently lie, the default trait impl now returns
    /// [`VsError::PolicyViolation`]. Two paths are available to callers:
    ///
    /// 1. **Local-forget** (the historical behaviour): call
    ///    [`Pkcs11CryptoProvider::forget_local_handle`] directly. This
    ///    clears the in-memory handle map without contacting the token.
    /// 2. **In-band token destruction**: enable the
    ///    `policy-allow-token-destroy` Cargo feature. With the feature
    ///    enabled this method issues `C_DestroyObject` against the
    ///    registered handle, then forgets it locally. The feature is
    ///    OFF by default because in-band destruction bypasses the HSM's
    ///    dual-control / key-lifecycle ceremony for most safety-critical
    ///    deployments; vendor tooling (`pkcs11-tool --delete-object`,
    ///    the KMS UI) is the recommended path.
    ///
    /// # Errors
    ///
    /// - Without the `policy-allow-token-destroy` feature: always
    ///   [`VsError::PolicyViolation`].
    /// - With the feature: [`VsError::InvalidInput`] if `key_id.0 >=
    ///   MAX_KEY_SLOTS` or no handle is registered for the slot; the
    ///   PKCS#11 error class mapped from `C_DestroyObject` on token
    ///   failure.
    #[doc(alias = "forget_local_handle")]
    #[cfg_attr(
        not(feature = "policy-allow-token-destroy"),
        allow(unused_variables)
    )]
    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
        // SECURITY (audit-M4): the default trait impl refuses rather
        // than silently performing a local-only forget that the trait
        // contract reads as full destruction. Callers that want the
        // historical local-forget behaviour must call
        // `forget_local_handle` directly; callers that want true token
        // destruction must opt in via the `policy-allow-token-destroy`
        // feature, which is destructive and irreversible.
        #[cfg(not(feature = "policy-allow-token-destroy"))]
        {
            Err(VsError::PolicyViolation)
        }

        #[cfg(feature = "policy-allow-token-destroy")]
        {
            let idx = key_id.0 as usize;
            if idx >= MAX_KEY_SLOTS {
                return Err(VsError::InvalidInput);
            }
            // Resolve the registered handle; if nothing is registered
            // there is no token-side object to destroy from this
            // provider's view, so refuse rather than silently no-op.
            let handle = self.handle_for(key_id)?;
            // SAFETY: `self.session` is a live PKCS#11 session opened
            // in `new()` and not yet closed (`Drop` is the only
            // closer); `handle` was supplied by the caller via
            // `register_key_handle` and is documented as a valid
            // `CK_OBJECT_HANDLE` on the same token.
            let rv = unsafe { (self.fn_list.c_destroy_object)(self.session, handle) };
            check_rv(rv)?;
            // Token destruction succeeded — clear the local mapping
            // and associated nonce cache.
            self.forget_local_handle(key_id)
        }
    }

    /// Generate a key on the HSM.
    ///
    /// Hardware-backed providers require keys to be provisioned on the token
    /// via HSM administration tools (e.g., `pkcs11-tool --keygen`), then
    /// registered with [`register_key_handle`](Self::register_key_handle).
    /// In-band key generation is disallowed by policy because it would
    /// bypass the HSM's key-lifecycle auditing and ceremony requirements.
    ///
    /// # Errors
    ///
    /// Always returns [`VsError::PolicyViolation`].
    fn generate_key(&mut self, _key_id: KeyId, _key_type: KeyType) -> Result<(), VsError> {
        Err(VsError::PolicyViolation)
    }

    /// Generate random bytes from the token's TRNG.
    ///
    /// When the sentinel check is enabled (see [`RANDOM_SENTINEL_ENABLED`])
    /// this method pre-fills the output buffer with a per-byte variable
    /// pattern and rejects the call (with `VsError::CryptoError`) if the
    /// post-call buffer is either all-zero or still bit-for-bit equal to
    /// the pre-fill — covering both a token that returns `CKR_OK` without
    /// writing and one that no-ops on a non-zero buffer. See audit-M5.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        if buf.is_empty() {
            return Ok(());
        }
        if buf.len() > 2048 {
            // PKCS#11 has no intrinsic limit, but we bound each call to the
            // crate-wide 2 KiB stack budget and expect callers to chunk larger
            // requests explicitly. Refusing early is friendlier than silent
            // truncation by misbehaving tokens.
            return Err(VsError::InvalidInput);
        }
        let len_u = to_ck_ulong(buf.len())?;

        // audit-M5: build a per-byte pre-fill so a TRNG that no-ops on a
        // non-zero buffer is also caught (the previous all-`0xE7` sentinel
        // missed that case). Stash the pattern in a small fixed-size buffer
        // for post-call comparison; `buf` is bounded to 2048 above.
        let mut pre_fill = [0u8; 2048];
        if RANDOM_SENTINEL_ENABLED {
            for (i, slot) in pre_fill.iter_mut().take(buf.len()).enumerate() {
                // Per-byte variability: distinct for every index so an all-
                // zero or constant-pattern overwrite is also detectable.
                *slot = (i as u8).wrapping_mul(0x9E);
            }
            buf.copy_from_slice(&pre_fill[..buf.len()]);
        }

        // SAFETY: buf is a valid mutable slice; length fits `CkUlong`.
        let rv = unsafe { (self.fn_list.c_generate_random)(self.session, buf.as_mut_ptr(), len_u) };
        check_rv(rv)?;

        if RANDOM_SENTINEL_ENABLED {
            // Two defensive checks (audit-M5):
            //   1. All-zero output — catches a token that returns success
            //      but writes nothing into an already-zero buffer, or that
            //      simply memsets to zero internally.
            //   2. Output bit-for-bit equal to the pre-fill — catches a
            //      token that no-ops on a non-zero buffer (the variant the
            //      original `all == SENTINEL` check missed).
            // Both conditions independently indicate a TRNG whose output
            // the caller must not consume; collapse them under a single
            // `WeakRng`-style rejection.
            let all_zero = buf.iter().all(|&b| b == 0);
            let unchanged = buf
                .iter()
                .zip(pre_fill.iter())
                .all(|(out, pre)| out == pre);
            if all_zero || unchanged {
                volatile_wipe(buf);
                volatile_wipe(&mut pre_fill);
                return Err(VsError::CryptoError);
            }
        }
        volatile_wipe(&mut pre_fill);
        Ok(())
    }

    /// Run a self-test: SHA-256 canary + token liveness check.
    ///
    /// Overrides the default trait implementation to additionally verify that
    /// the token is present by calling `C_GetTokenInfo`.
    fn self_test(&self) -> Result<(), VsError> {
        // SHA-256 known-answer test (inherited logic inlined).
        let mut hash = [0u8; SHA256_LEN];
        self.sha256(b"craton-shield-canary", &mut hash)?;
        let mut acc: u8 = 0;
        for &b in &hash {
            acc |= b;
        }
        if acc == 0 {
            return Err(VsError::CryptoError);
        }

        // Token liveness check.
        let mut info = CkTokenInfo {
            label: [0; 32],
            manufacturer_id: [0; 32],
            model: [0; 16],
            serial_number: [0; 16],
            flags: 0,
            ul_max_session_count: 0,
            ul_session_count: 0,
            ul_max_rw_session_count: 0,
            ul_rw_session_count: 0,
            ul_max_pin_len: 0,
            ul_min_pin_len: 0,
            ul_total_public_memory: 0,
            ul_free_public_memory: 0,
            ul_total_private_memory: 0,
            ul_free_private_memory: 0,
            hardware_version: types::CkVersion { major: 0, minor: 0 },
            firmware_version: types::CkVersion { major: 0, minor: 0 },
            utc_time: [0; 16],
        };
        // SAFETY: info is a valid zeroed CkTokenInfo struct on the stack.
        let rv = unsafe { (self.fn_list.c_get_token_info)(self.fn_list.slot_id, &mut info) };
        check_rv(rv)
    }
}

// ---------------------------------------------------------------------------
// Write-ahead persistence path (audit fix CRIT-2)
// ---------------------------------------------------------------------------

impl Pkcs11CryptoProvider {
    /// AES-256-GCM encrypt with **provider-derived nonce** backed by a
    /// caller-supplied write-ahead [`NoncePersistence`] sink.
    ///
    /// This is the preferred encrypt path. Mirrors the
    /// `vsoc_telemetry::TelemetryUplink::flush_with_persistence` write-ahead
    /// pattern: the next counter value is persisted to durable, rollback-
    /// resistant storage **before** any encryption happens. If the device
    /// loses power between `persistence.persist(...)` and the FFI encrypt,
    /// the counter is already burned and the next boot will move past it.
    ///
    /// # Nonce Derivation
    ///
    /// The 12-byte AES-GCM nonce is:
    ///
    /// ```text
    /// nonce = device_prefix[0..6] || counter_le[0..6]
    /// ```
    ///
    /// where `device_prefix` is a per-provider 6-byte value drawn from the
    /// token's TRNG at [`Pkcs11CryptoProvider::new`], and `counter_le` is
    /// the little-endian encoding of the next-counter slot (low 48 bits).
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] if the counter would overflow
    ///   [`MAX_NONCE_COUNTER`] (silent truncation into the 6-byte counter
    ///   slot would otherwise allow nonce reuse).
    /// - Whatever the persistence layer returns on a failed `persist` or
    ///   `load`. On any persist failure the in-memory counter is **not**
    ///   advanced, so the caller may retry safely after resolving the
    ///   underlying storage fault.
    /// - Whatever the token returns from `C_EncryptInit` / `C_Encrypt`.
    ///   If the FFI encrypt fails after a successful `persist`, the
    ///   in-memory counter is still advanced (jump-over invariant) so
    ///   that the next call moves to `counter + 1` and never reuses
    ///   the burned nonce.
    pub fn aes_gcm_encrypt_with_persistence<P: NoncePersistence>(
        &mut self,
        key_id: KeyId,
        persistence: &mut P,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; GCM_TAG_LEN],
    ) -> Result<[u8; 12], VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        // Validate the key handle BEFORE touching persistence so we don't
        // burn a counter value for an unconfigured slot.
        let _ = self.handle_for(key_id)?;

        // Load the current counter from persistence on first use for this
        // slot (or after a `register_key_handle`/`delete_key` that
        // invalidated the cache). Subsequent encrypts read from the cache
        // to keep the hot path off the persistence backend.
        let bit = 1u64 << idx;
        let current_counter = if (self.nonce_counter_loaded.get() & bit) == 0 {
            let loaded = persistence.load(key_id)?;
            self.nonce_counter[idx].set(loaded);
            self.nonce_counter_loaded
                .set(self.nonce_counter_loaded.get() | bit);
            loaded
        } else {
            self.nonce_counter[idx].get()
        };

        // Reject overflow BEFORE persist so we never burn a value that
        // would truncate into the 6-byte nonce slot.
        let next_counter = match current_counter.checked_add(1) {
            Some(v) if v <= MAX_NONCE_COUNTER => v,
            _ => return Err(VsError::ResourceExhausted),
        };

        // --- Write-ahead counter persistence (audit fix CRIT-2) ---
        // Persist the ADVANCED counter BEFORE any encrypt. If persist
        // itself fails we leave the in-memory counter untouched so the
        // caller may retry cleanly with the same value.
        persistence.persist(key_id, next_counter)?;

        // Jump-over invariant: advance the in-memory counter immediately
        // after a successful persist, BEFORE FFI encrypt runs. If
        // C_Encrypt fails the counter is still burned in both stores,
        // so the next call moves to `next_counter + 1` and the
        // already-issued nonce is never re-derived.
        self.nonce_counter[idx].set(next_counter);

        // Derive the 12-byte nonce: device_prefix[0..6] || counter_le[0..6].
        // We only take the low 6 bytes of the LE-encoded u64 because the
        // overflow guard above bounds `next_counter` to `2^48 - 1`.
        let counter_le = next_counter.to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce[..NONCE_DEVICE_PREFIX_LEN].copy_from_slice(&self.nonce_device_prefix);
        nonce[NONCE_DEVICE_PREFIX_LEN..].copy_from_slice(&counter_le[..NONCE_COUNTER_LEN]);

        // Hand off to the existing token-side encrypt path. The legacy
        // last_nonce repeat-detection cache will record this nonce; that
        // is harmless because every call here derives a strictly-fresh
        // nonce (counter is monotonic) so the cache check never trips.
        //
        // `#[allow(deprecated)]` because the legacy method is the
        // current home of the FFI-side logic. Future refactors may
        // extract the FFI core into a shared private helper.
        #[allow(deprecated)]
        <Self as CryptoProvider>::aes_gcm_encrypt(
            self,
            key_id,
            &nonce,
            plaintext,
            aad,
            ciphertext_out,
            tag_out,
        )?;

        Ok(nonce)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// FIX-4: `serial_test` macro expansion references `std`; this crate is
// `#![no_std]`, so we pull `std` in only for the `cfg(test)` build so the
// `#[serial]` attribute can resolve its prelude. Mirrors `crypto-tpm`.
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

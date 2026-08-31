// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_std]
#![allow(unsafe_code)] // Required: all unsafe blocks target the TSS2 ESAPI C ABI.

//! TPM 2.0 TSS2 ESAPI-backed implementation of [`CryptoProvider`].
//!
//! # Overview
//!
//! [`TpmCryptoProvider`] implements the `vs-crypto` [`CryptoProvider`] trait
//! by forwarding every operation to a TPM 2.0 device via caller-supplied TSS2
//! ESAPI function pointers ([`TpmFunctionList`]).
//!
//! Targets: **hardware TPM 2.0**, **swtpm** (development), **fTPM**
//! (firmware TPM on ARM `TrustZone` and Intel TXT).
//!
//! # AEAD on TPM 2.0 (AES-CFB + HMAC-SHA-256, Encrypt-then-MAC)
//!
//! The TPM 2.0 specification does not include a native AES-GCM command.
//! This provider implements the [`CryptoProvider::aes_gcm_encrypt`] /
//! [`CryptoProvider::aes_gcm_decrypt`] interface (also exposed as
//! [`TpmCryptoProvider::aead_encrypt`] / [`TpmCryptoProvider::aead_decrypt`]
//! inherent aliases with accurate names) using the following
//! **AES-CFB + HMAC-SHA-256 (Encrypt-then-MAC)** construction:
//!
//! ```text
//! Encrypt:
//!   CT  ← Esys_EncryptDecrypt2(k_enc, AES-CFB, IV=nonce[0..12]||0x00, PT)
//!   TAG ← Esys_HMAC(k_mac, SHA-256,
//!                   "VS-ETM01" || nonce(12B)
//!                                 || aad_len(LE,8B) || ct_len(LE,8B)
//!                                 || aad             || ct)[0..16]
//!
//! Decrypt:
//!   TAG' ← Esys_HMAC(k_mac, SHA-256, <same framed input as encrypt>)[0..16]
//!   verify TAG == TAG' (constant-time)
//!   PT  ← Esys_EncryptDecrypt2(k_enc, AES-CFB, IV=nonce[0..12]||0x00, CT)
//! ```
//!
//! The fixed-size prefix (`domain(8) || nonce(12) || aad_len(8) || ct_len(8)`)
//! precedes the variable-size payload (`aad || ct`). Length prefixes appear
//! before either value so the framed input is unambiguously parseable and
//! `(aad, ct)` and `(aad', ct')` with `aad || ct == aad' || ct'` cannot
//! collide (no canonicalisation attack).
//!
//! This is IND-CCA2 secure (Encrypt-then-MAC). The `tag_out` field carries
//! the first 16 bytes of the HMAC-SHA-256 over the canonically-framed input
//! above. The nonce is used as the AES-CFB initialisation vector
//! (zero-padded to 16 bytes as required by TPM's `EncryptDecrypt2`).
//!
//! # Key separation (audit CRIT C1)
//!
//! The cipher key and the MAC key MUST be distinct TPM objects. Callers
//! register them separately via
//! [`TpmCryptoProvider::register_key_handle`] (cipher) and
//! [`TpmCryptoProvider::register_mac_key_handle`] (MAC). Using the same
//! TPM key for both AES-CFB and HMAC-SHA-256 violates NIST SP 800-57
//! key-separation guidance and is rejected.
//!
//! # Nonce Management
//!
//! The AES-CFB + HMAC-SHA-256 Encrypt-then-MAC construction used by this
//! provider is vulnerable to plaintext recovery if a nonce (IV) is reused
//! with the same key. This provider accepts caller-supplied nonces and does
//! **not** track or enforce uniqueness. The caller **must** guarantee that
//! every `(key_id, nonce)` pair is used at most once. See
//! [`Pkcs11CryptoProvider`](../vs_crypto_pkcs11) for recommended strategies.
//!
//! # Design
//!
//! The crate is `#![no_std]` with zero heap allocations. The TSS2 ESAPI
//! allocates output buffers internally; this provider copies the data out
//! immediately and frees the allocation via `esys_free`. All intermediate
//! buffers are stack-allocated.
//!
//! # Safety
//!
//! All `unsafe` blocks invoke C function pointers supplied by the caller.
//! Each call site documents the invariants required.

mod error;
pub mod ffi;
mod types;

use error::{check_rc, rc_to_err};
use ffi::TpmFunctionList;
use subtle::{Choice, ConstantTimeEq};
use types::{
    EsysContext, EsysTr, Tpm2AlgId, Tpm2bData, Tpm2bDigest, Tpm2bEccPoint, Tpm2bMaxBuffer,
    Tpm2bNonce, TpmlPcrSelection, TpmsEccPoint, TpmsSignatureEcdsa, TpmtSignature, TpmtSymDef,
    TpmtTkHashcheck, TpmuSignature, ESYS_TR_NONE, ESYS_TR_PASSWORD, ESYS_TR_PCR0, ESYS_TR_RH_NULL,
    TPMA_SESSION_CONTINUE_SESSION, TPM2_ALG_CFB, TPM2_ALG_ECDSA, TPM2_ALG_NULL, TPM2_ALG_SHA256,
    TPM2_SE_HMAC, TPMI_NO, TPMI_YES,
};
use vs_crypto::{CryptoProvider, KeyId, KeyType};
use vs_types::VsError;

/// Maximum number of key slots (matches `vs-key-manager` `MAX_KEYS`).
const MAX_KEY_SLOTS: usize = 64;

/// AES-GCM / AES-CFB authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// SHA-256 output length in bytes.
const SHA256_LEN: usize = 32;

/// ECDSA P-256 raw signature: (r, s), 32 bytes each.
const ECDSA_SIG_LEN: usize = 64;

/// ECDH shared secret length (x-coordinate of the shared EC point).
const ECDH_SHARED_LEN: usize = 32;

/// `EtM` MAC domain separator (8 bytes). Prepended to every MAC input so the
/// MAC key can never see a message that might collide with some other
/// construction using the same key.
const ETM_DOMAIN: &[u8; 8] = b"VS-ETM01";

/// Fixed 32-byte plaintext used by [`TpmCryptoProvider::register_mac_key_handle`]
/// to drive its key-separation canary self-test (audit CRIT-7). The exact
/// bytes are not security-sensitive — only that they are constant across
/// invocations so the canary is reproducible and that they exercise both
/// AES-CFB and HMAC-SHA-256 on each registration.
const KEY_SEPARATION_CANARY: [u8; 32] = *b"vs-tpm-key-separation-canary-v1!";

/// Length of the framed MAC-input fixed-size prefix:
///
/// ```text
///   domain(8) || nonce(12) || aad_len(8) || ct_len(8) = 36 bytes
/// ```
const ETM_PREFIX_LEN: usize = 8 + 12 + 8 + 8;

/// Maximum plaintext / ciphertext size in one TPM `EncryptDecrypt2` call.
const MAX_BUF: usize = 2048;

/// Maximum bytes a single `TPM2_GetRandom` call may return — bounded by
/// the primary hash size per TCG TPM 2.0 Part 3 §16.1. Larger requests
/// loop in `random_bytes`.
const RNG_PER_CALL: usize = 32;

/// P-256 coordinate size in bytes.
const P256_COORD_LEN: usize = 32;

/// Uncompressed P-256 public key: `0x04 || X || Y`.
const EC_POINT_LEN: usize = 65;

// ---------------------------------------------------------------------------
// Cryptographic invariants enforced at compile time
// ---------------------------------------------------------------------------
//
// HMAC-SHA-256 produces 32 bytes; we truncate to `TAG_LEN` (16 bytes) for the
// Encrypt-then-MAC tag. Truncation to ≥128 bits is sound under the standard
// HMAC security argument (NIST SP 800-107 §5.3.4, Bellare 2006): the truncated
// MAC inherits PRF security from the full MAC. 128 bits meets the NIST-recommended
// minimum for interactive protocols and matches the tag size used by AES-GCM,
// preserving the `CryptoProvider` trait's API shape.
//
// If `TAG_LEN` is ever changed below 16 the truncation argument no longer
// applies — keep the static asserts below so the compiler catches it.
// The `>= 16` floor pins NIST SP 800-107 §5.3.4 (≥32 bits for short tags,
// ≥64 bits for general use) plus the 128-bit margin matching AES-GCM.
// Future relaxation below 16 bytes is rejected at compile time so the
// truncation argument can never silently regress past NIST minimums.
const _: () = assert!(TAG_LEN == 16);
const _: () = assert!(TAG_LEN >= 16);
const _: () = assert!(P256_COORD_LEN == 32);
const _: () = assert!(EC_POINT_LEN == 1 + 2 * P256_COORD_LEN);
// TPM2B `size` fields are `u16`. Every `len as u16` cast that populates a
// `Tpm2b*` in this crate is guarded by `len <= MAX_BUF`, so this bound must
// be provably ≤ u16::MAX for the cast to be lossless. If `MAX_BUF` is ever
// raised above 65_535 this assert fires and every size-cast site must grow
// an explicit runtime check.
const _: () = assert!(MAX_BUF <= u16::MAX as usize);
// `chunk_usize as u16` in `random_bytes` is lossless only while
// `RNG_PER_CALL <= u16::MAX`; pin that here.
const _: () = assert!(RNG_PER_CALL <= u16::MAX as usize);

// TPM2 format-1 response codes carry a session/parameter/handle index in
// the high nibble (TCG TPM 2.0 Part 1, Table 27). The raw code
// `TPM2_RC_SIGNATURE = 0x09D` appears as 0x09D (format-0, no index),
// 0x19D (format-1 parameter/session 1), or 0x29D (format-1 session 2).
// All three mean "signature did not verify" and must be mapped to
// `Ok(false)` rather than a provider error so callers can distinguish an
// authentic negative verification from a transport / state failure.
const TPM2_RC_SIGNATURE: types::Tss2Rc = 0x0000_009D;
const TPM2_RC_SIGNATURE_P1: types::Tss2Rc = 0x0000_019D;
const TPM2_RC_SIGNATURE_P2: types::Tss2Rc = 0x0000_029D;

/// Volatile-zero every byte of a stack-resident slice.
///
/// Audit HIGH-J: prevents the compiler from dead-store-eliminating the
/// wipe of transient plaintext / ciphertext / AAD / MAC-input buffers as
/// they go out of scope. The `write_volatile` store is observable at the
/// abstract machine level and cannot be elided. Mirrors the pattern used
/// by `vsoc-telemetry::volatile_wipe` (see `crates/vsoc-telemetry/src/lib.rs`).
///
/// `#[inline]` is required so the volatile stores are emitted at the call
/// site — moving the loop behind a non-inlined function call would let
/// LTO see the buffer as dead and defeat the wipe.
#[inline]
fn volatile_wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid writable reference into a stack-allocated
        // array. `write_volatile` with a u8 is always sound for a unique
        // mutable reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Volatile-zero the full `2048`-byte payload of a `Tpm2bMaxBuffer`.
///
/// Use BEFORE returning from any function that placed plaintext,
/// ciphertext, AAD, or framed MAC-input into the buffer. Also resets the
/// `size` field so a debugger / coredump cannot infer the original payload
/// length from a leftover prefix.
#[inline]
fn zeroize_max_buffer(buf: &mut Tpm2bMaxBuffer) {
    volatile_wipe(&mut buf.buffer);
    buf.size = 0;
}

// ---------------------------------------------------------------------------
// Audit M1 / H1 / M3 (HMAC bus-integrity session) — PARTIALLY RESOLVED
//
// Bus-integrity wiring is exposed through
// [`TpmCryptoProvider::enable_bus_integrity`] /
// [`TpmCryptoProvider::disable_bus_integrity`]. Once a caller calls
// `enable_bus_integrity`, the provider stores a long-lived HMAC session
// `ESYS_TR` in `self.bus_protection_session` and threads it through every
// sensitive command (`EncryptDecrypt2`, `HMAC`, `Sign`, `ECDH_ZGen`,
// `PCR_Extend`) in place of `ESYS_TR_PASSWORD`. The session is flushed
// in `Drop` and may be flushed explicitly via `disable_bus_integrity`.
//
// **Audit H1 (rename — accuracy).** The session is integrity-only: it
// uses `TpmtSymDef { algorithm: TPM2_ALG_NULL, .. }` and does NOT set
// `TPMA_SESSION_ENCRYPT` / `TPMA_SESSION_DECRYPT`. The earlier name
// (`enable_bus_protection`) oversold the wiring; it is now exposed as
// `enable_bus_integrity` with a deprecated alias kept for backwards
// compatibility. A bus tap can still recover plaintext command /
// response parameters.
//
// **Audit H1 (continue-session).** After `Esys_StartAuthSession` we
// call `Esys_TRSess_SetAttributes(... CONTINUE_SESSION ...)` so the
// session survives past one command. Without that bit the TPM closes
// the session after the first use and every subsequent provider call
// silently falls back to the unsalted password session.
//
// **Audit M3 (caller nonce).** `nonce_caller` is no longer null. We
// draw 32 bytes from `random_bytes` (TPM TRNG) into a stack buffer
// before opening the session, pass that as `Tpm2bNonce`, and
// `volatile_wipe` the buffer afterwards. The TPM still generates its
// own response nonce; together they form the session-key seed.
//
// **Graceful fallback.** Callers that do not enable bus integrity
// (typically dev / test) keep the previous password-session behaviour —
// every site routes through the `auth_session()` helper which returns
// `ESYS_TR_PASSWORD` when `bus_protection_session` is `ESYS_TR_NONE`.
// This preserves backwards compatibility for existing operators and for
// the unit-test mocks that do not implement session handling.
//
// **Sibling contexts.** Per audit M5, `new_sibling_context` returns a
// provider with `bus_protection_session = ESYS_TR_NONE` so the caller
// must call `enable_bus_integrity` again on the new context. ESYS_TR
// session handles are scoped to the ESAPI context that produced them.
//
// **Limits — parameter-encryption gap remains.** The current wiring
// opens an *unsalted, unbound* HMAC session (NULL salt key,
// `ESYS_TR_NONE` bind) with `TpmtSymDef.algorithm == TPM2_ALG_NULL`.
// This delivers command / response integrity over the bus but **not**
// confidentiality — operators that want parameter encryption
// (`TPMA_SESSION_ENCRYPT` / `TPMA_SESSION_DECRYPT` per TCG TPM 2.0
// Library §19.6) must additionally attach a salt key. A future
// extension may layer that on; the public API (`enable_bus_integrity`)
// is stable so the extension can land without touching every command
// site again.
// ---------------------------------------------------------------------------

/// Structure tag (`TPM_ST`) for a `TPMT_TK_VERIFIED` ticket — TCG TPM 2.0
/// Part 2 §6.9 (`TPM_ST` Constants). Used by the audit-M4 ticket-validity
/// check inside `verify_p256` so a misbehaving TPM cannot return
/// `TSS2_RC_SUCCESS` paired with a malformed / zero-tag ticket.
const TPM2_ST_VERIFIED: u16 = 0x8022;

/// `TPM_RH_NULL` — the null hierarchy used for verify-only tickets.
/// `verify_p256` always passes `ESYS_TR_NONE` for the hierarchy, so the
/// returned ticket's `hierarchy` field must equal `TPM2_RH_NULL` per
/// TCG TPM 2.0 Part 1 §22.7.
const TPM2_RH_NULL: u32 = 0x4000_0007;

// ---------------------------------------------------------------------------
// P-256 software on-curve validation (audit fixes C4 / M3).
//
// The validation logic — including U256 limb arithmetic and the curve
// equation y² ≡ x³ − 3x + b (mod p) for `secp256r1` — lives in the
// shared `vs-p256-validate` crate. It uses Solinas (FIPS 186-4 §D.2.3)
// fast reduction instead of bit-serial long division, so each P-256
// modular multiply is O(1) reduction steps instead of O(512).
//
// `crypto-pkcs11` re-exports the same routine. Centralising the
// implementation keeps the two providers' on-curve checks bit-for-bit
// identical and removes a maintenance hazard where one copy could
// silently drift from the other.
// ---------------------------------------------------------------------------

use vs_p256_validate::validate_p256_point_on_curve;

// Compile-time agreement on the uncompressed P-256 point length.
const _: () = assert!(EC_POINT_LEN == vs_p256_validate::EC_POINT_LEN);

// ---------------------------------------------------------------------------
// TPM signature scheme helper
// ---------------------------------------------------------------------------

/// `TPMT_SIG_SCHEME` for ECDSA-SHA-256.
///
/// Layout: `sigAlg: TPM2_ALG_ID (u16)` + `details.hashAlg: TPM2_ALG_ID (u16)`.
#[repr(C)]
struct TpmtSigScheme {
    sig_alg: Tpm2AlgId,
    hash_alg: Tpm2AlgId,
}

// ---------------------------------------------------------------------------
// Provider struct
// ---------------------------------------------------------------------------

/// TPM 2.0 TSS2 ESAPI-backed [`CryptoProvider`].
///
/// Holds a live ESAPI context and a map from [`KeyId`] to `ESYS_TR` handles.
/// Use [`new`](Self::new) to open an ESAPI context, then call
/// [`register_key_handle`](Self::register_key_handle) for each key the
/// platform will use.
///
/// # Thread Safety
///
/// This type is **not** thread-safe. A TPM ESAPI context must only be used
/// from a single thread. The `*mut EsysContext` prevents auto-derivation of
/// `Send` and `Sync`; we add an explicit `PhantomData` marker to make the
/// intent clear.
pub struct TpmCryptoProvider {
    /// TSS2 ESAPI function pointer table.
    fn_list: TpmFunctionList,
    /// Live ESAPI context pointer. Non-null after successful `new()`.
    esys_ctx: *mut EsysContext,
    /// Cipher-key slot map: `key_handles[key_id.0 as usize]` → `ESYS_TR`.
    ///
    /// `ESYS_TR_NONE` means the slot is not populated.
    key_handles: [EsysTr; MAX_KEY_SLOTS],
    /// Parallel MAC-key slot map. Same indexing as `key_handles`. Required
    /// by audit fix C1: the AEAD `EtM` construction must not reuse one TPM key
    /// as both AES-CFB encryption key and HMAC-SHA-256 authentication key.
    /// Callers populate via [`register_mac_key_handle`](Self::register_mac_key_handle).
    mac_handles: [EsysTr; MAX_KEY_SLOTS],
    /// Audit M1 / H1 / M3: long-lived HMAC session handle used in place
    /// of `ESYS_TR_PASSWORD` for command authorisation, so command and
    /// response parameters traversing a discrete TPM bus carry an HMAC
    /// integrity tag.
    ///
    /// The session is **integrity-only** — it does NOT add parameter
    /// encryption. See [`enable_bus_integrity`](Self::enable_bus_integrity)
    /// for the bus-tap caveat and the parameter-encryption gap.
    ///
    /// `ESYS_TR_NONE` means bus integrity is not active — every command
    /// authoriser falls back to `ESYS_TR_PASSWORD` (the original
    /// behaviour). Populated via
    /// [`enable_bus_integrity`](Self::enable_bus_integrity); cleared
    /// (and the session flushed) via
    /// [`disable_bus_integrity`](Self::disable_bus_integrity) or in
    /// `Drop`.
    bus_protection_session: EsysTr,
    /// Prevent `Send` and `Sync` — ESAPI contexts are not thread-safe.
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

impl TpmCryptoProvider {
    /// Create a new provider by initialising an ESAPI context.
    ///
    /// # Parameters
    ///
    /// - `fn_list`: Fully populated [`TpmFunctionList`]. All function pointer
    ///   fields must be non-null and valid.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::NotInitialized`] if `Esys_Initialize` fails.
    pub fn new(fn_list: TpmFunctionList) -> Result<Self, VsError> {
        let mut ctx: *mut EsysContext = core::ptr::null_mut();
        // SAFETY: caller guarantees `fn_list.esys_initialize` is a valid
        // TSS2 ESAPI entry point. `ctx` is a valid writable `*mut *mut
        // EsysContext` on the stack — ESAPI writes the allocated context
        // into it on success, or leaves it untouched on failure. Passing
        // null for `tcti` / `abi` selects the system-default TCTI and the
        // library's default ABI version; both are explicitly documented as
        // accepted by ESAPI. Ownership of `ctx` transfers to this provider
        // and is released exactly once in `Drop` via `esys_finalize`.
        let rc = unsafe {
            (fn_list.esys_initialize)(&mut ctx, core::ptr::null_mut(), core::ptr::null_mut())
        };
        check_rc(rc)?;
        if ctx.is_null() {
            return Err(VsError::NotInitialized);
        }
        Ok(Self {
            fn_list,
            esys_ctx: ctx,
            key_handles: [ESYS_TR_NONE; MAX_KEY_SLOTS],
            mac_handles: [ESYS_TR_NONE; MAX_KEY_SLOTS],
            bus_protection_session: ESYS_TR_NONE,
            _not_send_sync: core::marker::PhantomData,
        })
    }

    /// Map a [`KeyId`] to a TPM `ESYS_TR` handle.
    ///
    /// The handle is typically obtained via `Esys_TR_FromTPMPublic` using the
    /// persistent key's `TPM2_HANDLE` (e.g., `0x81000001`).
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `key_id` ≥ `MAX_KEY_SLOTS`.
    pub fn register_key_handle(&mut self, key_id: KeyId, handle: EsysTr) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        self.key_handles[idx] = handle;
        Ok(())
    }

    /// Look up the `ESYS_TR` for `key_id`.
    #[inline]
    fn handle_for(&self, key_id: KeyId) -> Result<EsysTr, VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        let h = self.key_handles[idx];
        if h == ESYS_TR_NONE {
            Err(VsError::InvalidInput)
        } else {
            Ok(h)
        }
    }

    /// Register a separate MAC key for slot `key_id`.
    ///
    /// Required for the `EtM` AEAD construction (audit fix C1). The MAC key
    /// handle must reference a distinct TPM object from the cipher key —
    /// callers are responsible for enforcing that invariant at key-creation
    /// time.
    ///
    /// # Key-separation canary (audit CRIT-7)
    ///
    /// Handle inequality alone is **necessary but not sufficient** under
    /// NIST SP 800-57 §5.2: two distinct `ESYS_TR` values can point at the
    /// same persistent TPM object loaded twice, or at two objects that were
    /// derived from the same raw key material without a proper KDF label.
    /// To raise the bar past pure structural inequality, every successful
    /// registration drives a one-shot canary self-test:
    ///
    /// 1. Encrypt a fixed 32-byte plaintext ([`KEY_SEPARATION_CANARY`])
    ///    with the cipher handle under AES-CFB.
    /// 2. HMAC-SHA-256 the same plaintext under the MAC handle (no `EtM`
    ///    framing — we are testing the *raw* PRF output of the two keys
    ///    over an identical input).
    /// 3. Compare the two outputs (truncated to `TAG_LEN` bytes, the size
    ///    naturally common to both) in constant time via [`subtle`].
    ///    Reject if they are byte-identical, or if either output is
    ///    all-zero (a stuck-rail / mocked-success TPM fingerprint).
    ///
    /// **Limits of the canary.** A colluding or compromised TPM that knows
    /// the construction can trivially return non-equal outputs while still
    /// using related underlying material — the canary detects accidental
    /// key reuse and trivial misconfiguration, not adversarial behaviour
    /// from the secure element itself. Operators MUST still derive the
    /// cipher and MAC keys via HKDF-Expand (RFC 5869) with distinct
    /// `info` labels during provisioning; this routine is a runtime
    /// backstop, not a substitute for proper key derivation.
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidInput`] if `key_id` ≥ `MAX_KEY_SLOTS`, if the
    ///   handle equals the cipher handle in the same slot, or if no
    ///   cipher handle has been registered for `key_id` (the canary
    ///   needs both keys).
    /// - [`VsError::PolicyViolation`] if the canary detects keys whose
    ///   PRF outputs cannot be distinguished (byte-equal outputs or
    ///   stuck-zero outputs from either primitive).
    /// - Any error surfaced by the underlying `Esys_EncryptDecrypt2` /
    ///   `Esys_HMAC` calls.
    pub fn register_mac_key_handle(
        &mut self,
        key_id: KeyId,
        handle: EsysTr,
    ) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        // Audit M5: reject MAC handle equal to the cipher key handle in the
        // same slot. EtM security requires independent keys.
        if handle != ESYS_TR_NONE && handle == self.key_handles[idx] {
            return Err(VsError::InvalidInput);
        }
        // Audit CRIT-7: handle-inequality is necessary but not sufficient.
        // Run the key-separation canary against the live TPM before
        // accepting the registration. A canary failure leaves the slot
        // untouched (the assignment below is reached only on success).
        if handle != ESYS_TR_NONE {
            let cipher_handle = self.key_handles[idx];
            if cipher_handle == ESYS_TR_NONE {
                // No cipher handle to canary against — refuse rather than
                // silently registering a MAC key that can never be paired.
                return Err(VsError::InvalidInput);
            }
            self.run_key_separation_canary(cipher_handle, handle)?;
        }
        self.mac_handles[idx] = handle;
        Ok(())
    }

    /// Drive the audit-CRIT-7 key-separation canary against two TPM
    /// handles. See [`register_mac_key_handle`](Self::register_mac_key_handle)
    /// for the full rationale and limits.
    ///
    /// Returns [`VsError::PolicyViolation`] when the canary indicates the
    /// keys produce indistinguishable PRF material; propagates any
    /// underlying FFI error otherwise.
    fn run_key_separation_canary(
        &self,
        cipher_handle: EsysTr,
        mac_handle: EsysTr,
    ) -> Result<(), VsError> {
        // 1. Encrypt the fixed canary under the cipher key (AES-CFB).
        //
        //    audit-LOW: the canary IV is drawn fresh from the TPM TRNG on
        //    every registration rather than hard-coded to all-zero. The
        //    provider is fully constructed by the time we run the canary
        //    (this method is only reachable from `register_mac_key_handle`),
        //    so `random_bytes` is always available. The canary plaintext
        //    itself is public, so the IV's job is purely defence-in-depth:
        //    audit-CRIT-7 already prevents the canary handle being
        //    registered as a real cipher key, but if an operator ever
        //    bypasses that path the first real encrypt under a random IV
        //    no longer lands on nonce=zero (an output that an attacker
        //    could have computed offline from the public canary
        //    plaintext). The 16-byte stack buffer is volatile-wiped
        //    immediately after the ESAPI call returns.
        let mut iv_bytes = [0u8; 16];
        if let Err(e) = <Self as CryptoProvider>::random_bytes(self, &mut iv_bytes) {
            volatile_wipe(&mut iv_bytes);
            return Err(e);
        }
        let mut iv_buf = Tpm2bData {
            size: 16,
            buffer: [0u8; 64],
        };
        iv_buf.buffer[..16].copy_from_slice(&iv_bytes);
        // Defence in depth: wipe the original stack copy now that the IV
        // has been deep-copied into the `Tpm2bData` struct ESAPI will
        // read. The `iv_buf` struct itself is wiped after the ESAPI call
        // below.
        volatile_wipe(&mut iv_bytes);
        let mut in_data = Tpm2bMaxBuffer {
            size: KEY_SEPARATION_CANARY.len() as u16,
            buffer: [0u8; 2048],
        };
        in_data.buffer[..KEY_SEPARATION_CANARY.len()].copy_from_slice(&KEY_SEPARATION_CANARY);

        let mut p_out_data: *mut Tpm2bMaxBuffer = core::ptr::null_mut();
        let mut p_iv_out: *mut Tpm2bData = core::ptr::null_mut();
        // SAFETY: `cipher_handle` is the value the caller is asking us to
        // pair with a MAC key — it was registered via `register_key_handle`
        // and is non-`ESYS_TR_NONE` (checked by the caller). `iv_buf` and
        // `in_data` live on this stack frame for the entire call; the two
        // out-pointers are valid double-pointers that ESAPI populates with
        // fresh allocations on success. Ownership of those allocations
        // transfers to this frame and is released exactly once below via
        // `esys_free`.
        let rc = unsafe {
            (self.fn_list.esys_encrypt_decrypt2)(
                self.esys_ctx,
                cipher_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                TPMI_NO, // encrypt
                TPM2_ALG_CFB,
                &iv_buf,
                &in_data,
                &mut p_out_data,
                &mut p_iv_out,
            )
        };

        let mut enc_canary = [0u8; TAG_LEN];
        let enc_result = if rc != types::TSS2_RC_SUCCESS {
            Err(rc_to_err(rc))
        } else if p_out_data.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: `p_out_data` is non-null (checked) and points to an
            // ESAPI-allocated `Tpm2bMaxBuffer`; not aliased.
            let out = unsafe { &*p_out_data };
            let ct_len = out.size as usize;
            // AES-CFB preserves length: any deviation is TPM/TSS2
            // misbehaviour and would render the canary read unreliable.
            if ct_len == KEY_SEPARATION_CANARY.len() {
                enc_canary.copy_from_slice(&out.buffer[..TAG_LEN]);
                Ok(())
            } else {
                Err(VsError::CryptoError)
            }
        };
        if !p_out_data.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_out_data as *mut core::ffi::c_void) };
        }
        if !p_iv_out.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_iv_out as *mut core::ffi::c_void) };
        }
        // audit-LOW: wipe the random canary IV as soon as ESAPI no longer
        // needs to read it. The TPM has either consumed it (success) or
        // rejected it (failure); either way the stack copy is no longer
        // needed and must not survive on the return path.
        volatile_wipe(&mut iv_buf.buffer);
        iv_buf.size = 0;
        enc_result?;

        // 2. HMAC-SHA-256 the same plaintext under the MAC key (raw, no
        //    EtM framing — we are probing the bare PRF behaviour).
        let mut hmac_buf = Tpm2bMaxBuffer {
            size: KEY_SEPARATION_CANARY.len() as u16,
            buffer: [0u8; 2048],
        };
        hmac_buf.buffer[..KEY_SEPARATION_CANARY.len()].copy_from_slice(&KEY_SEPARATION_CANARY);
        let mut mac_canary = [0u8; TAG_LEN];
        self.hmac_with_buf(mac_handle, &hmac_buf, &mut mac_canary)?;

        // 3. Combined constant-time canary check.
        //
        //    audit-LOW: the previous implementation took two `if`
        //    branches:
        //      (a) `enc_acc == 0 || mac_acc == 0` → reject stuck-zero,
        //      (b) `enc_canary.ct_eq(&mac_canary)` → reject collisions.
        //    Branch (a) leaks a 1-bit signal on key-derived material —
        //    a fingerprint of the underlying key even though the canary
        //    plaintext is public. The fix folds both decisions into a
        //    single `subtle::Choice` so the same instructions run
        //    regardless of `enc_canary` / `mac_canary` content, and the
        //    branch happens exactly once at the very end against the
        //    combined `Choice`.
        //
        //    The constant-time discipline relies on:
        //      - `[u8; TAG_LEN]::ct_eq` (from `subtle::ConstantTimeEq`)
        //        returning `Choice` without branching on input bytes,
        //      - `subtle::Choice`'s `BitAnd` / `Not` impls being
        //        constant-time,
        //      - converting back to `bool` only after the final
        //        `Choice` is fully composed, so the policy decision is
        //        the only data-dependent observable.
        let zero_tag = [0u8; TAG_LEN];
        let enc_is_zero: Choice = enc_canary.ct_eq(&zero_tag);
        let mac_is_zero: Choice = mac_canary.ct_eq(&zero_tag);
        let collides: Choice = enc_canary.ct_eq(&mac_canary);
        // `failure` is true iff (enc is zero) OR (mac is zero) OR
        // (enc == mac). Built from `Choice` operators throughout.
        let failure: Choice = enc_is_zero | mac_is_zero | collides;
        if bool::from(failure) {
            return Err(VsError::PolicyViolation);
        }

        Ok(())
    }

    /// Look up the MAC `ESYS_TR` for `key_id`.
    ///
    /// Returns [`VsError::InvalidInput`] if no MAC handle is registered for
    /// the slot. This is the enforcement path for audit fix C1: AEAD
    /// operations fail closed when the caller did not register a MAC key.
    #[inline]
    fn mac_handle_for(&self, key_id: KeyId) -> Result<EsysTr, VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        let h = self.mac_handles[idx];
        if h == ESYS_TR_NONE {
            Err(VsError::InvalidInput)
        } else {
            Ok(h)
        }
    }

    /// Audit M1 / H1: return the auth-session handle for the next TPM command.
    ///
    /// Returns the long-lived HMAC integrity session opened by
    /// [`enable_bus_integrity`](Self::enable_bus_integrity) when active,
    /// or `ESYS_TR_PASSWORD` (the original behaviour) when bus integrity
    /// is not enabled. Every command site that previously hard-coded
    /// `ESYS_TR_PASSWORD` now routes through this helper so the choice
    /// is made in exactly one place and individual callers cannot drift.
    #[inline]
    fn auth_session(&self) -> EsysTr {
        if self.bus_protection_session == ESYS_TR_NONE {
            ESYS_TR_PASSWORD
        } else {
            self.bus_protection_session
        }
    }

    /// Audit M1 / H1 / M3: open an HMAC **integrity** session over the
    /// TPM bus.
    ///
    /// Calls `Esys_StartAuthSession(TPM2_SE_HMAC, ...)` with no salt key
    /// and no bind handle (`ESYS_TR_NONE` for both), producing a
    /// session that authorises commands with an HMAC integrity tag
    /// instead of the plaintext password protocol. Once installed, every
    /// subsequent TPM command issued by this provider (`EncryptDecrypt2`,
    /// `HMAC`, `Sign`, `ECDH_ZGen`, `PCR_Extend`) uses the new session
    /// handle in place of `ESYS_TR_PASSWORD` — see
    /// [`auth_session`](Self::auth_session).
    ///
    /// # Security scope — integrity only, NOT confidentiality
    ///
    /// Provides **HMAC integrity** over command and response parameters
    /// per TCG TPM 2.0 Library §19.6. Does **NOT** provide
    /// confidentiality: the symmetric descriptor is
    /// `TpmtSymDef { algorithm: TPM2_ALG_NULL, .. }`, and the session
    /// attributes do NOT include `TPMA_SESSION_ENCRYPT` /
    /// `TPMA_SESSION_DECRYPT`. **A bus-tap can still recover plaintext
    /// command and response parameters** (e.g., PCR digests, signing
    /// inputs, ciphertexts going into `EncryptDecrypt2`); the integrity
    /// tag only stops an attacker from modifying them undetected.
    ///
    /// Operators that need full parameter encryption must additionally
    /// attach a salt key and request `TPMA_SESSION_ENCRYPT` /
    /// `TPMA_SESSION_DECRYPT`. A future extension may layer that on;
    /// the public API of this method is stable.
    ///
    /// # Continue-session attribute
    ///
    /// After the session is opened, we call
    /// `Esys_TRSess_SetAttributes(.., TPMA_SESSION_CONTINUE_SESSION,
    /// TPMA_SESSION_CONTINUE_SESSION)` so the session survives past one
    /// command and remains valid for every subsequent provider call.
    /// Without this attribute the TPM would tear the session down after
    /// the first use and the very next provider command would silently
    /// fall back to `ESYS_TR_PASSWORD` — the bug audit H1 was raised to
    /// catch.
    ///
    /// # Caller nonce (audit M3)
    ///
    /// `nonce_caller` is no longer null. We draw 32 bytes from the TPM
    /// TRNG (`random_bytes`) into a stack `Tpm2bNonce` buffer before
    /// opening the session and `volatile_wipe` the buffer afterwards.
    /// The TPM contributes its own response nonce; together they seed
    /// the session keys.
    ///
    /// # Idempotency
    ///
    /// Calling `enable_bus_integrity` while a session is already active
    /// is a no-op and returns `Ok(())`. Use
    /// [`disable_bus_integrity`](Self::disable_bus_integrity) to flush
    /// the current session before opening a new one.
    ///
    /// # Errors
    ///
    /// - Any error surfaced by the underlying `Esys_StartAuthSession` or
    ///   `Esys_TRSess_SetAttributes` calls (mapped via
    ///   [`error::rc_to_err`]).
    /// - Any error from the nonce-source `random_bytes` call.
    /// - [`VsError::CryptoError`] if the TPM returned `TSS2_RC_SUCCESS`
    ///   but a `ESYS_TR_NONE` session handle (a TPM / ESAPI protocol
    ///   violation).
    ///
    /// On any failure after `Esys_StartAuthSession` succeeds, the
    /// session handle is flushed via `Esys_FlushContext` and
    /// [`bus_protection_session`](Self) is left at `ESYS_TR_NONE` so the
    /// provider stays in a well-defined state.
    pub fn enable_bus_integrity(&mut self) -> Result<(), VsError> {
        if self.bus_protection_session != ESYS_TR_NONE {
            // Already active — nothing to do.
            return Ok(());
        }
        // Symmetric descriptor: TPM2_ALG_NULL = integrity-only HMAC
        // session, no parameter encryption. The `key_bits` and `mode`
        // fields are ignored by the TPM when `algorithm == NULL` but
        // must be syntactically valid in the C struct.
        let sym = TpmtSymDef {
            algorithm: TPM2_ALG_NULL,
            key_bits: 0,
            mode: TPM2_ALG_NULL,
        };

        // Audit M3: pre-populate a 32-byte caller nonce from the TPM
        // TRNG. We use the live `random_bytes` (it does not depend on a
        // bus-integrity session; it issues `ESYS_TR_NONE` for all
        // session handles in the TSS2 call). The buffer is wiped on
        // every exit path below, success or failure.
        let mut nonce_bytes = [0u8; 32];
        if let Err(e) = <Self as CryptoProvider>::random_bytes(self, &mut nonce_bytes) {
            volatile_wipe(&mut nonce_bytes);
            return Err(e);
        }
        let mut nonce = Tpm2bNonce {
            size: 32,
            buffer: [0u8; 64],
        };
        nonce.buffer[..32].copy_from_slice(&nonce_bytes);
        // Defence in depth: the original stack copy is wiped now that
        // the nonce has been deep-copied into the `Tpm2bNonce` struct
        // that ESAPI will read. The `nonce` struct itself is wiped at
        // the end of this function.
        volatile_wipe(&mut nonce_bytes);

        let mut session: EsysTr = ESYS_TR_NONE;
        // SAFETY: `esys_ctx` is non-null after a successful `new()`. The
        // `tpm_key` / `bind` handles are `ESYS_TR_NONE` (unsalted /
        // unbound) which ESAPI explicitly accepts (TCG TSS 2.0 Part 4
        // §`Esys_StartAuthSession`). `nonce` lives on this stack frame
        // for the duration of the call and is wiped before return.
        // `sym` lives on this stack frame for the duration of the call.
        // `session` is a writable `*mut EsysTr` that ESAPI populates
        // with the new session handle on success and leaves untouched
        // on failure.
        let rc = unsafe {
            (self.fn_list.esys_start_auth_session)(
                self.esys_ctx,
                ESYS_TR_NONE, // tpm_key (no salt)
                ESYS_TR_NONE, // bind (no bind handle)
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &nonce,
                TPM2_SE_HMAC,
                &sym,
                TPM2_ALG_SHA256,
                &mut session,
            )
        };
        // Wipe the caller nonce as soon as ESAPI no longer needs to
        // read it. The TPM has either copied it into its session state
        // (success) or rejected it (failure); either way our stack
        // copy is no longer needed.
        volatile_wipe(&mut nonce.buffer);
        nonce.size = 0;

        if let Err(e) = check_rc(rc) {
            // `Esys_StartAuthSession` failed — no handle to flush. The
            // session slot remains `ESYS_TR_NONE`.
            return Err(e);
        }
        if session == ESYS_TR_NONE {
            // Protocol violation — TPM cannot return success with a
            // null session handle. Refuse to install it. No flush
            // needed: there is no handle to flush.
            return Err(VsError::CryptoError);
        }

        // Audit H1: set `TPMA_SESSION_CONTINUE_SESSION` so the session
        // survives past one command. ESAPI applies only the bits
        // selected by `mask`, so passing identical `flags == mask ==
        // CONTINUE_SESSION` sets that single bit and leaves the others
        // alone.
        // SAFETY: `esys_ctx` is non-null; `session` is a valid session
        // handle just returned by `Esys_StartAuthSession` on the same
        // context. The flags / mask arguments are plain `u8` values.
        let attr_rc = unsafe {
            (self.fn_list.esys_tr_sess_set_attributes)(
                self.esys_ctx,
                session,
                TPMA_SESSION_CONTINUE_SESSION,
                TPMA_SESSION_CONTINUE_SESSION,
            )
        };
        if let Err(e) = check_rc(attr_rc) {
            // Mirror the existing error-path discipline: flush the
            // session and leave `bus_protection_session` at
            // `ESYS_TR_NONE`.
            // SAFETY: `session` is a live session handle on `esys_ctx`.
            let _ = unsafe { (self.fn_list.esys_flush_context)(self.esys_ctx, session) };
            return Err(e);
        }

        self.bus_protection_session = session;
        Ok(())
    }

    /// Returns true if an HMAC bus-integrity session is currently bound to this provider.
    ///
    /// NOTE: This indicates session-binding only. It does NOT guarantee that command/response
    /// parameter encryption is active — only HMAC integrity is provided. See `enable_bus_integrity`
    /// (or the deprecated `enable_bus_protection`) for the full security model.
    ///
    /// Sibling contexts created via `new_sibling_context` always return `false` here, even when
    /// the parent had a session — bus-protection sessions are per-provider, not shareable
    /// (audit-M1).
    #[inline]
    pub fn bus_protection_active(&self) -> bool {
        self.bus_protection_session != ESYS_TR_NONE
    }

    /// Deprecated alias for [`enable_bus_integrity`](Self::enable_bus_integrity).
    ///
    /// The old name overstated what the wiring delivers — the session
    /// is HMAC-integrity-only, not full bus protection. New code must
    /// use `enable_bus_integrity`; this alias exists only so existing
    /// callers keep compiling during migration.
    #[deprecated(
        since = "0.7.1",
        note = "renamed to `enable_bus_integrity` — the session is HMAC-integrity-only, \
                NOT confidentiality. Bus-tap can still recover plaintext parameters. \
                See TCG TPM 2.0 Library §19.6."
    )]
    pub fn enable_bus_protection(&mut self) -> Result<(), VsError> {
        self.enable_bus_integrity()
    }

    /// Audit M1 / H1: tear down the HMAC bus-integrity session.
    ///
    /// Calls `Esys_FlushContext` on the active session handle and
    /// resets [`bus_protection_session`](Self) to `ESYS_TR_NONE`,
    /// reverting subsequent commands to `ESYS_TR_PASSWORD`. Idempotent:
    /// if no session is active, returns `Ok(())` without calling the
    /// TPM.
    ///
    /// On a flush failure the slot is still cleared so the provider
    /// stays in a well-defined state (the same fail-closed strategy as
    /// `delete_key`); the underlying error is surfaced.
    pub fn disable_bus_integrity(&mut self) -> Result<(), VsError> {
        if self.bus_protection_session == ESYS_TR_NONE {
            return Ok(());
        }
        let session = self.bus_protection_session;
        // Clear up-front so an error path cannot leave a stale handle.
        self.bus_protection_session = ESYS_TR_NONE;
        // SAFETY: `esys_ctx` is non-null after `new()`; `session` is a
        // valid HMAC session handle produced by a prior
        // `Esys_StartAuthSession` on the same context.
        let rc = unsafe { (self.fn_list.esys_flush_context)(self.esys_ctx, session) };
        check_rc(rc)
    }

    /// Deprecated alias for [`disable_bus_integrity`](Self::disable_bus_integrity).
    ///
    /// See [`enable_bus_protection`](Self::enable_bus_protection) for
    /// the rename rationale.
    #[deprecated(
        since = "0.7.1",
        note = "renamed to `disable_bus_integrity` to match \
                `enable_bus_integrity`."
    )]
    pub fn disable_bus_protection(&mut self) -> Result<(), VsError> {
        self.disable_bus_integrity()
    }

    // -----------------------------------------------------------------------
    // TPM-specific extensions (beyond CryptoProvider)
    // -----------------------------------------------------------------------

    /// Extend PCR `index` with `measurement` (SHA-256 digest).
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `index` > 23 (standard PCR range).
    pub fn pcr_extend(&self, index: u8, measurement: &[u8; SHA256_LEN]) -> Result<(), VsError> {
        if index > 23 {
            return Err(VsError::InvalidInput);
        }
        // audit-LOW-3: defensive — the `index > 23` check above already
        // bounds the addend, but use `checked_add` instead of
        // `wrapping_add` so the handle arithmetic fails closed if the
        // upstream guard is ever removed or `ESYS_TR_PCR0` is bumped to
        // near `EsysTr::MAX`.
        let pcr_handle = ESYS_TR_PCR0
            .checked_add(EsysTr::from(index))
            .ok_or(VsError::InvalidInput)?;

        let digests = types::TpmlDigestValues {
            count: 1,
            hash_alg: TPM2_ALG_SHA256,
            _pad: 0,
            digest: *measurement,
        };

        // SAFETY: digests is a valid stack-allocated struct matching the C
        // `TPML_DIGEST_VALUES` layout. pcr_handle is a valid PCR index.
        // Audit M1: `auth_session()` returns the HMAC bus-protection
        // session when active, else `ESYS_TR_PASSWORD`.
        let rc = unsafe {
            (self.fn_list.esys_pcr_extend)(
                self.esys_ctx,
                pcr_handle,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &digests,
            )
        };
        check_rc(rc)
    }

    /// Read the current SHA-256 value of PCR `index`.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if `index` > 23.
    pub fn pcr_read(&self, index: u8, value: &mut [u8; SHA256_LEN]) -> Result<(), VsError> {
        if index > 23 {
            return Err(VsError::InvalidInput);
        }
        let mut sel = TpmlPcrSelection {
            count: 1,
            pcr_selections: [types::TpmsPcrSelection {
                hash: TPM2_ALG_SHA256,
                sizeof_select: 4,
                pcr_select: [0; 4],
            }; 16],
        };
        sel.pcr_selections[0].pcr_select[(index / 8) as usize] = 1 << (index % 8);

        let mut p_update_ctr: u32 = 0;
        let mut p_sel_out: *mut TpmlPcrSelection = core::ptr::null_mut();
        let mut p_values: *mut types::TpmlDigest = core::ptr::null_mut();

        // SAFETY: pointers receive ESAPI-allocated buffers that we free below.
        let rc = unsafe {
            (self.fn_list.esys_pcr_read)(
                self.esys_ctx,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &sel,
                &mut p_update_ctr,
                &mut p_sel_out,
                &mut p_values,
            )
        };
        check_rc(rc)?;

        let result = if p_values.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: p_values is non-null and points to a valid TpmlDigest.
            let digests = unsafe { &*p_values };
            if digests.count == 0 || digests.digests[0].size as usize != SHA256_LEN {
                Err(VsError::CryptoError)
            } else {
                value.copy_from_slice(&digests.digests[0].buffer[..SHA256_LEN]);
                Ok(())
            }
        };

        // Free ESAPI-allocated buffers.
        if !p_sel_out.is_null() {
            // SAFETY: `p_sel_out` was written by `esys_pcr_read` as a fresh
            // ESAPI allocation. Ownership is exclusive to this provider (no
            // aliasing has occurred since the call returned). We free it
            // exactly once here; the pointer is not read afterwards.
            unsafe { (self.fn_list.esys_free)(p_sel_out as *mut core::ffi::c_void) };
        }
        if !p_values.is_null() {
            // SAFETY: same ownership argument as `p_sel_out` above. If
            // `result` is `Err`, no caller observes the buffer contents; if
            // `Ok`, the values have already been copied out. Freeing once
            // here is safe and required.
            unsafe { (self.fn_list.esys_free)(p_values as *mut core::ffi::c_void) };
        }
        result
    }
}

impl Drop for TpmCryptoProvider {
    fn drop(&mut self) {
        // Audit M1 / H1: flush the bus-integrity HMAC session BEFORE finalising
        // the ESAPI context. `Esys_Finalize` would clean up all per-context
        // metadata regardless, but explicitly flushing the TPM-side object
        // releases the TPM's session slot promptly — important for
        // long-lived hosts that churn many providers and would otherwise
        // exhaust the TPM's small session budget (typically 3 active
        // sessions on a discrete TPM). A flush failure is intentionally
        // swallowed: `Drop` must not panic and the subsequent
        // `Esys_Finalize` will sweep up anything left behind.
        if self.bus_protection_session != ESYS_TR_NONE && !self.esys_ctx.is_null() {
            // SAFETY: `esys_ctx` is non-null (checked) and was obtained
            // from `Esys_Initialize`. `bus_protection_session` is a
            // session handle returned by a prior successful
            // `Esys_StartAuthSession` against the same context and has
            // not been flushed yet. ESAPI mutates only its internal
            // bookkeeping.
            let _ = unsafe {
                (self.fn_list.esys_flush_context)(self.esys_ctx, self.bus_protection_session)
            };
            self.bus_protection_session = ESYS_TR_NONE;
        }
        if !self.esys_ctx.is_null() {
            // SAFETY: esys_ctx is non-null and was obtained from Esys_Initialize.
            // Esys_Finalize sets the pointer to null.
            unsafe { (self.fn_list.esys_finalize)(&mut self.esys_ctx) };
        }
    }
}

impl TpmCryptoProvider {
    /// Returns a new provider that shares the underlying ESAPI **function
    /// table** but starts with an **empty handle map**. Handles registered
    /// on `self` are NOT visible to the returned provider — every key
    /// must be re-registered on the new instance before use.
    ///
    /// The name reflects that what you get back is a *sibling* context
    /// (parallel TSS2 ESAPI state), not a clone of `self`'s logical
    /// state. The previous name (`try_clone`) suggested otherwise.
    ///
    /// Unlike a hypothetical `Clone::clone`, this method:
    /// * propagates errors instead of silently sharing the ESAPI context
    ///   pointer (which would cause double-finalize in `Drop`), and
    /// * does **not** copy `key_handles` / `mac_handles` — they are
    ///   scoped to the originating ESAPI context (see "handle scope"
    ///   below).
    ///
    /// # Errors
    ///
    /// Returns [`VsError::NotInitialized`] if `Esys_Initialize` fails.
    ///
    /// # Audit fix M5 — handle scope
    ///
    /// `ESYS_TR` values are scoped to the ESAPI context that produced them
    /// (TSS2 spec: an `ESYS_TR` is a handle into the per-context object
    /// table). Blindly copying `key_handles` / `mac_handles` from `self`
    /// into the new context produces handles that point to the WRONG
    /// object (or to nothing) when used against the new context — a
    /// silent correctness/security bug.
    ///
    /// Since this crate doesn't track the underlying persistent TPM
    /// handle separately from the per-context `ESYS_TR`, the safe
    /// behaviour is to start the sibling with **empty** handle slots
    /// and require the caller to re-register every key. Tests that
    /// previously asserted handles survive a duplication now assert the
    /// opposite.
    ///
    /// The sibling provider starts WITHOUT a bus-integrity session even if
    /// the parent had one — callers must call `enable_bus_integrity` again
    /// on the sibling. Check `bus_protection_active()` to confirm session
    /// state.
    #[doc(alias = "try_clone")]
    #[doc(alias = "fork_context_reset_handles")]
    pub fn new_sibling_context(&self) -> Result<Self, VsError> {
        let mut ctx: *mut EsysContext = core::ptr::null_mut();
        // SAFETY: see `new()` for the full invariants — in short, `ctx` is a
        // valid writable double-pointer that ESAPI will populate on success.
        // The cloned provider will free its own context in `Drop`; we do not
        // share the original context pointer, preventing double-finalise.
        let rc = unsafe {
            (self.fn_list.esys_initialize)(&mut ctx, core::ptr::null_mut(), core::ptr::null_mut())
        };
        check_rc(rc)?;
        if ctx.is_null() {
            return Err(VsError::NotInitialized);
        }
        Ok(Self {
            fn_list: self.fn_list,
            esys_ctx: ctx,
            // Audit M5: do NOT copy handles across ESAPI contexts.
            key_handles: [ESYS_TR_NONE; MAX_KEY_SLOTS],
            mac_handles: [ESYS_TR_NONE; MAX_KEY_SLOTS],
            // SECURITY (audit-M1 + audit-H1): bus-integrity sessions are
            // per-provider, not shareable. `ESYS_TR` session handles are
            // scoped to the ESAPI context that opened them, AND the
            // single-owner invariant of the HMAC session forbids two
            // providers driving the same session in parallel — flushing
            // in either sibling's `Drop` would invalidate the other. We
            // therefore start the sibling with NO session, even if the
            // parent had one active. Operators auditing live state must
            // call `bus_protection_active()` on the sibling (it will
            // return `false`) and re-enable explicitly via
            // `enable_bus_integrity()` if bus integrity is desired.
            bus_protection_session: ESYS_TR_NONE,
            _not_send_sync: core::marker::PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider implementation
// ---------------------------------------------------------------------------

impl CryptoProvider for TpmCryptoProvider {
    /// **WARNING — name vs. construction.** Despite the trait-mandated
    /// name, this implementation is **NOT AES-GCM**. The TPM 2.0
    /// specification does not include a native AES-GCM command, so the
    /// AEAD interface is satisfied with **AES-256-CFB + HMAC-SHA-256
    /// (Encrypt-then-MAC)**. The `tag_out` field carries the first 16
    /// bytes of an HMAC-SHA-256 over a canonically framed input
    /// (`"VS-ETM01" || nonce || aad_len || ct_len || aad || ct`).
    ///
    /// See the crate-level documentation (lines 19-45 of `lib.rs`) for
    /// the canonical statement of the construction. The accurately-named
    /// inherent alias is [`TpmCryptoProvider::aead_encrypt`]; new code
    /// that statically dispatches on `TpmCryptoProvider` should prefer
    /// it for readability.
    ///
    /// The method name is preserved verbatim because it is required by
    /// the [`CryptoProvider`] trait shared with `vs-crypto-pkcs11`
    /// (which DOES implement true AES-GCM).
    #[doc(alias = "aes_cfb_etm_encrypt")]
    #[doc(alias = "aead_encrypt")]
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; TAG_LEN],
    ) -> Result<(), VsError> {
        if plaintext.len() != ciphertext_out.len() {
            return Err(VsError::InvalidInput);
        }
        if aad.len() > MAX_BUF || plaintext.len() > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        // Audit HIGH-K: atomicity. The framed-length precondition for
        // `compute_etm_tag` is checked here, BEFORE any TPM call, so the
        // encrypt path fails before `ciphertext_out` is ever written. Without
        // this guard, an oversized `(aad, plaintext)` would silently run
        // EncryptDecrypt2 (mutating `ciphertext_out`) and only then reject in
        // `compute_etm_tag`, leaving caller-visible state inconsistent with
        // an `Err` return.
        let framed_len = ETM_PREFIX_LEN
            .checked_add(aad.len())
            .and_then(|s| s.checked_add(plaintext.len()))
            .ok_or(VsError::InvalidInput)?;
        if framed_len > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        // Defense in depth: even though `MAX_BUF <= u16::MAX` is compile-time
        // asserted, convert via `try_from` so the u16 truncation cannot
        // silently happen if `MAX_BUF` is ever raised without touching the
        // cast site.
        let in_size = u16::try_from(plaintext.len()).map_err(|_| VsError::InvalidInput)?;
        let h_key = self.handle_for(key_id)?;
        // Audit C1: MAC key is a separate TPM object. Fail closed if the
        // caller has not registered it.
        let h_mac = self.mac_handle_for(key_id)?;

        // Build 16-byte IV: nonce (12 bytes) || zero (4 bytes).
        //
        // audit-LOW-1: the IV is NOT all-zero. The leading 12 bytes carry
        // the caller-supplied unique nonce; the trailing 4 bytes are a
        // deterministic zero pad, NOT key-derived material. They must be
        // deterministic because `aes_gcm_decrypt` derives the same IV
        // from the same nonce to invert the CFB stream. Randomising the
        // tail would prevent decryption. AES-CFB IV uniqueness is
        // already provided by the per-message nonce (`vs-crypto` trait
        // contract).
        let mut iv_buf = Tpm2bData {
            size: 16,
            buffer: [0u8; 64],
        };
        iv_buf.buffer[..12].copy_from_slice(nonce);

        // PERF: TPM AEAD requires three memcpys per call (plaintext in,
        // ESAPI internal, ciphertext out) and only the first is even
        // potentially avoidable. We do not avoid it because:
        //   • `Tpm2bMaxBuffer` is a size-prefixed C struct (u16 length +
        //     [u8; 2048]) and TSS2 expects the size prefix to be contiguous
        //     with the buffer bytes; the caller's `plaintext: &[u8]` has no
        //     such prefix, so we cannot pass it directly.
        //   • The ESAPI middle copy is hidden inside libtss2-esys.
        //   • The output copy is unavoidable because ESAPI owns the result
        //     allocation and we must release it via `esys_free`.
        // Net: input-side copy is structurally required. Workloads sensitive
        // to this cost should batch into larger plaintexts (up to MAX_BUF
        // per call) so the fixed FFI overhead is amortised.
        let mut in_data = Tpm2bMaxBuffer {
            size: in_size,
            buffer: [0u8; 2048],
        };
        in_data.buffer[..plaintext.len()].copy_from_slice(plaintext);

        let mut p_out_data: *mut Tpm2bMaxBuffer = core::ptr::null_mut();
        let mut p_iv_out: *mut Tpm2bData = core::ptr::null_mut();

        // SAFETY: h_key is a valid ESYS_TR. All in/out pointer arguments are
        // valid stack variables or pointers to receive ESAPI allocations.
        // Audit M1: route auth via `auth_session()` so HMAC bus
        // protection takes effect when enabled.
        let rc = unsafe {
            (self.fn_list.esys_encrypt_decrypt2)(
                self.esys_ctx,
                h_key,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                TPMI_NO, // decrypt=false → encrypt
                TPM2_ALG_CFB,
                &iv_buf,
                &in_data,
                &mut p_out_data,
                &mut p_iv_out,
            )
        };

        // Audit HIGH-J: `in_data` holds the caller's plaintext on the stack
        // and MUST be volatile-zeroed before this frame returns regardless
        // of which sub-step failed. Compute the result step-by-step into a
        // local, perform the wipe, then return.
        let rc_result = check_rc(rc);

        // Copy ciphertext out (only if the TPM call succeeded) and free
        // ESAPI-allocated buffers unconditionally.
        let enc_result = if rc_result.is_err() {
            // Surface the rc error; ESAPI may still have allocated outputs.
            rc_result
        } else if p_out_data.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: p_out_data is non-null, pointing to a valid Tpm2bMaxBuffer.
            let out = unsafe { &*p_out_data };
            let ct_len = out.size as usize;
            if ct_len == plaintext.len() {
                ciphertext_out.copy_from_slice(&out.buffer[..ct_len]);
                Ok(())
            } else {
                Err(VsError::CryptoError)
            }
        };

        if !p_out_data.is_null() {
            // SAFETY: p_out_data was ESAPI-allocated; free exactly once.
            unsafe { (self.fn_list.esys_free)(p_out_data as *mut core::ffi::c_void) };
        }
        if !p_iv_out.is_null() {
            // SAFETY: p_iv_out was ESAPI-allocated; free exactly once.
            unsafe { (self.fn_list.esys_free)(p_iv_out as *mut core::ffi::c_void) };
        }

        let result = enc_result
            .and_then(|()| self.compute_etm_tag(h_mac, nonce, aad, ciphertext_out, tag_out));

        // Audit HIGH-J: wipe stack-resident plaintext before return.
        zeroize_max_buffer(&mut in_data);
        result
    }

    /// **WARNING — name vs. construction.** Despite the trait-mandated
    /// name, this implementation is **NOT AES-GCM**. It performs
    /// **HMAC-SHA-256 tag verification first** (constant-time), then
    /// **AES-256-CFB decryption** — the inverse of the
    /// Encrypt-then-MAC construction documented on
    /// [`aes_gcm_encrypt`](Self::aes_gcm_encrypt) and at the crate root
    /// (lines 19-45 of `lib.rs`).
    ///
    /// The accurately-named inherent alias is
    /// [`TpmCryptoProvider::aead_decrypt`]. The trait name is preserved
    /// because the [`CryptoProvider`] trait shape is shared with
    /// `vs-crypto-pkcs11` (which DOES implement true AES-GCM).
    #[doc(alias = "aes_cfb_etm_decrypt")]
    #[doc(alias = "aead_decrypt")]
    fn aes_gcm_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        if ciphertext.len() != plaintext_out.len() {
            return Err(VsError::InvalidInput);
        }
        if aad.len() > MAX_BUF || ciphertext.len() > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        // Audit HIGH-K: atomicity, symmetric with `aes_gcm_encrypt`. Reject
        // oversized framed inputs BEFORE any TPM call so the decrypt path
        // exits cleanly without partial work on the TPM side.
        let framed_len = ETM_PREFIX_LEN
            .checked_add(aad.len())
            .and_then(|s| s.checked_add(ciphertext.len()))
            .ok_or(VsError::InvalidInput)?;
        if framed_len > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        // See note on the matching cast in `aes_gcm_encrypt` above.
        let in_size = u16::try_from(ciphertext.len()).map_err(|_| VsError::InvalidInput)?;
        let h_key = self.handle_for(key_id)?;
        // Audit C1: MAC key is a separate TPM object.
        let h_mac = self.mac_handle_for(key_id)?;

        // Verify authentication tag before decrypting (Encrypt-then-MAC).
        // Audit HIGH-J: `expected_tag` is a 16-byte secret-derived value;
        // wipe before return regardless of the verification outcome.
        let mut expected_tag = [0u8; TAG_LEN];
        let tag_result = self
            .compute_etm_tag(h_mac, nonce, aad, ciphertext, &mut expected_tag)
            .and_then(|()| {
                if bool::from(tag.ct_eq(&expected_tag)) {
                    Ok(())
                } else {
                    Err(VsError::AuthenticationFailure)
                }
            });
        volatile_wipe(&mut expected_tag);
        tag_result?;

        // Decrypt with AES-CFB.
        //
        // audit-LOW-1: see the matching note on `aes_gcm_encrypt`. The
        // IV mirrors the encrypt side (nonce || zero4) so the CFB
        // stream cancels exactly; the trailing zeros are a structural
        // constant, not a stuck-zero key fragment.
        let mut iv_buf = Tpm2bData {
            size: 16,
            buffer: [0u8; 64],
        };
        iv_buf.buffer[..12].copy_from_slice(nonce);

        // PERF: see the matching comment in `aes_gcm_encrypt`. The
        // ciphertext-in copy is unavoidable for the same reason — the
        // `Tpm2bMaxBuffer` size prefix is part of the C struct layout and
        // cannot be elided without changing the TSS2 ABI.
        let mut in_data = Tpm2bMaxBuffer {
            size: in_size,
            buffer: [0u8; 2048],
        };
        in_data.buffer[..ciphertext.len()].copy_from_slice(ciphertext);

        let mut p_out_data: *mut Tpm2bMaxBuffer = core::ptr::null_mut();
        let mut p_iv_out: *mut Tpm2bData = core::ptr::null_mut();

        // SAFETY: `h_key` is a valid ESYS_TR obtained from
        // `register_key_handle` (checked via `handle_for`). `iv_buf` and
        // `in_data` live on this stack frame for the entire call. `p_out_data`
        // and `p_iv_out` are writable double-pointers; ESAPI writes fresh
        // allocations into them on success, leaves them null on failure.
        // Ownership of both transfers to this frame and is released
        // unconditionally below via `esys_free`.
        // Audit M1: route auth via `auth_session()` so HMAC bus
        // protection takes effect when enabled.
        let rc = unsafe {
            (self.fn_list.esys_encrypt_decrypt2)(
                self.esys_ctx,
                h_key,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                TPMI_YES, // decrypt=true
                TPM2_ALG_CFB,
                &iv_buf,
                &in_data,
                &mut p_out_data,
                &mut p_iv_out,
            )
        };

        // Audit HIGH-J: `in_data` carries ciphertext (low-sensitivity in
        // isolation but still attacker-influenced), AND the ESAPI output
        // buffer carries decrypted plaintext that lands in
        // `plaintext_out`. We must wipe `in_data` regardless of which step
        // fails. Compute the result before wiping.
        let rc_result = check_rc(rc);
        let dec_result = if rc_result.is_err() {
            rc_result
        } else if p_out_data.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: `p_out_data` is non-null here (checked above), points to
            // a valid ESAPI-allocated `Tpm2bMaxBuffer`, and is not shared
            // with any other reference for the duration of this borrow.
            let out = unsafe { &*p_out_data };
            let pt_len = out.size as usize;
            if pt_len == ciphertext.len() {
                plaintext_out.copy_from_slice(&out.buffer[..pt_len]);
                Ok(())
            } else {
                Err(VsError::CryptoError)
            }
        };

        if !p_out_data.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_out_data as *mut core::ffi::c_void) };
        }
        if !p_iv_out.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_iv_out as *mut core::ffi::c_void) };
        }

        // Audit HIGH-J: wipe stack-resident ciphertext before return.
        zeroize_max_buffer(&mut in_data);
        dec_result
    }

    /// SHA-256 hash via `Esys_Hash`.
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; SHA256_LEN]) -> Result<(), VsError> {
        if data.len() > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        // See note on the matching cast in `aes_gcm_encrypt` above.
        let data_size = u16::try_from(data.len()).map_err(|_| VsError::InvalidInput)?;
        let mut buf = Tpm2bMaxBuffer {
            size: data_size,
            buffer: [0u8; 2048],
        };
        buf.buffer[..data.len()].copy_from_slice(data);

        let mut p_hash: *mut Tpm2bDigest = core::ptr::null_mut();
        let mut p_validation: *mut TpmtTkHashcheck = core::ptr::null_mut();

        // SAFETY: buf is a valid stack buffer; p_hash and p_validation receive
        // ESAPI-allocated memory which is freed below.
        let rc = unsafe {
            (self.fn_list.esys_hash)(
                self.esys_ctx,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &buf,
                TPM2_ALG_SHA256,
                ESYS_TR_RH_NULL,
                &mut p_hash,
                &mut p_validation,
            )
        };

        // Audit HIGH-J: `buf` may hold caller-supplied secret data
        // (passwords, key material, telemetry payloads). Wipe regardless
        // of which sub-step succeeds.
        let rc_result = check_rc(rc);
        let result = if rc_result.is_err() {
            rc_result
        } else if p_hash.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: p_hash is non-null and points to a valid Tpm2bDigest.
            let digest = unsafe { &*p_hash };
            if digest.size as usize == SHA256_LEN {
                hash_out.copy_from_slice(&digest.buffer[..SHA256_LEN]);
                Ok(())
            } else {
                Err(VsError::CryptoError)
            }
        };

        if !p_hash.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_hash as *mut core::ffi::c_void) };
        }
        if !p_validation.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_validation as *mut core::ffi::c_void) };
        }

        // Audit HIGH-J: wipe stack-resident input buffer before return.
        zeroize_max_buffer(&mut buf);
        result
    }

    /// HMAC-SHA-256 via `Esys_HMAC`.
    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; SHA256_LEN],
    ) -> Result<(), VsError> {
        let h_key = self.handle_for(key_id)?;
        self.hmac_sha256_full(h_key, data, mac_out)
    }

    /// ECDH P-256 shared-secret derivation via `Esys_ECDH_ZGen`.
    fn ecdh_derive_shared(
        &self,
        private_key_id: KeyId,
        peer_public: &[u8; EC_POINT_LEN],
        shared_out: &mut [u8; ECDH_SHARED_LEN],
    ) -> Result<(), VsError> {
        let h_key = self.handle_for(private_key_id)?;

        // Audit M3: full on-curve validation BEFORE any TPM FFI call.
        // On any rejection below we wipe the caller's shared-secret buffer.
        if let Err(e) = validate_p256_point_on_curve(peer_public) {
            shared_out.fill(0);
            return Err(e);
        }
        let mut in_point = Tpm2bEccPoint {
            size: core::mem::size_of::<types::TpmsEccPoint>() as u16,
            point: TpmsEccPoint {
                x: types::Tpm2bEccParameter {
                    size: P256_COORD_LEN as u16,
                    buffer: [0; 32],
                },
                y: types::Tpm2bEccParameter {
                    size: P256_COORD_LEN as u16,
                    buffer: [0; 32],
                },
            },
        };
        in_point.point.x.buffer.copy_from_slice(&peer_public[1..33]);
        in_point
            .point
            .y
            .buffer
            .copy_from_slice(&peer_public[33..65]);

        let mut p_out_point: *mut Tpm2bEccPoint = core::ptr::null_mut();

        // SAFETY: h_key is a valid ECC key handle; in_point is valid stack data.
        // Audit M1: route auth via `auth_session()` for bus protection.
        let rc = unsafe {
            (self.fn_list.esys_ecdh_zgen)(
                self.esys_ctx,
                h_key,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &in_point,
                &mut p_out_point,
            )
        };
        if let Err(e) = check_rc(rc) {
            shared_out.fill(0);
            return Err(e);
        }

        let result = if p_out_point.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: p_out_point is non-null and points to a valid Tpm2bEccPoint.
            let out = unsafe { &*p_out_point };
            if out.point.x.size as usize == P256_COORD_LEN {
                // Use only the x-coordinate as the shared secret (ECDH standard).
                shared_out.copy_from_slice(&out.point.x.buffer[..P256_COORD_LEN]);
                Ok(())
            } else {
                shared_out.fill(0);
                Err(VsError::CryptoError)
            }
        };

        if !p_out_point.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_out_point as *mut core::ffi::c_void) };
        }
        if result.is_err() {
            shared_out.fill(0);
        }
        result
    }

    /// ECDSA P-256 signing via `Esys_Sign`.
    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; SHA256_LEN],
        sig_out: &mut [u8; ECDSA_SIG_LEN],
    ) -> Result<(), VsError> {
        let h_key = self.handle_for(key_id)?;

        let mut tpm_digest = Tpm2bDigest {
            size: SHA256_LEN as u16,
            buffer: [0u8; 64],
        };
        tpm_digest.buffer[..SHA256_LEN].copy_from_slice(digest);

        let scheme = TpmtSigScheme {
            sig_alg: TPM2_ALG_ECDSA,
            hash_alg: TPM2_ALG_SHA256,
        };
        // Null validation ticket (not required when signing pre-hashed data).
        let validation = TpmtTkHashcheck {
            tag: 0x8024, // TPM2_ST_HASHCHECK
            hierarchy: types::ESYS_TR_RH_NULL,
            digest: Tpm2bDigest {
                size: 0,
                buffer: [0u8; 64],
            },
        };

        let mut p_sig: *mut TpmtSignature = core::ptr::null_mut();

        // SAFETY: h_key is a valid ECC key; all stack arguments are valid.
        // Audit M1: route auth via `auth_session()` for bus protection.
        let rc = unsafe {
            (self.fn_list.esys_sign)(
                self.esys_ctx,
                h_key,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &tpm_digest,
                &scheme as *const TpmtSigScheme as *const core::ffi::c_void,
                &validation,
                &mut p_sig,
            )
        };
        check_rc(rc)?;

        let result = if p_sig.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: `p_sig` is non-null (checked above) and points to an
            // ESAPI-allocated `TpmtSignature`. The ESAPI contract guarantees
            // that the `sig_alg` field identifies the active union variant.
            let sig = unsafe { &*p_sig };
            if sig.sig_alg != TPM2_ALG_ECDSA {
                // Safety gate: if the TPM returned a signature tagged as
                // something other than ECDSA, reading `ecdsa` would be UB.
                // Free the allocation and reject.
                if !p_sig.is_null() {
                    // SAFETY: `p_sig` is an ESAPI-allocated pointer that has
                    // not been freed yet and is not shared.
                    unsafe { (self.fn_list.esys_free)(p_sig as *mut core::ffi::c_void) };
                }
                return Err(VsError::CryptoError);
            }
            // SAFETY: the `if` above established that `sig_alg == ECDSA`,
            // which per TCG TPM 2.0 Part 2 §11.3.8 selects `signature.ecdsa`
            // as the single active member of the `TpmuSignature` union.
            // Reading any other variant would be undefined.
            let ecdsa = unsafe { &sig.signature.ecdsa };
            if ecdsa.signature_r.size as usize != P256_COORD_LEN
                || ecdsa.signature_s.size as usize != P256_COORD_LEN
            {
                Err(VsError::CryptoError)
            } else {
                sig_out[..P256_COORD_LEN]
                    .copy_from_slice(&ecdsa.signature_r.buffer[..P256_COORD_LEN]);
                sig_out[P256_COORD_LEN..]
                    .copy_from_slice(&ecdsa.signature_s.buffer[..P256_COORD_LEN]);
                Ok(())
            }
        };

        if !p_sig.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_sig as *mut core::ffi::c_void) };
        }
        result
    }

    /// ECDSA P-256 verification via `Esys_VerifySignature`.
    ///
    /// On each call the public key is loaded as a transient TPM object
    /// via `Esys_LoadExternal`, producing a transient `ESYS_TR` that is
    /// used for exactly one `Esys_VerifySignature` call and is always
    /// flushed via `Esys_FlushContext` on every exit path by
    /// [`TransientHandle`] (audit fix C4).
    ///
    /// # Public-key validation
    ///
    /// Before any TPM FFI call, the point is checked for: uncompressed
    /// prefix (`0x04`), not the point at infinity, coordinates < p,
    /// AND satisfies the P-256 curve equation `y^2 = x^3 - 3x + b`
    /// (software check, defence-in-depth).
    fn verify_p256(
        &self,
        pub_key: &[u8; EC_POINT_LEN],
        digest: &[u8; SHA256_LEN],
        sig: &[u8; ECDSA_SIG_LEN],
    ) -> Result<bool, VsError> {
        // Audit C4: full on-curve check BEFORE any TPM FFI.
        validate_p256_point_on_curve(pub_key)?;

        // Load the caller-supplied public key into a transient TPM slot.
        // `h_key` must be flushed on every exit; the guard below ensures it.
        let h_key = self.load_external_p256_verify_key(pub_key)?;

        // audit-M2: a hostile or misbehaving TPM could return an
        // `out_handle` that aliases one of the provider's registered
        // long-lived handles (cipher key, MAC key, password/hierarchy
        // sentinels, or — once audit-M1 lands — the bus-protection
        // session). If we wrapped that handle in `TransientHandle`, its
        // `Drop` would issue `Esys_FlushContext` on the colliding handle
        // and evict the live key. Reject the operation: flush the
        // transient handle ourselves (since we own it for one call) and
        // refuse to proceed to `Esys_VerifySignature`.
        if self.handle_collides_with_registered(h_key) {
            // SAFETY: `esys_ctx` is the live ESAPI context owned by this
            // provider; `h_key` was returned by `Esys_LoadExternal` in
            // the same operation and has not been flushed or closed
            // anywhere else. We are the sole owner. The RC is
            // intentionally ignored — even if the flush fails, refusing
            // the operation is the correct action.
            let _ = unsafe { (self.fn_list.esys_flush_context)(self.esys_ctx, h_key) };
            return Err(VsError::InvalidInput);
        }

        let _guard = TransientHandle::new(&self.fn_list, self.esys_ctx, h_key);

        // Build the TPM signature structure from the raw (r, s) bytes.
        let mut tpm_sig = TpmtSignature {
            sig_alg: TPM2_ALG_ECDSA,
            signature: TpmuSignature {
                ecdsa: core::mem::ManuallyDrop::new(TpmsSignatureEcdsa {
                    hash: TPM2_ALG_SHA256,
                    signature_r: types::Tpm2bEccParameter {
                        size: P256_COORD_LEN as u16,
                        buffer: [0u8; 32],
                    },
                    signature_s: types::Tpm2bEccParameter {
                        size: P256_COORD_LEN as u16,
                        buffer: [0u8; 32],
                    },
                }),
            },
        };
        // SAFETY: `TPMU_SIGNATURE` is a C union whose active member is
        // selected by the discriminant field `sig_alg`. We set
        // `tpm_sig.sig_alg = TPM2_ALG_ECDSA` above, which per TCG TPM 2.0
        // Part 2 §11.3.8 promises the `ecdsa` variant as the only valid
        // member to read or write afterwards — every other variant must
        // be considered uninitialised for the rest of this function.
        //
        // Wrapping the ECDSA variant in `ManuallyDrop` means the initial
        // struct assignment does not recursively drop the previous (zero-
        // initialised) union contents, which would otherwise observe bytes
        // that may be invalid for the dropped variant.
        //
        // `addr_of_mut!` returns a raw pointer to the union's interior
        // without creating a transient `&mut` that would imply the
        // surrounding union is fully initialised — a requirement of the
        // Rust reference model when any union variant is partially valid.
        //
        // `copy_nonoverlapping` is sound here because (a) `sig` and the
        // union buffer live on disjoint stack frames, (b) both regions are
        // exactly `P256_COORD_LEN` bytes long, (c) we write `P256_COORD_LEN`
        // bytes which matches the target buffer's declared size, and
        // (d) no other reference aliases the written buffer until the union
        // is handed to `esys_verify_signature` below.
        unsafe {
            let r_buf_ptr = core::ptr::addr_of_mut!((*tpm_sig.signature.ecdsa).signature_r.buffer);
            core::ptr::copy_nonoverlapping(sig.as_ptr(), (*r_buf_ptr).as_mut_ptr(), P256_COORD_LEN);
            let s_buf_ptr = core::ptr::addr_of_mut!((*tpm_sig.signature.ecdsa).signature_s.buffer);
            core::ptr::copy_nonoverlapping(
                sig[P256_COORD_LEN..].as_ptr(),
                (*s_buf_ptr).as_mut_ptr(),
                P256_COORD_LEN,
            );
        }

        let mut tpm_digest = Tpm2bDigest {
            size: SHA256_LEN as u16,
            buffer: [0u8; 64],
        };
        tpm_digest.buffer[..SHA256_LEN].copy_from_slice(digest);

        let mut p_validation: *mut types::TpmtTkVerified = core::ptr::null_mut();

        // SAFETY: h_key is valid; tpm_digest and tpm_sig are valid stack data.
        let rc = unsafe {
            (self.fn_list.esys_verify_signature)(
                self.esys_ctx,
                h_key,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &tpm_digest,
                &tpm_sig,
                &mut p_validation,
            )
        };

        // Audit M4: inspect the verification ticket on success before
        // declaring `Ok(true)`. The ticket fields are the TPM's
        // attestation that verification succeeded; a misbehaving (or
        // intermediated) ESAPI implementation could return
        // `TSS2_RC_SUCCESS` with a zeroed ticket. Defending against that
        // here turns "trust the RC alone" into "RC plus structured
        // attestation."
        let ticket_ok = if rc == types::TSS2_RC_SUCCESS && !p_validation.is_null() {
            // SAFETY: p_validation is non-null and points to an
            // ESAPI-allocated TPMT_TK_VERIFIED struct. We read fields
            // through a shared reference; the allocation is freed below.
            let ticket = unsafe { &*p_validation };
            // (1) Tag must be `TPM_ST_VERIFIED` (0x8022).
            // (2) Hierarchy must match what we passed in (`TPM2_RH_NULL`).
            // (3) digest.size must be non-zero — an empty validation
            //     digest is a malformed ticket and should never pair
            //     with a success RC.
            ticket.tag == TPM2_ST_VERIFIED
                && ticket.hierarchy == TPM2_RH_NULL
                && ticket.digest.size > 0
                && (ticket.digest.size as usize) <= ticket.digest.buffer.len()
        } else {
            // For non-success RCs the ticket inspection is irrelevant —
            // we will branch on the RC below and never return Ok(true).
            true
        };

        if !p_validation.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_validation as *mut core::ffi::c_void) };
        }

        // See module-level `TPM2_RC_SIGNATURE*` constants for RC semantics.
        match rc {
            types::TSS2_RC_SUCCESS => {
                if ticket_ok {
                    Ok(true)
                } else {
                    // Success RC paired with a malformed ticket — refuse
                    // to declare verification successful.
                    Err(VsError::CryptoError)
                }
            }
            TPM2_RC_SIGNATURE | TPM2_RC_SIGNATURE_P1 | TPM2_RC_SIGNATURE_P2 => Ok(false),
            // ESAPI layer returning AUTHORIZATION_FAILED on a verify-signature
            // call is also an authentic verification failure.
            err if err == types::TSS2_ESYS_RC_LAYER | types::TSS2_BASE_RC_AUTHORIZATION_FAILED => {
                Ok(false)
            }
            err => Err(rc_to_err(err)),
        }
    }

    /// Delete a key by flushing its TPM object and clearing its slots.
    ///
    /// Audit item 9: previously this only cleared the in-memory handle
    /// and left the transient TPM object alive. The implementation now
    /// also calls `Esys_FlushContext` on the cached cipher and MAC
    /// handles so the TPM releases its transient-slot resources. A
    /// missing handle (slot never populated) is tolerated; a flush
    /// failure is reported but the slot is still cleared so the
    /// provider stays in a known state.
    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::InvalidInput);
        }
        let cipher_h = self.key_handles[idx];
        let mac_h = self.mac_handles[idx];
        // Clear the slots up-front so we never leak on any return path.
        self.key_handles[idx] = ESYS_TR_NONE;
        self.mac_handles[idx] = ESYS_TR_NONE;

        let mut first_err: Option<VsError> = None;
        if cipher_h != ESYS_TR_NONE {
            // SAFETY: `esys_ctx` is a live ESAPI context; `cipher_h` was
            // registered by the caller as a valid `ESYS_TR`. ESAPI mutates
            // only its internal bookkeeping.
            let rc = unsafe { (self.fn_list.esys_flush_context)(self.esys_ctx, cipher_h) };
            if rc != types::TSS2_RC_SUCCESS {
                first_err = Some(rc_to_err(rc));
            }
        }
        if mac_h != ESYS_TR_NONE {
            // SAFETY: see above — `mac_h` was registered via
            // `register_mac_key_handle`.
            let rc = unsafe { (self.fn_list.esys_flush_context)(self.esys_ctx, mac_h) };
            if rc != types::TSS2_RC_SUCCESS && first_err.is_none() {
                first_err = Some(rc_to_err(rc));
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Generate a key on the TPM.
    ///
    /// Hardware-backed providers require keys to be created on the TPM
    /// via TPM administration tools (e.g., `tpm2_create`), then registered
    /// with [`register_key_handle`](Self::register_key_handle).
    /// In-band key generation is disallowed by policy because it would
    /// bypass the TPM's key-lifecycle auditing and ceremony requirements.
    ///
    /// # Errors
    ///
    /// Always returns [`VsError::PolicyViolation`].
    fn generate_key(&mut self, _key_id: KeyId, _key_type: KeyType) -> Result<(), VsError> {
        Err(VsError::PolicyViolation)
    }

    /// Generate random bytes from the TPM TRNG via `Esys_GetRandom`.
    ///
    /// The TPM 2.0 specification bounds `TPM2_GetRandom` to 32 bytes per
    /// call (matching the primary hash size — TCG TPM 2.0 Part 3 §16.1).
    /// Longer requests are chunked in the provider; requests larger than
    /// [`MAX_BUF`] are rejected to keep TPM round-trip counts bounded.
    ///
    /// # Performance
    ///
    /// **Each 32 bytes of output costs one TPM round-trip**, including
    /// command marshalling, bus traversal, and an ESAPI allocation that
    /// we copy from and free. On a discrete TPM the round-trip dominates
    /// every other cost in this function. Callers that need bulk
    /// randomness should request it in a single large call rather than
    /// looping over many small calls — for example, prefer one
    /// `random_bytes(&mut buf[..256])` to eight `random_bytes(&mut
    /// buf[..32])` invocations.
    ///
    /// The per-call limit cannot be raised: `TPM2_GetRandom` defines its
    /// `bytesRequested` argument as bounded by the primary hash size, and
    /// TSS2 enforces it. Substituting a KDF/HKDF expansion to amortise
    /// the cost would change the security profile (caller would no longer
    /// be reading TPM TRNG output) and is explicitly out of scope.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        if buf.is_empty() {
            return Ok(());
        }
        if buf.len() > MAX_BUF {
            return Err(VsError::InvalidInput);
        }

        // TPM2_GetRandom returns at most `RNG_PER_CALL` bytes per call
        // (see method docs); loop for longer requests.
        let total = buf.len();
        let mut offset = 0;
        while offset < total {
            let chunk_usize = (total - offset).min(RNG_PER_CALL);
            // Cast is lossless: `chunk_usize <= RNG_PER_CALL <= u16::MAX`.
            let chunk = chunk_usize as u16;
            let mut p_rnd: *mut Tpm2bDigest = core::ptr::null_mut();

            // SAFETY: `p_rnd` is a valid writable double-pointer on this
            // stack frame; ESAPI populates it with a fresh allocation on
            // success. `chunk <= PER_CALL` so we remain within the per-call
            // limit documented by TPM2_GetRandom. Context and session
            // handles are valid by construction.
            let rc = unsafe {
                (self.fn_list.esys_get_random)(
                    self.esys_ctx,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    chunk,
                    &mut p_rnd,
                )
            };
            check_rc(rc)?;

            if p_rnd.is_null() {
                return Err(VsError::CryptoError);
            }
            // SAFETY: `p_rnd` is non-null (checked) and points to a fresh
            // `Tpm2bDigest` whose lifetime is bounded by the `esys_free`
            // call below. No aliasing has occurred since the ESAPI return.
            let got = unsafe { (*p_rnd).size as usize };
            // Audit H3 (strict-rng feature): a short return from the TPM
            // is a protocol error, not a retry hint. Reject immediately.
            #[cfg(feature = "strict-rng")]
            if got < chunk_usize {
                // SAFETY: free the ESAPI allocation before returning.
                unsafe { (self.fn_list.esys_free)(p_rnd as *mut core::ffi::c_void) };
                return Err(VsError::CryptoError);
            }
            let copy_len = got.min(chunk_usize);
            if copy_len == 0 {
                // SAFETY: free before returning — no further reads.
                unsafe { (self.fn_list.esys_free)(p_rnd as *mut core::ffi::c_void) };
                return Err(VsError::CryptoError);
            }
            // SAFETY: same justification — we read `copy_len <= got` bytes
            // from the ESAPI buffer, which is at least `got` bytes long.
            buf[offset..offset + copy_len]
                .copy_from_slice(unsafe { &(&(*p_rnd).buffer)[..copy_len] });
            // SAFETY: `p_rnd` is ESAPI-allocated (non-null), ownership is
            // exclusive to this frame, freed exactly once here. The pointer
            // is not read after this call.
            unsafe { (self.fn_list.esys_free)(p_rnd as *mut core::ffi::c_void) };

            offset += copy_len;
        }

        // Audit H3 (strict-rng feature): non-constant self-test on 32-byte+
        // fills. If the first 16 bytes equal the second 16 bytes the TPM's
        // RNG is suspect (stuck output) and we fail closed.
        #[cfg(feature = "strict-rng")]
        if buf.len() >= 32 {
            let (a, rest) = buf.split_at(16);
            let b = &rest[..16];
            if bool::from(a.ct_eq(b)) {
                return Err(VsError::CryptoError);
            }
        }

        Ok(())
    }

    /// TPM self-test: run `Esys_SelfTest(fullTest=YES)` + SHA-256 canary.
    ///
    /// This is the **full** test path: the TPM re-runs every algorithm
    /// self-test regardless of whether it has been validated since power-on.
    /// Use this from cold-boot integrity checks. For warm-boot or hot-path
    /// liveness checks where startup latency matters, use
    /// [`TpmCryptoProvider::quick_self_test`] instead.
    fn self_test(&self) -> Result<(), VsError> {
        self.run_self_test_with_canary(TPMI_YES)
    }
}

impl TpmCryptoProvider {
    /// TPM self-test: run `Esys_SelfTest(fullTest=NO)` + SHA-256 canary.
    ///
    /// Passes `fullTest = TPMI_NO`, which instructs the TPM to test **only**
    /// algorithms that have not yet been validated since power-on. On a TPM
    /// that already completed a previous self-test this is a near-no-op;
    /// on a freshly powered TPM it covers every algorithm exactly once.
    ///
    /// # Tradeoff vs. [`self_test`](Self::self_test)
    ///
    /// `quick_self_test` is the right choice for periodic liveness checks
    /// and warm-boot paths where startup latency matters. It does **not**
    /// re-validate algorithms that the TPM has already tested in this
    /// power cycle, so it does not detect transient faults that arise
    /// after the initial validation. Use the full
    /// [`CryptoProvider::self_test`](CryptoProvider::self_test) for
    /// cold-boot integrity gates and after any TPM reset.
    ///
    /// Both variants run the SHA-256 canary afterwards so a misbehaving
    /// TPM that returns `TSS2_RC_SUCCESS` without actually testing
    /// anything still fails closed on the canary.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::CryptoError`] if the TPM self-test fails, the
    /// canary hash is all-zero, or any FFI call returns a non-success
    /// `TSS2_RC`.
    pub fn quick_self_test(&self) -> Result<(), VsError> {
        self.run_self_test_with_canary(TPMI_NO)
    }

    /// Internal: drive `Esys_SelfTest` with the supplied `fullTest` flag,
    /// then run the SHA-256 canary. Shared between
    /// [`self_test`](CryptoProvider::self_test) and
    /// [`quick_self_test`](Self::quick_self_test).
    #[inline]
    fn run_self_test_with_canary(&self, full_test: types::TpmiYesNo) -> Result<(), VsError> {
        // SAFETY: no key handles or buffers; pure TPM command.
        let rc = unsafe {
            (self.fn_list.esys_self_test)(
                self.esys_ctx,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                full_test,
            )
        };
        check_rc(rc)?;

        // SHA-256 canary: detect a TPM that returns `TSS2_RC_SUCCESS`
        // without producing a real hash output. Catches "always-ok" mocks
        // and stuck-zero faults.
        let mut hash = [0u8; SHA256_LEN];
        self.sha256(b"craton-shield-canary", &mut hash)?;
        // audit-LOW-2: replace the branchy `acc |= b; if acc == 0`
        // accumulator (which short-circuits on the first non-zero byte
        // in some optimiser configurations) with a `subtle::Choice`
        // comparison against the all-zero sentinel. The single
        // `bool::from(...)` at the policy-decision point is the only
        // branch that depends on derived material.
        let hash_zero: subtle::Choice = hash.ct_eq(&[0u8; SHA256_LEN]);
        if bool::from(hash_zero) {
            return Err(VsError::CryptoError);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// RAII guard that releases a transient TPM object on drop.
///
/// Cleanup happens in two ordered steps:
///
/// 1. `Esys_FlushContext` — instructs the TPM to evict the loaded transient
///    object (releases the TPM-side handle and any associated session
///    resources).
/// 2. `Esys_TR_Close` — releases the ESAPI's per-context metadata for the
///    `ESYS_TR` (a host-side allocation that survives `FlushContext` alone).
///
/// The order is load-bearing: closing the TR first would leave a stale TPM-
/// side object until the ESAPI context is finalised, leaking TPM slot
/// budget on long-lived providers that perform many transient-load
/// operations. Per the TSS2 spec, `Esys_TR_Close` does not touch the TPM
/// (`Esys_TR_Close` is purely a host-side metadata release), so calling it
/// after `Esys_FlushContext` is the correct sequence.
///
/// Either call returning a non-success `TSS2_RC` is intentionally
/// swallowed — Drop must not panic, and a half-completed cleanup is still
/// better than leaving the handle dangling. Callers concerned about
/// cleanup failures must call the underlying FFI explicitly.
struct TransientHandle<'a> {
    fn_list: &'a TpmFunctionList,
    esys_ctx: *mut EsysContext,
    handle: EsysTr,
}

impl<'a> TransientHandle<'a> {
    #[inline]
    fn new(fn_list: &'a TpmFunctionList, esys_ctx: *mut EsysContext, handle: EsysTr) -> Self {
        Self {
            fn_list,
            esys_ctx,
            handle,
        }
    }
}

impl Drop for TransientHandle<'_> {
    fn drop(&mut self) {
        if self.handle == ESYS_TR_NONE || self.esys_ctx.is_null() {
            return;
        }
        // SAFETY: `esys_ctx` is a live ESAPI context (non-null check above);
        // `self.handle` was returned by a prior `Esys_LoadExternal` in the
        // same operation and has not yet been freed. `Esys_FlushContext`
        // evicts the TPM-side object first.
        let _ = unsafe { (self.fn_list.esys_flush_context)(self.esys_ctx, self.handle) };
        // SAFETY: After `FlushContext`, the host-side `ESYS_TR` metadata
        // still exists in the ESAPI context's object table; `Esys_TR_Close`
        // releases it and writes `ESYS_TR_NONE` back through the pointer.
        // `&mut self.handle` is a valid writable pointer for the call.
        let _ = unsafe { (self.fn_list.esys_tr_close)(self.esys_ctx, &mut self.handle) };
    }
}

impl TpmCryptoProvider {
    /// audit-M2: collision check for transient handles returned by
    /// `Esys_LoadExternal` (and any other future `Esys_*`-style transient
    /// loader). A misbehaving or hostile TPM could return an `out_handle`
    /// that aliases one of our registered long-lived handles — were we to
    /// then drop the resulting [`TransientHandle`], its
    /// `Esys_FlushContext` would evict a live cipher/MAC key, producing a
    /// DoS or fault-injection primitive.
    ///
    /// This helper returns `true` when `handle` matches:
    /// - any populated cipher-key slot in `self.key_handles`,
    /// - any populated MAC-key slot in `self.mac_handles`,
    /// - the `ESYS_TR_NONE` sentinel (also rejected by the explicit check
    ///   in `load_external_p256_verify_key`, but covered here for
    ///   defence-in-depth and reuse),
    /// - the `ESYS_TR_PASSWORD` sentinel (the password session — flushing
    ///   it would corrupt every subsequent authorised TPM call),
    /// - any of the well-known reserved/hierarchy handles
    ///   (`ESYS_TR_RH_OWNER`, `ESYS_TR_RH_ENDORSEMENT`,
    ///   `ESYS_TR_RH_PLATFORM`, `ESYS_TR_RH_NULL`) — these must never be
    ///   passed to `Esys_FlushContext`.
    ///
    /// When the bus-protection session lands (audit-M1), its handle must
    /// be added to this list as well — the helper is the single source of
    /// truth for "handles the provider owns and must never let a transient
    /// drop flush".
    #[inline]
    fn handle_collides_with_registered(&self, handle: EsysTr) -> bool {
        // Sentinels and reserved hierarchies — flushing any of these
        // would break the ESAPI invariants the rest of the crate relies on.
        if handle == ESYS_TR_NONE
            || handle == ESYS_TR_PASSWORD
            || handle == types::ESYS_TR_RH_OWNER
            || handle == types::ESYS_TR_RH_ENDORSEMENT
            || handle == types::ESYS_TR_RH_PLATFORM
            || handle == types::ESYS_TR_RH_NULL
        {
            return true;
        }
        // Registered long-lived handles owned by this provider.
        for i in 0..MAX_KEY_SLOTS {
            let h = self.key_handles[i];
            if h != ESYS_TR_NONE && h == handle {
                return true;
            }
            let mh = self.mac_handles[i];
            if mh != ESYS_TR_NONE && mh == handle {
                return true;
            }
        }
        false
    }

    /// Load an external P-256 public key as a transient TPM object.
    fn load_external_p256_verify_key(
        &self,
        pub_key: &[u8; EC_POINT_LEN],
    ) -> Result<EsysTr, VsError> {
        let mut in_public = types::Tpm2bPublic {
            size: core::mem::size_of::<types::TpmtPublic>() as u16,
            public_area: types::TpmtPublic {
                object_type: types::TPM2_ALG_ECC,
                name_alg: TPM2_ALG_SHA256,
                object_attributes: types::TPMA_OBJECT_SIGN
                    | types::TPMA_OBJECT_USERWITHAUTH
                    | types::TPMA_OBJECT_NO_DA,
                auth_policy: Tpm2bDigest {
                    size: 0,
                    buffer: [0u8; 64],
                },
                parameters: types::TpmuPublicParms {
                    ecc_detail: types::TpmsEccParms {
                        symmetric: types::TpmtSymDefObject {
                            algorithm: types::TPM2_ALG_NULL,
                            key_bits: 0,
                            mode: types::TPM2_ALG_NULL,
                        },
                        scheme: types::TpmtEccScheme {
                            scheme: TPM2_ALG_ECDSA,
                            details: types::TpmsSchemeHash {
                                hash_alg: TPM2_ALG_SHA256,
                            },
                        },
                        curve_id: types::TPM2_ECC_NIST_P256,
                        kdf: types::TpmtKdfScheme {
                            scheme: types::TPM2_ALG_NULL,
                            details: types::TpmsSchemeHash {
                                hash_alg: types::TPM2_ALG_NULL,
                            },
                        },
                    },
                },
                unique: types::TpmuPublicId {
                    ecc: TpmsEccPoint {
                        x: types::Tpm2bEccParameter {
                            size: P256_COORD_LEN as u16,
                            buffer: [0u8; 32],
                        },
                        y: types::Tpm2bEccParameter {
                            size: P256_COORD_LEN as u16,
                            buffer: [0u8; 32],
                        },
                    },
                },
            },
        };
        // SAFETY: object_type = TPM2_ALG_ECC selects the ecc variant of TpmuPublicId.
        unsafe {
            in_public
                .public_area
                .unique
                .ecc
                .x
                .buffer
                .copy_from_slice(&pub_key[1..33]);
            in_public
                .public_area
                .unique
                .ecc
                .y
                .buffer
                .copy_from_slice(&pub_key[33..65]);
        }

        let mut out_handle: EsysTr = ESYS_TR_NONE;
        // SAFETY: in_public fully initialised; null in_private loads only the public half.
        let rc = unsafe {
            (self.fn_list.esys_load_external)(
                self.esys_ctx,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                core::ptr::null(),
                &in_public,
                types::ESYS_TR_RH_NULL,
                &mut out_handle,
            )
        };
        check_rc(rc)?;
        if out_handle == ESYS_TR_NONE {
            return Err(VsError::CryptoError);
        }
        Ok(out_handle)
    }

    /// Accurately-named inherent alias for the AEAD encrypt operation.
    ///
    /// This is the **same code** as the trait method
    /// [`<Self as CryptoProvider>::aes_gcm_encrypt`](CryptoProvider::aes_gcm_encrypt),
    /// but with a name that reflects what actually runs on the TPM —
    /// the implementation is **AES-256-CFB + HMAC-SHA-256
    /// (Encrypt-then-MAC)**, not AES-GCM, because the TPM 2.0
    /// specification has no native AES-GCM command. See the crate-level
    /// documentation (lines 19-45 of `lib.rs`) for the full construction.
    ///
    /// Prefer this method over `aes_gcm_encrypt` in call sites that
    /// statically dispatch on `TpmCryptoProvider` — the name carries
    /// useful auditing information. Code that is generic over
    /// `CryptoProvider` must continue to use the trait method.
    #[doc(alias = "aes_cfb_etm_encrypt")]
    pub fn aead_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; TAG_LEN],
    ) -> Result<(), VsError> {
        <Self as CryptoProvider>::aes_gcm_encrypt(
            self,
            key_id,
            nonce,
            plaintext,
            aad,
            ciphertext_out,
            tag_out,
        )
    }

    /// Accurately-named inherent alias for the AEAD decrypt operation.
    ///
    /// This is the **same code** as the trait method
    /// [`<Self as CryptoProvider>::aes_gcm_decrypt`](CryptoProvider::aes_gcm_decrypt).
    /// The name reflects what actually runs on the TPM: HMAC-SHA-256
    /// tag verification (constant-time), followed by AES-256-CFB
    /// decryption — the inverse of the Encrypt-then-MAC construction
    /// documented at the crate root (lines 19-45 of `lib.rs`). It is
    /// **not** AES-GCM.
    ///
    /// Prefer this method over `aes_gcm_decrypt` in call sites that
    /// statically dispatch on `TpmCryptoProvider`. Code that is generic
    /// over `CryptoProvider` must continue to use the trait method.
    #[doc(alias = "aes_cfb_etm_decrypt")]
    pub fn aead_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        <Self as CryptoProvider>::aes_gcm_decrypt(
            self,
            key_id,
            nonce,
            ciphertext,
            aad,
            tag,
            plaintext_out,
        )
    }
}

impl TpmCryptoProvider {
    /// Compute the `EtM` authentication tag (truncated HMAC-SHA-256) over a
    /// canonically framed MAC input.
    ///
    /// The framed input (audit fixes C2 + C3) is:
    ///
    /// ```text
    ///   "VS-ETM01" (8B) || nonce (12B)
    ///       || aad_len (LE u64, 8B) || aad
    ///       || ct_len  (LE u64, 8B) || ct
    /// ```
    ///
    /// Both `aad.len() <= MAX_BUF` and `ciphertext.len() <= MAX_BUF` are
    /// enforced before the call, and the total framed length is bounded by
    /// `ETM_PREFIX_LEN + 2 * MAX_BUF`. The MAC buffer backing store is
    /// sized to fit that worst case.
    #[inline]
    fn compute_etm_tag(
        &self,
        h_mac: EsysTr,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag_out: &mut [u8; TAG_LEN],
    ) -> Result<(), VsError> {
        if aad.len() > MAX_BUF || ciphertext.len() > MAX_BUF {
            return Err(VsError::InvalidInput);
        }

        // Build the framed MAC input on the stack. The framed input can be
        // larger than `MAX_BUF` (because it contains AAD || CT plus the
        // prefix) — so we cannot reuse `Tpm2bMaxBuffer` directly as the
        // transport. Instead we hash the framed buffer with `Esys_HashSequence`
        // semantics emulated via a single-shot HMAC call — but ESAPI's
        // `Esys_HMAC` caps its input at `Tpm2bMaxBuffer::buffer.len()`
        // (2 KiB). We therefore require the framed input to fit in 2 KiB
        // and reject otherwise.
        let framed_len = ETM_PREFIX_LEN
            .checked_add(aad.len())
            .and_then(|s| s.checked_add(ciphertext.len()))
            .ok_or(VsError::InvalidInput)?;
        if framed_len > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        let framed_size = u16::try_from(framed_len).map_err(|_| VsError::InvalidInput)?;

        // PERF (P4): avoid zero-initialising the full 2 KiB
        // `Tpm2bMaxBuffer::buffer`. TSS2 `Esys_HMAC` reads exactly
        // `size` bytes from `buffer[..size]` — the trailing region is
        // never observed by the TPM (TCG TPM 2.0 Part 2 §10.4: a TPM2B
        // is a size-prefixed buffer whose `size` field is the
        // authoritative read bound). We therefore allocate the stack
        // frame uninitialised via `MaybeUninit` and only write the
        // `size` field plus the framed prefix bytes.
        //
        // SAFETY: `Tpm2bMaxBuffer` is `#[repr(C)] { size: u16, buffer:
        // [u8; 2048] }` (see `types.rs`) — both fields are plain
        // integer-array types with no padding or drop hazards.
        // Raw-pointer writes through `addr_of_mut!` legally initialise
        // individual fields of a `MaybeUninit`-backed allocation
        // without first reading any uninitialised memory. After the
        // writes below, every byte the FFI will read (`size = u16` and
        // `buffer[..framed_len]`) is initialised; the tail
        // `buffer[framed_len..]` stays uninitialised, which is sound
        // because we hand the FFI a *shared reference* (`*const`
        // pointer in the TSS2 ABI; see `ffi.rs` → `esys_hmac.buffer`)
        // and TSS2 does not access the tail.
        let mut mac_input_uninit: core::mem::MaybeUninit<Tpm2bMaxBuffer> =
            core::mem::MaybeUninit::uninit();
        let mac_input_ptr = mac_input_uninit.as_mut_ptr();
        // SAFETY: `mac_input_ptr` points to writable, exclusively-owned
        // stack memory for a `Tpm2bMaxBuffer`. The `size` field is a
        // plain `u16` with no invariants — a direct field write via
        // `addr_of_mut!` is sound and does not read uninitialised
        // memory.
        unsafe {
            core::ptr::addr_of_mut!((*mac_input_ptr).size).write(framed_size);
        }
        // SAFETY: `addr_of_mut!((*mac_input_ptr).buffer)` yields a
        // `*mut [u8; 2048]` pointing at exclusively-owned, properly-
        // aligned memory. Writing `framed_len` consecutive bytes
        // starting at element 0 stays within the array (`framed_len <=
        // MAX_BUF = 2048` checked above). `core::ptr::copy_nonoverlapping`
        // performs raw byte writes without reading the destination, so
        // the uninitialised target is fine.
        unsafe {
            let buf_ptr = core::ptr::addr_of_mut!((*mac_input_ptr).buffer).cast::<u8>();
            let mut w = 0usize;
            core::ptr::copy_nonoverlapping(ETM_DOMAIN.as_ptr(), buf_ptr.add(w), 8);
            w += 8;
            core::ptr::copy_nonoverlapping(nonce.as_ptr(), buf_ptr.add(w), 12);
            w += 12;
            let aad_len_le = (aad.len() as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(aad_len_le.as_ptr(), buf_ptr.add(w), 8);
            w += 8;
            let ct_len_le = (ciphertext.len() as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(ct_len_le.as_ptr(), buf_ptr.add(w), 8);
            w += 8;
            core::ptr::copy_nonoverlapping(aad.as_ptr(), buf_ptr.add(w), aad.len());
            w += aad.len();
            core::ptr::copy_nonoverlapping(ciphertext.as_ptr(), buf_ptr.add(w), ciphertext.len());
            // w + ciphertext.len() == framed_len by construction.
            debug_assert_eq!(w + ciphertext.len(), framed_len);
        }

        // SAFETY: `mac_input_uninit` is now initialised for all bytes
        // the FFI will read: `size = framed_size` plus
        // `buffer[..framed_len]`. The unread tail
        // `buffer[framed_len..]` remains uninitialised; this is sound
        // because we expose only a shared reference to the FFI and
        // TSS2 honours the `size` prefix as the authoritative read
        // bound.
        let mac_input = unsafe { mac_input_uninit.assume_init_ref() };

        self.hmac_with_buf(h_mac, mac_input, tag_out)
    }

    /// HMAC core: accepts a pre-populated `Tpm2bMaxBuffer`. Truncates the
    /// ESAPI output to `TAG_LEN` bytes. Callers that already hold a
    /// `Tpm2bMaxBuffer` (e.g. `compute_etm_tag`) call this directly to
    /// avoid an extra copy.
    fn hmac_with_buf(
        &self,
        h_key: EsysTr,
        buf: &Tpm2bMaxBuffer,
        out: &mut [u8; TAG_LEN],
    ) -> Result<(), VsError> {
        let mut p_hmac: *mut Tpm2bDigest = core::ptr::null_mut();

        // SAFETY: h_key is valid; buf is valid stack data; p_hmac receives ESAPI alloc.
        // Audit M1: route auth via `auth_session()` for bus protection.
        let rc = unsafe {
            (self.fn_list.esys_hmac)(
                self.esys_ctx,
                h_key,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                buf,
                TPM2_ALG_SHA256,
                &mut p_hmac,
            )
        };
        check_rc(rc)?;

        let result = if p_hmac.is_null() {
            Err(VsError::CryptoError)
        } else {
            // SAFETY: p_hmac is non-null and points to a valid Tpm2bDigest.
            let mac = unsafe { &*p_hmac };
            // Audit H1: SHA-256 HMAC output must be exactly 32 bytes. Any
            // other size indicates TPM / TSS2 misbehaviour and must not
            // silently yield a truncated tag.
            if mac.size as usize == SHA256_LEN {
                out.copy_from_slice(&mac.buffer[..TAG_LEN]);
                Ok(())
            } else {
                Err(VsError::CryptoError)
            }
        };

        if !p_hmac.is_null() {
            // SAFETY: ESAPI-allocated, freed exactly once.
            unsafe { (self.fn_list.esys_free)(p_hmac as *mut core::ffi::c_void) };
        }
        result
    }

    /// Overload for callers providing a 32-byte MAC output buffer.
    fn hmac_sha256_full(
        &self,
        h_key: EsysTr,
        data: &[u8],
        out: &mut [u8; SHA256_LEN],
    ) -> Result<(), VsError> {
        if data.len() > MAX_BUF {
            return Err(VsError::InvalidInput);
        }
        let data_size = u16::try_from(data.len()).map_err(|_| VsError::InvalidInput)?;

        // PERF (P4): skip the 2 KiB zero-init of `Tpm2bMaxBuffer::buffer`
        // — TSS2 `Esys_HMAC` reads only `buffer[..size]` (TCG TPM 2.0
        // Part 2 §10.4). See the matching block in `compute_etm_tag`
        // for the full SAFETY argument; the same invariants hold here.
        let mut buf_uninit: core::mem::MaybeUninit<Tpm2bMaxBuffer> =
            core::mem::MaybeUninit::uninit();
        let buf_ptr_struct = buf_uninit.as_mut_ptr();
        // SAFETY: writing a `u16` into the `size` field of an
        // exclusively-owned `MaybeUninit<Tpm2bMaxBuffer>` via
        // `addr_of_mut!` does not read uninitialised memory.
        unsafe {
            core::ptr::addr_of_mut!((*buf_ptr_struct).size).write(data_size);
        }
        // SAFETY: `addr_of_mut!((*buf_ptr_struct).buffer)` yields a
        // `*mut [u8; 2048]` to exclusively-owned, properly-aligned
        // memory. We copy `data.len() <= MAX_BUF = 2048` bytes
        // starting at index 0 — in bounds — via raw-byte writes
        // (`copy_nonoverlapping`) which do not read the destination.
        unsafe {
            let buf_ptr = core::ptr::addr_of_mut!((*buf_ptr_struct).buffer).cast::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());
        }
        // SAFETY: `size = data_size` and `buffer[..data.len()]` are
        // now initialised. The trailing `buffer[data.len()..]` stays
        // uninitialised; TSS2 honours `size` as the authoritative
        // read bound and we expose only a shared reference (no value
        // copy), so the tail is never read.
        // SAFETY (P4): we wrote `size` and `buffer[..data.len()]` above, so
        // those fields are initialised. The tail of `buffer` is uninitialised
        // but never read by the FFI (TSS2 reads only `buffer[..size]`). We
        // take `&mut` here because `zeroize_max_buffer` at the end of this
        // function needs mutable access to wipe the secret-bearing prefix.
        let buf: &mut Tpm2bMaxBuffer = unsafe { buf_uninit.assume_init_mut() };

        let mut p_hmac: *mut Tpm2bDigest = core::ptr::null_mut();

        // SAFETY: same as hmac_internal.
        // Audit M1: route auth via `auth_session()` for bus protection.
        let rc = unsafe {
            (self.fn_list.esys_hmac)(
                self.esys_ctx,
                h_key,
                self.auth_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                buf,
                TPM2_ALG_SHA256,
                &mut p_hmac,
            )
        };

        // Audit HIGH-J: `buf` carries the HMAC input (which is secret-bearing
        // in any KDF / authenticator use-case). Wipe before return regardless
        // of which sub-step failed.
        let rc_result = check_rc(rc);
        let result = if rc_result.is_err() {
            rc_result
        } else if p_hmac.is_null() {
            Err(VsError::CryptoError)
        } else {
            let mac = unsafe { &*p_hmac };
            if mac.size as usize == SHA256_LEN {
                out.copy_from_slice(&mac.buffer[..SHA256_LEN]);
                Ok(())
            } else {
                Err(VsError::CryptoError)
            }
        };

        if !p_hmac.is_null() {
            unsafe { (self.fn_list.esys_free)(p_hmac as *mut core::ffi::c_void) };
        }

        // Audit HIGH-J: wipe stack-resident HMAC input before return.
        // `buf` is already `&mut Tpm2bMaxBuffer` from the P4 `assume_init_mut`,
        // so reborrow rather than re-take `&mut` (which would give
        // `&mut &mut _`).
        zeroize_max_buffer(buf);
        result
    }
}

// The dangling design-comment block that previously sat here described
// behaviour already satisfied by the `CryptoProvider::hmac_sha256` impl
// above (which writes the full 32-byte HMAC-SHA-256 into `mac_out`). No
// further override is needed.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

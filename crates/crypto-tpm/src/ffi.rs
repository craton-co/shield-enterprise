// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! TPM 2.0 TSS2 ESAPI function pointer table.
//!
//! Rather than declaring link-time `extern "C"` symbols (which would require
//! the TSS2 libraries at link time), this crate accepts a [`TpmFunctionList`]
//! struct populated by the caller. The caller is responsible for linking
//! `libtss2-esys` and resolving the function pointers before constructing a
//! [`super::TpmCryptoProvider`].
//!
//! This design:
//! - Keeps the crate `no_std` compatible (no `libtss2` linkage).
//! - Allows runtime selection of TPM backends without recompilation.
//! - Enables unit testing with pure-Rust mock implementations.

use crate::types::{
    EsysContext, EsysTr, Tpm2AlgId, Tpm2Handle, Tpm2Se, Tpm2bData, Tpm2bDigest, Tpm2bEccPoint,
    Tpm2bMaxBuffer, Tpm2bNonce, Tpm2bPublic, Tpm2bSensitive, TpmaSession, TpmiYesNo, TpmlDigest,
    TpmlPcrSelection, TpmtSignature, TpmtSymDef, TpmtTkHashcheck, TpmtTkVerified, Tss2Rc,
    Tss2TctiContext,
};

/// Complete TSS2 ESAPI function pointer table.
///
/// Holds only the ESAPI functions used by [`super::TpmCryptoProvider`].
/// All fields must be valid function pointers before being passed to
/// [`super::TpmCryptoProvider::new`].
#[derive(Clone, Copy)]
pub struct TpmFunctionList {
    // -----------------------------------------------------------------------
    // Context lifecycle
    // -----------------------------------------------------------------------
    /// `Esys_Initialize` — create and connect an ESAPI context.
    ///
    /// Pass `null` for `tctiContext` to use the system default TCTI
    /// (reads `TPM2TOOLS_TCTI` / `TCTI` env var, or `/dev/tpmrm0`).
    pub esys_initialize: unsafe extern "C" fn(
        esys_context: *mut *mut EsysContext,
        tcti_context: *mut Tss2TctiContext,
        abi_version: *mut core::ffi::c_void,
    ) -> Tss2Rc,

    /// `Esys_Finalize` — disconnect and free the ESAPI context.
    pub esys_finalize: unsafe extern "C" fn(context: *mut *mut EsysContext),

    // -----------------------------------------------------------------------
    // Self-test
    // -----------------------------------------------------------------------
    /// `Esys_SelfTest` — command the TPM to run its built-in self-tests.
    ///
    /// Pass `TPMI_YES` for `fullTest` to run all tests (slower but thorough).
    pub esys_self_test: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        full_test: TpmiYesNo,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // Hash (SHA-256)
    // -----------------------------------------------------------------------
    /// `Esys_Hash` — compute a hash using the TPM's hash engine.
    pub esys_hash: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        data: *const Tpm2bMaxBuffer,
        hash_alg: Tpm2AlgId,
        hierarchy: EsysTr,
        out_hash: *mut *mut Tpm2bDigest,
        out_validation: *mut *mut TpmtTkHashcheck,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // HMAC
    // -----------------------------------------------------------------------
    /// `Esys_HMAC` — compute HMAC using a key loaded in the TPM.
    pub esys_hmac: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        buffer: *const Tpm2bMaxBuffer,
        hash_alg: Tpm2AlgId,
        out_outhmac: *mut *mut Tpm2bDigest,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // Symmetric encryption (AES-CFB — TPM native)
    // -----------------------------------------------------------------------
    /// `Esys_EncryptDecrypt2` — symmetric encrypt or decrypt using a loaded key.
    ///
    /// For AES-256 in CFB mode, pass:
    /// - `decrypt = TPMI_NO` for encryption
    /// - `decrypt = TPMI_YES` for decryption
    /// - `mode = TPM2_ALG_CFB`
    pub esys_encrypt_decrypt2: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        key_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        decrypt: TpmiYesNo,
        mode: Tpm2AlgId,
        iv_in: *const Tpm2bData,
        in_data: *const Tpm2bMaxBuffer,
        out_out_data: *mut *mut Tpm2bMaxBuffer,
        out_iv_out: *mut *mut Tpm2bData,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // ECDSA sign / verify
    // -----------------------------------------------------------------------
    /// `Esys_Sign` — sign a digest using a loaded ECC key.
    pub esys_sign: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        key_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        digest: *const Tpm2bDigest,
        in_scheme: *const core::ffi::c_void, // TPMT_SIG_SCHEME*
        validation: *const TpmtTkHashcheck,
        out_signature: *mut *mut TpmtSignature,
    ) -> Tss2Rc,

    /// `Esys_VerifySignature` — verify an ECDSA signature against a loaded key.
    pub esys_verify_signature: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        key_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        digest: *const Tpm2bDigest,
        signature: *const TpmtSignature,
        out_validation: *mut *mut TpmtTkVerified,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // ECDH key agreement
    // -----------------------------------------------------------------------
    /// `Esys_ECDH_ZGen` — compute the ECDH shared secret (Z-point).
    ///
    /// Returns the EC point `[d]Q` where `d` is the key's private scalar
    /// and `Q` is the peer's public key. Only the x-coordinate is used
    /// as the shared secret.
    pub esys_ecdh_zgen: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        key_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        in_point: *const Tpm2bEccPoint,
        out_out_point: *mut *mut Tpm2bEccPoint,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // Random number generation
    // -----------------------------------------------------------------------
    /// `Esys_GetRandom` — obtain random bytes from the TPM TRNG.
    pub esys_get_random: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        bytes_requested: u16,
        out_random_bytes: *mut *mut Tpm2bDigest,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // PCR operations (TPM-specific extensions, not part of CryptoProvider)
    // -----------------------------------------------------------------------
    /// `Esys_PCR_Extend` — extend a PCR with a new measurement.
    pub esys_pcr_extend: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        pcr_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        digests: *const crate::types::TpmlDigestValues,
    ) -> Tss2Rc,

    /// `Esys_PCR_Read` — read the current value of one or more PCRs.
    pub esys_pcr_read: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        pcr_selection_in: *const TpmlPcrSelection,
        out_pcr_update_counter: *mut u32,
        out_pcr_selection_out: *mut *mut TpmlPcrSelection,
        out_pcr_values: *mut *mut TpmlDigest,
    ) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // Memory management (TSS2_MU / ESAPI allocates; we must free)
    // -----------------------------------------------------------------------
    /// `Esys_Free` — release ESAPI-allocated memory.
    ///
    /// All `*mut *mut T` out-parameters from ESAPI calls are heap-allocated
    /// by the library. This function must be called to release them.
    pub esys_free: unsafe extern "C" fn(ptr: *mut core::ffi::c_void),

    // -----------------------------------------------------------------------
    // Key loading (transient key handles)
    // -----------------------------------------------------------------------
    /// `Esys_TR_FromTPMPublic` — load a persistent key by its TPM handle,
    /// returning an `ESYS_TR` for use in crypto operations.
    pub esys_tr_from_tpm_public: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        tpm_handle: Tpm2Handle,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        out_object: *mut EsysTr,
    ) -> Tss2Rc,

    /// `Esys_TR_Close` — flush a transient `ESYS_TR` without destroying the
    /// underlying TPM object.
    pub esys_tr_close:
        unsafe extern "C" fn(esys_context: *mut EsysContext, object: *mut EsysTr) -> Tss2Rc,

    /// `Esys_LoadExternal` — load an external public (and optionally
    /// sensitive) key into the TPM, returning a transient `ESYS_TR` suitable
    /// for `Esys_VerifySignature`. Used by [`super::TpmCryptoProvider::verify_p256`]
    /// to bind the caller-supplied public key for the duration of one verify
    /// operation (audit fix C4).
    pub esys_load_external: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        in_private: *const Tpm2bSensitive,
        in_public: *const Tpm2bPublic,
        hierarchy: EsysTr,
        out_object_handle: *mut EsysTr,
    ) -> Tss2Rc,

    /// `Esys_FlushContext` — evict a transient object from the TPM.
    /// Used by `delete_key` (audit item 9) and the transient-handle cleanup
    /// in `verify_p256` (audit item 4).
    pub esys_flush_context:
        unsafe extern "C" fn(esys_context: *mut EsysContext, flush_handle: EsysTr) -> Tss2Rc,

    // -----------------------------------------------------------------------
    // Audit M1 — HMAC session for TPM-bus protection
    // -----------------------------------------------------------------------
    /// `Esys_StartAuthSession` — open a session (HMAC, policy, or trial)
    /// that can be used as the auth handle for subsequent TPM commands.
    ///
    /// Used by [`super::TpmCryptoProvider::enable_bus_integrity`] to open
    /// an HMAC integrity session over the TPM bus, so that command and
    /// response parameters carry an HMAC tag that an attacker cannot
    /// forge without the session key (audit fix M1 / H1). Parameter
    /// **encryption** is NOT enabled by this entry — see the security
    /// notes on `enable_bus_integrity`.
    ///
    /// Parameters mirror the TSS2 ESAPI signature: `tpm_key` and `bind` are
    /// optional salt / bind handles (`ESYS_TR_NONE` ⇒ unsalted, unbound —
    /// the simplest configuration suitable for HMAC integrity). The
    /// caller-supplied `nonce_caller` may be `NULL`, in which case the TPM
    /// generates the initial nonce.
    pub esys_start_auth_session: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        tpm_key: EsysTr,
        bind: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        nonce_caller: *const Tpm2bNonce,
        session_type: Tpm2Se,
        symmetric: *const TpmtSymDef,
        auth_hash: Tpm2AlgId,
        out_session_handle: *mut EsysTr,
    ) -> Tss2Rc,

    /// `Esys_TRSess_SetAttributes` — set the `TPMA_SESSION` attribute
    /// bitfield on an existing session handle returned by
    /// [`esys_start_auth_session`](Self::esys_start_auth_session).
    ///
    /// Audit H1 + M3: the bus-integrity wiring uses this entry to set
    /// `TPMA_SESSION_CONTINUE_SESSION` on the freshly-opened HMAC
    /// session so the session survives past one command. Without it,
    /// the TPM tears the session down after the first use and every
    /// subsequent provider command falls back to the unsalted password
    /// session — silently downgrading the integrity guarantee.
    ///
    /// The `mask` argument selects which bits of `flags` are applied;
    /// other bits are left at their current value. Passing
    /// `flags == mask` therefore *sets* the masked bits, and `flags == 0
    /// && mask != 0` *clears* them.
    ///
    /// # Host integration
    ///
    /// The host populating [`TpmFunctionList`] MUST resolve this
    /// symbol from `libtss2-esys.so`. Older TSS2 builds (< 2.4.0) shipped
    /// the function but did not export it in the headers; on those
    /// builds, dynamic resolution via `dlsym("Esys_TRSess_SetAttributes")`
    /// is required.
    pub esys_tr_sess_set_attributes: unsafe extern "C" fn(
        esys_context: *mut EsysContext,
        session: EsysTr,
        flags: TpmaSession,
        mask: TpmaSession,
    ) -> Tss2Rc,
}

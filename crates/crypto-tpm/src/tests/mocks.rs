// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Shared mock TSS2 ESAPI implementation used by the in-crate unit tests.
//!
//! All allocations use `static mut` storage to avoid heap. Tests use
//! `#[serial]` (from `serial_test`) to prevent concurrent access to this
//! shared mock state. Per-test failure mocks live alongside their
//! `#[test]` functions in `crate::tests`.

#![allow(static_mut_refs)] // Test-only static-mut counters; serialised by #[serial].

use super::super::*;
use types::{
    EsysTr, Tpm2AlgId, Tpm2bData, Tpm2bDigest, Tpm2bEccPoint, Tpm2bMaxBuffer, TpmiYesNo,
    TpmlPcrSelection, TpmtSignature, TpmtTkHashcheck, Tss2Rc, Tss2TctiContext,
};

// -----------------------------------------------------------------------
// Mock TSS2 ESAPI implementation
//
// All allocations use static mutable storage to avoid heap.
// Tests use #[serial] to prevent concurrent access to shared mock state.
// -----------------------------------------------------------------------

pub(super) static mut MOCK_DIGEST_BUF: Tpm2bDigest = Tpm2bDigest {
    size: 0,
    buffer: [0u8; 64],
};
pub(super) static mut MOCK_MAX_BUF: Tpm2bMaxBuffer = Tpm2bMaxBuffer {
    size: 0,
    buffer: [0u8; 2048],
};
pub(super) static mut MOCK_IV_BUF: Tpm2bData = Tpm2bData {
    size: 0,
    buffer: [0u8; 64],
};
static mut MOCK_ECC_POINT: Tpm2bEccPoint = Tpm2bEccPoint {
    size: 0,
    point: TpmsEccPoint {
        x: types::Tpm2bEccParameter {
            size: 32,
            buffer: [0xAA; 32],
        },
        y: types::Tpm2bEccParameter {
            size: 32,
            buffer: [0xBB; 32],
        },
    },
};
static mut MOCK_SIG: TpmtSignature = TpmtSignature {
    sig_alg: TPM2_ALG_ECDSA,
    signature: TpmuSignature {
        _padding: [0u8; 288],
    },
};
static mut MOCK_PCR_SEL: TpmlPcrSelection = TpmlPcrSelection {
    count: 1,
    pcr_selections: [types::TpmsPcrSelection {
        hash: TPM2_ALG_SHA256,
        sizeof_select: 4,
        pcr_select: [0u8; 4],
    }; 16],
};
static mut MOCK_DIGEST_LIST: types::TpmlDigest = types::TpmlDigest {
    count: 1,
    digests: [Tpm2bDigest {
        size: 32,
        buffer: [0xCCu8; 64],
    }; 8],
};
/// Default mock ticket for `verify_p256` — passes the audit-M4 ticket
/// inspection: tag = `TPM_ST_VERIFIED` (`0x8022`), hierarchy =
/// `TPM2_RH_NULL` (`0x4000_0007`), digest non-empty. Tests that want to
/// pin the ticket-rejection path mutate these fields before driving
/// `verify_p256` (see `verify_p256_rejects_malformed_ticket`).
pub(super) static mut MOCK_TK_VERIFIED: types::TpmtTkVerified = types::TpmtTkVerified {
    tag: 0x8022,
    hierarchy: 0x4000_0007,
    digest: Tpm2bDigest {
        size: 32,
        buffer: [0xA5u8; 64],
    },
};

// Sentinel non-null "context" pointer — we never dereference it in mocks.
static MOCK_CTX_SENTINEL: u8 = 0xFF;

pub(super) unsafe extern "C" fn mock_esys_initialize(
    ctx: *mut *mut EsysContext,
    _tcti: *mut Tss2TctiContext,
    _abi: *mut core::ffi::c_void,
) -> Tss2Rc {
    // SAFETY: ctx is a valid double pointer provided by new().
    unsafe { *ctx = &MOCK_CTX_SENTINEL as *const u8 as *mut EsysContext };
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_finalize(ctx: *mut *mut EsysContext) {
    // SAFETY: ctx is a valid double pointer.
    unsafe { *ctx = core::ptr::null_mut() };
}
pub(super) unsafe extern "C" fn mock_esys_self_test(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _full: TpmiYesNo,
) -> Tss2Rc {
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_hash(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    data: *const Tpm2bMaxBuffer,
    _alg: Tpm2AlgId,
    _hier: EsysTr,
    out_hash: *mut *mut Tpm2bDigest,
    out_val: *mut *mut TpmtTkHashcheck,
) -> Tss2Rc {
    // SAFETY: MOCK_DIGEST_BUF is a static that we write to and return.
    unsafe {
        let len = (*data).size as usize;
        MOCK_DIGEST_BUF.size = 32;
        for (i, b) in MOCK_DIGEST_BUF.buffer[..32].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(len as u8).wrapping_add(1);
        }
        *out_hash = &raw mut MOCK_DIGEST_BUF;
        *out_val = core::ptr::null_mut();
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_hmac(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _buf: *const Tpm2bMaxBuffer,
    _alg: Tpm2AlgId,
    out_hmac: *mut *mut Tpm2bDigest,
) -> Tss2Rc {
    // SAFETY: MOCK_DIGEST_BUF is a static that we write to and return.
    unsafe {
        MOCK_DIGEST_BUF.size = 32;
        MOCK_DIGEST_BUF.buffer[..32].fill(0xAB);
        *out_hmac = &raw mut MOCK_DIGEST_BUF;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_encrypt_decrypt2(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _decrypt: TpmiYesNo,
    _mode: Tpm2AlgId,
    _iv: *const Tpm2bData,
    in_data: *const Tpm2bMaxBuffer,
    out_data: *mut *mut Tpm2bMaxBuffer,
    out_iv: *mut *mut Tpm2bData,
) -> Tss2Rc {
    // SAFETY: MOCK_MAX_BUF is a static; in_data is a valid stack pointer.
    unsafe {
        let size = (*in_data).size;
        MOCK_MAX_BUF.size = size;
        MOCK_MAX_BUF.buffer[..size as usize]
            .copy_from_slice(&(&(*in_data).buffer)[..size as usize]);
        *out_data = &raw mut MOCK_MAX_BUF;
        *out_iv = &raw mut MOCK_IV_BUF;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_sign(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _digest: *const Tpm2bDigest,
    _scheme: *const core::ffi::c_void,
    _val: *const TpmtTkHashcheck,
    out_sig: *mut *mut TpmtSignature,
) -> Tss2Rc {
    // SAFETY: MOCK_SIG is a valid static.
    unsafe {
        MOCK_SIG.sig_alg = TPM2_ALG_ECDSA;
        // Write via the union padding to avoid UB (union access in mutable static).
        let ecdsa = &mut *(&raw mut MOCK_SIG.signature as *mut TpmsSignatureEcdsa);
        ecdsa.hash = TPM2_ALG_SHA256;
        ecdsa.signature_r.size = 32;
        ecdsa.signature_r.buffer.fill(0xDD);
        ecdsa.signature_s.size = 32;
        ecdsa.signature_s.buffer.fill(0xEE);
        *out_sig = &raw mut MOCK_SIG;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_verify_signature(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _digest: *const Tpm2bDigest,
    _sig: *const TpmtSignature,
    out_val: *mut *mut types::TpmtTkVerified,
) -> Tss2Rc {
    // SAFETY: MOCK_TK_VERIFIED is a valid static.
    unsafe { *out_val = &raw mut MOCK_TK_VERIFIED };
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_ecdh_zgen(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _in_pt: *const Tpm2bEccPoint,
    out_pt: *mut *mut Tpm2bEccPoint,
) -> Tss2Rc {
    // SAFETY: MOCK_ECC_POINT is a valid static with pre-filled data.
    unsafe {
        MOCK_ECC_POINT.point.x.size = 32;
        MOCK_ECC_POINT.point.y.size = 32;
        *out_pt = &raw mut MOCK_ECC_POINT;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_get_random(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    bytes: u16,
    out_rnd: *mut *mut Tpm2bDigest,
) -> Tss2Rc {
    // SAFETY: MOCK_DIGEST_BUF is a valid static.
    unsafe {
        MOCK_DIGEST_BUF.size = bytes;
        for (i, b) in MOCK_DIGEST_BUF.buffer[..bytes as usize]
            .iter_mut()
            .enumerate()
        {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        *out_rnd = &raw mut MOCK_DIGEST_BUF;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_pcr_extend(
    _ctx: *mut EsysContext,
    _pcr: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _digests: *const types::TpmlDigestValues,
) -> Tss2Rc {
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_pcr_read(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _sel: *const TpmlPcrSelection,
    out_ctr: *mut u32,
    out_sel: *mut *mut TpmlPcrSelection,
    out_vals: *mut *mut types::TpmlDigest,
) -> Tss2Rc {
    // SAFETY: statics are valid; all pointers are valid out-params.
    unsafe {
        *out_ctr = 1;
        *out_sel = &raw mut MOCK_PCR_SEL;
        *out_vals = &raw mut MOCK_DIGEST_LIST;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_tr_from_tpm_public(
    _ctx: *mut EsysContext,
    _handle: types::Tpm2Handle,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    out: *mut EsysTr,
) -> Tss2Rc {
    // SAFETY: out is a valid writable pointer.
    unsafe { *out = 0x0001 };
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_tr_close(
    _ctx: *mut EsysContext,
    obj: *mut EsysTr,
) -> Tss2Rc {
    // SAFETY: `obj` is a valid writable pointer; serial test → no
    // concurrent access to the static counters.
    unsafe {
        let handle = *obj;
        if TR_CLOSE_CALLS < TR_CLOSE_HANDLES.len() {
            TR_CLOSE_HANDLES[TR_CLOSE_CALLS] = handle;
        }
        TR_CLOSE_CALLS += 1;
        TR_CLOSE_SEQ = CLEANUP_SEQ;
        CLEANUP_SEQ = CLEANUP_SEQ.wrapping_add(1);
        // ESAPI sets the handle to `ESYS_TR_NONE` on success.
        *obj = ESYS_TR_NONE;
    }
    types::TSS2_RC_SUCCESS
}
pub(super) unsafe extern "C" fn mock_esys_free(_ptr: *mut core::ffi::c_void) {
    // No-op: our mock "allocations" are statics.
}

// -----------------------------------------------------------------------
// Instrumentation counters for audit-fix tests.
// -----------------------------------------------------------------------
//
// These `static mut` are accessed only from `#[serial]` tests on a
// single thread, so concurrent access is impossible. The 2024-edition
// lint `static_mut_refs` is silenced module-wide above.

pub(super) static mut LOAD_EXTERNAL_CALLS: usize = 0;
/// The x-coordinate bytes observed by the most recent load-external call.
pub(super) static mut LOAD_EXTERNAL_LAST_X: [u8; 32] = [0u8; 32];
/// The y-coordinate bytes observed by the most recent load-external call.
pub(super) static mut LOAD_EXTERNAL_LAST_Y: [u8; 32] = [0u8; 32];
pub(super) static mut FLUSH_CONTEXT_CALLS: usize = 0;
/// Handles observed by flush-context, in call order (small cap).
pub(super) static mut FLUSH_CONTEXT_HANDLES: [EsysTr; 16] = [ESYS_TR_NONE; 16];
pub(super) static mut TR_CLOSE_CALLS: usize = 0;
/// Handles observed by `Esys_TR_Close`, in call order (small cap).
pub(super) static mut TR_CLOSE_HANDLES: [EsysTr; 16] = [ESYS_TR_NONE; 16];

// Monotonic sequence number used to verify the FlushContext → TR_Close
// ordering inside `TransientHandle::drop`. Each cleanup step records the
// value of `CLEANUP_SEQ` at the time it is invoked, then bumps it.
pub(super) static mut CLEANUP_SEQ: u32 = 0;
/// Sequence number observed by the most recent `Esys_FlushContext` call.
pub(super) static mut FLUSH_CONTEXT_SEQ: u32 = u32::MAX;
/// Sequence number observed by the most recent `Esys_TR_Close` call.
pub(super) static mut TR_CLOSE_SEQ: u32 = u32::MAX;

pub(super) fn reset_counters() {
    // SAFETY: tests are serialised via #[serial]; no concurrent access.
    unsafe {
        LOAD_EXTERNAL_CALLS = 0;
        LOAD_EXTERNAL_LAST_X = [0u8; 32];
        LOAD_EXTERNAL_LAST_Y = [0u8; 32];
        FLUSH_CONTEXT_CALLS = 0;
        FLUSH_CONTEXT_HANDLES = [ESYS_TR_NONE; 16];
        TR_CLOSE_CALLS = 0;
        TR_CLOSE_HANDLES = [ESYS_TR_NONE; 16];
        CLEANUP_SEQ = 0;
        FLUSH_CONTEXT_SEQ = u32::MAX;
        TR_CLOSE_SEQ = u32::MAX;
        START_AUTH_SESSION_CALLS = 0;
        START_AUTH_SESSION_LAST_NONCE_SIZE = 0;
        TR_SESS_SET_ATTRIBUTES_CALLS = 0;
        TR_SESS_SET_ATTRIBUTES_LAST_SESSION = ESYS_TR_NONE;
        TR_SESS_SET_ATTRIBUTES_LAST_FLAGS = 0;
        TR_SESS_SET_ATTRIBUTES_LAST_MASK = 0;
    }
}

pub(super) unsafe extern "C" fn mock_esys_load_external(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _in_private: *const types::Tpm2bSensitive,
    in_public: *const types::Tpm2bPublic,
    _hier: EsysTr,
    out_handle: *mut EsysTr,
) -> Tss2Rc {
    // SAFETY: in_public is a valid stack pointer provided by the provider.
    unsafe {
        LOAD_EXTERNAL_CALLS += 1;
        let x = (*in_public).public_area.unique.ecc.x.buffer;
        let y = (*in_public).public_area.unique.ecc.y.buffer;
        LOAD_EXTERNAL_LAST_X.copy_from_slice(&x);
        LOAD_EXTERNAL_LAST_Y.copy_from_slice(&y);
        // Return a synthetic non-none handle.
        *out_handle = 0x0FEE_D001;
    }
    types::TSS2_RC_SUCCESS
}

pub(super) unsafe extern "C" fn mock_esys_flush_context(
    _ctx: *mut EsysContext,
    handle: EsysTr,
) -> Tss2Rc {
    // SAFETY: serial test; single-threaded static mutation.
    unsafe {
        if FLUSH_CONTEXT_CALLS < FLUSH_CONTEXT_HANDLES.len() {
            FLUSH_CONTEXT_HANDLES[FLUSH_CONTEXT_CALLS] = handle;
        }
        FLUSH_CONTEXT_CALLS += 1;
        FLUSH_CONTEXT_SEQ = CLEANUP_SEQ;
        CLEANUP_SEQ = CLEANUP_SEQ.wrapping_add(1);
    }
    types::TSS2_RC_SUCCESS
}

// Audit M1: mock `Esys_StartAuthSession` for the bus-protection path.
// Returns a synthetic non-`ESYS_TR_NONE` session handle so the provider
// stores it in `bus_protection_session` and routes subsequent commands
// through `auth_session()`.
pub(super) const MOCK_SESSION_HANDLE: EsysTr = 0x0BAD_5E55;
pub(super) static mut START_AUTH_SESSION_CALLS: usize = 0;
/// The most recent `nonce_caller` size observed by
/// `mock_esys_start_auth_session`. Audit M3: tests assert this is `32`
/// (i.e., the provider supplied a non-null 32-byte nonce) rather than
/// `0` (the old null-nonce behaviour).
pub(super) static mut START_AUTH_SESSION_LAST_NONCE_SIZE: u16 = 0;

pub(super) unsafe extern "C" fn mock_esys_start_auth_session(
    _ctx: *mut types::EsysContext,
    _tpm_key: EsysTr,
    _bind: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    nonce: *const types::Tpm2bNonce,
    _session_type: types::Tpm2Se,
    _symmetric: *const types::TpmtSymDef,
    _hash: Tpm2AlgId,
    out_session: *mut EsysTr,
) -> Tss2Rc {
    // SAFETY: serial test → exclusive access to the counter; out_session
    // is a writable pointer provided by the provider. `nonce` may be
    // null (old behaviour) or point to a valid Tpm2bNonce (new
    // behaviour) — we record the size so tests can assert the audit-M3
    // contract.
    unsafe {
        START_AUTH_SESSION_CALLS += 1;
        START_AUTH_SESSION_LAST_NONCE_SIZE = if nonce.is_null() { 0 } else { (*nonce).size };
        *out_session = MOCK_SESSION_HANDLE;
    }
    types::TSS2_RC_SUCCESS
}

// Audit H1: mock `Esys_TRSess_SetAttributes`. Tracks call count and the
// most recent (flags, mask, session) so positive / negative tests can
// confirm the bus-integrity wiring sets `TPMA_SESSION_CONTINUE_SESSION`
// after `Esys_StartAuthSession` succeeds.
pub(super) static mut TR_SESS_SET_ATTRIBUTES_CALLS: usize = 0;
pub(super) static mut TR_SESS_SET_ATTRIBUTES_LAST_SESSION: EsysTr = ESYS_TR_NONE;
pub(super) static mut TR_SESS_SET_ATTRIBUTES_LAST_FLAGS: types::TpmaSession = 0;
pub(super) static mut TR_SESS_SET_ATTRIBUTES_LAST_MASK: types::TpmaSession = 0;

pub(super) unsafe extern "C" fn mock_esys_tr_sess_set_attributes(
    _ctx: *mut types::EsysContext,
    session: EsysTr,
    flags: types::TpmaSession,
    mask: types::TpmaSession,
) -> Tss2Rc {
    // SAFETY: serial test → exclusive access to the counters.
    unsafe {
        TR_SESS_SET_ATTRIBUTES_CALLS += 1;
        TR_SESS_SET_ATTRIBUTES_LAST_SESSION = session;
        TR_SESS_SET_ATTRIBUTES_LAST_FLAGS = flags;
        TR_SESS_SET_ATTRIBUTES_LAST_MASK = mask;
    }
    types::TSS2_RC_SUCCESS
}

pub(super) fn mock_fn_list() -> TpmFunctionList {
    TpmFunctionList {
        esys_initialize: mock_esys_initialize,
        esys_finalize: mock_esys_finalize,
        esys_self_test: mock_esys_self_test,
        esys_hash: mock_esys_hash,
        esys_hmac: mock_esys_hmac,
        esys_encrypt_decrypt2: mock_esys_encrypt_decrypt2,
        esys_sign: mock_esys_sign,
        esys_verify_signature: mock_esys_verify_signature,
        esys_ecdh_zgen: mock_esys_ecdh_zgen,
        esys_get_random: mock_esys_get_random,
        esys_pcr_extend: mock_esys_pcr_extend,
        esys_pcr_read: mock_esys_pcr_read,
        esys_tr_from_tpm_public: mock_esys_tr_from_tpm_public,
        esys_tr_close: mock_esys_tr_close,
        esys_free: mock_esys_free,
        esys_load_external: mock_esys_load_external,
        esys_flush_context: mock_esys_flush_context,
        esys_start_auth_session: mock_esys_start_auth_session,
        esys_tr_sess_set_attributes: mock_esys_tr_sess_set_attributes,
    }
}

pub(super) fn provider_with_key(key_id: KeyId, handle: EsysTr) -> TpmCryptoProvider {
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.register_key_handle(key_id, handle).unwrap();
    // Register a distinct MAC handle so AEAD tests exercise the real
    // key-separation path (audit fix C1). Handle value is arbitrary
    // provided it differs from `handle`.
    p.register_mac_key_handle(key_id, handle.wrapping_add(1000))
        .unwrap();
    p
}

/// The uncompressed bytes of the P-256 generator `G`. Used by tests
/// that need a valid on-curve point without pulling a P-256 crate.
pub(super) const P256_GENERATOR: [u8; 65] = [
    0x04, // X
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    // Y
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

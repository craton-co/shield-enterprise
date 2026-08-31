// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Shared mock PKCS#11 implementation used by the in-crate unit tests.
//!
//! These bare `extern "C"` functions stand in for a real PKCS#11 library.
//! They are intentionally minimal: they return `CKR_OK` and write
//! deterministic test data to output buffers. Per-test failure mocks
//! (which often pair with their own static counters) live alongside their
//! `#[test]` functions in `crate::tests`.

use super::super::*;

// -----------------------------------------------------------------------
// Mock PKCS#11 implementation
//
// These bare `extern "C"` functions stand in for a real PKCS#11 library.
// They are intentionally minimal: they return CKR_OK and write
// deterministic test data to output buffers.
// -----------------------------------------------------------------------

pub(super) unsafe extern "C" fn mock_c_initialize(_: *mut core::ffi::c_void) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_finalize(_: *mut core::ffi::c_void) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_open_session(
    _slot: types::CkSlotId,
    _flags: types::CkFlags,
    _app: *mut core::ffi::c_void,
    _notify: Option<
        unsafe extern "C" fn(
            types::CkSessionHandle,
            types::CkUlong,
            *mut core::ffi::c_void,
        ) -> types::CkRv,
    >,
    ph_session: *mut types::CkSessionHandle,
) -> types::CkRv {
    // SAFETY: caller guarantees ph_session is a valid writable pointer.
    unsafe { *ph_session = 1 };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_close_session(_: types::CkSessionHandle) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_logout(_: types::CkSessionHandle) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_login(
    _: types::CkSessionHandle,
    _: types::CkUserType,
    _: *const types::CkByte,
    _: types::CkUlong,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_get_token_info(
    _: types::CkSlotId,
    _: *mut types::CkTokenInfo,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_find_objects_init(
    _: types::CkSessionHandle,
    _: *const types::CkAttribute,
    _: types::CkUlong,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_find_objects(
    _: types::CkSessionHandle,
    _: *mut types::CkObjectHandle,
    _: types::CkUlong,
    pul: *mut types::CkUlong,
) -> types::CkRv {
    // SAFETY: pul is a valid writable pointer.
    unsafe { *pul = 0 };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_find_objects_final(
    _: types::CkSessionHandle,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_get_attribute_value(
    _: types::CkSessionHandle,
    _: types::CkObjectHandle,
    p_template: *mut types::CkAttribute,
    ul_count: types::CkUlong,
) -> types::CkRv {
    // Write 32 bytes of deterministic data to CKA_VALUE buffers.
    // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
    // for pointer-arithmetic and slice construction.
    let count = ul_count as usize;
    for i in 0..count {
        // SAFETY: p_template is a valid slice of CkAttribute structs.
        let attr = unsafe { &mut *p_template.add(i) };
        if !attr.p_value.is_null() && attr.ul_value_len >= 32 {
            // SAFETY: p_value was set to a valid buffer by the caller.
            let slice = unsafe {
                core::slice::from_raw_parts_mut(
                    attr.p_value as *mut u8,
                    attr.ul_value_len as usize,
                )
            };
            for (j, byte) in slice.iter_mut().enumerate() {
                *byte = (j as u8).wrapping_add(0xAB);
            }
        }
    }
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_encrypt_init(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_encrypt(
    _: types::CkSessionHandle,
    p_data: *const types::CkByte,
    ul_data_len: types::CkUlong,
    p_out: *mut types::CkByte,
    pul_out_len: *mut types::CkUlong,
) -> types::CkRv {
    // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
    // for pointer-arithmetic and slice construction.
    let len = ul_data_len as usize;
    // SAFETY: slices constructed from valid pointers provided by the caller.
    let src = unsafe { core::slice::from_raw_parts(p_data, len) };
    let total = len + GCM_TAG_LEN;
    let dst = unsafe { core::slice::from_raw_parts_mut(p_out, total) };
    dst[..len].copy_from_slice(src); // "encrypt" = identity
    dst[len..].fill(0xBE); // deterministic tag
    unsafe { *pul_out_len = total as types::CkUlong };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_decrypt_init(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_decrypt(
    _: types::CkSessionHandle,
    p_enc: *const types::CkByte,
    ul_enc_len: types::CkUlong,
    p_out: *mut types::CkByte,
    pul_out_len: *mut types::CkUlong,
) -> types::CkRv {
    // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
    // for pointer-arithmetic and slice construction.
    let total = ul_enc_len as usize;
    if total < GCM_TAG_LEN {
        return types::CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    let pt_len = total - GCM_TAG_LEN;
    // SAFETY: slices are valid for their respective sizes.
    let src = unsafe { core::slice::from_raw_parts(p_enc, pt_len) };
    let dst = unsafe { core::slice::from_raw_parts_mut(p_out, pt_len) };
    dst.copy_from_slice(src);
    unsafe { *pul_out_len = pt_len as types::CkUlong };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_digest_init(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_digest(
    _: types::CkSessionHandle,
    _: *const types::CkByte,
    _: types::CkUlong,
    p_digest: *mut types::CkByte,
    pul_len: *mut types::CkUlong,
) -> types::CkRv {
    // Respect caller-supplied output buffer size (in/out parameter).
    // SAFETY: pul_len is a valid writable pointer.
    // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
    // for pointer-arithmetic and slice construction.
    let cap = unsafe { *pul_len } as usize;
    let len = cap.min(SHA256_LEN);
    // SAFETY: p_digest points to at least `cap` bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(p_digest, len) };
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(1);
    }
    unsafe { *pul_len = len as types::CkUlong };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_sign_init(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_sign(
    _: types::CkSessionHandle,
    _: *const types::CkByte,
    _: types::CkUlong,
    p_sig: *mut types::CkByte,
    pul_sig_len: *mut types::CkUlong,
) -> types::CkRv {
    // Per PKCS#11, `pul_sig_len` is in/out: caller supplies the output
    // buffer size. Respect it so the same mock can back both the
    // 32-byte HMAC and the 64-byte ECDSA code paths without overrunning
    // the caller's stack buffer.
    // SAFETY: pul_sig_len is a valid writable pointer.
    // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
    // for pointer-arithmetic and slice construction.
    let len = unsafe { *pul_sig_len } as usize;
    // SAFETY: p_sig points to `len` writable bytes as asserted by caller.
    let out = unsafe { core::slice::from_raw_parts_mut(p_sig, len) };
    // Audit fix FIX-3: align with HIGH-M position-varying sentinel.
    // The production wrapper pre-fills the output with `SENTINEL ^ i` and
    // rejects ANY byte still matching that pattern (sign_p256 SENTINEL=0x3C
    // over 64 bytes; hmac_sha256 SENTINEL=0x5A over 32 bytes). The
    // previous `(i + 0xCC) as u8` pattern collides with `0x3C ^ i` at
    // i = 56..59, producing a spurious `VsError::CryptoError`. 0x77 is a
    // safe constant because:
    //   0x77 == 0x3C ^ i → i = 0x4B = 75  (outside 0..64)
    //   0x77 == 0x5A ^ i → i = 0x2D = 45  (outside 0..32)
    out.fill(0x77);
    unsafe { *pul_sig_len = len as types::CkUlong };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_verify_init(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_verify(
    _: types::CkSessionHandle,
    _: *const types::CkByte,
    _: types::CkUlong,
    p_sig: *const types::CkByte,
    ul_sig_len: types::CkUlong,
) -> types::CkRv {
    // Accept any non-empty signature as valid (test only).
    if ul_sig_len == 0 || p_sig.is_null() {
        types::CKR_SIGNATURE_INVALID
    } else {
        types::CKR_OK
    }
}
pub(super) unsafe extern "C" fn mock_c_derive_key(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
    _: *const types::CkAttribute,
    _: types::CkUlong,
    ph_key: *mut types::CkObjectHandle,
) -> types::CkRv {
    // Return a sentinel non-zero handle for the derived key.
    // SAFETY: ph_key is a valid writable pointer.
    unsafe { *ph_key = 0xDEAD };
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_destroy_object(
    _: types::CkSessionHandle,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_generate_random(
    _: types::CkSessionHandle,
    p_buf: *mut types::CkByte,
    ul_len: types::CkUlong,
) -> types::CkRv {
    // SAFETY: p_buf is a valid writable buffer of ul_len bytes.
    // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
    // for slice construction.
    let out = unsafe { core::slice::from_raw_parts_mut(p_buf, ul_len as usize) };
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(0x42);
    }
    types::CKR_OK
}
pub(super) unsafe extern "C" fn mock_c_create_object(
    _: types::CkSessionHandle,
    _: *const types::CkAttribute,
    _: types::CkUlong,
    ph_obj: *mut types::CkObjectHandle,
) -> types::CkRv {
    // SAFETY: ph_obj is a valid writable pointer.
    unsafe { *ph_obj = 0xBEEF };
    types::CKR_OK
}

pub(super) fn mock_fn_list() -> Pkcs11FunctionList {
    Pkcs11FunctionList {
        c_initialize: mock_c_initialize,
        c_finalize: mock_c_finalize,
        c_open_session: mock_c_open_session,
        c_close_session: mock_c_close_session,
        c_logout: mock_c_logout,
        c_login: mock_c_login,
        c_get_token_info: mock_c_get_token_info,
        c_find_objects_init: mock_c_find_objects_init,
        c_find_objects: mock_c_find_objects,
        c_find_objects_final: mock_c_find_objects_final,
        c_get_attribute_value: mock_c_get_attribute_value,
        c_encrypt_init: mock_c_encrypt_init,
        c_encrypt: mock_c_encrypt,
        c_decrypt_init: mock_c_decrypt_init,
        c_decrypt: mock_c_decrypt,
        c_digest_init: mock_c_digest_init,
        c_digest: mock_c_digest,
        c_sign_init: mock_c_sign_init,
        c_sign: mock_c_sign,
        c_verify_init: mock_c_verify_init,
        c_verify: mock_c_verify,
        c_derive_key: mock_c_derive_key,
        c_destroy_object: mock_c_destroy_object,
        c_generate_random: mock_c_generate_random,
        c_create_object: mock_c_create_object,
        slot_id: 0,
        library_pre_initialized: 0,
    }
}

pub(super) fn provider_with_key(key_id: KeyId, handle: CkObjectHandle) -> Pkcs11CryptoProvider {
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"1234").unwrap();
    p.register_key_handle(key_id, handle).unwrap();
    p
}

/// Uncompressed bytes of the P-256 generator `G` — a guaranteed
/// on-curve point used by tests that exercise verify/ecdh paths.
pub(super) const P256_GENERATOR: [u8; 65] = [
    0x04, // X
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    // Y
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

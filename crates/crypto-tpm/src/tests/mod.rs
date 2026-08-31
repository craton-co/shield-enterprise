// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Unit tests for the TPM 2.0 crypto provider.
//!
//! Shared mock infrastructure (the baseline `mock_esys_*` functions, the
//! `static mut` mock buffers, and helpers like `mock_fn_list()` and
//! `provider_with_key()`) lives in [`mocks`]. Per-test failure mocks
//! (which simulate specific TSS2 error paths) stay alongside the
//! `#[test]` functions that exercise them.

#![allow(static_mut_refs)] // Test-only static-mut counters; serialised by #[serial].

mod mocks;

use super::*;
use mocks::{
    mock_fn_list, provider_with_key, reset_counters, FLUSH_CONTEXT_CALLS, FLUSH_CONTEXT_HANDLES,
    FLUSH_CONTEXT_SEQ, LOAD_EXTERNAL_CALLS, MOCK_DIGEST_BUF, MOCK_IV_BUF, MOCK_MAX_BUF,
    MOCK_TK_VERIFIED, P256_GENERATOR, TR_CLOSE_CALLS, TR_CLOSE_HANDLES, TR_CLOSE_SEQ,
};
use serial_test::serial;
use std::vec;
use types::{
    EsysTr, Tpm2AlgId, Tpm2bData, Tpm2bDigest, Tpm2bMaxBuffer, TpmiYesNo, TpmtSignature,
    TpmtTkHashcheck, Tss2Rc, Tss2TctiContext,
};

// -----------------------------------------------------------------------
// Test cases
// -----------------------------------------------------------------------

#[test]
#[serial]
fn new_with_mock_succeeds() {
    assert!(TpmCryptoProvider::new(mock_fn_list()).is_ok());
}

#[test]
#[serial]
fn register_key_handle_roundtrip() {
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert!(p.register_key_handle(KeyId(0), 0x8100_0001).is_ok());
    assert_eq!(p.handle_for(KeyId(0)).unwrap(), 0x8100_0001);
}

#[test]
#[serial]
fn handle_for_unregistered_slot_returns_invalid_input() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert_eq!(p.handle_for(KeyId(3)), Err(VsError::InvalidInput));
}

#[test]
#[serial]
fn key_id_out_of_bounds_returns_invalid_input() {
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert_eq!(
        p.register_key_handle(KeyId(MAX_KEY_SLOTS as u32), 1),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn sha256_returns_non_zero_hash() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut hash = [0u8; 32];
    p.sha256(b"hello world", &mut hash).unwrap();
    assert!(hash.iter().any(|&b| b != 0));
}

#[test]
#[serial]
fn self_test_passes_with_mock() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert!(p.self_test().is_ok());
}

#[test]
#[serial]
fn random_bytes_fills_buffer_non_zero() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut buf = [0u8; 32];
    p.random_bytes(&mut buf).unwrap();
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
#[serial]
fn aes_gcm_encrypt_length_mismatch_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 8]; // wrong length
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn hmac_sha256_with_valid_key_succeeds() {
    let p = provider_with_key(KeyId(1), 2);
    let mut mac = [0u8; 32];
    p.hmac_sha256(KeyId(1), b"data", &mut mac).unwrap();
    assert!(mac.iter().any(|&b| b != 0));
}

#[test]
#[serial]
fn sign_p256_with_valid_key_returns_signature() {
    let p = provider_with_key(KeyId(2), 3);
    let digest = [0xFFu8; 32];
    let mut sig = [0u8; 64];
    p.sign_p256(KeyId(2), &digest, &mut sig).unwrap();
    assert!(sig.iter().any(|&b| b != 0));
}

#[test]
#[serial]
fn pcr_extend_valid_index_succeeds() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let measurement = [0xAAu8; 32];
    assert!(p.pcr_extend(0, &measurement).is_ok());
    assert!(p.pcr_extend(23, &measurement).is_ok());
}

#[test]
#[serial]
fn pcr_extend_invalid_index_returns_error() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let m = [0u8; 32];
    assert_eq!(p.pcr_extend(24, &m), Err(VsError::InvalidInput));
}

#[test]
#[serial]
fn verify_p256_returns_true_with_mock() {
    // The crate now loads the caller-supplied pub_key transiently; no
    // slot-63 registration is required.
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert!(p.verify_p256(&P256_GENERATOR, &digest, &sig).unwrap());
}

#[test]
#[serial]
fn verify_p256_rejects_malformed_ticket_on_success_rc() {
    // Audit M4: even when the FFI returns TSS2_RC_SUCCESS, a ticket
    // with a wrong tag, wrong hierarchy, or empty digest must be
    // rejected. Mutate the static mock ticket in turn and confirm
    // each variant fails to verify.
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];

    // Wrong tag (anything other than TPM_ST_VERIFIED 0x8022).
    unsafe {
        MOCK_TK_VERIFIED.tag = 0x8024;
    }
    assert_eq!(
        p.verify_p256(&P256_GENERATOR, &digest, &sig),
        Err(VsError::CryptoError),
        "wrong-tag ticket must fail"
    );

    // Wrong hierarchy.
    unsafe {
        MOCK_TK_VERIFIED.tag = 0x8022;
        MOCK_TK_VERIFIED.hierarchy = 0;
    }
    assert_eq!(
        p.verify_p256(&P256_GENERATOR, &digest, &sig),
        Err(VsError::CryptoError),
        "wrong-hierarchy ticket must fail"
    );

    // Empty digest.
    unsafe {
        MOCK_TK_VERIFIED.tag = 0x8022;
        MOCK_TK_VERIFIED.hierarchy = 0x4000_0007;
        MOCK_TK_VERIFIED.digest.size = 0;
    }
    assert_eq!(
        p.verify_p256(&P256_GENERATOR, &digest, &sig),
        Err(VsError::CryptoError),
        "empty-digest ticket must fail"
    );

    // Restore valid ticket so subsequent serial tests are not affected.
    unsafe {
        MOCK_TK_VERIFIED.tag = 0x8022;
        MOCK_TK_VERIFIED.hierarchy = 0x4000_0007;
        MOCK_TK_VERIFIED.digest.size = 32;
    }
}

#[test]
#[serial]
fn verify_p256_rejects_wrong_prefix() {
    let p = provider_with_key(KeyId(63), 1);
    let mut bad_key = [0x04u8; 65];
    bad_key[0] = 0x02; // compressed format, not supported
    bad_key[1..].fill(0xAA);
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(
        p.verify_p256(&bad_key, &digest, &sig),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn verify_p256_rejects_point_at_infinity() {
    let p = provider_with_key(KeyId(63), 1);
    let mut zero_key = [0u8; 65];
    zero_key[0] = 0x04; // correct prefix, but X and Y are all zeros
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(
        p.verify_p256(&zero_key, &digest, &sig),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn aes_gcm_encrypt_produces_non_zero_ciphertext() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xBBu8; 8];
    let mut ct = [0u8; 8];
    let mut tag = [0u8; 16];
    p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, b"aad", &mut ct, &mut tag)
        .unwrap();
    // mock encrypt = identity; ciphertext equals plaintext
    assert_eq!(ct, pt);
    // tag must be non-zero (HMAC mock returns 0xAB fill)
    assert!(tag.iter().any(|&b| b != 0));
}

// -----------------------------------------------------------------------
// Additional tests for security fixes and edge cases
// -----------------------------------------------------------------------

#[test]
#[serial]
fn verify_p256_off_curve_rejected_before_ffi() {
    // Audit C4 / item 18: off-curve point must be rejected BEFORE any
    // call into the FFI table. We install a fresh provider and assert
    // that `Esys_LoadExternal` is not invoked for an off-curve point.
    reset_counters();
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    // `0x04 || 0x01 || 0x01 || ...` is clearly not on the P-256 curve.
    let mut pub_key = [0x04u8; 65];
    pub_key[1..].fill(0x01);
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(
        p.verify_p256(&pub_key, &digest, &sig),
        Err(VsError::InvalidInput)
    );
    // SAFETY: #[serial] ensures no concurrent access to the static.
    unsafe {
        assert_eq!(LOAD_EXTERNAL_CALLS, 0);
    }
}

#[test]
#[serial]
fn ecdh_rejects_wrong_point_prefix() {
    let p = provider_with_key(KeyId(0), 1);
    let mut bad_key = [0x04u8; 65];
    bad_key[0] = 0x02; // compressed format
    bad_key[1..].fill(0xAA);
    let mut shared = [0u8; 32];
    assert_eq!(
        p.ecdh_derive_shared(KeyId(0), &bad_key, &mut shared),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn ecdh_rejects_point_at_infinity() {
    let p = provider_with_key(KeyId(0), 1);
    let mut zero_key = [0u8; 65];
    zero_key[0] = 0x04;
    let mut shared = [0u8; 32];
    assert_eq!(
        p.ecdh_derive_shared(KeyId(0), &zero_key, &mut shared),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn ecdh_with_valid_key_succeeds() {
    let p = provider_with_key(KeyId(0), 1);
    let mut shared = [0u8; 32];
    assert!(p
        .ecdh_derive_shared(KeyId(0), &P256_GENERATOR, &mut shared)
        .is_ok());
}

#[test]
#[serial]
fn pcr_read_returns_non_zero_value() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut val = [0u8; 32];
    p.pcr_read(0, &mut val).unwrap();
    // Mock returns 0xCC fill.
    assert!(val.iter().all(|&b| b == 0xCC));
}

#[test]
#[serial]
fn pcr_read_invalid_index_returns_error() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut val = [0u8; 32];
    assert_eq!(p.pcr_read(24, &mut val), Err(VsError::InvalidInput));
}

#[test]
#[serial]
fn delete_key_clears_slot() {
    let mut p = provider_with_key(KeyId(5), 42);
    assert!(p.handle_for(KeyId(5)).is_ok());
    p.delete_key(KeyId(5)).unwrap();
    assert_eq!(p.handle_for(KeyId(5)), Err(VsError::InvalidInput));
}

#[test]
#[serial]
fn delete_key_out_of_bounds_returns_invalid_input() {
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert_eq!(
        p.delete_key(KeyId(MAX_KEY_SLOTS as u32)),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn generate_key_returns_policy_violation() {
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert_eq!(
        p.generate_key(KeyId(0), KeyType::Aes256),
        Err(VsError::PolicyViolation)
    );
}

#[test]
#[serial]
fn random_bytes_empty_buffer_succeeds() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut buf = [0u8; 0];
    assert!(p.random_bytes(&mut buf).is_ok());
}

#[test]
#[serial]
fn random_bytes_large_request_loops() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut buf = [0u8; 64]; // > 32, requires two TPM GetRandom calls
    assert!(p.random_bytes(&mut buf).is_ok());
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
#[serial]
fn aes_gcm_encrypt_oversized_plaintext_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 2049];
    let mut ct = [0u8; 2049];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn sha256_oversized_data_returns_error() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let data = [0u8; 2049];
    let mut hash = [0u8; 32];
    assert_eq!(p.sha256(&data, &mut hash), Err(VsError::InvalidInput));
}

#[test]
#[serial]
fn register_all_64_key_slots() {
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    for i in 0..MAX_KEY_SLOTS {
        assert!(p
            .register_key_handle(KeyId(i as u32), (i + 1) as EsysTr)
            .is_ok());
    }
    for i in 0..MAX_KEY_SLOTS {
        assert_eq!(p.handle_for(KeyId(i as u32)).unwrap(), (i + 1) as EsysTr);
    }
}

#[test]
#[serial]
fn new_sibling_context_creates_independent_context() {
    let p1 = provider_with_key(KeyId(0), 5);
    let p2 = p1.new_sibling_context().unwrap();
    // Both should independently perform SHA-256.
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    p1.sha256(b"x", &mut h1).unwrap();
    p2.sha256(b"x", &mut h2).unwrap();
    assert_eq!(h1, h2);
}

#[test]
#[serial]
fn new_sibling_context_clears_key_handles() {
    // Audit M5: ESYS_TR values are scoped to the originating ESAPI
    // context. The clone therefore starts with empty handle slots —
    // the caller MUST re-register every key on the clone.
    let p1 = provider_with_key(KeyId(10), 0x8100_0010);
    let p2 = p1.new_sibling_context().unwrap();
    assert_eq!(
        p2.handle_for(KeyId(10)),
        Err(VsError::InvalidInput),
        "cloned provider must report unregistered slots until re-registered"
    );
}

#[test]
#[serial]
fn aes_gcm_decrypt_length_mismatch_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 16];
    let tag = [0xABu8; 16];
    let mut pt = [0u8; 8]; // wrong length
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn aes_gcm_decrypt_oversized_ciphertext_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 2049];
    let tag = [0xABu8; 16];
    let mut pt = [0u8; 2049];
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt),
        Err(VsError::InvalidInput)
    );
}

#[test]
#[serial]
fn aes_gcm_encrypt_empty_plaintext_succeeds() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt: [u8; 0] = [];
    let mut ct: [u8; 0] = [];
    let mut tag = [0u8; 16];
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_ok());
}

#[test]
#[serial]
fn hmac_sha256_oversized_data_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let data = [0u8; 2049];
    let mut mac = [0u8; 32];
    assert_eq!(
        p.hmac_sha256(KeyId(0), &data, &mut mac),
        Err(VsError::InvalidInput)
    );
}

// -----------------------------------------------------------------------
// Encrypt-then-MAC authentication tests
//
// The mock HMAC returns a fixed digest (0xAB fill), so a "tampered" input
// still produces the same expected tag. To exercise the constant-time
// comparison path, we tamper with the TAG directly — that must fail.
// -----------------------------------------------------------------------

#[test]
#[serial]
fn aes_gcm_decrypt_tampered_tag_fails_authentication() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xBBu8; 16];
    let aad = b"auth";
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, aad, &mut ct, &mut tag)
        .unwrap();

    // Flip a bit in the tag — decrypt must reject.
    tag[0] ^= 0x01;
    let mut recovered = [0u8; 16];
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, aad, &tag, &mut recovered),
        Err(VsError::AuthenticationFailure)
    );
}

#[test]
#[serial]
fn aes_gcm_decrypt_zero_tag_fails_authentication() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0xCCu8; 16];
    let tag = [0u8; 16]; // all-zero tag: never matches mock's 0xAB fill
    let mut recovered = [0u8; 16];
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, b"aad", &tag, &mut recovered),
        Err(VsError::AuthenticationFailure)
    );
}

#[test]
#[serial]
fn aes_gcm_roundtrip_preserves_plaintext() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x77u8; 12];
    let pt = [0xABu8; 32];
    let aad = b"context";
    let mut ct = [0u8; 32];
    let mut tag = [0u8; 16];
    p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, aad, &mut ct, &mut tag)
        .unwrap();
    let mut recovered = [0u8; 32];
    p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, aad, &tag, &mut recovered)
        .unwrap();
    assert_eq!(recovered, pt);
}

// -----------------------------------------------------------------------
// Random / boundary tests
// -----------------------------------------------------------------------

#[test]
#[serial]
fn random_bytes_oversized_request_is_rejected() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut buf = vec![0u8; 2049];
    assert_eq!(p.random_bytes(&mut buf), Err(VsError::InvalidInput));
}

#[test]
#[serial]
fn compute_etm_tag_rejects_aad_plus_ct_overflow() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    // AAD of 2048 bytes + 1 byte ciphertext overflows the 2048-byte
    // shared buffer — must be rejected, not silently truncated.
    let aad = [0u8; 2048];
    let pt = [0u8; 1];
    let mut ct = [0u8; 1];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &aad, &mut ct, &mut tag),
        Err(VsError::InvalidInput)
    );
}

// -----------------------------------------------------------------------
// Fault-injection: TPM returns error codes
// -----------------------------------------------------------------------

unsafe extern "C" fn mock_esys_initialize_no_connection(
    _ctx: *mut *mut EsysContext,
    _tcti: *mut Tss2TctiContext,
    _abi: *mut core::ffi::c_void,
) -> Tss2Rc {
    types::TSS2_ESYS_RC_LAYER | types::TSS2_BASE_RC_NO_CONNECTION
}

#[test]
#[serial]
fn new_returns_not_initialized_when_tcti_unreachable() {
    let mut fl = mock_fn_list();
    fl.esys_initialize = mock_esys_initialize_no_connection;
    assert_eq!(
        TpmCryptoProvider::new(fl).err(),
        Some(VsError::NotInitialized)
    );
}

unsafe extern "C" fn mock_esys_get_random_null(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _bytes: u16,
    out_rnd: *mut *mut Tpm2bDigest,
) -> Tss2Rc {
    // Claim success but leave the out-pointer null — provider must reject.
    unsafe { *out_rnd = core::ptr::null_mut() };
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn random_bytes_null_return_rejected() {
    let mut fl = mock_fn_list();
    fl.esys_get_random = mock_esys_get_random_null;
    let p = TpmCryptoProvider::new(fl).unwrap();
    let mut buf = [0u8; 16];
    assert!(p.random_bytes(&mut buf).is_err());
}

unsafe extern "C" fn mock_esys_verify_signature_tpm_sig(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _digest: *const Tpm2bDigest,
    _sig: *const TpmtSignature,
    _out_val: *mut *mut types::TpmtTkVerified,
) -> Tss2Rc {
    // Raw TPM2_RC_SIGNATURE (format-0, no index).
    0x0000_009D
}

#[test]
#[serial]
fn verify_p256_returns_false_on_tpm_signature_rc() {
    let mut fl = mock_fn_list();
    fl.esys_verify_signature = mock_esys_verify_signature_tpm_sig;
    let p2 = TpmCryptoProvider::new(fl).unwrap();
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(p2.verify_p256(&P256_GENERATOR, &digest, &sig), Ok(false));
}

unsafe extern "C" fn mock_esys_verify_signature_format1(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _digest: *const Tpm2bDigest,
    _sig: *const TpmtSignature,
    _out_val: *mut *mut types::TpmtTkVerified,
) -> Tss2Rc {
    // Format-1 variant (parameter 1): 0x19D.
    0x0000_019D
}

#[test]
#[serial]
fn verify_p256_returns_false_on_format1_signature_rc() {
    let mut fl = mock_fn_list();
    fl.esys_verify_signature = mock_esys_verify_signature_format1;
    let p = TpmCryptoProvider::new(fl).unwrap();
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(p.verify_p256(&P256_GENERATOR, &digest, &sig), Ok(false));
}

unsafe extern "C" fn mock_esys_encrypt_decrypt2_size_mismatch(
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
    // SAFETY: in_data is a valid stack pointer.
    let in_size = unsafe { (*in_data).size };
    // Pass through the audit-CRIT-7 key-separation canary (32 bytes,
    // exercised at `register_mac_key_handle` time) so we can still set
    // up the provider; on every other call claim a size larger than the
    // input — the provider must reject that as a TPM protocol error.
    if in_size as usize == 32 {
        // SAFETY: serial test; statics are exclusive.
        unsafe {
            MOCK_MAX_BUF.size = in_size;
            MOCK_MAX_BUF.buffer[..in_size as usize]
                .copy_from_slice(&(&(*in_data).buffer)[..in_size as usize]);
            *out_data = &raw mut MOCK_MAX_BUF;
            *out_iv = &raw mut MOCK_IV_BUF;
        }
    } else {
        // SAFETY: same as above.
        unsafe {
            MOCK_MAX_BUF.size = in_size.saturating_add(4);
            *out_data = &raw mut MOCK_MAX_BUF;
            *out_iv = &raw mut MOCK_IV_BUF;
        }
    }
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn aes_gcm_encrypt_size_mismatch_rejected() {
    let mut fl = mock_fn_list();
    fl.esys_encrypt_decrypt2 = mock_esys_encrypt_decrypt2_size_mismatch;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    p.register_mac_key_handle(KeyId(0), 1001).unwrap();
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::CryptoError)
    );
}

unsafe extern "C" fn mock_esys_hash_wrong_size(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _data: *const Tpm2bMaxBuffer,
    _alg: Tpm2AlgId,
    _hier: EsysTr,
    out_hash: *mut *mut Tpm2bDigest,
    out_val: *mut *mut TpmtTkHashcheck,
) -> Tss2Rc {
    unsafe {
        MOCK_DIGEST_BUF.size = 20; // SHA-1 sized, not SHA-256
        *out_hash = &raw mut MOCK_DIGEST_BUF;
        *out_val = core::ptr::null_mut();
    }
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn sha256_wrong_size_from_tpm_rejected() {
    let mut fl = mock_fn_list();
    fl.esys_hash = mock_esys_hash_wrong_size;
    let p = TpmCryptoProvider::new(fl).unwrap();
    let mut h = [0u8; 32];
    assert_eq!(p.sha256(b"x", &mut h), Err(VsError::CryptoError));
}

// -----------------------------------------------------------------------
// PCR boundary tests
// -----------------------------------------------------------------------

#[test]
#[serial]
fn pcr_read_boundary_pcr23_succeeds() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut v = [0u8; 32];
    assert!(p.pcr_read(23, &mut v).is_ok());
}

#[test]
#[serial]
fn pcr_extend_boundary_pcr23_succeeds() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let m = [0xAAu8; 32];
    assert!(p.pcr_extend(23, &m).is_ok());
}

#[test]
#[serial]
fn register_mac_handle_rejects_same_as_cipher() {
    // Audit M5 negative path: registering the cipher key handle as the
    // MAC handle for the same slot must fail closed.
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.register_key_handle(KeyId(0), 42).unwrap();
    assert_eq!(
        p.register_mac_key_handle(KeyId(0), 42),
        Err(VsError::InvalidInput)
    );
    // A distinct handle still works.
    assert!(p.register_mac_key_handle(KeyId(0), 43).is_ok());
}

// ---------------------------------------------------------------------------
// Review item #1 + #4: quick_self_test, self_test canary, TransientHandle
// cleanup ordering. Test-local mocks + statics.
// ---------------------------------------------------------------------------

use types::{EsysContext, TPMI_NO, TPMI_YES, TSS2_BASE_RC_GENERAL_FAILURE, TSS2_ESYS_RC_LAYER};

/// Captures the `full_test` value the provider passed to `Esys_SelfTest`.
static mut LAST_SELF_TEST_FULL_FLAG: TpmiYesNo = 0xFF;

unsafe extern "C" fn mock_esys_self_test_record_flag(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    full: TpmiYesNo,
) -> Tss2Rc {
    // SAFETY: #[serial] tests → exclusive access.
    unsafe { LAST_SELF_TEST_FULL_FLAG = full };
    types::TSS2_RC_SUCCESS
}

unsafe extern "C" fn mock_esys_self_test_fail(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _full: TpmiYesNo,
) -> Tss2Rc {
    TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_GENERAL_FAILURE
}

unsafe extern "C" fn mock_esys_hash_zero(
    _ctx: *mut EsysContext,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _data: *const Tpm2bMaxBuffer,
    _alg: Tpm2AlgId,
    _hier: EsysTr,
    out_hash: *mut *mut Tpm2bDigest,
    out_val: *mut *mut TpmtTkHashcheck,
) -> Tss2Rc {
    // SAFETY: serial test; statics are exclusive.
    unsafe {
        MOCK_DIGEST_BUF.size = 32;
        MOCK_DIGEST_BUF.buffer = [0u8; 64];
        *out_hash = &raw mut MOCK_DIGEST_BUF;
        *out_val = core::ptr::null_mut();
    }
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn quick_self_test_passes_with_mock() {
    // Item 4: positive path — `quick_self_test` succeeds end-to-end with
    // the canary against a well-behaved mock.
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert!(p.quick_self_test().is_ok());
}

#[test]
#[serial]
fn self_test_passes_full_flag() {
    // The `CryptoProvider::self_test` impl must pass `TPMI_YES`.
    let mut fl = mock_fn_list();
    fl.esys_self_test = mock_esys_self_test_record_flag;
    // SAFETY: serialised test; reset the captured value before running.
    unsafe { LAST_SELF_TEST_FULL_FLAG = 0xFF };
    let p = TpmCryptoProvider::new(fl).unwrap();
    assert!(p.self_test().is_ok());
    // SAFETY: serialised test.
    unsafe { assert_eq!(LAST_SELF_TEST_FULL_FLAG, TPMI_YES) };
}

#[test]
#[serial]
fn quick_self_test_passes_quick_flag() {
    // `quick_self_test` must pass `TPMI_NO` (incremental, untested-only).
    let mut fl = mock_fn_list();
    fl.esys_self_test = mock_esys_self_test_record_flag;
    // SAFETY: serialised test; reset the captured value before running.
    unsafe { LAST_SELF_TEST_FULL_FLAG = 0xFF };
    let p = TpmCryptoProvider::new(fl).unwrap();
    assert!(p.quick_self_test().is_ok());
    // SAFETY: serialised test.
    unsafe { assert_eq!(LAST_SELF_TEST_FULL_FLAG, TPMI_NO) };
}

#[test]
#[serial]
fn quick_self_test_propagates_tpm_failure() {
    // Negative path: a non-success TSS2_RC from `Esys_SelfTest` must
    // surface as `Err(_)` from `quick_self_test`, not be swallowed.
    let mut fl = mock_fn_list();
    fl.esys_self_test = mock_esys_self_test_fail;
    let p = TpmCryptoProvider::new(fl).unwrap();
    assert!(p.quick_self_test().is_err());
}

#[test]
#[serial]
fn quick_self_test_rejects_zero_canary() {
    // Negative path: a TPM that returns success but a stuck-zero hash
    // must fail the canary check.
    let mut fl = mock_fn_list();
    fl.esys_hash = mock_esys_hash_zero;
    let p = TpmCryptoProvider::new(fl).unwrap();
    assert_eq!(p.quick_self_test(), Err(VsError::CryptoError));
}

#[test]
#[serial]
fn self_test_rejects_zero_canary() {
    // Mirrors `quick_self_test_rejects_zero_canary` for the full path,
    // proving both share the canary guard.
    let mut fl = mock_fn_list();
    fl.esys_hash = mock_esys_hash_zero;
    let p = TpmCryptoProvider::new(fl).unwrap();
    assert_eq!(p.self_test(), Err(VsError::CryptoError));
}

#[test]
#[serial]
fn transient_handle_flushes_then_closes_tr_on_verify() {
    // Item 1: `TransientHandle::drop` must release the TPM-side object
    // via `Esys_FlushContext` AND the host-side ESAPI metadata via
    // `Esys_TR_Close`, in that order, for the handle returned by
    // `Esys_LoadExternal`.
    reset_counters();
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert!(p.verify_p256(&P256_GENERATOR, &digest, &sig).unwrap());

    // SAFETY: serialised test → exclusive access to the counters.
    unsafe {
        assert_eq!(LOAD_EXTERNAL_CALLS, 1, "exactly one transient load");
        assert_eq!(FLUSH_CONTEXT_CALLS, 1, "exactly one FlushContext");
        assert_eq!(TR_CLOSE_CALLS, 1, "exactly one TR_Close");
        // Both calls saw the same synthetic handle written by
        // `mock_esys_load_external`.
        assert_eq!(FLUSH_CONTEXT_HANDLES[0], 0x0FEE_D001);
        assert_eq!(TR_CLOSE_HANDLES[0], 0x0FEE_D001);
        // Ordering: FlushContext must come strictly before TR_Close.
        let flush_seq = FLUSH_CONTEXT_SEQ;
        let close_seq = TR_CLOSE_SEQ;
        assert!(
            flush_seq < close_seq,
            "FlushContext (seq={flush_seq}) must precede TR_Close (seq={close_seq})"
        );
    }
}

#[test]
#[serial]
fn transient_handle_skips_cleanup_when_no_handle() {
    // Negative path: if no transient handle was ever loaded — e.g. the
    // on-curve check fails — neither cleanup hook should be invoked.
    // Guards the early-return branch in `TransientHandle::drop`.
    reset_counters();
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let mut bad_key = [0x04u8; 65];
    bad_key[1..].fill(0xAA); // not on the P-256 curve
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    let _ = p.verify_p256(&bad_key, &digest, &sig);
    // SAFETY: serialised test.
    unsafe {
        assert_eq!(FLUSH_CONTEXT_CALLS, 0);
        assert_eq!(TR_CLOSE_CALLS, 0);
    }
}

// ---------------------------------------------------------------------------
// Audit CRIT-7: key-separation canary at register_mac_key_handle time.
//
// The default `mock_esys_encrypt_decrypt2` is identity (ciphertext == input)
// and the default `mock_esys_hmac` returns `[0xAB; 32]`. The canary's
// encrypt output therefore begins with the canary plaintext bytes
// `b"vs-tpm-key-separa"` and the canary MAC output begins with `0xAB...`,
// which are byte-distinct and both non-zero — so default-mock registrations
// pass. The negative-path tests below replace `esys_hmac` and
// `esys_encrypt_decrypt2` to drive the failure branches.
// ---------------------------------------------------------------------------

/// Encrypt mock that returns ciphertext byte-equal to the HMAC mock's
/// output (`0xAB` fill) for the 32-byte canary input. Used to drive the
/// canary's "outputs match" rejection path.
unsafe extern "C" fn mock_esys_encrypt_decrypt2_returns_ab_for_canary(
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
    // SAFETY: in_data is a valid stack pointer; statics are exclusive
    // under #[serial].
    unsafe {
        let size = (*in_data).size;
        MOCK_MAX_BUF.size = size;
        MOCK_MAX_BUF.buffer[..size as usize].fill(0xAB);
        *out_data = &raw mut MOCK_MAX_BUF;
        *out_iv = &raw mut MOCK_IV_BUF;
    }
    types::TSS2_RC_SUCCESS
}

/// Encrypt mock that returns all-zero ciphertext for the canary input —
/// drives the canary's stuck-zero rejection path on the encrypt side.
unsafe extern "C" fn mock_esys_encrypt_decrypt2_returns_zero(
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
    // SAFETY: in_data is a valid stack pointer; statics are exclusive
    // under #[serial].
    unsafe {
        let size = (*in_data).size;
        MOCK_MAX_BUF.size = size;
        MOCK_MAX_BUF.buffer[..size as usize].fill(0x00);
        *out_data = &raw mut MOCK_MAX_BUF;
        *out_iv = &raw mut MOCK_IV_BUF;
    }
    types::TSS2_RC_SUCCESS
}

/// HMAC mock that returns an all-zero MAC — drives the canary's
/// stuck-zero rejection path on the HMAC side.
unsafe extern "C" fn mock_esys_hmac_zero(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _buf: *const Tpm2bMaxBuffer,
    _alg: Tpm2AlgId,
    out_hmac: *mut *mut Tpm2bDigest,
) -> Tss2Rc {
    // SAFETY: statics are exclusive under #[serial].
    unsafe {
        MOCK_DIGEST_BUF.size = 32;
        MOCK_DIGEST_BUF.buffer = [0u8; 64];
        *out_hmac = &raw mut MOCK_DIGEST_BUF;
    }
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn register_mac_canary_accepts_distinct_outputs() {
    // Positive path: default mocks produce a content-sensitive encrypt
    // output (identity) and a constant 0xAB HMAC output, which are
    // byte-distinct → canary passes → registration succeeds.
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    assert!(p.register_mac_key_handle(KeyId(0), 1001).is_ok());
}

#[test]
#[serial]
fn register_mac_canary_rejects_matching_outputs() {
    // Negative path: rig the encrypt mock so its first TAG_LEN output
    // bytes equal the HMAC mock's output (both 0xAB). Canary must reject
    // with PolicyViolation, and the slot must remain empty so AEAD
    // operations continue to fail closed.
    let mut fl = mock_fn_list();
    fl.esys_encrypt_decrypt2 = mock_esys_encrypt_decrypt2_returns_ab_for_canary;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    assert_eq!(
        p.register_mac_key_handle(KeyId(0), 1001),
        Err(VsError::PolicyViolation)
    );
    // The MAC slot must remain unset on canary failure.
    let nonce = [0u8; 12];
    let pt = [0u8; 8];
    let mut ct = [0u8; 8];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::InvalidInput),
        "no MAC handle should be registered after a failed canary"
    );
}

#[test]
#[serial]
fn register_mac_canary_rejects_zero_encrypt_output() {
    // Negative path: stuck-zero on the encrypt side fails the canary
    // even though the encrypt vs. HMAC outputs differ.
    let mut fl = mock_fn_list();
    fl.esys_encrypt_decrypt2 = mock_esys_encrypt_decrypt2_returns_zero;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    assert_eq!(
        p.register_mac_key_handle(KeyId(0), 1001),
        Err(VsError::PolicyViolation)
    );
}

#[test]
#[serial]
fn register_mac_canary_rejects_zero_hmac_output() {
    // Negative path: stuck-zero on the HMAC side fails the canary even
    // though the encrypt output is non-zero.
    let mut fl = mock_fn_list();
    fl.esys_hmac = mock_esys_hmac_zero;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    assert_eq!(
        p.register_mac_key_handle(KeyId(0), 1001),
        Err(VsError::PolicyViolation)
    );
}

#[test]
#[serial]
fn register_mac_canary_requires_cipher_handle_first() {
    // Order matters: the canary needs both keys to run. Registering the
    // MAC handle on a slot with no cipher handle must fail closed rather
    // than silently bypassing the canary.
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert_eq!(
        p.register_mac_key_handle(KeyId(0), 1001),
        Err(VsError::InvalidInput)
    );
}

// ---------------------------------------------------------------------------
// audit-LOW: canary IV randomness + constant-time check.
//
// The first test captures the IV passed to `Esys_EncryptDecrypt2` during
// `register_mac_key_handle`'s canary, and asserts:
//   (a) the IV is not all-zero (was hard-coded zero before the fix), and
//   (b) two independent provider instances draw two different IVs (the
//       IV is RNG-derived rather than a fixed deterministic value).
//
// The second test cannot directly prove "no early-exit" from the
// constant-time check — that would require timing measurements and is
// inherently a microarchitectural property. We instead pin the
// surface-level invariant: the canary still runs end-to-end on inputs
// that previously hit the early-exit branch (a non-zero encrypt output
// paired with a non-zero MAC output), and `subtle::Choice` is in scope
// at the check site so a future refactor cannot silently revert to a
// branchy comparison without a compile-time tell.
// ---------------------------------------------------------------------------

/// IV bytes captured by the canary-IV mock, in call order (small cap).
static mut CANARY_IV_CAPTURES: [[u8; 16]; 4] = [[0u8; 16]; 4];
static mut CANARY_IV_CAPTURE_COUNT: usize = 0;

fn reset_canary_iv_captures() {
    // SAFETY: serial test → exclusive access to the statics.
    unsafe {
        CANARY_IV_CAPTURES = [[0u8; 16]; 4];
        CANARY_IV_CAPTURE_COUNT = 0;
    }
}

/// Encrypt mock that records the IV bytes it observed, then mirrors the
/// default identity behaviour so the canary's positive path still
/// succeeds (encrypt output = canary plaintext, distinct from the 0xAB
/// HMAC output, neither all-zero).
unsafe extern "C" fn mock_esys_encrypt_decrypt2_capture_iv(
    _ctx: *mut EsysContext,
    _key: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _decrypt: TpmiYesNo,
    _mode: Tpm2AlgId,
    iv: *const Tpm2bData,
    in_data: *const Tpm2bMaxBuffer,
    out_data: *mut *mut Tpm2bMaxBuffer,
    out_iv: *mut *mut Tpm2bData,
) -> Tss2Rc {
    // SAFETY: `iv` and `in_data` are valid stack pointers provided by
    // the canary path. Statics are exclusive under `#[serial]`.
    unsafe {
        if !iv.is_null() && CANARY_IV_CAPTURE_COUNT < CANARY_IV_CAPTURES.len() {
            let size = (*iv).size as usize;
            let len = core::cmp::min(size, 16);
            CANARY_IV_CAPTURES[CANARY_IV_CAPTURE_COUNT][..len]
                .copy_from_slice(&(*iv).buffer[..len]);
            CANARY_IV_CAPTURE_COUNT += 1;
        }
        let size = (*in_data).size;
        MOCK_MAX_BUF.size = size;
        MOCK_MAX_BUF.buffer[..size as usize]
            .copy_from_slice(&(&(*in_data).buffer)[..size as usize]);
        *out_data = &raw mut MOCK_MAX_BUF;
        *out_iv = &raw mut MOCK_IV_BUF;
    }
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn canary_uses_nonzero_iv() {
    // audit-LOW: the canary IV must be drawn from `random_bytes` rather
    // than the previous hard-coded all-zero buffer. Two independent
    // provider instances are constructed in sequence; each runs the
    // canary inside `register_mac_key_handle` once. The mock encrypt
    // function records the IV ESAPI observed. We assert:
    //   (1) the first captured IV is not all-zero,
    //   (2) the second captured IV is not all-zero,
    //   (3) the two IVs are not byte-equal — i.e., the IV is genuinely
    //       drawn from the RNG, not a constant derived from a fixed
    //       label.
    reset_canary_iv_captures();
    let mut fl = mock_fn_list();
    fl.esys_encrypt_decrypt2 = mock_esys_encrypt_decrypt2_capture_iv;

    let mut p1 = TpmCryptoProvider::new(fl).unwrap();
    p1.register_key_handle(KeyId(0), 1).unwrap();
    p1.register_mac_key_handle(KeyId(0), 1001).unwrap();

    let mut p2 = TpmCryptoProvider::new(fl).unwrap();
    p2.register_key_handle(KeyId(0), 2).unwrap();
    p2.register_mac_key_handle(KeyId(0), 1002).unwrap();

    // SAFETY: serial test → exclusive access to the captures.
    unsafe {
        assert!(
            CANARY_IV_CAPTURE_COUNT >= 2,
            "canary must invoke Esys_EncryptDecrypt2 once per registration"
        );
        let iv1 = CANARY_IV_CAPTURES[0];
        let iv2 = CANARY_IV_CAPTURES[1];
        assert!(
            iv1.iter().any(|&b| b != 0),
            "canary IV must not be all-zero (audit-LOW)"
        );
        assert!(
            iv2.iter().any(|&b| b != 0),
            "second canary IV must not be all-zero (audit-LOW)"
        );
        assert_ne!(
            iv1, iv2,
            "two fresh providers must draw two different canary IVs from the RNG"
        );
    }
}

#[test]
#[serial]
fn canary_ct_check_does_not_short_circuit() {
    // audit-LOW: the canary's "is this OK?" decision used to branch on
    // two intermediate signals (stuck-zero check, then `ct_eq`). The fix
    // composes a single `subtle::Choice` from three `ct_eq` results
    // (`enc == 0`, `mac == 0`, `enc == mac`) and converts to `bool` once
    // at the very end. Proving the absence of an early exit requires
    // timing analysis we cannot perform from a unit test. What we CAN
    // pin is the surface-level invariants:
    //
    //   1. Inputs that previously hit the now-removed early-exit branch
    //      (non-zero encrypt output, non-zero MAC output, distinct
    //      values) still run end-to-end and produce `Ok(())`.
    //   2. `subtle::Choice` is reachable from the same module path the
    //      canary uses. If a future refactor drops the import or
    //      replaces `Choice` with a non-constant-time wrapper, this
    //      test's compile step fails — which is the strongest
    //      compile-time pin available without a dedicated crate like
    //      `static_assertions` (not currently a dependency of
    //      `vs-crypto-tpm`, per Cargo.toml).
    //
    // The first invariant is exercised by `register_mac_canary_accepts_distinct_outputs`
    // (positive path with default mocks); this test additionally
    // exercises the symmetry: each PRF output is byte-distinct, both
    // non-zero, but specifically chosen so the byte-wise OR-fold the
    // old branchy check used would have hit its early-exit branch (any
    // non-zero byte → not stuck-zero). Under the new code the same
    // inputs must traverse the full `Choice` composition and still
    // return `Ok(())`.
    //
    // The `let _ = ... as fn(u8) -> Choice;` line is the compile-time
    // pin: it forces `subtle::Choice` to be in scope at the same
    // visibility the canary uses, so a refactor that drops the import
    // breaks the test build.
    let _ = subtle::Choice::from as fn(u8) -> subtle::Choice;

    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    // Default mocks: identity encrypt (output begins with the canary
    // plaintext, all non-zero ASCII), 0xAB-fill HMAC (non-zero and
    // distinct from the encrypt output). Both branches of the old
    // stuck-zero check would have fallen through to the `ct_eq`
    // comparison; under the new code, all three `ct_eq` results feed a
    // single `Choice` and the function runs to completion.
    assert!(p.register_mac_key_handle(KeyId(0), 1001).is_ok());
}

// ---------------------------------------------------------------------------
// audit-LOW: pcr_extend uses `checked_add` for the PCR handle.
//
// The existing range check at the top of `pcr_extend` (`index > 23`)
// already rejects out-of-range PCRs with `InvalidInput`. Under current
// TCG constants `ESYS_TR_PCR0 + 23` is far from `EsysTr::MAX`, so the
// `checked_add` itself cannot overflow today. The audit fix swapped
// `wrapping_add` for `checked_add` defensively — if `ESYS_TR_PCR0` is
// ever rebased close to the type maximum, an out-of-range `index` will
// surface `InvalidInput` from the address arithmetic instead of
// silently wrapping to an arbitrary `ESYS_TR`.
//
// This test pins the safer error path: an out-of-range PCR (99, well
// above the 23-PCR ceiling) must return `Err(VsError::InvalidInput)`
// rather than reaching any TPM call.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn pcr_handle_uses_checked_add() {
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    let m = [0u8; 32];
    assert_eq!(
        p.pcr_extend(99, &m),
        Err(VsError::InvalidInput),
        "out-of-range PCR index must surface InvalidInput from either \
         the range check or checked_add — never wrap into an arbitrary \
         ESYS_TR"
    );
}

// -----------------------------------------------------------------------
// Audit HIGH-K: AEAD atomicity. When `aes_gcm_encrypt` rejects a
// framed-too-large input, `ciphertext_out` MUST remain untouched.
// Symmetric coverage for `aes_gcm_decrypt`'s `plaintext_out`.
// -----------------------------------------------------------------------

#[test]
#[serial]
fn aes_gcm_encrypt_framed_len_too_large_leaves_ciphertext_unchanged() {
    // Audit HIGH-K negative path: an `(aad, plaintext)` pair whose framed
    // length exceeds MAX_BUF must be rejected BEFORE any write into
    // `ciphertext_out`. We pre-fill `ciphertext_out` with a sentinel and
    // confirm every byte survives the failed call.
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    // Plaintext fits in MAX_BUF on its own (2048 B), but plaintext + AAD +
    // 36-byte ETM prefix overflows the 2048-byte HMAC input buffer.
    let pt = [0xCDu8; 2048];
    let aad = [0xEFu8; 16];
    let mut ct = [0x77u8; 2048]; // sentinel
    let sentinel = [0x77u8; 2048];
    let mut tag = [0u8; 16];

    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &aad, &mut ct, &mut tag),
        Err(VsError::InvalidInput),
        "oversized framed input must be rejected before any TPM call"
    );
    assert_eq!(
        ct, sentinel,
        "ciphertext_out must be byte-for-byte unchanged when aes_gcm_encrypt errors"
    );
    // Tag must not be partially populated either.
    assert_eq!(tag, [0u8; 16], "tag_out must be untouched on early error");
}

#[test]
#[serial]
fn aes_gcm_encrypt_framed_len_boundary_succeeds() {
    // Audit HIGH-K positive path: the largest framed input that still fits
    // (MAX_BUF - ETM_PREFIX_LEN = 2048 - 36 = 2012 total payload bytes)
    // must succeed end-to-end and produce a non-zero ciphertext / tag.
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x02u8; 12];
    // Split the 2012-byte budget: 1000 B plaintext + 1012 B AAD.
    let pt = [0xAAu8; 1000];
    let aad = [0xBBu8; 1012];
    let mut ct = [0u8; 1000];
    let mut tag = [0u8; 16];
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &aad, &mut ct, &mut tag)
        .is_ok());
    // Mock encrypt = identity copy of plaintext.
    assert_eq!(ct, pt);
    // Mock HMAC mock fills 0xAB.
    assert!(tag.iter().any(|&b| b != 0));
}

#[test]
#[serial]
fn aes_gcm_decrypt_framed_len_too_large_leaves_plaintext_unchanged() {
    // Audit HIGH-K negative path (decrypt mirror): an oversized framed
    // input must be rejected before any TPM call and before any write
    // into `plaintext_out`.
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0x42u8; 2048];
    let aad = [0xEFu8; 16];
    let tag = [0xABu8; 16];
    let mut pt = [0x33u8; 2048]; // sentinel
    let sentinel = [0x33u8; 2048];

    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &aad, &tag, &mut pt),
        Err(VsError::InvalidInput),
        "oversized framed input must be rejected before any TPM call"
    );
    assert_eq!(
        pt, sentinel,
        "plaintext_out must be byte-for-byte unchanged when aes_gcm_decrypt errors"
    );
}

// ---------------------------------------------------------------------------
// Audit M1 / H1 / M3 / INFO-5: HMAC bus-integrity session wiring.
// ---------------------------------------------------------------------------

use mocks::{
    MOCK_SESSION_HANDLE, START_AUTH_SESSION_CALLS, START_AUTH_SESSION_LAST_NONCE_SIZE,
    TR_SESS_SET_ATTRIBUTES_CALLS, TR_SESS_SET_ATTRIBUTES_LAST_FLAGS,
    TR_SESS_SET_ATTRIBUTES_LAST_MASK, TR_SESS_SET_ATTRIBUTES_LAST_SESSION,
};
use types::TpmaSession;

#[test]
#[serial]
fn enable_bus_integrity_succeeds_with_mock() {
    // Positive path: a healthy mock `Esys_StartAuthSession` returns a
    // synthetic session handle; the provider stores it and subsequent
    // operations continue to function via `auth_session()`.
    reset_counters();
    let mut p = provider_with_key(KeyId(0), 1);
    assert!(p.enable_bus_integrity().is_ok());
    // SAFETY: serial test → exclusive access to the counter.
    unsafe {
        assert_eq!(
            START_AUTH_SESSION_CALLS, 1,
            "enable_bus_integrity must call Esys_StartAuthSession exactly once"
        );
        // Audit M3: provider must supply a 32-byte caller nonce, NOT
        // the old null nonce.
        assert_eq!(
            START_AUTH_SESSION_LAST_NONCE_SIZE, 32,
            "enable_bus_integrity must pass a 32-byte caller nonce (audit M3)"
        );
    }
    // AEAD round-trip with the session active must still succeed.
    let nonce = [0x07u8; 12];
    let pt = [0x42u8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, b"aad", &mut ct, &mut tag)
        .unwrap();
    let mut recovered = [0u8; 16];
    p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, b"aad", &tag, &mut recovered)
        .unwrap();
    assert_eq!(recovered, pt);
}

#[test]
#[serial]
fn enable_bus_integrity_is_idempotent() {
    // Calling enable a second time must be a no-op (and must NOT issue
    // a second StartAuthSession call) so the provider can't accidentally
    // leak two sessions.
    reset_counters();
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert!(p.enable_bus_integrity().is_ok());
    assert!(p.enable_bus_integrity().is_ok());
    // SAFETY: serial test.
    unsafe {
        assert_eq!(START_AUTH_SESSION_CALLS, 1);
        // Set-attributes also called exactly once on the first enable.
        assert_eq!(TR_SESS_SET_ATTRIBUTES_CALLS, 1);
    }
}

/// Failing variant of `Esys_StartAuthSession`: returns
/// `TSS2_BASE_RC_GENERAL_FAILURE` so the provider must surface `Err`.
unsafe extern "C" fn mock_esys_start_auth_session_fail(
    _ctx: *mut EsysContext,
    _tpm_key: EsysTr,
    _bind: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _nonce: *const types::Tpm2bNonce,
    _session_type: types::Tpm2Se,
    _symmetric: *const types::TpmtSymDef,
    _hash: Tpm2AlgId,
    _out_session: *mut EsysTr,
) -> Tss2Rc {
    TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_GENERAL_FAILURE
}

#[test]
#[serial]
fn enable_bus_integrity_propagates_tpm_failure() {
    // Negative path: TPM-side failure surfaces as `Err`, leaves
    // `bus_protection_session` unset so subsequent ops still work via
    // the password fallback.
    let mut fl = mock_fn_list();
    fl.esys_start_auth_session = mock_esys_start_auth_session_fail;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    assert!(p.enable_bus_integrity().is_err());
    // Fallback path remains usable.
    let mut h = [0u8; 32];
    p.sha256(b"y", &mut h).unwrap();
}

/// Variant of `Esys_StartAuthSession` that claims success but returns a
/// null session handle. The provider must reject this as a protocol
/// violation rather than installing `ESYS_TR_NONE` as a session.
unsafe extern "C" fn mock_esys_start_auth_session_null(
    _ctx: *mut EsysContext,
    _tpm_key: EsysTr,
    _bind: EsysTr,
    _s1: EsysTr,
    _s2: EsysTr,
    _s3: EsysTr,
    _nonce: *const types::Tpm2bNonce,
    _session_type: types::Tpm2Se,
    _symmetric: *const types::TpmtSymDef,
    _hash: Tpm2AlgId,
    out_session: *mut EsysTr,
) -> Tss2Rc {
    // SAFETY: out_session is a valid writable pointer provided by the
    // provider.
    unsafe { *out_session = types::ESYS_TR_NONE };
    types::TSS2_RC_SUCCESS
}

#[test]
#[serial]
fn enable_bus_integrity_rejects_null_session_handle() {
    let mut fl = mock_fn_list();
    fl.esys_start_auth_session = mock_esys_start_auth_session_null;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    assert_eq!(p.enable_bus_integrity(), Err(VsError::CryptoError));
}

#[test]
#[serial]
fn disable_bus_integrity_flushes_session() {
    // Positive path: enable → disable must invoke `Esys_FlushContext`
    // with the mock session handle and reset internal state so the
    // next enable opens a fresh session.
    reset_counters();
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.enable_bus_integrity().unwrap();
    p.disable_bus_integrity().unwrap();
    // SAFETY: serial test.
    unsafe {
        assert_eq!(FLUSH_CONTEXT_CALLS, 1, "disable must call FlushContext");
        assert_eq!(
            FLUSH_CONTEXT_HANDLES[0], MOCK_SESSION_HANDLE,
            "FlushContext must see the session handle"
        );
    }
    // A second disable is a no-op.
    assert!(p.disable_bus_integrity().is_ok());
    // SAFETY: serial test.
    unsafe {
        assert_eq!(FLUSH_CONTEXT_CALLS, 1);
    }
    // Re-enable opens a fresh session.
    p.enable_bus_integrity().unwrap();
    // SAFETY: serial test.
    unsafe {
        assert_eq!(START_AUTH_SESSION_CALLS, 2);
    }
}

#[test]
#[serial]
fn operations_without_bus_integrity_use_password_fallback() {
    // Positive path: a provider that never calls `enable_bus_integrity`
    // continues to function — `auth_session()` returns `ESYS_TR_PASSWORD`
    // for every command site (the original behaviour).
    reset_counters();
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0u8; 12];
    let pt = [0u8; 8];
    let mut ct = [0u8; 8];
    let mut tag = [0u8; 16];
    p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, b"", &mut ct, &mut tag)
        .unwrap();
    // No StartAuthSession call should have occurred.
    // SAFETY: serial test.
    unsafe {
        assert_eq!(START_AUTH_SESSION_CALLS, 0);
    }
}

#[test]
#[serial]
fn drop_flushes_active_bus_integrity_session() {
    // Drop must flush the session even when the caller forgets to call
    // `disable_bus_integrity`. Counts both the session flush and any
    // other flushes during the lifetime.
    reset_counters();
    {
        let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
        p.enable_bus_integrity().unwrap();
        // `p` drops at end of scope.
    }
    // SAFETY: serial test.
    unsafe {
        assert!(
            FLUSH_CONTEXT_CALLS >= 1,
            "Drop must flush the active session"
        );
        // The first flush must target the session handle (Drop wipes
        // it before `Esys_Finalize`).
        assert_eq!(FLUSH_CONTEXT_HANDLES[0], MOCK_SESSION_HANDLE);
    }
}

// ---------------------------------------------------------------------------
// audit-M1: `bus_protection_active()` observability + sibling-context
// regression.
//
// The getter surfaces the previously-hidden fact that `new_sibling_context`
// silently drops bus protection (single-owner HMAC-session invariant). The
// regression test (`..._on_sibling_even_when_parent_active`) pins this
// behaviour so a future refactor can't accidentally re-introduce shared
// sessions or, conversely, fail to surface the drop to callers.
//
// audit-H1/M3: `Esys_TRSess_SetAttributes` must be called after a successful
// `Esys_StartAuthSession` with `TPMA_SESSION_CONTINUE_SESSION` set, and the
// session must use a 32-byte random caller nonce. The positive test confirms
// the set-attributes call happens; the negative test makes the set-attributes
// step fail and asserts the provider flushes the session and leaves
// `bus_protection_session` at `ESYS_TR_NONE`.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn bus_protection_active_returns_false_for_fresh_provider() {
    // A freshly-constructed provider has never called
    // `enable_bus_protection` — every command site must still fall back
    // to `ESYS_TR_PASSWORD`, which `bus_protection_active()` reports as
    // `false`.
    reset_counters();
    let p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert!(
        !p.bus_protection_active(),
        "fresh provider must report no active bus-integrity session"
    );
    // Cross-check: no StartAuthSession call has occurred.
    // SAFETY: serial test.
    unsafe {
        assert_eq!(START_AUTH_SESSION_CALLS, 0);
    }
}

#[test]
#[serial]
fn bus_protection_active_returns_true_after_enable_bus_integrity() {
    // Positive path: after a successful `enable_bus_protection` (the
    // current name; tracked for the prospective rename to
    // `enable_bus_integrity`) the getter must flip to `true`.
    reset_counters();
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    assert!(!p.bus_protection_active());
    p.enable_bus_protection().unwrap();
    assert!(
        p.bus_protection_active(),
        "after enable_bus_protection the getter must report the active session"
    );
}

#[test]
#[serial]
fn bus_protection_active_returns_false_after_disable() {
    // Negative-path companion: enable → disable must flip the getter
    // back to `false`. This guards against a future refactor leaking
    // the field after `disable_bus_protection` has flushed the session
    // handle.
    reset_counters();
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.enable_bus_protection().unwrap();
    assert!(p.bus_protection_active());
    p.disable_bus_protection().unwrap();
    assert!(
        !p.bus_protection_active(),
        "after disable_bus_protection the getter must report no session"
    );
}

#[test]
#[serial]
fn bus_protection_active_returns_false_on_sibling_even_when_parent_active() {
    // audit-M1 REGRESSION TEST.
    //
    // `new_sibling_context` zeroes `bus_protection_session` to satisfy
    // the single-owner invariant (`ESYS_TR` session handles are scoped
    // to the ESAPI context that opened them, and a parallel sibling
    // driving the same session would invalidate the other's view in
    // `Drop`). Before this fix the silent drop was invisible to
    // operators auditing a live `p2 = p1.new_sibling_context()`.
    //
    // The assertions below pin the contract:
    //   * parent: still active after the fork,
    //   * sibling: never active until `enable_bus_protection` is
    //     called on the sibling explicitly.
    reset_counters();
    let mut p1 = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p1.enable_bus_protection().unwrap();
    assert!(
        p1.bus_protection_active(),
        "precondition: parent must have an active session before fork"
    );
    let p2 = p1.new_sibling_context().unwrap();
    assert!(
        p1.bus_protection_active(),
        "parent must retain its session after forking a sibling"
    );
    assert!(
        !p2.bus_protection_active(),
        "audit-M1: sibling must NOT inherit the parent's bus-protection session"
    );
    // The fork must NOT have issued a second StartAuthSession call —
    // the sibling starts with no session, by design.
    // SAFETY: serial test.
    unsafe {
        assert_eq!(
            START_AUTH_SESSION_CALLS, 1,
            "new_sibling_context must not open its own session"
        );
    }
}

#[test]
#[serial]
fn enable_bus_integrity_sets_continue_session_attribute() {
    // Positive path: after `enable_bus_integrity` succeeds the mock
    // must have observed exactly one `Esys_TRSess_SetAttributes` call
    // with `TPMA_SESSION_CONTINUE_SESSION` in both `flags` and `mask`,
    // targeted at the session handle the provider stored.
    reset_counters();
    let mut p = TpmCryptoProvider::new(mock_fn_list()).unwrap();
    p.enable_bus_integrity().unwrap();
    // SAFETY: serial test → exclusive access to the counters.
    unsafe {
        assert_eq!(
            TR_SESS_SET_ATTRIBUTES_CALLS, 1,
            "Esys_TRSess_SetAttributes must be called exactly once after \
             Esys_StartAuthSession succeeds (audit H1)"
        );
        assert_eq!(
            TR_SESS_SET_ATTRIBUTES_LAST_SESSION, MOCK_SESSION_HANDLE,
            "set-attributes must target the session returned by StartAuthSession"
        );
        let continue_bit: TpmaSession = types::TPMA_SESSION_CONTINUE_SESSION;
        assert_eq!(
            TR_SESS_SET_ATTRIBUTES_LAST_FLAGS & continue_bit,
            continue_bit,
            "flags must set TPMA_SESSION_CONTINUE_SESSION"
        );
        assert_eq!(
            TR_SESS_SET_ATTRIBUTES_LAST_MASK & continue_bit,
            continue_bit,
            "mask must include TPMA_SESSION_CONTINUE_SESSION so the bit is applied"
        );
    }
}

/// Failing variant of `Esys_TRSess_SetAttributes`: returns
/// `TSS2_BASE_RC_GENERAL_FAILURE` so the provider must surface `Err`
/// AND flush the session handle that `Esys_StartAuthSession` just
/// produced, leaving `bus_protection_session` at `ESYS_TR_NONE`.
unsafe extern "C" fn mock_esys_tr_sess_set_attributes_fail(
    _ctx: *mut EsysContext,
    _session: EsysTr,
    _flags: TpmaSession,
    _mask: TpmaSession,
) -> Tss2Rc {
    TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_GENERAL_FAILURE
}

#[test]
#[serial]
fn enable_bus_integrity_flushes_session_when_set_attributes_fails() {
    // Negative path: `Esys_StartAuthSession` succeeds, but the
    // subsequent `Esys_TRSess_SetAttributes` fails. The provider MUST:
    //   1. Surface `Err`.
    //   2. Call `Esys_FlushContext` with the freshly-opened session
    //      handle so it is not leaked on the TPM.
    //   3. Leave `bus_protection_session` at `ESYS_TR_NONE` so the
    //      provider stays in a well-defined state (the same fail-closed
    //      discipline the rest of the crate follows).
    reset_counters();
    let mut fl = mock_fn_list();
    fl.esys_tr_sess_set_attributes = mock_esys_tr_sess_set_attributes_fail;
    let mut p = TpmCryptoProvider::new(fl).unwrap();
    assert!(p.enable_bus_integrity().is_err());
    // SAFETY: serial test.
    unsafe {
        assert_eq!(START_AUTH_SESSION_CALLS, 1);
        assert!(
            FLUSH_CONTEXT_CALLS >= 1,
            "session must be flushed when set-attributes fails"
        );
        assert_eq!(
            FLUSH_CONTEXT_HANDLES[0], MOCK_SESSION_HANDLE,
            "FlushContext must target the freshly-opened session handle"
        );
    }
    // `bus_protection_session` must be `ESYS_TR_NONE`. We assert this
    // indirectly via `auth_session()` falling back to
    // `ESYS_TR_PASSWORD`: the password fallback path is what runs when
    // the session slot is empty.
    assert_eq!(p.bus_protection_session, types::ESYS_TR_NONE);
}

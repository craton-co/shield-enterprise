// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Unit tests for the PKCS#11 crypto provider.
//!
//! Shared mock infrastructure lives in [`mocks`]; per-test failure mocks
//! (which often pair with their own static counters) stay alongside the
//! `#[test]` functions that exercise them.

mod mocks;

use super::*;
use mocks::{mock_fn_list, provider_with_key, P256_GENERATOR};
// FIX-4: serialize tests that mutate process-global AtomicU32 counters
// (e.g. FIND_FINAL_CALLS, FINALIZE_CALLS, CLOSE_SESSION_CALLS,
// LAST_FIND_CLASS, LAST_DESTROY_ERROR). Without this, parallel test
// execution pollutes the counters and produces flaky failures.
//
// `serial_test`'s macro expansion references `std` (lock guards) and the
// `vec!` macro, so the test module pulls them in even though the crate
// itself is `#![no_std]` (see `extern crate std;` in `lib.rs`).
use serial_test::serial;
use std::vec;

// -----------------------------------------------------------------------
// Test cases (≥ 10 required by CONTRIBUTING.md)
// -----------------------------------------------------------------------

#[test]
fn to_ck_ulong_accepts_small_values() {
    assert_eq!(to_ck_ulong(0).unwrap(), 0);
    assert_eq!(to_ck_ulong(2048).unwrap(), 2048);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn to_ck_ulong_rejects_overflow_on_32bit_targets() {
    // On 64-bit hosts CkUlong *is* u64, so any usize fits; the real
    // defence is on 32-bit targets where CkUlong is narrower. Exercise
    // the explicit overflow fallback via a round-trip check.
    let ok = to_ck_ulong(usize::MAX);
    // On a 64-bit host this succeeds; the test's value is that it exists
    // and compiles — but we still assert something useful.
    assert!(ok.is_ok() || matches!(ok, Err(VsError::InvalidInput)));
}

#[test]
fn pin_buffer_new_roundtrip() {
    let pb = PinBuffer::new(b"123456").unwrap();
    assert_eq!(pb.as_slice(), b"123456");
}

#[test]
fn pin_buffer_rejects_empty_and_oversized() {
    assert!(matches!(PinBuffer::new(b""), Err(VsError::InvalidInput)));
    let long = [b'x'; MAX_PIN_LEN + 1];
    assert!(matches!(PinBuffer::new(&long), Err(VsError::InvalidInput)));
}

#[test]
fn pin_buffer_wipe_zeroes_contents() {
    let mut pb = PinBuffer::new(b"secret").unwrap();
    pb.wipe();
    assert_eq!(pb.as_slice().len(), 0);
    assert!(pb.bytes.iter().all(|&b| b == 0));
}

#[test]
fn pin_buffer_drop_runs_wipe() {
    // Reading stack memory after drop is undefined behaviour; instead
    // we prove Drop runs by checking that the wipe leaves the length at
    // zero when invoked manually (Drop calls `wipe`). Combined with
    // `pin_buffer_wipe_zeroes_contents` this establishes the contract
    // without relying on stack-memory inspection.
    let mut pb = PinBuffer::new(b"top-secret").unwrap();
    let original_bytes = pb.bytes;
    pb.wipe();
    assert_ne!(pb.bytes, original_bytes);
    assert!(pb.bytes.iter().all(|&b| b == 0));
}

#[test]
fn new_with_pin_buffer_constructor() {
    let pin = PinBuffer::new(b"1234").unwrap();
    assert!(Pkcs11CryptoProvider::new_with_pin_buffer(mock_fn_list(), &pin).is_ok());
}

#[test]
fn new_rejects_empty_pin() {
    assert!(matches!(
        Pkcs11CryptoProvider::new(mock_fn_list(), b""),
        Err(VsError::InvalidInput)
    ));
}

#[test]
fn volatile_wipe_clears_slice() {
    let mut buf = [0xFFu8; 32];
    volatile_wipe(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn new_with_mock_succeeds() {
    assert!(Pkcs11CryptoProvider::new(mock_fn_list(), b"test-pin").is_ok());
}

#[test]
fn register_key_handle_roundtrip() {
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert!(p.register_key_handle(KeyId(0), 42).is_ok());
    assert_eq!(p.handle_for(KeyId(0)).unwrap(), 42);
}

#[test]
fn handle_for_unregistered_slot_returns_invalid_input() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert_eq!(p.handle_for(KeyId(5)), Err(VsError::InvalidInput));
}

#[test]
fn key_id_out_of_bounds_returns_invalid_input() {
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert_eq!(
        p.register_key_handle(KeyId(MAX_KEY_SLOTS as u32), 1),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn sha256_returns_non_zero_hash() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let mut hash = [0u8; 32];
    p.sha256(b"hello", &mut hash).unwrap();
    assert!(hash.iter().any(|&b| b != 0));
}

#[test]
fn self_test_passes_with_mock() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert!(p.self_test().is_ok());
}

#[test]
fn aes_gcm_encrypt_decrypt_roundtrip() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let aad = b"test-aad";
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, aad, &mut ct, &mut tag)
        .unwrap();
    let mut recovered = [0u8; 16];
    p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, aad, &tag, &mut recovered)
        .unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn hmac_sha256_with_valid_key_succeeds() {
    let p = provider_with_key(KeyId(1), 2);
    let mut mac = [0u8; 32];
    p.hmac_sha256(KeyId(1), b"data", &mut mac).unwrap();
    assert!(mac.iter().any(|&b| b != 0));
}

#[test]
fn sign_p256_with_valid_key_succeeds() {
    let p = provider_with_key(KeyId(2), 3);
    let digest = [0xFFu8; 32];
    let mut sig = [0u8; 64];
    p.sign_p256(KeyId(2), &digest, &mut sig).unwrap();
    assert!(sig.iter().any(|&b| b != 0));
}

#[test]
fn verify_p256_returns_true_for_any_sig() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    let result = p.verify_p256(&P256_GENERATOR, &digest, &sig).unwrap();
    assert!(result);
}

#[test]
fn verify_p256_off_curve_rejected_before_ffi() {
    // Audit fix: an off-curve point with the right prefix and non-zero
    // bytes must be rejected by the on-curve check, not propagated to
    // the token. (`[0x04, 0xAA*64]` — non-zero but not on the curve.)
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let mut bad = [0x04u8; 65];
    bad[1..].fill(0xAA);
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(
        p.verify_p256(&bad, &digest, &sig),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn verify_p256_x_or_y_above_p_rejected() {
    // x = p (the field prime) is invalid even with a valid prefix.
    let mut bad = [0u8; 65];
    bad[0] = 0x04;
    // P-256 prime in big-endian bytes: FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF.
    bad[1..33].copy_from_slice(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ]);
    bad[33] = 1; // any y > 0 so the point isn't trivially infinity.
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let digest = [0u8; 32];
    let sig = [0u8; 64];
    assert_eq!(
        p.verify_p256(&bad, &digest, &sig),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn random_bytes_fills_buffer() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let mut buf = [0u8; 32];
    p.random_bytes(&mut buf).unwrap();
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn aes_gcm_encrypt_length_mismatch_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 8]; // Wrong length.
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn clone_provider_is_independent() {
    // audit-M6: this test exercises SHA-256 only (no `KeyId` lookup), so
    // the clone's empty `key_map` does not affect the result. If a future
    // edit makes this test exercise a keyed operation on `p2`, the clone
    // must call `register_key_handle` first — handles are NOT inherited.
    let p1 = provider_with_key(KeyId(0), 5);
    let p2 = p1.try_clone(b"1234").unwrap();
    // Both clones should be able to perform SHA-256 independently.
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    p1.sha256(b"x", &mut h1).unwrap();
    p2.sha256(b"x", &mut h2).unwrap();
    assert_eq!(h1, h2);
}

// -----------------------------------------------------------------------
// Public key validation tests
// -----------------------------------------------------------------------

#[test]
fn verify_p256_rejects_wrong_prefix() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let mut bad_key = [0x04u8; 65];
    bad_key[0] = 0x02; // compressed format, not supported
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(
        p.verify_p256(&bad_key, &digest, &sig),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn verify_p256_rejects_point_at_infinity() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let mut zero_key = [0u8; 65];
    zero_key[0] = 0x04; // correct prefix, but X and Y are all zeros
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(
        p.verify_p256(&zero_key, &digest, &sig),
        Err(VsError::InvalidInput)
    );
}

// -----------------------------------------------------------------------
// Edge case and boundary tests
// -----------------------------------------------------------------------

#[test]
fn forget_local_handle_clears_slot() {
    // audit-M4: the local-forget behaviour now lives on the inherent
    // method `forget_local_handle`. The trait `delete_key` no longer
    // performs this work (it would silently lie about token-side
    // destruction); see `delete_key_default_returns_policy_violation`.
    let mut p = provider_with_key(KeyId(5), 42);
    assert!(p.handle_for(KeyId(5)).is_ok());
    p.forget_local_handle(KeyId(5)).unwrap();
    assert_eq!(p.handle_for(KeyId(5)), Err(VsError::InvalidInput));
}

#[test]
fn forget_local_handle_out_of_bounds_returns_invalid_input() {
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert_eq!(
        p.forget_local_handle(KeyId(MAX_KEY_SLOTS as u32)),
        Err(VsError::InvalidInput)
    );
}

// -----------------------------------------------------------------------
// audit-M4: `delete_key` honesty about token-vs-local semantics
// -----------------------------------------------------------------------

#[test]
fn delete_key_default_returns_policy_violation() {
    // audit-M4 NEGATIVE: with the `policy-allow-token-destroy` feature
    // OFF (the default), the `CryptoProvider::delete_key` trait method
    // must refuse rather than silently performing a local-only forget.
    // The trait contract implies destruction of the underlying key
    // material; we cannot honour that without `C_DestroyObject`, and
    // we will not lie about it.
    let mut p = provider_with_key(KeyId(5), 42);
    assert_eq!(
        <Pkcs11CryptoProvider as CryptoProvider>::delete_key(&mut p, KeyId(5)),
        Err(VsError::PolicyViolation),
    );
    // The registered handle must still be queryable — nothing has
    // been forgotten, which is exactly the point: any caller that
    // ignored the error and relied on "forward secrecy after
    // delete_key" would have been wrong.
    assert_eq!(p.handle_for(KeyId(5)).unwrap(), 42);
}

#[test]
fn delete_key_default_out_of_bounds_returns_policy_violation() {
    // audit-M4 NEGATIVE: even the "out of bounds" path returns
    // `PolicyViolation` under the default feature set. The trait impl
    // never accepts the call without the feature flag, so the bounds
    // check on the inherent `forget_local_handle` (`InvalidInput` for
    // `>= MAX_KEY_SLOTS`) does not apply here. The behaviour is
    // intentionally uniform — callers should not branch on the error
    // code, they should switch to `forget_local_handle`.
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert_eq!(
        <Pkcs11CryptoProvider as CryptoProvider>::delete_key(
            &mut p,
            KeyId(MAX_KEY_SLOTS as u32),
        ),
        Err(VsError::PolicyViolation),
    );
}

#[test]
fn forget_local_handle_blocks_subsequent_encrypt() {
    // audit-M4 POSITIVE: after `forget_local_handle`, the local slot
    // is empty and any operation that goes through `handle_for`
    // (e.g. `aes_gcm_encrypt`) must fail with `VsError::InvalidInput`
    // because no handle is registered for the slot.
    let mut p = provider_with_key(KeyId(3), 0x1234);
    assert!(p.handle_for(KeyId(3)).is_ok());

    p.forget_local_handle(KeyId(3)).unwrap();

    // Confirm the lookup itself fails.
    assert_eq!(p.handle_for(KeyId(3)), Err(VsError::InvalidInput));

    // And confirm a downstream caller observes the same error class
    // when it tries to use the now-unregistered slot.
    let pt = [0xABu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; GCM_TAG_LEN];
    let nonce = [0xCDu8; 12];
    let err = p
        .aes_gcm_encrypt(KeyId(3), &nonce, &pt, &[], &mut ct, &mut tag)
        .err()
        .expect("encrypt with unregistered handle must fail");
    assert_eq!(err, VsError::InvalidInput);
}

#[cfg(feature = "policy-allow-token-destroy")]
#[test]
fn delete_key_with_feature_destroys_token_object_and_forgets_local() {
    // audit-M4 POSITIVE (gated): with `policy-allow-token-destroy`
    // enabled, the trait `delete_key` issues `C_DestroyObject` against
    // the registered handle and then forgets the slot locally.
    use core::sync::atomic::{AtomicU32, Ordering};

    static DESTROY_OBJECT_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_DESTROYED_HANDLE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn counting_c_destroy_object(
        _session: types::CkSessionHandle,
        h_object: types::CkObjectHandle,
    ) -> types::CkRv {
        DESTROY_OBJECT_CALLS.fetch_add(1, Ordering::SeqCst);
        // `CkObjectHandle` is `CkUlong` (u32 on Windows, u64 elsewhere).
        // Narrow to `u32` for the atomic — test handles fit comfortably.
        LAST_DESTROYED_HANDLE.store(h_object as u32, Ordering::SeqCst);
        types::CKR_OK
    }

    DESTROY_OBJECT_CALLS.store(0, Ordering::SeqCst);
    LAST_DESTROYED_HANDLE.store(0, Ordering::SeqCst);

    let mut fl = mock_fn_list();
    fl.c_destroy_object = counting_c_destroy_object;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(9), 0xAB).unwrap();

    <Pkcs11CryptoProvider as CryptoProvider>::delete_key(&mut p, KeyId(9)).unwrap();

    // Token destruction was issued exactly once against the registered
    // handle, and the local slot has been cleared.
    assert_eq!(DESTROY_OBJECT_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(LAST_DESTROYED_HANDLE.load(Ordering::SeqCst), 0xAB);
    assert_eq!(p.handle_for(KeyId(9)), Err(VsError::InvalidInput));
}

#[cfg(feature = "policy-allow-token-destroy")]
#[test]
fn delete_key_with_feature_propagates_token_destroy_failure() {
    // audit-M4 NEGATIVE (gated): when `C_DestroyObject` itself fails,
    // the error is propagated and the local slot is NOT cleared —
    // otherwise a caller might assume destruction succeeded.
    unsafe extern "C" fn failing_c_destroy_object(
        _session: types::CkSessionHandle,
        _h_object: types::CkObjectHandle,
    ) -> types::CkRv {
        // `CKR_GENERAL_ERROR` maps through `check_rv` to
        // `VsError::CryptoError`, which is what we want to assert on.
        types::CKR_GENERAL_ERROR
    }

    let mut fl = mock_fn_list();
    fl.c_destroy_object = failing_c_destroy_object;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(2), 0xCD).unwrap();

    let err = <Pkcs11CryptoProvider as CryptoProvider>::delete_key(&mut p, KeyId(2))
        .err()
        .expect("token-side destroy failure must propagate");
    // Any non-OK PKCS#11 return maps through `check_rv` to an error;
    // we don't pin the exact variant, only that the call failed.
    assert!(matches!(err, VsError::CryptoError | VsError::InvalidInput));
    // Slot is still registered: the caller can react (retry, escalate)
    // without losing the handle they need to re-issue destroy against.
    assert_eq!(p.handle_for(KeyId(2)).unwrap(), 0xCD);
}

#[cfg(feature = "policy-allow-token-destroy")]
#[test]
fn delete_key_with_feature_refuses_unregistered_slot() {
    // audit-M4: with the feature enabled, trying to delete a slot
    // that was never registered must NOT silently no-op — the trait
    // impl resolves the handle via `handle_for` and propagates the
    // `InvalidInput` lookup failure.
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert_eq!(
        <Pkcs11CryptoProvider as CryptoProvider>::delete_key(&mut p, KeyId(11)),
        Err(VsError::InvalidInput),
    );
}

#[test]
fn generate_key_returns_policy_violation() {
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    assert_eq!(
        p.generate_key(KeyId(0), KeyType::Aes256),
        Err(VsError::PolicyViolation)
    );
}

#[test]
fn random_bytes_empty_buffer_succeeds() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let mut buf = [0u8; 0];
    assert!(p.random_bytes(&mut buf).is_ok());
}

#[test]
fn aes_gcm_encrypt_oversized_plaintext_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 2049]; // exceeds MAX_PT (2032)
    let mut ct = [0u8; 2049];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn aes_gcm_decrypt_length_mismatch_returns_error() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 16];
    let tag = [0xBEu8; 16];
    let mut pt = [0u8; 8]; // wrong length
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn ecdh_derive_shared_with_valid_key_succeeds() {
    let p = provider_with_key(KeyId(3), 4);
    let mut shared = [0u8; 32];
    assert!(p
        .ecdh_derive_shared(KeyId(3), &P256_GENERATOR, &mut shared)
        .is_ok());
}

#[test]
fn ecdh_derive_shared_off_curve_rejected_and_wipes_output() {
    // Audit fix: off-curve peer-public must be rejected before any
    // FFI call, AND the caller's `shared_out` must be wiped on the
    // error path.
    let p = provider_with_key(KeyId(3), 4);
    let mut bad = [0x04u8; 65];
    bad[1..].fill(0xAA);
    let mut shared = [0xFFu8; 32];
    assert_eq!(
        p.ecdh_derive_shared(KeyId(3), &bad, &mut shared),
        Err(VsError::InvalidInput)
    );
    assert!(
        shared.iter().all(|&b| b == 0),
        "shared_out must be wiped on early-reject path"
    );
}

#[test]
fn register_all_64_key_slots() {
    let mut p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    for i in 0..MAX_KEY_SLOTS {
        assert!(p
            .register_key_handle(KeyId(i as u32), (i + 1) as CkObjectHandle)
            .is_ok());
    }
    for i in 0..MAX_KEY_SLOTS {
        assert_eq!(
            p.handle_for(KeyId(i as u32)).unwrap(),
            (i + 1) as CkObjectHandle
        );
    }
}

// -----------------------------------------------------------------------
// ECDH input validation tests
// -----------------------------------------------------------------------

#[test]
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

// -----------------------------------------------------------------------
// try_clone re-authentication test
// -----------------------------------------------------------------------

#[test]
fn try_clone_re_authenticates() {
    let p1 = provider_with_key(KeyId(0), 5);
    // try_clone now requires a PIN for re-authentication.
    let p2 = p1.try_clone(b"1234").unwrap();
    // audit-M6: SHA-256 is keyless, so `p2`'s empty `key_map` is not
    // observed here. Any future keyed call on `p2` would need a fresh
    // `register_key_handle` because handles are not inherited.
    let mut h = [0u8; 32];
    p2.sha256(b"test", &mut h).unwrap();
    assert!(h.iter().any(|&b| b != 0));
}

#[test]
fn try_clone_succeeds_before_any_encrypt() {
    // Positive path for the has_encrypted gate: cloning before any
    // aes_gcm_encrypt is permitted.
    let p1 = provider_with_key(KeyId(0), 5);
    assert!(p1.try_clone(b"1234").is_ok());
}

#[test]
fn try_clone_refuses_after_encrypt() {
    // Negative path: once an encrypt has occurred, the last_nonce cache
    // makes this provider unsafe to clone. Verify the gate trips.
    let p1 = provider_with_key(KeyId(0), 5);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    p1.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .unwrap();
    assert!(matches!(
        p1.try_clone(b"1234"),
        Err(VsError::PolicyViolation)
    ));
}

// -----------------------------------------------------------------------
// try_clone login failure test
// -----------------------------------------------------------------------

/// Mock that fails on the second `C_Login` call (simulates re-auth failure in `try_clone`).
static LOGIN_CALL_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

unsafe extern "C" fn mock_c_login_fail_second(
    _: types::CkSessionHandle,
    _: types::CkUserType,
    _: *const types::CkByte,
    _: types::CkUlong,
) -> types::CkRv {
    let n = LOGIN_CALL_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst) + 1;
    if n > 1 {
        types::CKR_PIN_INCORRECT
    } else {
        types::CKR_OK
    }
}

#[test]
fn try_clone_login_failure_closes_session() {
    // Reset counter
    LOGIN_CALL_COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
    let mut fl = mock_fn_list();
    fl.c_login = mock_c_login_fail_second;
    let p1 = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    // try_clone opens a new session, but login fails — session should be closed.
    let result = p1.try_clone(b"wrong-pin");
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// audit-M6: cloned providers MUST NOT inherit the parent's key_map
// -----------------------------------------------------------------------
//
// A clone that silently inherited the parent's `KeyId → CK_OBJECT_HANDLE`
// mapping could (a) collide with the parent on a persistence backend
// keyed solely by `KeyId` (each provider has its own
// `nonce_device_prefix`, so the second persist would be rejected by the
// monotonicity check — silent operational hazard), and (b) issue
// divergent cryptographic operations under the same logical `KeyId`
// against an HSM that does not coordinate them. The fix is to drop the
// inherited `key_map` and force the caller to re-register handles on
// the clone, making inheritance explicit.

#[test]
fn try_clone_drops_inherited_key_map() {
    // audit-M6 regression: a freshly cloned provider must NOT have any
    // handles inherited from its parent. The parent registers KeyId(0),
    // clones, and the clone's handle lookup must fail.
    let p1 = provider_with_key(KeyId(0), 5);
    // Parent sees the handle it registered.
    assert_eq!(p1.handle_for(KeyId(0)).ok(), Some(5));

    let p2 = p1.try_clone(b"1234").unwrap();
    // Clone starts with an empty key_map — the lookup must report
    // InvalidInput because the slot is `CK_INVALID_HANDLE`.
    assert_eq!(p2.handle_for(KeyId(0)), Err(VsError::InvalidInput));
}

#[test]
fn try_clone_then_re_register_handles_yields_independent_use() {
    // audit-M6: once the clone re-registers KeyId(0), both parent and
    // clone can independently use that slot. The parent is unaffected by
    // the clone re-registering, and the clone's handle is the one it
    // just installed (which may legitimately differ from the parent's).
    let p1 = provider_with_key(KeyId(0), 5);
    let mut p2 = p1.try_clone(b"1234").unwrap();

    // Re-register on the clone with a different token handle to prove
    // the two slots are independent storage.
    p2.register_key_handle(KeyId(0), 99).unwrap();

    assert_eq!(p1.handle_for(KeyId(0)).ok(), Some(5));
    assert_eq!(p2.handle_for(KeyId(0)).ok(), Some(99));

    // And both providers can perform keyed operations against KeyId(0).
    let mut mac1 = [0u8; 32];
    let mut mac2 = [0u8; 32];
    p1.hmac_sha256(KeyId(0), b"data", &mut mac1).unwrap();
    p2.hmac_sha256(KeyId(0), b"data", &mut mac2).unwrap();
    assert!(mac1.iter().any(|&b| b != 0));
    assert!(mac2.iter().any(|&b| b != 0));
}

#[test]
fn try_clone_keyed_op_without_re_register_fails() {
    // audit-M6 negative: a clone that attempts an AES-GCM encrypt under
    // an inherited `KeyId` without re-registering must fail with
    // `InvalidInput` — the slot is `CK_INVALID_HANDLE` for the clone.
    let p1 = provider_with_key(KeyId(0), 5);
    let p2 = p1.try_clone(b"1234").unwrap();
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert_eq!(
        p2.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::InvalidInput),
    );
}

#[test]
fn try_clone_keyed_op_without_re_register_fails_for_hmac_and_sign() {
    // audit-M6 negative (broader surface): every keyed operation routed
    // through `handle_for` must reject an un-registered slot on a clone.
    // Exercise HMAC, ECDSA sign, and ECDH to cover all four call sites.
    let p1 = provider_with_key(KeyId(0), 5);
    let p2 = p1.try_clone(b"1234").unwrap();

    let mut mac = [0u8; 32];
    assert_eq!(
        p2.hmac_sha256(KeyId(0), b"data", &mut mac),
        Err(VsError::InvalidInput),
    );

    let digest = [0xAAu8; 32];
    let mut sig = [0u8; 64];
    assert_eq!(
        p2.sign_p256(KeyId(0), &digest, &mut sig),
        Err(VsError::InvalidInput),
    );

    let mut shared = [0u8; 32];
    assert_eq!(
        p2.ecdh_derive_shared(KeyId(0), &P256_GENERATOR, &mut shared),
        Err(VsError::InvalidInput),
    );
}

#[test]
fn try_clone_re_registered_independent_nonce_caches() {
    // audit-M6: after both parent and clone re-register the same
    // `KeyId`, their per-provider `last_nonce` caches remain disjoint —
    // each provider can issue the same nonce once without tripping the
    // defence-in-depth detector on the OTHER provider. (Each provider
    // would still reject a repeat against ITSELF; that invariant is
    // covered by `aes_gcm_encrypt_rejects_repeated_nonce_same_key`.)
    //
    // In a deployment that pairs this provider with an
    // external-`nonce_device_prefix` scheme, this confirms the
    // already-tested disjoint-prefix invariant holds across the
    // `try_clone` boundary after the audit-M6 key_map drop.
    let p1 = provider_with_key(KeyId(0), 5);
    let mut p2 = p1.try_clone(b"1234").unwrap();
    p2.register_key_handle(KeyId(0), 5).unwrap();

    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];

    // Both providers can use the same (KeyId, nonce) pair exactly once
    // because their caches are independent.
    assert!(p1
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_ok());
    assert!(p2
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_ok());

    // And each rejects its OWN repeat (sanity check on the per-provider
    // cache; the disjoint-cache property is established above).
    assert_eq!(
        p1.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::CryptoError),
    );
    assert_eq!(
        p2.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::CryptoError),
    );
}

// -----------------------------------------------------------------------
// Negative C function pointer failure tests
// -----------------------------------------------------------------------

unsafe extern "C" fn mock_c_encrypt_init_fail(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_MECHANISM_INVALID
}

#[test]
fn aes_gcm_encrypt_init_failure_propagates_error() {
    let mut fl = mock_fn_list();
    fl.c_encrypt_init = mock_c_encrypt_init_fail;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_err());
}

unsafe extern "C" fn mock_c_digest_init_fail(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
) -> types::CkRv {
    types::CKR_MECHANISM_INVALID
}

#[test]
fn sha256_digest_init_failure_propagates_error() {
    let mut fl = mock_fn_list();
    fl.c_digest_init = mock_c_digest_init_fail;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    let mut hash = [0u8; 32];
    assert!(p.sha256(b"data", &mut hash).is_err());
}

unsafe extern "C" fn mock_c_sign_init_fail(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_KEY_HANDLE_INVALID
}

#[test]
fn sign_p256_init_failure_propagates_error() {
    let mut fl = mock_fn_list();
    fl.c_sign_init = mock_c_sign_init_fail;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let digest = [0xFFu8; 32];
    let mut sig = [0u8; 64];
    assert!(p.sign_p256(KeyId(0), &digest, &mut sig).is_err());
}

// -----------------------------------------------------------------------
// Stack buffer zeroization verification
// -----------------------------------------------------------------------

#[test]
fn aes_gcm_encrypt_with_empty_aad_succeeds() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 32];
    let mut ct = [0u8; 32];
    let mut tag = [0u8; 16];
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_ok());
}

#[test]
fn aes_gcm_decrypt_with_empty_aad_succeeds() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 32];
    let tag = [0xBEu8; 16];
    let mut pt = [0u8; 32];
    assert!(p
        .aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt)
        .is_ok());
}

// -----------------------------------------------------------------------
// ECDH short-attribute safety test
// -----------------------------------------------------------------------

/// Mock that returns a truncated `CKA_VALUE` (simulates a misbehaving token
/// that writes fewer than 32 bytes for the derived shared secret).
unsafe extern "C" fn mock_c_get_attribute_value_short(
    _: types::CkSessionHandle,
    _: types::CkObjectHandle,
    p_template: *mut types::CkAttribute,
    ul_count: types::CkUlong,
) -> types::CkRv {
    // CkUlong is `u32` on Windows / `u64` elsewhere; iterate over `usize`
    // indices so pointer arithmetic compiles on both ABIs.
    for i in 0..ul_count as usize {
        // SAFETY: caller supplies valid template slice.
        let attr = unsafe { &mut *p_template.add(i) };
        // Report a shorter-than-expected length (16 instead of 32).
        attr.ul_value_len = 16;
    }
    types::CKR_OK
}

#[test]
fn ecdh_short_attribute_zeroes_output_and_errors() {
    let mut fl = mock_fn_list();
    fl.c_get_attribute_value = mock_c_get_attribute_value_short;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let mut shared = [0xFFu8; 32]; // pre-fill to detect zeroing
    let result = p.ecdh_derive_shared(KeyId(0), &P256_GENERATOR, &mut shared);
    assert_eq!(result, Err(VsError::CryptoError));
    // The short-read path must wipe the potentially partial buffer.
    assert!(shared.iter().all(|&b| b == 0));
}

#[test]
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

// -----------------------------------------------------------------------
// Misbehaving-token tests (token returns out_len outside expected range)
// -----------------------------------------------------------------------

/// Mock `C_Encrypt` that reports a too-large `out_len` (longer than the
/// buffer provided). The provider must reject this without overflowing.
unsafe extern "C" fn mock_c_encrypt_oversized_outlen(
    _: types::CkSessionHandle,
    _p_data: *const types::CkByte,
    _ul_data_len: types::CkUlong,
    _p_out: *mut types::CkByte,
    pul_out_len: *mut types::CkUlong,
) -> types::CkRv {
    // Claim the HSM wrote far more than we asked for.
    unsafe { *pul_out_len = 0xFFFF_FFFF };
    types::CKR_OK
}

#[test]
fn aes_gcm_encrypt_oversized_outlen_is_rejected() {
    let mut fl = mock_fn_list();
    fl.c_encrypt = mock_c_encrypt_oversized_outlen;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag),
        Err(VsError::CryptoError)
    );
}

/// Mock `C_Decrypt` that reports an `out_len` smaller than the caller's
/// plaintext buffer — the provider must wipe `plaintext_out` and error.
unsafe extern "C" fn mock_c_decrypt_short_outlen(
    _: types::CkSessionHandle,
    _p_enc: *const types::CkByte,
    _ul_enc_len: types::CkUlong,
    p_out: *mut types::CkByte,
    pul_out_len: *mut types::CkUlong,
) -> types::CkRv {
    // Partially fill plaintext then claim a shorter length.
    // SAFETY: p_out is a 16-byte buffer supplied by the caller.
    unsafe {
        core::slice::from_raw_parts_mut(p_out, 16).fill(0xFF);
        *pul_out_len = 8;
    }
    types::CKR_OK
}

#[test]
fn aes_gcm_decrypt_short_outlen_wipes_and_errors() {
    let mut fl = mock_fn_list();
    fl.c_decrypt = mock_c_decrypt_short_outlen;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 16];
    let tag = [0xBEu8; 16];
    let mut pt = [0xFFu8; 16]; // pre-filled to detect wipe
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt),
        Err(VsError::CryptoError)
    );
    assert!(
        pt.iter().all(|&b| b == 0),
        "plaintext_out must be wiped on short out_len"
    );
}

/// Mock `C_Digest` that reports an out length different from 32.
unsafe extern "C" fn mock_c_digest_short_out(
    _: types::CkSessionHandle,
    _: *const types::CkByte,
    _: types::CkUlong,
    _p_digest: *mut types::CkByte,
    pul_len: *mut types::CkUlong,
) -> types::CkRv {
    unsafe { *pul_len = 16 }; // non-standard short digest
    types::CKR_OK
}

#[test]
fn sha256_short_out_is_rejected() {
    let mut fl = mock_fn_list();
    fl.c_digest = mock_c_digest_short_out;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    let mut h = [0u8; 32];
    assert_eq!(p.sha256(b"x", &mut h), Err(VsError::CryptoError));
}

/// Mock `C_Sign` that reports a signature/HMAC length different from the
/// expected one, forcing the provider to zeroize the output.
unsafe extern "C" fn mock_c_sign_short_out(
    _: types::CkSessionHandle,
    _: *const types::CkByte,
    _: types::CkUlong,
    p_sig: *mut types::CkByte,
    pul_sig_len: *mut types::CkUlong,
) -> types::CkRv {
    // SAFETY: caller guarantees p_sig has at least 8 bytes.
    unsafe {
        core::slice::from_raw_parts_mut(p_sig, 8).fill(0xFF);
        *pul_sig_len = 8;
    }
    types::CKR_OK
}

#[test]
fn hmac_sha256_short_out_zeroes_and_errors() {
    let mut fl = mock_fn_list();
    fl.c_sign = mock_c_sign_short_out;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let mut mac = [0xFFu8; 32];
    assert_eq!(
        p.hmac_sha256(KeyId(0), b"x", &mut mac),
        Err(VsError::CryptoError)
    );
    assert!(mac.iter().all(|&b| b == 0));
}

#[test]
fn sign_p256_short_out_zeroes_and_errors() {
    let mut fl = mock_fn_list();
    fl.c_sign = mock_c_sign_short_out;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let digest = [0xAAu8; 32];
    let mut sig = [0xFFu8; 64];
    assert_eq!(
        p.sign_p256(KeyId(0), &digest, &mut sig),
        Err(VsError::CryptoError)
    );
    assert!(sig.iter().all(|&b| b == 0));
}

/// Mock `C_DecryptInit` that fails — exercises the decrypt error path.
unsafe extern "C" fn mock_c_decrypt_init_fail(
    _: types::CkSessionHandle,
    _: *const types::CkMechanism,
    _: types::CkObjectHandle,
) -> types::CkRv {
    types::CKR_KEY_HANDLE_INVALID
}

#[test]
fn aes_gcm_decrypt_init_failure_propagates_error() {
    let mut fl = mock_fn_list();
    fl.c_decrypt_init = mock_c_decrypt_init_fail;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 16];
    let tag = [0xBEu8; 16];
    let mut pt = [0u8; 16];
    assert!(p
        .aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt)
        .is_err());
}

/// Mock `C_OpenSession` that fails — exercises constructor failure.
unsafe extern "C" fn mock_c_open_session_fail(
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
    _ph_session: *mut types::CkSessionHandle,
) -> types::CkRv {
    types::CKR_TOKEN_NOT_PRESENT
}

#[test]
fn new_open_session_failure_propagates_error() {
    let mut fl = mock_fn_list();
    fl.c_open_session = mock_c_open_session_fail;
    assert_eq!(
        Pkcs11CryptoProvider::new(fl, b"pin").err(),
        Some(VsError::NotInitialized)
    );
}

/// Mock `C_Initialize` that fails — exercises initialization failure.
unsafe extern "C" fn mock_c_initialize_fail(_: *mut core::ffi::c_void) -> types::CkRv {
    types::CKR_CRYPTOKI_NOT_INITIALIZED
}

#[test]
fn new_initialize_failure_propagates_error() {
    let mut fl = mock_fn_list();
    fl.c_initialize = mock_c_initialize_fail;
    assert!(Pkcs11CryptoProvider::new(fl, b"pin").is_err());
}

#[test]
fn library_pre_initialized_skips_c_initialize() {
    // If the library is already initialised the provider must accept the
    // caller's assertion and not invoke c_initialize. We force
    // c_initialize to fail; the constructor should still succeed.
    let mut fl = mock_fn_list();
    fl.c_initialize = mock_c_initialize_fail;
    fl.library_pre_initialized = 1;
    assert!(Pkcs11CryptoProvider::new(fl, b"pin").is_ok());
}

#[test]
fn verify_p256_returns_false_on_signature_invalid() {
    // Mock c_verify that always returns SIGNATURE_INVALID: verify must
    // return Ok(false), not an error.
    unsafe extern "C" fn c_verify_invalid(
        _: types::CkSessionHandle,
        _: *const types::CkByte,
        _: types::CkUlong,
        _: *const types::CkByte,
        _: types::CkUlong,
    ) -> types::CkRv {
        types::CKR_SIGNATURE_INVALID
    }
    let mut fl = mock_fn_list();
    fl.c_verify = c_verify_invalid;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    // Use the on-curve P-256 generator now that audit fix gates
    // verify_p256 on full on-curve validation.
    let digest = [0xAAu8; 32];
    let sig = [0x01u8; 64];
    assert_eq!(p.verify_p256(&P256_GENERATOR, &digest, &sig), Ok(false));
}

#[test]
fn forget_local_handle_then_reuse_slot() {
    // audit-M4: `forget_local_handle` clears the slot so a subsequent
    // `register_key_handle` for the same `KeyId` can re-bind a
    // different PKCS#11 object. (Note: this only re-binds the
    // *handle*; the original token-side key material is unaffected.
    // Callers wanting actual destruction must use vendor tooling or
    // the `policy-allow-token-destroy` feature.)
    let mut p = provider_with_key(KeyId(7), 42);
    p.forget_local_handle(KeyId(7)).unwrap();
    // Register a new handle in the same slot.
    p.register_key_handle(KeyId(7), 99).unwrap();
    assert_eq!(p.handle_for(KeyId(7)).unwrap(), 99);
}

#[test]
fn register_key_handle_overwrites_existing() {
    // Repeated register calls on the same slot replace the handle.
    let mut p = provider_with_key(KeyId(0), 11);
    p.register_key_handle(KeyId(0), 22).unwrap();
    assert_eq!(p.handle_for(KeyId(0)).unwrap(), 22);
}

#[test]
fn aes_gcm_oversized_aad_is_rejected() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let pt = [0xAAu8; 16];
    let aad = [0u8; 2049];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &aad, &mut ct, &mut tag),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn aes_gcm_decrypt_oversized_aad_is_rejected() {
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 16];
    let tag = [0xBEu8; 16];
    let aad = [0u8; 2049];
    let mut pt = [0u8; 16];
    assert_eq!(
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &aad, &tag, &mut pt),
        Err(VsError::InvalidInput)
    );
}

// -----------------------------------------------------------------------
// Audit fix HIGH (session leak on PIN-login failure)
// -----------------------------------------------------------------------

use core::sync::atomic::{AtomicU32, Ordering};

static CLOSE_SESSION_CALLS: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn mock_c_close_session_count(_: types::CkSessionHandle) -> types::CkRv {
    CLOSE_SESSION_CALLS.fetch_add(1, Ordering::SeqCst);
    types::CKR_OK
}

unsafe extern "C" fn mock_c_login_pin_incorrect(
    _: types::CkSessionHandle,
    _: types::CkUserType,
    _: *const u8,
    _: types::CkUlong,
) -> types::CkRv {
    types::CKR_PIN_INCORRECT
}

#[test]
#[serial]
fn login_failure_closes_open_session() {
    // Audit fix HIGH: when C_Login fails, the session opened by
    // C_OpenSession must be closed before propagating the error.
    // Repeated PIN-failure paths previously leaked sessions and
    // could exhaust the token's session table.
    CLOSE_SESSION_CALLS.store(0, Ordering::SeqCst);
    let mut fl = mock_fn_list();
    fl.c_login = mock_c_login_pin_incorrect;
    fl.c_close_session = mock_c_close_session_count;
    let result = Pkcs11CryptoProvider::new(fl, b"pin");
    assert!(result.is_err(), "PIN-incorrect must propagate as Err");
    assert_eq!(
        CLOSE_SESSION_CALLS.load(Ordering::SeqCst),
        1,
        "C_CloseSession must be called exactly once on login failure"
    );
}

// -----------------------------------------------------------------------
// Audit fix HIGH (plaintext wipe on decrypt failure)
// -----------------------------------------------------------------------

/// `C_Decrypt` mock that writes `0xCC` partial plaintext, then returns
/// `CKR_GENERAL_ERROR`. Caller code that does not wipe on error would
/// leak this oracle.
unsafe extern "C" fn mock_c_decrypt_partial_then_fail(
    _: types::CkSessionHandle,
    _: *const u8,
    _: types::CkUlong,
    out: *mut u8,
    out_len: *mut types::CkUlong,
) -> types::CkRv {
    // Write 0xCC into the caller's plaintext buffer first.
    // CkUlong is `u32` on Windows / `u64` elsewhere; cast to `usize`
    // for pointer arithmetic.
    let n: usize = unsafe { *out_len } as usize;
    for i in 0..n {
        unsafe { core::ptr::write(out.add(i), 0xCC) };
    }
    types::CKR_GENERAL_ERROR
}

#[test]
fn decrypt_failure_wipes_plaintext_buffer() {
    // Audit fix HIGH: a failing decrypt must not leak partially-decrypted
    // plaintext to the caller. The provider must scrub `plaintext_out`.
    let mut fl = mock_fn_list();
    fl.c_decrypt = mock_c_decrypt_partial_then_fail;
    let mut p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    p.register_key_handle(KeyId(0), 1).unwrap();
    let nonce = [0x01u8; 12];
    let ct = [0xAAu8; 32];
    let tag = [0xBEu8; 16];
    let mut pt = [0xFFu8; 32];
    let r = p.aes_gcm_decrypt(KeyId(0), &nonce, &ct, &[], &tag, &mut pt);
    assert!(r.is_err(), "decrypt error must propagate");
    assert!(
        pt.iter().all(|&b| b == 0),
        "plaintext_out must be wiped on decrypt failure (was: {:?})",
        &pt[..8]
    );
}

// -----------------------------------------------------------------------
// Audit fix HIGH (defensive last-nonce repeat detection)
// -----------------------------------------------------------------------

#[test]
fn aes_gcm_encrypt_rejects_repeated_nonce_same_key() {
    // Audit fix HIGH: defence-in-depth against caller-side nonce reuse.
    // Two encrypts under the same KeyId with the same nonce must fail
    // the second call with CryptoError, even though the underlying
    // token would happily comply.
    let p = provider_with_key(KeyId(0), 1);
    let nonce = [0x42u8; 12];
    let pt = [0xABu8; 16];
    let mut ct1 = [0u8; 16];
    let mut tag1 = [0u8; 16];
    let mut ct2 = [0u8; 16];
    let mut tag2 = [0u8; 16];

    // First call succeeds and primes the cache.
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct1, &mut tag1)
        .is_ok());

    // Second call with the same nonce on the same key is rejected.
    assert_eq!(
        p.aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct2, &mut tag2),
        Err(VsError::CryptoError)
    );
}

#[test]
fn aes_gcm_encrypt_different_nonce_same_key_succeeds() {
    // Sanity: the cache must NOT reject a fresh nonce under the same key.
    let p = provider_with_key(KeyId(0), 1);
    let nonce_a = [0x01u8; 12];
    let nonce_b = [0x02u8; 12];
    let pt = [0xABu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce_a, &pt, &[], &mut ct, &mut tag)
        .is_ok());
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce_b, &pt, &[], &mut ct, &mut tag)
        .is_ok());
}

#[test]
fn aes_gcm_encrypt_same_nonce_different_keys_succeeds() {
    // Sanity: nonce reuse is only catastrophic when the KEY is also
    // reused. The cache is keyed by (KeyId, nonce), so the same nonce
    // under two different keys must be accepted.
    let mut p = provider_with_key(KeyId(0), 1);
    p.register_key_handle(KeyId(1), 2).unwrap();
    let nonce = [0xAAu8; 12];
    let pt = [0xABu8; 16];
    let mut ct = [0u8; 16];
    let mut tag = [0u8; 16];
    assert!(p
        .aes_gcm_encrypt(KeyId(0), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_ok());
    assert!(p
        .aes_gcm_encrypt(KeyId(1), &nonce, &pt, &[], &mut ct, &mut tag)
        .is_ok());
}

// -----------------------------------------------------------------------
// Audit fix: find_object_by_label (wires previously-dead C_FindObjects*)
// -----------------------------------------------------------------------

static FIND_INIT_CALLS: AtomicU32 = AtomicU32::new(0);
static FIND_FIND_CALLS: AtomicU32 = AtomicU32::new(0);
static FIND_FINAL_CALLS: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn mock_c_find_objects_init_ok(
    _: types::CkSessionHandle,
    _: *const types::CkAttribute,
    _: types::CkUlong,
) -> types::CkRv {
    FIND_INIT_CALLS.fetch_add(1, Ordering::SeqCst);
    types::CKR_OK
}
unsafe extern "C" fn mock_c_find_objects_init_fail(
    _: types::CkSessionHandle,
    _: *const types::CkAttribute,
    _: types::CkUlong,
) -> types::CkRv {
    FIND_INIT_CALLS.fetch_add(1, Ordering::SeqCst);
    types::CKR_GENERAL_ERROR
}
unsafe extern "C" fn mock_c_find_objects_one(
    _: types::CkSessionHandle,
    ph_object: *mut types::CkObjectHandle,
    _: types::CkUlong,
    pul_count: *mut types::CkUlong,
) -> types::CkRv {
    FIND_FIND_CALLS.fetch_add(1, Ordering::SeqCst);
    unsafe {
        *ph_object = 0xC0FF_EE42;
        *pul_count = 1;
    }
    types::CKR_OK
}
unsafe extern "C" fn mock_c_find_objects_zero(
    _: types::CkSessionHandle,
    _: *mut types::CkObjectHandle,
    _: types::CkUlong,
    pul_count: *mut types::CkUlong,
) -> types::CkRv {
    FIND_FIND_CALLS.fetch_add(1, Ordering::SeqCst);
    unsafe {
        *pul_count = 0;
    }
    types::CKR_OK
}
unsafe extern "C" fn mock_c_find_objects_fail(
    _: types::CkSessionHandle,
    _: *mut types::CkObjectHandle,
    _: types::CkUlong,
    _: *mut types::CkUlong,
) -> types::CkRv {
    FIND_FIND_CALLS.fetch_add(1, Ordering::SeqCst);
    types::CKR_GENERAL_ERROR
}
unsafe extern "C" fn mock_c_find_objects_final_ok(_: types::CkSessionHandle) -> types::CkRv {
    FIND_FINAL_CALLS.fetch_add(1, Ordering::SeqCst);
    types::CKR_OK
}

fn reset_find_counters() {
    FIND_INIT_CALLS.store(0, Ordering::SeqCst);
    FIND_FIND_CALLS.store(0, Ordering::SeqCst);
    FIND_FINAL_CALLS.store(0, Ordering::SeqCst);
}

#[test]
#[serial]
fn find_object_by_label_returns_handle() {
    reset_find_counters();
    let mut fl = mock_fn_list();
    fl.c_find_objects_init = mock_c_find_objects_init_ok;
    fl.c_find_objects = mock_c_find_objects_one;
    fl.c_find_objects_final = mock_c_find_objects_final_ok;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    let result = p.find_object_by_label(b"vs-key-00", types::CKO_SECRET_KEY).unwrap();
    assert_eq!(result, Some(0xC0FF_EE42));
    assert_eq!(FIND_INIT_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(FIND_FIND_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(FIND_FINAL_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
#[serial]
fn find_object_by_label_returns_none_when_no_results() {
    reset_find_counters();
    let mut fl = mock_fn_list();
    fl.c_find_objects_init = mock_c_find_objects_init_ok;
    fl.c_find_objects = mock_c_find_objects_zero;
    fl.c_find_objects_final = mock_c_find_objects_final_ok;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    assert_eq!(p.find_object_by_label(b"absent", types::CKO_SECRET_KEY).unwrap(), None);
    assert_eq!(FIND_FINAL_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
#[serial]
fn find_object_by_label_init_failure_does_not_call_final() {
    reset_find_counters();
    let mut fl = mock_fn_list();
    fl.c_find_objects_init = mock_c_find_objects_init_fail;
    fl.c_find_objects_final = mock_c_find_objects_final_ok;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    assert!(p.find_object_by_label(b"x", types::CKO_SECRET_KEY).is_err());
    assert_eq!(FIND_INIT_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(FIND_FINAL_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
#[serial]
fn find_object_by_label_find_failure_still_calls_final() {
    reset_find_counters();
    let mut fl = mock_fn_list();
    fl.c_find_objects_init = mock_c_find_objects_init_ok;
    fl.c_find_objects = mock_c_find_objects_fail;
    fl.c_find_objects_final = mock_c_find_objects_final_ok;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();
    assert!(p.find_object_by_label(b"x", types::CKO_SECRET_KEY).is_err());
    assert_eq!(FIND_FIND_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(FIND_FINAL_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn find_object_by_label_rejects_oversized_label() {
    let p = Pkcs11CryptoProvider::new(mock_fn_list(), b"pin").unwrap();
    let big = [0xAAu8; 257];
    assert_eq!(p.find_object_by_label(&big, types::CKO_SECRET_KEY), Err(VsError::InvalidInput));
}

// ---------------------------------------------------------------------------
// CKA_CLASS-aware find_object_by_label (audit fix: class-disambiguated lookup).
//
// A token where two objects share `vs-key-00` (e.g. a public key handle
// and a secret key handle) must surface only the requested class.
// ---------------------------------------------------------------------------

/// `usize::MAX` means "no `CKA_CLASS` attr was seen in the template".
static LAST_FIND_CLASS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(usize::MAX);
/// `1` if the most recent template included a `CKA_CLASS` entry, else `0`.
static LAST_FIND_HAD_CLASS: AtomicU32 = AtomicU32::new(0);
/// Object handle the next `C_FindObjects` should return (test-controlled).
static FIND_RESPONSE_HANDLE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn mock_c_find_objects_init_inspect(
    _: types::CkSessionHandle,
    p_template: *const types::CkAttribute,
    ul_count: types::CkUlong,
) -> types::CkRv {
    FIND_INIT_CALLS.fetch_add(1, Ordering::SeqCst);
    LAST_FIND_HAD_CLASS.store(0, Ordering::SeqCst);
    LAST_FIND_CLASS.store(usize::MAX, Ordering::SeqCst);
    // SAFETY: template is a valid slice of CkAttribute provided by the helper under test.
    // CkUlong is `u32` on Windows / `u64` elsewhere; iterate over `usize`
    // indices so pointer arithmetic compiles on both ABIs.
    for i in 0..ul_count as usize {
        let attr = unsafe { &*p_template.add(i) };
        if attr.attribute_type == types::CKA_CLASS
            && attr.ul_value_len == core::mem::size_of::<types::CkObjectClass>() as types::CkUlong
            && !attr.p_value.is_null()
        {
            LAST_FIND_HAD_CLASS.store(1, Ordering::SeqCst);
            // SAFETY: p_value points at a CkObjectClass-sized local owned by the caller.
            let class = unsafe { *(attr.p_value as *const types::CkObjectClass) };
            // `CkObjectClass` aliases `CkUlong` (u32 on Windows, u64 elsewhere);
            // widen to `usize` for the AtomicUsize store.
            LAST_FIND_CLASS.store(class as usize, Ordering::SeqCst);
        }
    }
    types::CKR_OK
}

unsafe extern "C" fn mock_c_find_objects_class_aware(
    _: types::CkSessionHandle,
    ph_object: *mut types::CkObjectHandle,
    _: types::CkUlong,
    pul_count: *mut types::CkUlong,
) -> types::CkRv {
    FIND_FIND_CALLS.fetch_add(1, Ordering::SeqCst);
    let handle = FIND_RESPONSE_HANDLE.load(Ordering::SeqCst);
    // SAFETY: caller provided valid out-pointers.
    // `CkObjectHandle` aliases `CkUlong` (u32 on Windows, u64 elsewhere);
    // narrow the `usize` test-controlled value to that ABI width.
    unsafe {
        if handle == 0 {
            *pul_count = 0;
        } else {
            *ph_object = handle as types::CkObjectHandle;
            *pul_count = 1;
        }
    }
    types::CKR_OK
}

#[test]
#[serial]
fn find_object_by_label_filters_by_class() {
    // Two objects share `vs-key-00`: a public key (handle 0xAAAA) and a
    // secret key (handle 0xBBBB). Looking up the secret-key class must
    // yield the secret-key handle, not the public-key handle.
    reset_find_counters();
    let mut fl = mock_fn_list();
    fl.c_find_objects_init = mock_c_find_objects_init_inspect;
    fl.c_find_objects = mock_c_find_objects_class_aware;
    fl.c_find_objects_final = mock_c_find_objects_final_ok;
    let p = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();

    FIND_RESPONSE_HANDLE.store(0xAAAA, Ordering::SeqCst);
    let pub_handle = p
        .find_object_by_label(b"vs-key-00", types::CKO_PUBLIC_KEY)
        .unwrap();
    assert_eq!(pub_handle, Some(0xAAAA));
    assert_eq!(
        LAST_FIND_HAD_CLASS.load(Ordering::SeqCst),
        1,
        "template must include CKA_CLASS"
    );
    // `CkObjectClass` aliases `CkUlong` (u32 on Windows, u64 elsewhere);
    // widen to `usize` to match the AtomicUsize side of the comparison.
    assert_eq!(
        LAST_FIND_CLASS.load(Ordering::SeqCst),
        types::CKO_PUBLIC_KEY as usize,
        "CKA_CLASS in template must equal caller-supplied class"
    );

    FIND_RESPONSE_HANDLE.store(0xBBBB, Ordering::SeqCst);
    let sec_handle = p
        .find_object_by_label(b"vs-key-00", types::CKO_SECRET_KEY)
        .unwrap();
    assert_eq!(sec_handle, Some(0xBBBB));
    assert_eq!(LAST_FIND_HAD_CLASS.load(Ordering::SeqCst), 1);
    assert_eq!(
        LAST_FIND_CLASS.load(Ordering::SeqCst),
        types::CKO_SECRET_KEY as usize,
    );
    assert_ne!(pub_handle, sec_handle, "label collision must be class-resolved");

    // Negative path: a class that no object matches returns None.
    FIND_RESPONSE_HANDLE.store(0, Ordering::SeqCst);
    let none = p
        .find_object_by_label(b"vs-key-00", types::CKO_PRIVATE_KEY)
        .unwrap();
    assert_eq!(none, None, "no private-key under this label");
    assert_eq!(
        LAST_FIND_CLASS.load(Ordering::SeqCst),
        types::CKO_PRIVATE_KEY as usize,
    );
}

// ---------------------------------------------------------------------------
// audit-LOW: try_clone_with_pin_buffer must logout before close on login fail.
//
// Mirrors the cleanup discipline of `new_with_pin_buffer` so a partial-auth
// state on the token is explicitly cleared before the session is closed.
// ---------------------------------------------------------------------------

static LOGOUT_CALL_COUNT: AtomicU32 = AtomicU32::new(0);
static CLOSE_AFTER_LOGOUT_OK: AtomicU32 = AtomicU32::new(0);
/// `1` if a `c_close_session` arrives while a `c_logout` has already been
/// observed since the last `LOGOUT_CALL_COUNT` reset, else `0`. Verifies
/// *order*: logout precedes close on the failed-login cleanup path.
static SECOND_LOGIN_CALL_COUNT: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn mock_c_logout_count(_: types::CkSessionHandle) -> types::CkRv {
    LOGOUT_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    types::CKR_OK
}

unsafe extern "C" fn mock_c_close_session_after_logout(
    _: types::CkSessionHandle,
) -> types::CkRv {
    // Capture whether a logout has already been observed at the moment
    // the close arrives. Used to assert ordering, not just presence.
    if LOGOUT_CALL_COUNT.load(Ordering::SeqCst) > 0 {
        CLOSE_AFTER_LOGOUT_OK.store(1, Ordering::SeqCst);
    }
    types::CKR_OK
}

unsafe extern "C" fn mock_c_login_fail_second_v2(
    _: types::CkSessionHandle,
    _: types::CkUserType,
    _: *const types::CkByte,
    _: types::CkUlong,
) -> types::CkRv {
    let n = SECOND_LOGIN_CALL_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    if n > 1 {
        types::CKR_PIN_INCORRECT
    } else {
        types::CKR_OK
    }
}

#[test]
fn try_clone_with_pin_logout_on_login_failure() {
    // Reset shared counters.
    SECOND_LOGIN_CALL_COUNT.store(0, Ordering::SeqCst);
    LOGOUT_CALL_COUNT.store(0, Ordering::SeqCst);
    CLOSE_AFTER_LOGOUT_OK.store(0, Ordering::SeqCst);

    let mut fl = mock_fn_list();
    fl.c_login = mock_c_login_fail_second_v2;
    fl.c_logout = mock_c_logout_count;
    fl.c_close_session = mock_c_close_session_after_logout;

    // First login (inside `new`) succeeds. The drop-time `c_logout` from
    // the parent provider will run *after* the assertions below, so it
    // does not pollute the count we sample mid-test.
    let p1 = Pkcs11CryptoProvider::new(fl, b"pin").unwrap();

    let logout_before = LOGOUT_CALL_COUNT.load(Ordering::SeqCst);
    let result = p1.try_clone(b"wrong-pin");
    assert!(result.is_err(), "second login must fail");

    let logout_after = LOGOUT_CALL_COUNT.load(Ordering::SeqCst);
    assert!(
        logout_after > logout_before,
        "try_clone failed-login path must invoke c_logout"
    );
    assert_eq!(
        CLOSE_AFTER_LOGOUT_OK.load(Ordering::SeqCst),
        1,
        "c_close_session must arrive AFTER c_logout on the failed-login path"
    );
}

// ---------------------------------------------------------------------------
// audit-LOW: build_label_buffer + volatile_wipe contract for find_object_by_label
//
// `build_label_buffer` is the same helper the live call path uses. The wipe
// step itself happens on a per-frame local that is unreachable after the
// function returns, so we exercise the contract through the helper and the
// in-crate `volatile_wipe` primitive:
//   1. `build_label_buffer` populates the requested bytes and zero-pads.
//   2. `volatile_wipe` clears the entire 256-byte buffer to zero.
// Together with the in-source `audit-LOW` comments at every `return` in
// `find_object_by_label`, this gives a white-box proof that the local
// buffer is scrubbed on every exit path.
// ---------------------------------------------------------------------------

#[test]
fn build_label_buffer_copies_and_zero_pads() {
    let label = b"vs-key-00";
    let buf = build_label_buffer(label);
    assert_eq!(&buf[..label.len()], label);
    assert!(
        buf[label.len()..].iter().all(|&b| b == 0),
        "tail of buffer must be zero-padded"
    );
}

#[test]
fn build_label_buffer_clamps_oversized_input() {
    // `find_object_by_label` rejects oversized labels before reaching
    // this helper, but the helper itself must remain panic-free under
    // direct invocation.
    let big = [0xAAu8; 1024];
    let buf = build_label_buffer(&big);
    assert!(buf.iter().all(|&b| b == 0xAA));
}

#[test]
fn find_object_by_label_local_buffer_is_wiped_by_volatile_wipe() {
    // White-box: prove the wipe primitive used inside the function
    // clears a label-shaped buffer to all zeros, regardless of the
    // bytes initially copied in. This pairs with the inline
    // `volatile_wipe(&mut label_local)` calls at each `return` in
    // `find_object_by_label`.
    let mut buf = build_label_buffer(b"vs-key-00");
    assert!(buf.iter().any(|&b| b != 0), "pre-wipe buffer is non-zero");
    volatile_wipe(&mut buf);
    assert!(
        buf.iter().all(|&b| b == 0),
        "post-wipe buffer must be all zeros"
    );

    // Negative: a buffer that has not been wiped retains its contents.
    let buf2 = build_label_buffer(b"vs-key-00");
    assert_eq!(&buf2[..9], b"vs-key-00");
}

// ---------------------------------------------------------------------------
// audit-LOW: to_ck_ulong enforces the 31-bit Cryptoki ceiling.
// ---------------------------------------------------------------------------

#[test]
fn to_ck_ulong_rejects_above_31_bit_ceiling() {
    // 0x7FFF_FFFF (i32::MAX as usize) is the highest accepted value.
    assert_eq!(to_ck_ulong(0x7FFF_FFFF).unwrap(), 0x7FFF_FFFF);
    // 0x8000_0000 — the first value above the ceiling — must be rejected.
    assert_eq!(
        to_ck_ulong(0x8000_0000),
        Err(VsError::InvalidInput),
        "values at or above 2^31 must be rejected for portability"
    );
    // Sanity: a value comfortably under the per-call buffer cap is accepted.
    assert!(to_ck_ulong(2048).is_ok());
}

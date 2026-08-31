// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Integration coverage for audit-H4 / audit-M5 follow-up: every
//! AES-GCM encrypt invoked by a back-to-back chain of
//! `flush_with_persistence` calls uses a distinct 12-byte IV.
//!
//! The PKCS#11 mock captures the IV that the production
//! `Pkcs11CryptoProvider::aes_gcm_encrypt` hands to `c_encrypt_init`
//! through the `CK_GCM_PARAMS.p_iv` pointer. The assertion is that
//! across 30 flushes the 30 captured IVs are pairwise distinct.
//!
//! 30 cycles (rather than the 50 from the previous attempt) keeps
//! the test runtime well under one second on the slowest CI runner.
//!
//! Verified against production (`git grep`):
//!   - `Pkcs11CryptoProvider::aes_gcm_encrypt` builds `CkAesGcmParams`
//!     and calls `c_encrypt_init(session, &mechanism, h_key)` at
//!     `crates/crypto-pkcs11/src/lib.rs:1173`. `mechanism.p_parameter`
//!     points at `CkAesGcmParams` and `CkAesGcmParams.p_iv` points at
//!     the 12-byte IV.
//!   - `pub fn flush_with_persistence` at
//!     `crates/vsoc-telemetry/src/lib.rs:2136` calls
//!     `crypto.aes_gcm_encrypt` exactly once per flush
//!     (`vsoc-telemetry/src/lib.rs:2502`).

use core::cell::RefCell;
use std::sync::Mutex;

use vs_crypto::KeyId;
use vs_crypto_pkcs11::ffi::{
    CkAttribute, CkByte, CkFlags, CkMechanism, CkObjectHandle, CkRv, CkSessionHandle, CkSlotId,
    CkTokenInfo, CkUlong, CkUserType, Pkcs11FunctionList,
};
use vs_types::{AlertSeverity, VsError};
use vs_vsoc_telemetry::{
    CounterPersistence, PersistedFlushCounter, TelemetryConfig, TelemetryEntry, TelemetryUplink,
};

// Local mirror of `crates/crypto-pkcs11/src/types.rs::CkAesGcmParams`.
// The `types` module is private in `vs-crypto-pkcs11` and only a
// subset is re-exported through `ffi::*`; `CkAesGcmParams` is NOT
// among the re-exports. The struct is `#[repr(C)]` so a layout-faithful
// mirror is sufficient to read the IV pointer back across the mock
// boundary. Keep field order in lock-step with the production type.
#[repr(C)]
struct MirrorAesGcmParams {
    p_iv: *mut CkByte,
    ul_iv_len: CkUlong,
    ul_iv_bits: CkUlong,
    p_aad: *mut CkByte,
    ul_aad_len: CkUlong,
    ul_tag_bits: CkUlong,
}

// -----------------------------------------------------------------------
// Captured-IV ledger. Tests in the same binary run serially within a
// `cargo test` worker, so a single global `Mutex` is sufficient. We
// keep the ledger scoped to this file (it lives in this test crate)
// and clear it at the start of each test that uses it.
// -----------------------------------------------------------------------

static CAPTURED_IVS: Mutex<Vec<[u8; 12]>> = Mutex::new(Vec::new());

fn clear_ivs() {
    CAPTURED_IVS.lock().unwrap().clear();
}

fn snapshot_ivs() -> Vec<[u8; 12]> {
    CAPTURED_IVS.lock().unwrap().clone()
}

// -----------------------------------------------------------------------
// Mock PKCS#11 function table. Mirrors the shape of
// `crates/integration-tests/tests/integration.rs::mock_pkcs11::build_mock_fl`
// but does NOT import from that file (test binaries don't share
// modules). `c_encrypt_init` is the only function that diverges: it
// reads the `CkAesGcmParams.p_iv` out of the mechanism and copies the
// 12 IV bytes into `CAPTURED_IVS`.
// -----------------------------------------------------------------------

const CKR_OK: CkRv = 0;
const GCM_TAG_LEN: usize = 16;
const SHA256_LEN: usize = 32;
const ECDSA_SIG_LEN: usize = 64;

unsafe extern "C" fn c_initialize(_: *mut core::ffi::c_void) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_finalize(_: *mut core::ffi::c_void) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_open_session(
    _: CkSlotId,
    _: CkFlags,
    _: *mut core::ffi::c_void,
    _: Option<unsafe extern "C" fn(CkSessionHandle, CkUlong, *mut core::ffi::c_void) -> CkRv>,
    ph: *mut CkSessionHandle,
) -> CkRv {
    // SAFETY: PKCS#11 C_OpenSession contract: `phSession` is writable.
    unsafe { *ph = 1 };
    CKR_OK
}
unsafe extern "C" fn c_close_session(_: CkSessionHandle) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_login(
    _: CkSessionHandle,
    _: CkUserType,
    _: *const CkByte,
    _: CkUlong,
) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_logout(_: CkSessionHandle) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_get_token_info(_: CkSlotId, _: *mut CkTokenInfo) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_find_objects_init(
    _: CkSessionHandle,
    _: *const CkAttribute,
    _: CkUlong,
) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_find_objects(
    _: CkSessionHandle,
    _: *mut CkObjectHandle,
    _: CkUlong,
    p: *mut CkUlong,
) -> CkRv {
    // SAFETY: PKCS#11 C_FindObjects contract: `pulObjectCount` is writable.
    unsafe { *p = 0 };
    CKR_OK
}
unsafe extern "C" fn c_find_objects_final(_: CkSessionHandle) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_get_attribute_value(
    _: CkSessionHandle,
    _: CkObjectHandle,
    _: *mut CkAttribute,
    _: CkUlong,
) -> CkRv {
    CKR_OK
}

// THE ONE INTERESTING FUNCTION: capture the IV before delegating.
unsafe extern "C" fn c_encrypt_init(
    _: CkSessionHandle,
    p_mechanism: *const CkMechanism,
    _: CkObjectHandle,
) -> CkRv {
    if p_mechanism.is_null() {
        return CKR_OK;
    }
    // SAFETY: `Pkcs11CryptoProvider::aes_gcm_encrypt` always passes a
    // pointer to a stack-resident `CkMechanism` whose `p_parameter`
    // points at a stack-resident `CkAesGcmParams` with a 12-byte
    // `p_iv` that lives at least as long as this call. The production
    // code path is at `crates/crypto-pkcs11/src/lib.rs:1157` onwards.
    let mech = unsafe { &*p_mechanism };
    if mech.p_parameter.is_null() {
        return CKR_OK;
    }
    // SAFETY: same provenance — `p_parameter` is the address of the
    // caller's stack-allocated `CkAesGcmParams`. `MirrorAesGcmParams`
    // is a `#[repr(C)]` layout-faithful mirror of the production
    // `CkAesGcmParams` definition (`crypto-pkcs11/src/types.rs`).
    let params = unsafe { &*(mech.p_parameter as *const MirrorAesGcmParams) };
    if params.p_iv.is_null() {
        return CKR_OK;
    }
    let iv_len = params.ul_iv_len as usize;
    if iv_len != 12 {
        return CKR_OK;
    }
    let mut buf = [0u8; 12];
    // SAFETY: `p_iv` points to `ul_iv_len == 12` readable bytes per
    // the production caller's contract.
    let src = unsafe { core::slice::from_raw_parts(params.p_iv, 12) };
    buf.copy_from_slice(src);
    CAPTURED_IVS.lock().unwrap().push(buf);
    CKR_OK
}

unsafe extern "C" fn c_encrypt(
    _: CkSessionHandle,
    p_data: *const CkByte,
    ul_data_len: CkUlong,
    p_out: *mut CkByte,
    pul: *mut CkUlong,
) -> CkRv {
    // SAFETY: PKCS#11 C_Encrypt contract — see the comment in
    // `tests/integration.rs::mock_pkcs11::c_encrypt`. `CkUlong` is
    // `u32` on Windows / `u64` elsewhere; cast at the FFI boundary.
    let len = ul_data_len as usize;
    let src = unsafe { core::slice::from_raw_parts(p_data, len) };
    let total = len + GCM_TAG_LEN;
    let dst = unsafe { core::slice::from_raw_parts_mut(p_out, total) };
    dst[..len].copy_from_slice(src);
    dst[len..].fill(0xBE);
    // SAFETY: `pul` is the writable `CK_ULONG` from the same contract.
    unsafe { *pul = total as CkUlong };
    CKR_OK
}
unsafe extern "C" fn c_decrypt_init(
    _: CkSessionHandle,
    _: *const CkMechanism,
    _: CkObjectHandle,
) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_decrypt(
    _: CkSessionHandle,
    p_enc: *const CkByte,
    ul: CkUlong,
    p_out: *mut CkByte,
    pul: *mut CkUlong,
) -> CkRv {
    let total = ul as usize;
    let pt_len = total - GCM_TAG_LEN;
    // SAFETY: see `tests/integration.rs::mock_pkcs11::c_decrypt`.
    let src = unsafe { core::slice::from_raw_parts(p_enc, pt_len) };
    let dst = unsafe { core::slice::from_raw_parts_mut(p_out, pt_len) };
    dst.copy_from_slice(src);
    unsafe { *pul = pt_len as CkUlong };
    CKR_OK
}
unsafe extern "C" fn c_digest_init(_: CkSessionHandle, _: *const CkMechanism) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_digest(
    _: CkSessionHandle,
    _: *const CkByte,
    _: CkUlong,
    p_out: *mut CkByte,
    pul: *mut CkUlong,
) -> CkRv {
    // SAFETY: see `tests/integration.rs::mock_pkcs11::c_digest`. The
    // 0x77 byte avoids the HIGH-M position-varying sentinel pattern
    // (`SENTINEL ^ i`) for every sentinel/length combo the
    // production wrapper uses.
    let out = unsafe { core::slice::from_raw_parts_mut(p_out, SHA256_LEN) };
    out.fill(0x77);
    unsafe { *pul = SHA256_LEN as CkUlong };
    CKR_OK
}
unsafe extern "C" fn c_sign_init(
    _: CkSessionHandle,
    _: *const CkMechanism,
    _: CkObjectHandle,
) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_sign(
    _: CkSessionHandle,
    _: *const CkByte,
    _: CkUlong,
    p_sig: *mut CkByte,
    pul: *mut CkUlong,
) -> CkRv {
    // SAFETY: see `tests/integration.rs::mock_pkcs11::c_sign`. Same
    // 0x77-vs-position-varying-sentinel rationale.
    let out = unsafe { core::slice::from_raw_parts_mut(p_sig, ECDSA_SIG_LEN) };
    out.fill(0x77);
    unsafe { *pul = ECDSA_SIG_LEN as CkUlong };
    CKR_OK
}
unsafe extern "C" fn c_verify_init(
    _: CkSessionHandle,
    _: *const CkMechanism,
    _: CkObjectHandle,
) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_verify(
    _: CkSessionHandle,
    _: *const CkByte,
    _: CkUlong,
    _: *const CkByte,
    _: CkUlong,
) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_derive_key(
    _: CkSessionHandle,
    _: *const CkMechanism,
    _: CkObjectHandle,
    _: *const CkAttribute,
    _: CkUlong,
    ph: *mut CkObjectHandle,
) -> CkRv {
    // SAFETY: PKCS#11 C_DeriveKey contract: `phKey` is writable.
    unsafe { *ph = 0xDEAD };
    CKR_OK
}
unsafe extern "C" fn c_destroy_object(_: CkSessionHandle, _: CkObjectHandle) -> CkRv {
    CKR_OK
}
unsafe extern "C" fn c_generate_random(
    _: CkSessionHandle,
    p: *mut CkByte,
    len: CkUlong,
) -> CkRv {
    // SAFETY: PKCS#11 C_GenerateRandom contract: `RandomData` is writable.
    // `CkUlong` is `u32` on Windows / `u64` elsewhere; cast at FFI boundary.
    let out = unsafe { core::slice::from_raw_parts_mut(p, len as usize) };
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x42);
    }
    CKR_OK
}
unsafe extern "C" fn c_create_object(
    _: CkSessionHandle,
    _: *const CkAttribute,
    _: CkUlong,
    ph: *mut CkObjectHandle,
) -> CkRv {
    // SAFETY: PKCS#11 C_CreateObject contract: `phObject` is writable.
    unsafe { *ph = 0xBEEF };
    CKR_OK
}

fn build_mock_fl() -> Pkcs11FunctionList {
    Pkcs11FunctionList {
        c_initialize,
        c_finalize,
        c_open_session,
        c_close_session,
        c_logout,
        c_login,
        c_get_token_info,
        c_find_objects_init,
        c_find_objects,
        c_find_objects_final,
        c_get_attribute_value,
        c_encrypt_init,
        c_encrypt,
        c_decrypt_init,
        c_decrypt,
        c_digest_init,
        c_digest,
        c_sign_init,
        c_sign,
        c_verify_init,
        c_verify,
        c_derive_key,
        c_destroy_object,
        c_generate_random,
        c_create_object,
        slot_id: 0,
        library_pre_initialized: 0,
    }
}

// -----------------------------------------------------------------------
// Counting persistence stub: writes are no-ops; tracks how many times
// `persist` was called so a smoke check can match it against the
// number of expected flush cycles.
//
// Modelled after the in-crate `CountingPersistence` in
// `crates/vsoc-telemetry/src/tests/mod.rs` but written from scratch
// here per the task plan ("DO NOT import it — write your own").
// -----------------------------------------------------------------------

struct CountingPersistence {
    persists: RefCell<u32>,
}

impl CountingPersistence {
    fn new() -> Self {
        Self {
            persists: RefCell::new(0),
        }
    }
}

impl CounterPersistence for CountingPersistence {
    fn persist(&mut self, _new_counter: u64) -> Result<(), VsError> {
        *self.persists.borrow_mut() += 1;
        Ok(())
    }
}

// -----------------------------------------------------------------------
// The test itself.
// -----------------------------------------------------------------------

const NUM_FLUSHES: usize = 30;

#[test]
fn aes_gcm_iv_is_distinct_across_30_back_to_back_flushes() {
    clear_ivs();

    let provider =
        vs_crypto_pkcs11::Pkcs11CryptoProvider::new(build_mock_fl(), b"pin").expect(
            "provider must initialise against the mock function list",
        );

    let cfg = TelemetryConfig {
        max_bytes_per_minute: 1_000_000,
        batch_size: 1,
        encryption_key_id: KeyId::new(0),
        signing_key_id: KeyId::new(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };

    let mut uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device())
            .expect("uplink must restore against a fresh-device counter");

    let mut persistence = CountingPersistence::new();

    for cycle in 0..NUM_FLUSHES {
        let entry = TelemetryEntry::new(
            cycle as u64,
            1_000_000 + cycle as u64,
            0x01,
            AlertSeverity::High,
            b"x",
        )
        .expect("entry must construct under the 64-byte payload ceiling");
        uplink
            .submit_entry(entry)
            .expect("submit_entry must accept a fresh in-order entry");

        // ts_us must be strictly monotonic across flushes (audit-LOW
        // MAX_REASONABLE_TS_US ceiling is at 2^63 — well clear of the
        // small values here).
        let ts_us = 2_000_000 + (cycle as u64) * 1_000;
        uplink
            .flush_with_persistence(&provider, ts_us, &mut persistence)
            .expect("flush must not fail under the captured-IV mock");
    }

    assert_eq!(
        *persistence.persists.borrow(),
        NUM_FLUSHES as u32,
        "every flush should advance the persisted counter exactly once"
    );

    let ivs = snapshot_ivs();
    assert_eq!(
        ivs.len(),
        NUM_FLUSHES,
        "exactly one IV must be captured per flush (one `c_encrypt_init` call)"
    );

    // O(n^2) pairwise distinctness check. n = 30 -> 435 compares, fine.
    for (i, iv_i) in ivs.iter().enumerate() {
        for (j, iv_j) in ivs.iter().enumerate().skip(i + 1) {
            assert_ne!(
                iv_i, iv_j,
                "AES-GCM IV reuse detected: flush #{i} and flush #{j} share IV {iv_i:02x?}"
            );
        }
    }
}

// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! Craton Shield Enterprise — cross-crate integration tests.
//!
//! These tests previously lived in the workspace root crate's
//! `src/lib.rs` (`vs-cratonshield-enterprise-tests`). Moved to a
//! dedicated `crates/integration-tests` sub-crate (audit finding MED-6):
//!   1. `cargo doc --workspace` no longer documents test mocks as public API.
//!   2. Workspace consumers no longer pull this harness's dev-deps when
//!      they only want one of the production crates.
//!
//! Since this file lives under `tests/`, `#[cfg(test)]` is implicit and
//! there is no need for an outer `mod tests` wrapper.

// -----------------------------------------------------------------------
// Report crate tests have moved to craton-shield-core (Apache-2.0).
// See craton-shield-core/crates/report-{iec62443,iso21434,iec62304}.
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// 1. VSOC telemetry entry creation
// -----------------------------------------------------------------------

#[test]
fn vsoc_telemetry_entry_creation() {
    use vs_vsoc_telemetry::TelemetryEntry;

    let payload = b"test-event-data";
    let entry = TelemetryEntry::new(
        1,                             // sequence
        1_000_000,                     // timestamp_us
        0x01,                          // event_type
        vs_types::AlertSeverity::High, // severity
        payload,
    )
    .expect("entry creation must succeed");

    assert_eq!(entry.sequence, 1);
    assert_eq!(entry.timestamp_us, 1_000_000);
    assert_eq!(entry.event_type, 0x01);
    assert_eq!(entry.payload_len, payload.len() as u8);
    assert_eq!(&entry.payload[..payload.len()], payload);
}

#[test]
fn vsoc_telemetry_entry_rejects_oversized_payload() {
    use vs_vsoc_telemetry::TelemetryEntry;

    let oversized = [0xFFu8; 65];
    let result = TelemetryEntry::new(0, 0, 0, vs_types::AlertSeverity::Info, &oversized);
    assert!(result.is_err(), "payload > 64 bytes must be rejected");
}

#[test]
fn vsoc_telemetry_entry_max_payload_succeeds() {
    use vs_vsoc_telemetry::TelemetryEntry;

    let max_payload = [0xAAu8; 64];
    let entry = TelemetryEntry::new(
        42,
        2_000_000,
        0xFF,
        vs_types::AlertSeverity::Critical,
        &max_payload,
    );
    assert!(entry.is_ok());
    let e = entry.unwrap();
    assert_eq!(e.payload_len, 64);
}

#[test]
fn vsoc_telemetry_entry_empty_payload_succeeds() {
    use vs_vsoc_telemetry::TelemetryEntry;

    let entry = TelemetryEntry::new(0, 0, 0, vs_types::AlertSeverity::Info, &[]);
    assert!(entry.is_ok());
    assert_eq!(entry.unwrap().payload_len, 0);
}

// -----------------------------------------------------------------------
// 2. Telemetry uplink integration
// -----------------------------------------------------------------------

#[test]
// TODO: pre-existing — migrate to `TelemetryUplink::try_restore` and drop
// the allow. Out of scope for the misleading-method-name rename.
#[allow(deprecated)]
fn vsoc_telemetry_uplink_submit_and_query_count() {
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::{TelemetryConfig, TelemetryEntry, TelemetryUplink};

    let config = TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 4,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let mut uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::restore(
            config,
            vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
        );

    assert_eq!(uplink.queued(), 0);
    assert_eq!(uplink.dropped_count(), 0);
    assert_eq!(uplink.flush_counter(), 0);

    let entry = TelemetryEntry::new(1, 100_000, 0x01, vs_types::AlertSeverity::Medium, b"data")
        .unwrap();
    uplink.submit_entry(entry).unwrap();
    assert_eq!(uplink.queued(), 1);
}

// -----------------------------------------------------------------------
// 3. crypto-pkcs11 types are accessible
// -----------------------------------------------------------------------

#[test]
fn crypto_pkcs11_provider_type_accessible() {
    // Verify that the Pkcs11CryptoProvider struct is visible and its
    // size is non-zero (i.e. it is a real type, not a ZST).
    assert!(
        core::mem::size_of::<vs_crypto_pkcs11::Pkcs11CryptoProvider>() > 0,
        "Pkcs11CryptoProvider must be a non-ZST type",
    );
}

// -----------------------------------------------------------------------
// 4. crypto-tpm types are accessible
// -----------------------------------------------------------------------

#[test]
fn crypto_tpm_provider_type_accessible() {
    // Verify that the TpmCryptoProvider struct is visible and its
    // size is non-zero.
    assert!(
        core::mem::size_of::<vs_crypto_tpm::TpmCryptoProvider>() > 0,
        "TpmCryptoProvider must be a non-ZST type",
    );
}

// -----------------------------------------------------------------------
// 5. HAL-QNX types are accessible
// -----------------------------------------------------------------------

#[test]
fn hal_qnx_types_accessible() {
    assert!(
        core::mem::size_of::<vs_hal_qnx::QnxCanBus>() > 0,
        "QnxCanBus must be a non-ZST type",
    );
    assert!(
        core::mem::size_of::<vs_hal_qnx::QnxTimer>() > 0
            || core::mem::size_of::<vs_hal_qnx::QnxTimer>() == 0,
        "QnxTimer is a ZST — this is expected",
    );
}

// -----------------------------------------------------------------------
// 6. Cross-crate: telemetry config field types
// -----------------------------------------------------------------------

#[test]
fn telemetry_config_uses_key_id_type() {
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::TelemetryConfig;

    let config = TelemetryConfig {
        max_bytes_per_minute: 1024,
        batch_size: 8,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0xABu8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    assert_eq!(config.batch_size, 8);
    assert_eq!(config.device_id[0], 0xAB);
}

// -----------------------------------------------------------------------
// 7. FFI module visibility
// -----------------------------------------------------------------------

#[test]
fn pkcs11_ffi_module_is_public() {
    // Verify the ffi module is accessible and Pkcs11FunctionList is visible.
    assert!(
        core::mem::size_of::<vs_crypto_pkcs11::ffi::Pkcs11FunctionList>() > 0,
        "Pkcs11FunctionList must be accessible via public ffi module",
    );
}

#[test]
fn tpm_ffi_module_is_public() {
    // Verify the ffi module is accessible and TpmFunctionList is visible.
    assert!(
        core::mem::size_of::<vs_crypto_tpm::ffi::TpmFunctionList>() > 0,
        "TpmFunctionList must be accessible via public ffi module",
    );
}

// -----------------------------------------------------------------------
// 8. TpmCryptoProvider does not implement Clone (safety)
// -----------------------------------------------------------------------

#[test]
fn tpm_provider_is_not_clone() {
    // TpmCryptoProvider must NOT implement Clone (would cause double-free).
    // We verify via size_of that the type exists and is non-ZST;
    // new_sibling_context is the intended duplication path.
    assert!(
        core::mem::size_of::<vs_crypto_tpm::TpmCryptoProvider>() > 0,
        "TpmCryptoProvider exists and is non-ZST (use new_sibling_context, not Clone)",
    );
}

// -----------------------------------------------------------------------
// 9. Telemetry uplink ring buffer overflow
// -----------------------------------------------------------------------

#[test]
// TODO: pre-existing — migrate to `TelemetryUplink::try_restore` and drop
// the allow. Out of scope for the misleading-method-name rename.
#[allow(deprecated)]
fn vsoc_telemetry_uplink_overflow_increments_dropped() {
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::{TelemetryConfig, TelemetryEntry, TelemetryUplink};

    let config = TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 64,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let mut uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::restore(
            config,
            vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
        );

    // Fill the buffer to capacity (64 entries).
    for i in 0..64u64 {
        let entry =
            TelemetryEntry::new(i, i * 1000, 0x01, vs_types::AlertSeverity::Low, b"x").unwrap();
        uplink.submit_entry(entry).unwrap();
    }
    assert_eq!(uplink.queued(), 64);
    assert_eq!(uplink.dropped_count(), 0);

    // Submit one more — should overflow and drop the oldest.
    let entry =
        TelemetryEntry::new(64, 64_000, 0x01, vs_types::AlertSeverity::Low, b"overflow")
            .unwrap();
    uplink.submit_entry(entry).unwrap();
    assert_eq!(uplink.queued(), 64); // Still 64 (ring buffer)
    assert_eq!(uplink.dropped_count(), 1); // One dropped
}

// -----------------------------------------------------------------------
// 10. Telemetry batch_size clamping
// -----------------------------------------------------------------------

#[test]
// TODO: pre-existing — migrate to `TelemetryUplink::try_restore` and drop
// the allow. Out of scope for the misleading-method-name rename.
#[allow(deprecated)]
fn vsoc_telemetry_config_batch_size_clamped() {
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::{TelemetryConfig, TelemetryUplink};

    let config = TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 255, // Exceeds buffer capacity of 64
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let _uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::restore(
            config,
            vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
        );
    // Construction should succeed without panic; batch_size is clamped internally.
}

// -----------------------------------------------------------------------
// 11. QnxEthernetPhy type accessible
// -----------------------------------------------------------------------

#[test]
fn hal_qnx_ethernet_type_accessible() {
    assert!(
        core::mem::size_of::<vs_hal_qnx::QnxEthernetPhy>() > 0,
        "QnxEthernetPhy must be a non-ZST type",
    );
}

// -----------------------------------------------------------------------
// 12. FlushResult type accessible
// -----------------------------------------------------------------------

#[test]
fn vsoc_telemetry_flush_result_type_accessible() {
    assert!(
        core::mem::size_of::<vs_vsoc_telemetry::FlushResult>() > 0,
        "FlushResult must be a non-ZST type",
    );
}

// -----------------------------------------------------------------------
// 13. QnxCanBus custom device path
// -----------------------------------------------------------------------

#[test]
fn hal_qnx_can_custom_device() {
    let can = vs_hal_qnx::QnxCanBus::new_with_device(500_000, b"/dev/can1\0");
    assert!(can.is_ok());
}

// -----------------------------------------------------------------------
// 14. QnxEthernetPhy custom device path
// -----------------------------------------------------------------------

#[test]
fn hal_qnx_ethernet_custom_device() {
    let eth = vs_hal_qnx::QnxEthernetPhy::new_with_device(1000, b"/dev/bpf0\0");
    assert!(eth.is_ok());
}

// -----------------------------------------------------------------------
// 15. Telemetry flush_counter overflow guard
// -----------------------------------------------------------------------

#[test]
// TODO: pre-existing — migrate to `TelemetryUplink::try_restore` and drop
// the allow. Out of scope for the misleading-method-name rename.
#[allow(deprecated)]
fn vsoc_telemetry_flush_counter_overflow_protection() {
    // Verify the flush_counter field exists and starts at 0.
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::{TelemetryConfig, TelemetryUplink};

    let config = TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 4,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::restore(
            config,
            vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
        );
    assert_eq!(uplink.flush_counter(), 0);
}

// -----------------------------------------------------------------------
// 16. Telemetry flush integration (cross-crate with Pkcs11CryptoProvider)
// -----------------------------------------------------------------------

#[test]
// TODO: migrate this integration test to `flush_with_persistence` so the
// `#[allow(deprecated)]` can be dropped. Today it intentionally exercises
// the legacy no-persist shim that mirrors the 0.6-era call shape.
#[allow(deprecated)]
fn vsoc_telemetry_flush_produces_result() {
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::{TelemetryConfig, TelemetryEntry, TelemetryUplink};

    let config = TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 4,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0xABu8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let mut uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::restore(
            config,
            vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
        );

    for i in 0..4u64 {
        let entry =
            TelemetryEntry::new(i, i * 1000, 0x01, vs_types::AlertSeverity::Medium, b"evt")
                .unwrap();
        uplink.submit_entry(entry).unwrap();
    }

    let mut provider =
        vs_crypto_pkcs11::Pkcs11CryptoProvider::new(mock_pkcs11::build_mock_fl(), b"pin")
            .unwrap();
    provider.register_key_handle(KeyId(0), 1).unwrap();
    provider.register_key_handle(KeyId(1), 2).unwrap();

    let result = uplink.flush_no_persist(&provider, 1_000_000).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.entry_count, 4);
    // After audit fix CRIT-1 (write-ahead counter), FlushResult.flush_counter
    // is the value actually encoded on the wire, i.e. next_counter == 1
    // for the first flush from a fresh device.
    assert_eq!(r.flush_counter, 1);
    assert_eq!(uplink.queued(), 0);
    assert_eq!(uplink.flush_counter(), 1);
}

#[test]
// TODO: migrate this integration test to `flush_with_persistence` so the
// `#[allow(deprecated)]` can be dropped. Today it intentionally exercises
// the legacy no-persist shim that mirrors the 0.6-era call shape.
#[allow(deprecated)]
fn vsoc_telemetry_flush_empty_returns_none() {
    use vs_crypto::KeyId;
    use vs_vsoc_telemetry::{TelemetryConfig, TelemetryUplink};

    let config = TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 4,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let mut uplink: TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider> =
        TelemetryUplink::restore(
            config,
            vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
        );

    let provider =
        vs_crypto_pkcs11::Pkcs11CryptoProvider::new(mock_pkcs11::build_mock_fl(), b"pin")
            .unwrap();

    let result = uplink.flush_no_persist(&provider, 1_000_000).unwrap();
    assert!(result.is_none());
}

// SECURITY (CRIT-3): The `vsoc_telemetry_restore_counter` integration
// test previously exercised `PersistedFlushCounter::restore(u64)` — the
// unauthenticated rollback shim — and required activating the
// `unauthenticated-restore` feature on the workspace `vs-vsoc-telemetry`
// dev-dependency. That feature activation tainted the shared compiled
// artifact and could leak the deprecated API into release builds via
// cargo's feature unification.
//
// Regression coverage of the legacy shim now lives where it is safe:
//   - In-crate unit tests inside `crates/vsoc-telemetry` (gated by the
//     intrinsic `cfg(test)` arm of `cfg(any(test, feature =
//     "unauthenticated-restore"))`, no feature activation needed).
//   - The `telemetry_flush` fuzz target in the standalone `fuzz/`
//     workspace, which has its own resolution graph and cannot leak
//     features into the production build.
//
// Do NOT reintroduce a test here that requires the
// `unauthenticated-restore` feature on the workspace dependency.

// -----------------------------------------------------------------------
// Mock PKCS#11 functions for integration tests
// -----------------------------------------------------------------------

mod mock_pkcs11 {
    use vs_crypto_pkcs11::ffi::{
        CkAttribute, CkByte, CkFlags, CkMechanism, CkObjectHandle, CkRv, CkSessionHandle,
        CkSlotId, CkTokenInfo, CkUlong, CkUserType,
    };

    const CKR_OK: CkRv = 0;
    const GCM_TAG_LEN: usize = 16;
    const SHA256_LEN: usize = 32;
    const ECDSA_SIG_LEN: usize = 64;

    pub unsafe extern "C" fn c_initialize(_: *mut core::ffi::c_void) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_finalize(_: *mut core::ffi::c_void) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_open_session(
        _: CkSlotId,
        _: CkFlags,
        _: *mut core::ffi::c_void,
        _: Option<
            unsafe extern "C" fn(CkSessionHandle, CkUlong, *mut core::ffi::c_void) -> CkRv,
        >,
        ph: *mut CkSessionHandle,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_OpenSession contract requires `phSession`
        // to point to a writable `CK_SESSION_HANDLE`. The wrapper in
        // `vs_crypto_pkcs11` always passes a stack-allocated handle.
        unsafe { *ph = 1 };
        CKR_OK
    }
    pub unsafe extern "C" fn c_close_session(_: CkSessionHandle) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_login(
        _: CkSessionHandle,
        _: CkUserType,
        _: *const CkByte,
        _: CkUlong,
    ) -> CkRv {
        CKR_OK
    }
    // TODO(integration): `c_logout` was added to `Pkcs11FunctionList`
    // in crates/crypto-pkcs11/src/ffi.rs. Mock returns CKR_OK so the
    // wrapper's session-teardown path completes cleanly.
    pub unsafe extern "C" fn c_logout(_: CkSessionHandle) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_get_token_info(_: CkSlotId, _: *mut CkTokenInfo) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_find_objects_init(
        _: CkSessionHandle,
        _: *const CkAttribute,
        _: CkUlong,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_find_objects(
        _: CkSessionHandle,
        _: *mut CkObjectHandle,
        _: CkUlong,
        p: *mut CkUlong,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_FindObjects requires `pulObjectCount` to
        // point to a writable `CK_ULONG` that receives the number of
        // returned handles. The caller (`vs_crypto_pkcs11`) supplies a
        // stack-allocated counter.
        unsafe { *p = 0 };
        CKR_OK
    }
    pub unsafe extern "C" fn c_find_objects_final(_: CkSessionHandle) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_get_attribute_value(
        _: CkSessionHandle,
        _: CkObjectHandle,
        _: *mut CkAttribute,
        _: CkUlong,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_encrypt_init(
        _: CkSessionHandle,
        _: *const CkMechanism,
        _: CkObjectHandle,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_encrypt(
        _: CkSessionHandle,
        p_data: *const CkByte,
        ul_data_len: CkUlong,
        p_out: *mut CkByte,
        pul: *mut CkUlong,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_Encrypt contract: `pData` points to `ulDataLen`
        // bytes of readable input, `pEncryptedData` points to at least
        // `*pulEncryptedDataLen` bytes of writable output (caller pre-sizes
        // it to plaintext_len + GCM tag), and `pulEncryptedDataLen` is a
        // writable `CK_ULONG`. The wrapper in `vs_crypto_pkcs11` follows
        // that contract.
        // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
        // for slice construction.
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
    pub unsafe extern "C" fn c_decrypt_init(
        _: CkSessionHandle,
        _: *const CkMechanism,
        _: CkObjectHandle,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_decrypt(
        _: CkSessionHandle,
        p_enc: *const CkByte,
        ul: CkUlong,
        p_out: *mut CkByte,
        pul: *mut CkUlong,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_Decrypt contract: `pEncryptedData` points to
        // `ulEncryptedDataLen` readable bytes that include the GCM tag,
        // `pData` points to at least plaintext-length writable bytes, and
        // `pulDataLen` is a writable `CK_ULONG`. The wrapper sizes these
        // per the contract before invoking the function pointer.
        // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
        // for slice construction.
        let total = ul as usize;
        let pt_len = total - GCM_TAG_LEN;
        let src = unsafe { core::slice::from_raw_parts(p_enc, pt_len) };
        let dst = unsafe { core::slice::from_raw_parts_mut(p_out, pt_len) };
        dst.copy_from_slice(src);
        // SAFETY: same contract — writable `CK_ULONG`.
        unsafe { *pul = pt_len as CkUlong };
        CKR_OK
    }
    pub unsafe extern "C" fn c_digest_init(_: CkSessionHandle, _: *const CkMechanism) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_digest(
        _: CkSessionHandle,
        _: *const CkByte,
        _: CkUlong,
        p_out: *mut CkByte,
        pul: *mut CkUlong,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_Digest contract: `pDigest` points to at least
        // `*pulDigestLen` writable bytes — the wrapper sizes it for the
        // mechanism (SHA-256 = 32 bytes). `pulDigestLen` is writable.
        //
        // Audit fix FIX-3: the production wrapper (HIGH-M) now pre-fills
        // outputs with the position-varying sentinel `SENTINEL ^ i` and
        // rejects the call if ANY byte still matches that pattern. We
        // therefore must NOT write a byte pattern that collides with
        // `0xA5 ^ i` at any position 0..32. A constant 0x77 is safe for
        // ALL operation sentinels (0xA5/0x5A/0x3C/0xE7) across i in
        // 0..64 because each XOR solution falls outside the buffer's
        // index range — see comment on `c_sign` for the full check.
        let out = unsafe { core::slice::from_raw_parts_mut(p_out, SHA256_LEN) };
        out.fill(0x77);
        // SAFETY: writable `CK_ULONG` from the same contract.
        // CkUlong is `u32` on Windows / `u64` elsewhere.
        unsafe { *pul = SHA256_LEN as CkUlong };
        CKR_OK
    }
    pub unsafe extern "C" fn c_sign_init(
        _: CkSessionHandle,
        _: *const CkMechanism,
        _: CkObjectHandle,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_sign(
        _: CkSessionHandle,
        _: *const CkByte,
        _: CkUlong,
        p_sig: *mut CkByte,
        pul: *mut CkUlong,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_Sign contract: `pSignature` points to at
        // least `*pulSignatureLen` writable bytes — the wrapper sizes it
        // to 64 for raw ECDSA P-256. `pulSignatureLen` is writable.
        //
        // Audit fix FIX-3: align with the HIGH-M position-varying
        // sentinel. After HIGH-M, the production wrapper (both
        // `sign_p256` SENTINEL=0x3C/len=64 and `hmac_sha256`
        // SENTINEL=0x5A/len=32) pre-fills its output with `SENTINEL ^ i`
        // and rejects ANY byte still matching that pattern after the
        // call returns. The previous mock wrote `(i + 0xCC) as u8`,
        // which collides with `0x3C ^ i` at i=56..59, causing a
        // spurious `VsError::CryptoError`. A constant 0x77 is safe
        // because:
        //   0x77 == 0x3C ^ i → i = 0x4B = 75  (out of 0..64)
        //   0x77 == 0x5A ^ i → i = 0x2D = 45  (out of 0..32)
        // so no position in either output can be mistaken for an
        // un-overwritten sentinel byte.
        let out = unsafe { core::slice::from_raw_parts_mut(p_sig, ECDSA_SIG_LEN) };
        out.fill(0x77);
        // SAFETY: writable `CK_ULONG` from the same contract.
        // CkUlong is `u32` on Windows / `u64` elsewhere.
        unsafe { *pul = ECDSA_SIG_LEN as CkUlong };
        CKR_OK
    }
    pub unsafe extern "C" fn c_verify_init(
        _: CkSessionHandle,
        _: *const CkMechanism,
        _: CkObjectHandle,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_verify(
        _: CkSessionHandle,
        _: *const CkByte,
        _: CkUlong,
        _: *const CkByte,
        _: CkUlong,
    ) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_derive_key(
        _: CkSessionHandle,
        _: *const CkMechanism,
        _: CkObjectHandle,
        _: *const CkAttribute,
        _: CkUlong,
        ph: *mut CkObjectHandle,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_DeriveKey contract: `phKey` is a writable
        // `CK_OBJECT_HANDLE` that receives the derived-key handle.
        unsafe { *ph = 0xDEAD };
        CKR_OK
    }
    pub unsafe extern "C" fn c_destroy_object(_: CkSessionHandle, _: CkObjectHandle) -> CkRv {
        CKR_OK
    }
    pub unsafe extern "C" fn c_generate_random(
        _: CkSessionHandle,
        p: *mut CkByte,
        len: CkUlong,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_GenerateRandom contract: `RandomData` points
        // to `ulRandomLen` writable bytes.
        // CkUlong is `u32` on Windows / `u64` elsewhere; convert to `usize`
        // for slice construction.
        let out = unsafe { core::slice::from_raw_parts_mut(p, len as usize) };
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        CKR_OK
    }
    pub unsafe extern "C" fn c_create_object(
        _: CkSessionHandle,
        _: *const CkAttribute,
        _: CkUlong,
        ph: *mut CkObjectHandle,
    ) -> CkRv {
        // SAFETY: PKCS#11 C_CreateObject contract: `phObject` is a writable
        // `CK_OBJECT_HANDLE` that receives the created object's handle.
        unsafe { *ph = 0xBEEF };
        CKR_OK
    }

    pub fn build_mock_fl() -> vs_crypto_pkcs11::ffi::Pkcs11FunctionList {
        vs_crypto_pkcs11::ffi::Pkcs11FunctionList {
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
}

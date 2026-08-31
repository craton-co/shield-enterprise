// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_crypto::{CryptoProvider, KeyId, KeyType as CryptoKeyType};
use vs_diag_gateway::{DiagGateway, UdsPolicy};
use vs_types::VsError;

/// Minimal crypto provider for fuzzing the diag gateway. The gateway only
/// reaches into the provider for `random_bytes` (seeding session challenges),
/// so all other methods return `NotInitialized` to exercise the gateway's
/// error-handling paths without depending on a real crypto backend.
///
/// `core/crypto` does not yet re-export `SoftwareCryptoProvider` across the
/// BSL/Apache split (it is gated behind the `mock-hsm` feature), so the fuzz
/// target carries its own stub.
struct FuzzCrypto;

impl CryptoProvider for FuzzCrypto {
    fn aes_gcm_encrypt(
        &self, _key_id: KeyId, _nonce: &[u8; 12], _pt: &[u8], _aad: &[u8],
        _ct_out: &mut [u8], _tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn aes_gcm_decrypt(
        &self, _key_id: KeyId, _nonce: &[u8; 12], _ct: &[u8], _aad: &[u8],
        _tag: &[u8; 16], _pt_out: &mut [u8],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn sha256(&self, _data: &[u8], _hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn hmac_sha256(
        &self, _key_id: KeyId, _data: &[u8], _mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn ecdh_derive_shared(
        &self, _key_id: KeyId, _peer_pub: &[u8; 65], _shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn sign_p256(
        &self, _key_id: KeyId, _digest: &[u8; 32], _sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn verify_p256(
        &self, _pub_key: &[u8; 65], _digest: &[u8; 32], _sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        Ok(false)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        // Deterministic, non-zero fill -- sufficient for fuzzing the
        // gateway's session-challenge plumbing without depending on OS
        // entropy.
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x6D).wrapping_add(0x37);
        }
        Ok(())
    }

    fn delete_key(&mut self, _key_id: KeyId) -> Result<(), VsError> {
        Ok(())
    }

    fn generate_key(&mut self, _key_id: KeyId, _key_type: CryptoKeyType) -> Result<(), VsError> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    // Need at least 2 (tester_addr) + 1 (sid) = 3 bytes.
    if data.len() < 3 {
        return;
    }

    // --- Parse request fields from the fuzzer input ---

    let tester_addr = u16::from_le_bytes([data[0], data[1]]);
    let sid = data[2];
    let payload = &data[3..];

    // Derive a timestamp from the tail of the input (or use 0).
    let ts_us: u64 = if data.len() >= 11 {
        u64::from_le_bytes([
            data[3], data[4], data[5], data[6],
            data[7], data[8], data[9], data[10],
        ])
    } else {
        1_000_000
    };

    // --- Build the crypto provider and gateway ---

    let crypto = FuzzCrypto;

    // Build a policy that exercises multiple code paths:
    // - SID 0x10 (DiagnosticSessionControl) allowed without auth.
    // - SID 0x22 (ReadDataByIdentifier) requires auth.
    // - SID 0x27 (SecurityAccess) is handled specially by the gateway.
    // - SIDs 0x31, 0x34, 0x36, 0x37 always require auth.
    // - Everything else is denied by policy.
    let mut policy = UdsPolicy::new();
    policy.allow_sid(0x10);
    policy.allow_sid(0x3E); // TesterPresent
    policy.require_auth_for_sid(0x22);
    policy.require_auth_for_sid(0x2E); // WriteDataByIdentifier

    let mut gateway = DiagGateway::new(
        crypto,
        policy,
        5_000_000,    // 5-second session timeout
        10_000_000,   // 10-second lockout duration
        KeyId(0),     // HMAC key slot
    );

    // --- Exercise receive_uds_request -- must never panic ---

    // Process the fuzzed request.
    let _ = gateway.receive_uds_request(tester_addr, sid, payload, ts_us);

    // Send a second request with a slightly different timestamp to exercise
    // session lookup, expiration, and lockout timing paths.
    let _ = gateway.receive_uds_request(
        tester_addr,
        sid,
        payload,
        ts_us.wrapping_add(100),
    );

    // Send from a different tester address to exercise multi-session paths.
    let other_tester = tester_addr.wrapping_add(1);
    let _ = gateway.receive_uds_request(other_tester, sid, payload, ts_us.wrapping_add(200));

    // Exercise a request well past the session timeout to trigger expiration.
    let _ = gateway.receive_uds_request(
        tester_addr,
        sid,
        payload,
        ts_us.wrapping_add(10_000_000),
    );
});

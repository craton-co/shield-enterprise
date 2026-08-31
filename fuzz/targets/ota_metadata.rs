// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_crypto::{CryptoProvider, KeyId, KeyType as CryptoKeyType};
use vs_ota_validator::{KeyType, OtaValidator, TufKey, TufRoot};
use vs_types::VsError;

/// Minimal crypto provider for fuzzing that implements just enough to
/// exercise the OTA validator without requiring real cryptographic keys.
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

    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // PERF: weak mock — replace with real SHA-256 when accessible from
        // fuzz target. `core/crypto` does not yet re-export a software
        // SHA-256 across the BSL/Apache split; until it does, this XOR-fold
        // is what we have. It is collision-prone but deterministic, which
        // is what the OTA validator needs to exercise both the
        // hash-mismatch and hash-match code paths.
        *hash_out = [0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash_out[i % 32] ^= byte;
            hash_out[(i.wrapping_add(7)) % 32] =
                hash_out[(i.wrapping_add(7)) % 32].wrapping_add(byte);
        }
        Ok(())
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
        // Always return false so that signature checks fail gracefully
        // without panicking.
        Ok(false)
    }

    fn random_bytes(&self, _buf: &mut [u8]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn delete_key(&mut self, _key_id: KeyId) -> Result<(), VsError> {
        Ok(())
    }

    fn generate_key(&mut self, _key_id: KeyId, _key_type: CryptoKeyType) -> Result<(), VsError> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    // --- Build a trusted root for the validator ---

    let root_key = TufKey {
        key_id: [0x01; 32],
        key_type: KeyType::EcdsaP256,
        public_key: [0x04; 65],
    };
    let root = TufRoot {
        version: 1,
        expires_us: u64::MAX,
        root_keys: [Some(root_key), None, None, None],
        threshold: 1,
        targets_keys: [Some(root_key), None, None, None],
        targets_threshold: 1,
        snapshot_keys: [Some(root_key), None, None, None],
        snapshot_threshold: 1,
        timestamp_keys: [Some(root_key), None, None, None],
        timestamp_threshold: 1,
    };

    let validator = match OtaValidator::new(FuzzCrypto, root) {
        Ok(v) => v,
        Err(_) => return,
    };

    // --- Use the fuzzer data as "firmware" bytes ---

    let firmware_bytes = data;

    // Derive an expected hash from a portion of the input. If the input is
    // long enough, pull 32 bytes for the hash; otherwise zero-fill.
    let mut expected_hash = [0u8; 32];
    if data.len() >= 32 {
        expected_hash.copy_from_slice(&data[..32]);
    } else {
        expected_hash[..data.len()].copy_from_slice(data);
    }

    // Derive an expected length from the input. Try several values to
    // exercise both the length-mismatch and length-match paths.
    let expected_length = firmware_bytes.len() as u64;

    // --- Exercise verify_target -- must never panic ---

    // Call with the matching length (exercises the hash comparison path).
    let _ = validator.verify_target(&expected_hash, expected_length, firmware_bytes);

    // Call with a mismatched length (exercises the early length-check return).
    let _ = validator.verify_target(&expected_hash, expected_length.wrapping_add(1), firmware_bytes);

    // Call with a zero-length expectation against non-empty data.
    let _ = validator.verify_target(&expected_hash, 0, firmware_bytes);

    // Call with an all-zero hash to exercise the hash-mismatch path.
    let zero_hash = [0u8; 32];
    let _ = validator.verify_target(&zero_hash, expected_length, firmware_bytes);

    // Call with empty firmware bytes.
    let _ = validator.verify_target(&expected_hash, 0, &[]);
});

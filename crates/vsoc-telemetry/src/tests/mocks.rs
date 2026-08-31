// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Shared `CryptoProvider` mocks and config helpers used by the in-crate
//! unit tests.
//!
//! Per-test mocks that simulate specific failure modes (e.g. `FailingSha256`,
//! `FailingSign`, `DeterministicHmacCrypto`, `CountingPersistence`) live
//! alongside their `#[test]` functions in `crate::tests`.

use super::super::*;
use vs_crypto::KeyType;

/// Minimal deterministic `CryptoProvider` for testing flush logic.
pub(super) struct MockCrypto;

impl CryptoProvider for MockCrypto {
    fn aes_gcm_encrypt(
        &self,
        _key_id: KeyId,
        _nonce: &[u8; 12],
        plaintext: &[u8],
        _aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        ciphertext_out[..plaintext.len()].copy_from_slice(plaintext);
        tag_out.fill(0xAA);
        Ok(())
    }
    fn aes_gcm_decrypt(
        &self,
        _key_id: KeyId,
        _nonce: &[u8; 12],
        ciphertext: &[u8],
        _aad: &[u8],
        _tag: &[u8; 16],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        plaintext_out[..ciphertext.len()].copy_from_slice(ciphertext);
        Ok(())
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Deterministic non-zero hash based on data length.
        for (i, b) in hash_out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(data.len() as u8).wrapping_add(1);
        }
        Ok(())
    }
    fn hmac_sha256(
        &self,
        _key_id: KeyId,
        _data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        mac_out.fill(0xBB);
        Ok(())
    }
    fn ecdh_derive_shared(
        &self,
        _: KeyId,
        _: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        shared_out.fill(0xCC);
        Ok(())
    }
    fn sign_p256(
        &self,
        _key_id: KeyId,
        _digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        sig_out.fill(0xDD);
        Ok(())
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        Ok(true)
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        buf.fill(0x42);
        Ok(())
    }
    fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
        Ok(())
    }
    fn generate_key(&mut self, _: KeyId, _: KeyType) -> Result<(), VsError> {
        Err(VsError::CryptoError)
    }
}

pub(super) fn test_config() -> TelemetryConfig {
    TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 4,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0xABu8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    }
}

pub(super) fn make_entry(seq: u64) -> TelemetryEntry {
    TelemetryEntry::new(seq, seq * 1000, 0x01, AlertSeverity::Medium, b"test").unwrap()
}

/// `CryptoProvider` mock that captures the last AES-GCM nonce it saw.
///
/// Used by the nonce-layout regression tests below to assert that the
/// nonce is constructed exactly as documented (no XOR mixing, no
/// cross-device collisions).
pub(super) struct NonceCapturingCrypto {
    pub(super) last_nonce: core::cell::Cell<[u8; 12]>,
}

impl NonceCapturingCrypto {
    pub(super) fn new() -> Self {
        Self {
            last_nonce: core::cell::Cell::new([0u8; 12]),
        }
    }
}

impl CryptoProvider for NonceCapturingCrypto {
    fn aes_gcm_encrypt(
        &self,
        _: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        _: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        self.last_nonce.set(*nonce);
        ciphertext_out[..plaintext.len()].copy_from_slice(plaintext);
        tag_out.fill(0xAA);
        Ok(())
    }
    fn aes_gcm_decrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &[u8; 16],
        _: &mut [u8],
    ) -> Result<(), VsError> {
        Ok(())
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Toy "hash" sufficient for the per-device-prefix tests.
        // Build a 32-byte state via per-output-byte FNV-like rolling
        // accumulators with distinct seeds, then mix every input
        // byte into every output byte. Distinct inputs that change
        // any input position perturb every output byte.
        let mut state = [0u8; 32];
        for (i, slot) in state.iter_mut().enumerate() {
            let mut acc: u32 = 0x811C_9DC5u32 ^ (i as u32).wrapping_mul(0x9E37_79B1);
            for (k, b) in data.iter().enumerate() {
                acc = acc.wrapping_mul(0x0100_0193);
                acc ^= u32::from(*b);
                acc = acc.rotate_left(((k as u32).wrapping_add(i as u32) & 0x1F).max(1));
            }
            *slot = (acc & 0xFF) as u8;
        }
        hash_out.copy_from_slice(&state);
        Ok(())
    }
    fn hmac_sha256(&self, _: KeyId, _: &[u8], m: &mut [u8; 32]) -> Result<(), VsError> {
        m.fill(0xBB);
        Ok(())
    }
    fn ecdh_derive_shared(&self, _: KeyId, _: &[u8; 65], s: &mut [u8; 32]) -> Result<(), VsError> {
        s.fill(0xCC);
        Ok(())
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], sig: &mut [u8; 64]) -> Result<(), VsError> {
        sig.fill(0xDD);
        Ok(())
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        Ok(true)
    }
    fn random_bytes(&self, b: &mut [u8]) -> Result<(), VsError> {
        b.fill(0x42);
        Ok(())
    }
    fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
        Ok(())
    }
    fn generate_key(&mut self, _: KeyId, _: KeyType) -> Result<(), VsError> {
        Err(VsError::CryptoError)
    }
}

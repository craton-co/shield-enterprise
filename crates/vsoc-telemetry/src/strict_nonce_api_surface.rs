// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Strict-nonce-mode API-surface smoke test.
//!
//! Under `--features strict-nonce` the deprecated/insecure entry points
//! (`PersistedFlushCounter::restore`, `TelemetryUplink::new`,
//! `TelemetryUplink::new_with_counter`, `TelemetryUplink::flush_no_persist`)
//! are gated out via `#[cfg(not(feature = "strict-nonce"))]`. This
//! integration-style test module is itself gated on the feature: when it
//! compiles, every caller below uses ONLY the strict-mode API surface
//! (`try_restore` + authenticated counter + `flush_outcome` or
//! `flush_with_persistence`).
//!
//! Pair `cargo check --workspace --features strict-nonce` (which proves
//! the absence of deprecated items) with this strict-API smoke test so
//! that an accidental over-gate (e.g. removing `try_restore` by mistake)
//! also fails CI.

use super::*;
use vs_crypto::KeyType;

struct StubCrypto;
impl CryptoProvider for StubCrypto {
    fn aes_gcm_encrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        pt: &[u8],
        _: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), VsError> {
        ct[..pt.len()].copy_from_slice(pt);
        tag.fill(0xAA);
        Ok(())
    }
    fn aes_gcm_decrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        ct: &[u8],
        _: &[u8],
        _: &[u8; 16],
        pt: &mut [u8],
    ) -> Result<(), VsError> {
        pt[..ct.len()].copy_from_slice(ct);
        Ok(())
    }
    fn sha256(&self, data: &[u8], out: &mut [u8; 32]) -> Result<(), VsError> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(data.len() as u8).wrapping_add(1);
        }
        Ok(())
    }
    fn hmac_sha256(&self, _: KeyId, _: &[u8], out: &mut [u8; 32]) -> Result<(), VsError> {
        out.fill(0xBB);
        Ok(())
    }
    fn ecdh_derive_shared(
        &self,
        _: KeyId,
        _: &[u8; 65],
        out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        out.fill(0xCC);
        Ok(())
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], out: &mut [u8; 64]) -> Result<(), VsError> {
        out.fill(0xDD);
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

fn strict_config() -> TelemetryConfig {
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

#[test]
fn strict_api_supports_fresh_device_flush_outcome() {
    // Only the strict-API entry points are reachable here:
    //   - `PersistedFlushCounter::fresh_device` (always available)
    //   - `TelemetryUplink::try_restore` (always available)
    //   - `flush_outcome` / `flush_with_persistence` (always available)
    let mut uplink: TelemetryUplink<StubCrypto> =
        TelemetryUplink::try_restore(strict_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    let entry = TelemetryEntry::new(0, 0, 0x01, AlertSeverity::High, b"x").unwrap();
    uplink.submit_entry(entry).unwrap();
    let outcome = uplink
        .flush_outcome(&StubCrypto, 1_000_000, &mut NoOpPersistence)
        .expect("flush_outcome compiles and runs under strict-nonce");
    match outcome {
        FlushOutcome::Sent(r) => assert_eq!(r.entry_count, 1),
        other => panic!("expected Sent, got {other:?}"),
    }
}

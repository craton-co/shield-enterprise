// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]

//! Structured fuzz target for the `TelemetryUplink` submit / flush
//! state machine.
//!
//! Drives a randomized sequence of operations (submit, flush) against
//! an uplink wired to a deterministic mock `CryptoProvider` and a
//! mock `CounterPersistence`. The fuzzer-supplied `Op` stream
//! exercises rate-limit windows, ring-buffer overflow, batch-size
//! boundaries, and nonce-counter advancement together.
//!
//! Properties asserted by construction:
//! - No operation may panic.
//! - The persisted counter must be `>=` the in-memory counter at all
//!   times (write-ahead invariant).

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vs_crypto::{CryptoProvider, KeyId};
use vs_types::{AlertSeverity, VsError};
use vs_vsoc_telemetry::{
    CounterPersistence, PersistedFlushCounter, TelemetryConfig, TelemetryEntry, TelemetryUplink,
};

/// Deterministic in-memory mock — enough to satisfy `submit_entry`
/// and `flush_with_persistence` without exercising real cryptography.
struct MockCrypto;

impl CryptoProvider for MockCrypto {
    fn aes_gcm_encrypt(
        &self,
        _key_id: KeyId,
        _nonce: &[u8; 12],
        pt: &[u8],
        _aad: &[u8],
        ct_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        let n = pt.len().min(ct_out.len());
        ct_out[..n].copy_from_slice(&pt[..n]);
        *tag_out = [0xA5u8; 16];
        Ok(())
    }

    fn aes_gcm_decrypt(
        &self,
        _key_id: KeyId,
        _nonce: &[u8; 12],
        ct: &[u8],
        _aad: &[u8],
        _tag: &[u8; 16],
        pt_out: &mut [u8],
    ) -> Result<(), VsError> {
        let n = ct.len().min(pt_out.len());
        pt_out[..n].copy_from_slice(&ct[..n]);
        Ok(())
    }

    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // PERF: weak mock — replace with real SHA-256 when accessible
        // from the fuzz target (core/crypto does not yet re-export a
        // software SHA-256 across the BSL/Apache boundary).
        *hash_out = [0u8; 32];
        for (i, &b) in data.iter().enumerate() {
            hash_out[i % 32] ^= b;
        }
        Ok(())
    }

    fn hmac_sha256(
        &self,
        _key_id: KeyId,
        _data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        *mac_out = [0x5Au8; 32];
        Ok(())
    }

    fn ecdh_derive_shared(
        &self,
        _key_id: KeyId,
        _peer_pub: &[u8; 65],
        _shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn sign_p256(
        &self,
        _key_id: KeyId,
        _digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        *sig_out = [0xCCu8; 64];
        Ok(())
    }

    fn verify_p256(
        &self,
        _pub_key: &[u8; 65],
        _digest: &[u8; 32],
        _sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        Ok(true)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x33);
        }
        Ok(())
    }

    fn delete_key(&mut self, _key_id: KeyId) -> Result<(), VsError> {
        Ok(())
    }

    fn generate_key(
        &mut self,
        _key_id: KeyId,
        _key_type: vs_crypto::KeyType,
    ) -> Result<(), VsError> {
        Ok(())
    }
}

/// In-memory persistence — tracks the highest counter ever committed.
struct MockPersistence {
    committed: u64,
}

impl CounterPersistence for MockPersistence {
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError> {
        // The crate's contract: persistence advances monotonically.
        // We accept any non-decreasing value.
        if new_counter < self.committed {
            return Err(VsError::InvalidInput);
        }
        self.committed = new_counter;
        Ok(())
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    Submit { event_type: u8, severity: u8, payload_len: u8 },
    Flush { ts_us: u32 },
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    batch_size: u8,
    max_bytes_per_minute: u32,
    reserved_critical_slots: u8,
    device_id_seed: u8,
    initial_counter: u8,
    ops: [Op; 16],
}

fuzz_target!(|scenario: Scenario| {
    let config = TelemetryConfig {
        max_bytes_per_minute: scenario.max_bytes_per_minute.max(1),
        batch_size: scenario.batch_size.max(1).min(64),
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [scenario.device_id_seed; 32],
        reserved_critical_slots: scenario.reserved_critical_slots.min(64),
        // Fuzz is fed monotonic entries from a single producer; the
        // strict-default is the more interesting code path to exercise.
        allow_out_of_order_entries: false,
    };
    let counter = PersistedFlushCounter::restore(scenario.initial_counter as u64);
    let mut uplink: TelemetryUplink<MockCrypto> = match TelemetryUplink::try_restore(config, counter)
    {
        Ok(u) => u,
        Err(_) => return,
    };
    let crypto = MockCrypto;
    let mut persistence = MockPersistence {
        committed: scenario.initial_counter as u64,
    };

    let mut seq: u64 = 0;
    let mut ts_acc: u64 = 0;

    for op in scenario.ops.iter() {
        match *op {
            Op::Submit { event_type, severity, payload_len } => {
                let sev = match severity & 0b11 {
                    0 => AlertSeverity::Low,
                    1 => AlertSeverity::Medium,
                    2 => AlertSeverity::High,
                    _ => AlertSeverity::Critical,
                };
                let pl_len = (payload_len as usize) & 0x3F; // 0..=63
                let payload = [0xEFu8; 64];
                if let Ok(entry) =
                    TelemetryEntry::new(seq, ts_acc, event_type, sev, &payload[..pl_len])
                {
                    let _ = uplink.submit_entry(entry);
                    seq = seq.wrapping_add(1);
                }
            }
            Op::Flush { ts_us } => {
                ts_acc = ts_acc.wrapping_add(ts_us as u64);
                let _ = uplink.flush_with_persistence(&crypto, ts_acc, &mut persistence);
            }
        }
    }

    // Write-ahead invariant: persisted counter must never fall behind
    // the in-memory counter (audit fix CRIT-1).
    assert!(persistence.committed >= uplink.flush_counter());
});

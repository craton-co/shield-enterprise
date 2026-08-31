// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! Illustrative: boot-time recovery of the persisted `flush_counter`.
//!
//! Mirrors the worked example in `docs/threat-model.md` (T2/D1
//! mitigation). Shows the canonical flow:
//!
//!   1. Read the 40-byte `counter_le(8) || hmac_sha256_tag(32)` blob
//!      from durable storage.
//!   2. Verify the HMAC tag via
//!      [`PersistedFlushCounter::restore_authenticated`] — rejects
//!      rollback, device-id substitution, and bit-flip tamper.
//!   3. Hand the authenticated counter to
//!      [`TelemetryUplink::try_restore`].
//!
//! This file is host-side (uses `std`) and does NOT perform real
//! crypto — the storage read and the `CryptoProvider` call are
//! sketched as `// ...`. The production VSOC telemetry crate is
//! `#![no_std]`.
//!
//! Run: `cargo run --example telemetry_counter_recovery`

use vs_crypto::{CryptoProvider, KeyId};
use vs_types::VsError;
use vs_vsoc_telemetry::{PersistedFlushCounter, TelemetryConfig, TelemetryUplink};

/// Boot-time recovery. Returns an uplink whose `flush_counter` has
/// been authenticated against the device-unique `mac_key_id`.
fn recover_uplink<C: CryptoProvider>(
    config: TelemetryConfig,
    mac_key_id: KeyId,
    crypto: &C,
    blob: &[u8; 40],
) -> Result<TelemetryUplink<C>, VsError> {
    // (1) Verify the HMAC tag in constant time. A failure here means
    //     rollback / wrong-device / tamper — the caller MUST rotate
    //     the AES-GCM encryption key before bringing up an uplink.
    let counter = PersistedFlushCounter::restore_authenticated(blob, crypto, mac_key_id)?;

    // (2) Strict construction: rejects out-of-range config fields
    //     instead of silently clamping them.
    TelemetryUplink::try_restore(config, counter)
}

fn main() {
    println!("=== Craton Shield: Telemetry Counter Recovery ===");
    println!();
    println!("Boot-time recovery flow (see docs/threat-model.md, T2/D1):");
    println!();
    println!("  1. Read 40-byte blob from durable storage:");
    println!("       counter_le(8) || hmac_sha256_tag(32)");
    println!("  2. Verify tag with device-unique mac_key_id (HSM/TPM slot)");
    println!("  3. Construct TelemetryUplink::try_restore(config, counter)");
    println!();
    println!("On VsError::CryptoError from restore_authenticated:");
    println!("  - rollback attempt (old blob replayed)");
    println!("  - device-id substitution (another device's blob)");
    println!("  - blob tamper (bit-flip in counter or tag)");
    println!("  -> rotate the AES-GCM encryption key; do NOT flush.");
    println!();

    // Sketch the type-level call site. The production caller would
    // supply a real CryptoProvider implementation (PKCS#11 or TPM)
    // and read `blob` from NVRAM / eMMC.
    let _config = TelemetryConfig {
        max_bytes_per_minute: 65_536,
        batch_size: 4,
        encryption_key_id: KeyId(0),
        signing_key_id: KeyId(1),
        device_id: [0xABu8; 32],
        reserved_critical_slots: 8,
        allow_out_of_order_entries: false,
    };
    let _mac_key_id = KeyId(2);
    let _blob: [u8; 40] = [0u8; 40]; // would come from durable storage

    // The signature below pins the recovery API; uncomment with a real
    // provider and authentic blob to exercise it end-to-end:
    //   let uplink = recover_uplink(_config, _mac_key_id, &crypto, &_blob)?;
    let _recover_fn: fn(
        TelemetryConfig,
        KeyId,
        &vs_crypto_pkcs11::Pkcs11CryptoProvider,
        &[u8; 40],
    ) -> Result<TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider>, VsError> =
        recover_uplink::<vs_crypto_pkcs11::Pkcs11CryptoProvider>;

    println!("recover_uplink<Pkcs11CryptoProvider> type-checks.");
}

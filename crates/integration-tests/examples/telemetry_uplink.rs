// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! Demonstrates the VSOC telemetry uplink ring buffer and flush cycle.
//!
//! This example creates a telemetry uplink, submits entries, and shows
//! the buffering and rate-limiting behavior. No actual crypto or network
//! operations are performed (would require a real CryptoProvider).
//!
//! Run: `cargo run --example telemetry_uplink`
//!
//! # Logging note
//!
//! This example only prints `VsError` kinds and integer counters. Do NOT
//! extend this pattern to debug-print `TelemetryEntry` values — their
//! payload bytes are sensitive, which is why `TelemetryEntry` deliberately
//! does not implement `Display`. See `docs/threat-model.md` §I3.

// NOTE: this example is host-side (uses `std`); the production VSOC
// telemetry crate is `#![no_std]` and runs on the firmware.

fn main() {
    println!("=== Craton Shield: VSOC Telemetry Uplink Demo ===");
    println!();

    // Show TelemetryEntry construction.
    let payload = b"CAN-flood-0x100";
    let entry = match vs_vsoc_telemetry::TelemetryEntry::new(
        1,                             // sequence
        1_000_000,                     // timestamp_us (1 second)
        0x01,                          // event_type
        vs_types::AlertSeverity::High, // severity
        payload,
    ) {
        Ok(e) => e,
        Err(err) => {
            // SAFE: `err` is a `VsError`, an opaque kind enum that carries
            // no payload bytes, key material, or other sensitive content.
            // Do NOT extend this to debug-print `entry` or any
            // `TelemetryEntry`/`FlushResult` — see the module-level
            // logging note above and `docs/threat-model.md` §I3.
            eprintln!("telemetry entry construction failed: {:?}", err);
            return;
        }
    };

    // Demonstrate the recommended uplink construction path:
    // `try_restore` + `PersistedFlushCounter::fresh_device` for a
    // factory-fresh device (or `::restore(persisted_counter)` after
    // reboot). `try_restore` is the strict variant that surfaces an
    // error if the config fails validation instead of silently
    // clamping.
    let config = vs_vsoc_telemetry::TelemetryConfig {
        max_bytes_per_minute: 65536,
        batch_size: 4,
        encryption_key_id: vs_crypto::KeyId(0),
        signing_key_id: vs_crypto::KeyId(1),
        device_id: [0xABu8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    };
    let _uplink_attempt: Result<
        vs_vsoc_telemetry::TelemetryUplink<vs_crypto_pkcs11::Pkcs11CryptoProvider>,
        _,
    > = vs_vsoc_telemetry::TelemetryUplink::try_restore(
        config,
        vs_vsoc_telemetry::PersistedFlushCounter::fresh_device(),
    );

    println!("Created TelemetryEntry:");
    // SAFE: prints non-sensitive counter (monotonic sequence number).
    println!("  sequence:     {}", entry.sequence);
    // SAFE: prints non-sensitive counter (microsecond timestamp).
    println!("  timestamp_us: {}", entry.timestamp_us);
    // SAFE: prints non-sensitive enum-like byte (event type discriminant).
    println!("  event_type:   0x{:02X}", entry.event_type);
    // SAFE: prints non-sensitive length only — NEVER print `entry.payload`.
    println!("  payload_len:  {}", entry.payload_len);
    println!();

    // Show config.
    println!("TelemetryConfig fields:");
    println!("  max_bytes_per_minute: rate limit for uplink bandwidth");
    println!("  batch_size:           entries per flush (1-64)");
    println!("  encryption_key_id:    AES-GCM key slot in CryptoProvider");
    println!("  signing_key_id:       ECDSA P-256 key slot in CryptoProvider");
    println!("  device_id:            32-byte device identifier");
    println!();

    // Show buffer behavior.
    println!("Ring buffer capacity: 64 entries");
    println!("On overflow: oldest entry dropped, dropped_count incremented");
    println!();

    // Show flush result.
    println!("FlushResult contains:");
    println!("  encrypted_digest: AES-GCM encrypted batch digest (32 bytes)");
    println!("  tag:              AES-GCM authentication tag (16 bytes)");
    println!("  signature:        ECDSA P-256 signature (64 bytes)");
    println!("  entry_count:      number of entries in this batch");
    println!("  flush_counter:    monotonic counter for replay protection");
    println!();
    println!("The caller forwards these fields to the VSOC backend via");
    println!("the appropriate transport (MQTT, TLS, CAN-TP, etc.).");
}

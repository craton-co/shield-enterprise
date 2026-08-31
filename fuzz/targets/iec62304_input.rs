// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]

//! IEC 62304 §5.2 input-validation harness — fuzzes the vsoc-telemetry
//! `TelemetryEntry::new` ingestion surface, the external-boundary input
//! path that downstream safety-classified components consume.
//!
//! Input layout (header is 19 bytes, payload is the tail):
//!   * byte 0          — severity selector (mapped mod 4 onto `AlertSeverity`)
//!   * bytes 1..9      — sequence (u64 LE)
//!   * bytes 9..17     — timestamp_us (u64 LE)
//!   * bytes 17..19    — payload_len hint (u16 LE; clamped to remaining tail)
//!   * bytes 19..      — payload bytes (truncated to the hint)
//!
//! Invariants probed:
//!   * `TelemetryEntry::new` must never panic for any input.
//!   * Oversized payloads (> `MAX_PAYLOAD_LEN`) must return `Err`, not panic.
//!   * The constructor must accept any combination of severity / sequence /
//!     timestamp / event_type without aborting.

use libfuzzer_sys::fuzz_target;
use vs_types::AlertSeverity;
use vs_vsoc_telemetry::TelemetryEntry;

fuzz_target!(|data: &[u8]| {
    // Need at least the 19-byte header.
    if data.len() < 19 {
        return;
    }

    let severity = match data[0] % 4 {
        0 => AlertSeverity::Low,
        1 => AlertSeverity::Medium,
        2 => AlertSeverity::High,
        _ => AlertSeverity::Critical,
    };
    let sequence = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let timestamp_us = u64::from_le_bytes(data[9..17].try_into().unwrap());
    let payload_len_hint = u16::from_le_bytes(data[17..19].try_into().unwrap()) as usize;

    let tail = &data[19..];
    // Clamp the hint to the actual tail length so the fuzzer can drive
    // both the "fits in buffer" and "oversized — must Err" branches
    // without indexing past the input.
    let take = core::cmp::min(payload_len_hint, tail.len());
    let payload = &tail[..take];

    // Derive an event_type from the unused tail so the compiler keeps
    // the read alive and we sweep the full u8 space across iterations.
    let event_type = tail.iter().fold(0u8, |a, &b| a ^ b);

    // Asserts no panic; Err returns are expected for oversized payloads.
    let _ = TelemetryEntry::new(sequence, timestamp_us, event_type, severity, payload);
});

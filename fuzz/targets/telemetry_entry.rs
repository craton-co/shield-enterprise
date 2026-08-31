// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_vsoc_telemetry::TelemetryEntry;
use vs_types::AlertSeverity;

fuzz_target!(|data: &[u8]| {
    if data.len() < 19 {
        return;
    }
    let sequence = u64::from_le_bytes(data[..8].try_into().unwrap());
    let timestamp = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let event_type = data[16];
    let severity = match data[17] % 4 {
        0 => AlertSeverity::Low,
        1 => AlertSeverity::Medium,
        2 => AlertSeverity::High,
        _ => AlertSeverity::Critical,
    };
    let payload = &data[18..];
    let _ = TelemetryEntry::new(sequence, timestamp, event_type, severity, payload);
});

// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_can_monitor::{CanFrame, CanMonitor, CanRule};
use vs_types::AlertSeverity;

fuzz_target!(|data: &[u8]| {
    // Need at least 4 (id) + 1 (dlc) + 1 (flags) = 6 bytes to construct a
    // meaningful frame; anything shorter is silently skipped.
    if data.len() < 6 {
        return;
    }

    // --- Parse fields out of the fuzzer-supplied byte buffer ---

    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let dlc = data[4];
    let flags = data[5];
    let is_extended = flags & 0x01 != 0;
    let is_fd = flags & 0x02 != 0;

    // Remaining bytes become the payload (up to 64).
    let payload_src = &data[6..];
    let mut frame_data = [0u8; 64];
    let copy_len = payload_src.len().min(64);
    frame_data[..copy_len].copy_from_slice(&payload_src[..copy_len]);

    let frame = CanFrame {
        id,
        is_extended,
        is_fd,
        dlc,
        data: frame_data,
    };

    // --- Set up a monitor with a few representative rules ---

    let mut monitor = CanMonitor::new([0u8; 16]);

    // Catch-all rule for standard IDs (mask 0x000 matches everything).
    let _ = monitor.add_rule(CanRule {
        id: 0x000,
        id_mask: 0x000,
        id_filter: 0x000,
        min_interval_us: 5_000,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::Medium,
    });

    // Exact-match rule for a common powertrain ID.
    let _ = monitor.add_rule(CanRule {
        id: 0x100,
        id_mask: 0x7FF,
        id_filter: 0x100,
        min_interval_us: 10_000,
        max_dlc: 8,
        is_extended: false,
        severity: AlertSeverity::High,
    });

    // Extended-ID rule.
    let _ = monitor.add_rule(CanRule {
        id: 0x18DA_00F1,
        id_mask: 0x1FFF_FFFF,
        id_filter: 0x18DA_00F1,
        min_interval_us: 0,
        max_dlc: 4,
        is_extended: true,
        severity: AlertSeverity::Critical,
    });

    // --- Exercise process_frame -- must never panic ---

    // Use part of the fuzz input as a pseudo-timestamp to vary timing paths.
    let ts_base: u64 = if data.len() >= 14 {
        u64::from_le_bytes([
            data[6], data[7], data[8], data[9],
            data[10], data[11], data[12], data[13],
        ])
    } else {
        0
    };

    // First call seeds the per-ID stats.
    let _ = monitor.process_frame(&frame, ts_base);

    // Second call with a small time delta can trigger flood detection.
    let _ = monitor.process_frame(&frame, ts_base.wrapping_add(1));

    // Third call with a larger gap exercises the non-flooding path.
    let _ = monitor.process_frame(&frame, ts_base.wrapping_add(1_000_000));

    // Also exercise bus-error reporting with the fuzzed timestamp.
    let _ = monitor.report_error(ts_base);
});

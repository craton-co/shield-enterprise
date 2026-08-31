// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]

//! Fuzz target for `vs_hal_qnx::parse_can_frame` (and round-trip via
//! `serialize_can_frame` when the parse succeeds).
//!
//! Requires the `vs-hal-qnx` crate's `fuzz` feature, which gates the
//! `pub` visibility of the otherwise crate-private parser helpers.
//! The dependency in `fuzz/Cargo.toml` enables `features = ["fuzz"]`
//! so this target compiles out-of-the-box.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = vs_hal_qnx::parse_can_frame(data) {
        // Round-trip: a frame the parser accepted should survive
        // serialize+parse without panicking. The serialize buffer is
        // sized for the maximum classic + CAN-FD payload.
        let mut buf = [0u8; 128];
        if let Ok(n) = vs_hal_qnx::serialize_can_frame(&frame, &mut buf) {
            let _ = vs_hal_qnx::parse_can_frame(&buf[..n]);
        }
    }
});

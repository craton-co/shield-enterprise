// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]

//! Fuzz target for the PKCS#11 provider's PIN-handling boundary.
//!
//! # Scope
//!
//! This target fuzzes the `PinBuffer` constructor only. `PinBuffer` is
//! the first surface any caller's PIN bytes hit on the way to
//! `Pkcs11CryptoProvider::new`, so it MUST never panic, overflow, or
//! leak regardless of input shape. The properties asserted below mirror
//! the constructor's contract (round-trip on Ok, empty-or-oversized on
//! Err).
//!
//! # Not yet covered
//!
//! The cryptographic paths (`aes_gcm_encrypt`, `sign_p256`, etc.) live
//! behind caller-supplied C function pointers and need a mock
//! `Pkcs11FunctionList` to be reached from a fuzz harness. Wiring that
//! up is tracked in ROADMAP.md; until then the end-to-end FFI surface
//! is exercised only by the unit tests.

use libfuzzer_sys::fuzz_target;
use vs_crypto_pkcs11::{PinBuffer, MAX_PIN_LEN};

fuzz_target!(|data: &[u8]| {
    // PinBuffer::new must either succeed with the exact bytes stored, or
    // return InvalidInput — never panic — for any slice shape up to 4 KiB.
    match PinBuffer::new(data) {
        Ok(pb) => {
            // Post-condition: slice length equals input length (≤ MAX_PIN_LEN).
            assert_eq!(pb.as_slice().len(), data.len());
            assert!(pb.as_slice().len() <= MAX_PIN_LEN);
            assert_eq!(pb.as_slice(), data);
        }
        Err(_) => {
            // Only valid error condition is an empty or oversized PIN.
            assert!(data.is_empty() || data.len() > MAX_PIN_LEN);
        }
    }
});

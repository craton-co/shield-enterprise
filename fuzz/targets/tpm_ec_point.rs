// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]

//! Real fuzz harness exercising the SEC1 uncompressed-encoding validation
//! path that defends against invalid-curve attacks on HSM/TPM-issued keys.
//!
//! # What this drives
//!
//! `vs_p256_validate::validate_p256_point_on_curve` is the single entry
//! point both `vs-crypto-pkcs11` and `vs-crypto-tpm` call before handing a
//! public key to the underlying hardware token. It performs:
//!
//! 1. SEC1 shape checks — prefix byte must be `0x04`, neither `X` nor `Y`
//!    may be all-zero.
//! 2. Field-range checks — `X < p` and `Y < p`.
//! 3. The on-curve check `y^2 ≡ x^3 − 3x + b (mod p)`, using the
//!    Solinas fast-reduction routine in the same crate.
//!
//! The fuzzer feeds arbitrary 65-byte buffers (zero-padded if the
//! libFuzzer input is shorter) and asserts the routine never panics —
//! it must always return `Ok(())` or `Err(VsError::InvalidInput)`.
//!
//! # History
//!
//! Replaces the previous "smoke harness" that only re-implemented the
//! cheap shape check inline and never actually called into the validator
//! crate. The harness now exercises the full validation pipeline that
//! certification evidence claims it does (see MED-9 in the security
//! review, and `docs/certification-status.md §3`).

use libfuzzer_sys::fuzz_target;
use vs_p256_validate::{validate_p256_point_on_curve, EC_POINT_LEN};

fuzz_target!(|data: &[u8]| {
    // Build a fixed-size 65-byte buffer from the fuzzer input. Short
    // inputs are zero-padded on the right so libFuzzer can still explore
    // small-seed mutations near the boundary; longer inputs are
    // truncated.
    let mut pk = [0u8; EC_POINT_LEN];
    let copy_len = core::cmp::min(data.len(), EC_POINT_LEN);
    pk[..copy_len].copy_from_slice(&data[..copy_len]);

    // The contract is "never panic". `validate_p256_point_on_curve` must
    // return `Ok(())` for a valid uncompressed point on the curve and
    // `Err(VsError::InvalidInput)` for everything else — but it must
    // never unwind, regardless of input.
    let _ = validate_p256_point_on_curve(&pk);
});

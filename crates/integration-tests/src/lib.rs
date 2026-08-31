// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! Placeholder library for the Craton Shield Enterprise integration-test crate.
//!
//! This crate exists solely to host cross-crate integration tests under
//! `tests/` and illustrative examples under `examples/`. It is
//! `publish = false`, has `doctest = false`, and exposes no public API.
//!
//! The real per-crate documentation lives in:
//!
//! - [`vs-crypto-pkcs11`](../vs_crypto_pkcs11)
//! - [`vs-crypto-tpm`](../vs_crypto_tpm)
//! - [`vs-hal-qnx`](../vs_hal_qnx)
//! - [`vs-vsoc-telemetry`](../vs_vsoc_telemetry)
//!
//! # License
//!
//! Business Source License 1.1 — converts to Apache-2.0 on 2030-09-01.

#![allow(clippy::missing_const_for_fn)]

/// No-op placeholder so the crate has at least one item.
///
/// Integration tests under `tests/` do not call into this — they
/// depend on the production crates directly via `[dev-dependencies]`.
pub fn placeholder() {}

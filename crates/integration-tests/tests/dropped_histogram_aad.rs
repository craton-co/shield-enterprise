// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Integration coverage for INFO-1 + audit-M13/M14 follow-up: the
//! public `dropped_count()` accessor on `TelemetryUplink` advances
//! correctly across the two distinct overflow paths the audit fixes
//! introduced.
//!
//! NOTE: the per-severity histogram (`dropped_per_severity`,
//! `dropped_other`, `histogram_saturated`) is bound into the AAD
//! bytes but is NOT exposed through any public accessor — verified
//! with `git grep "pub fn dropped_per_severity"` returning ZERO
//! matches. The per-severity slots are only readable by inspecting
//! the AAD pointer the encrypt mock receives, which would couple
//! this integration test to private byte offsets without adding
//! signal beyond what the in-crate AAD wire-layout tests already
//! cover. We therefore scope this file to the public-accessor
//! contract: `dropped_count()` must monotonically advance across
//! both the reserved-critical-slots gate (audit-MED-2) and the
//! ring-buffer overflow path (audit-INFO-1).
//!
//! Verified against production (`git grep`):
//!   - `pub fn dropped_count(&self) -> u64`
//!                                  in `vsoc-telemetry/src/lib.rs:2576`
//!   - reserved-slots drop bumps `dropped_count` via `account_drop`
//!                                  at `vsoc-telemetry/src/lib.rs:1757`
//!   - ring-overflow drop bumps `dropped_count` via `account_drop`
//!                                  at `vsoc-telemetry/src/lib.rs:1785`
//!   - per-severity dropped accessor: `git grep "pub fn
//!     dropped_per_severity"` returned ZERO matches (private field
//!     only).

use vs_crypto::{CryptoProvider, KeyId, KeyType};
use vs_types::{AlertSeverity, VsError};
use vs_vsoc_telemetry::{
    PersistedFlushCounter, TelemetryConfig, TelemetryEntry, TelemetryUplink,
};

// -----------------------------------------------------------------------
// Inert CryptoProvider: every method is a no-op / sentinel. The tests
// in this file never flush — they only exercise `submit_entry` and
// `dropped_count()` — so the crypto provider is purely a type witness
// for `TelemetryUplink<C: CryptoProvider>`.
// -----------------------------------------------------------------------

struct InertCrypto;

impl CryptoProvider for InertCrypto {
    fn aes_gcm_encrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
        _: &mut [u8; 16],
    ) -> Result<(), VsError> {
        Ok(())
    }
    fn aes_gcm_decrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &[u8; 16],
        _: &mut [u8],
    ) -> Result<(), VsError> {
        Ok(())
    }
    fn sha256(&self, _: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        hash_out.fill(0);
        Ok(())
    }
    fn hmac_sha256(
        &self,
        _: KeyId,
        _: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        mac_out.fill(0);
        Ok(())
    }
    fn ecdh_derive_shared(
        &self,
        _: KeyId,
        _: &[u8; 65],
        _: &mut [u8; 32],
    ) -> Result<(), VsError> {
        Ok(())
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
        Ok(())
    }
    fn verify_p256(
        &self,
        _: &[u8; 65],
        _: &[u8; 32],
        _: &[u8; 64],
    ) -> Result<bool, VsError> {
        Ok(true)
    }
    fn random_bytes(&self, _: &mut [u8]) -> Result<(), VsError> {
        Ok(())
    }
    fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
        Ok(())
    }
    fn generate_key(&mut self, _: KeyId, _: KeyType) -> Result<(), VsError> {
        Err(VsError::CryptoError)
    }
}

/// Shared test config: large enough rate budget to never trip
/// rate-limit, batch_size = 64 so no auto-flush happens during the
/// long submit loops below, and `reserved_critical_slots` defaulted
/// per-test.
fn base_config() -> TelemetryConfig {
    TelemetryConfig {
        max_bytes_per_minute: 1_000_000,
        batch_size: 64,
        encryption_key_id: KeyId::new(0),
        signing_key_id: KeyId::new(1),
        device_id: [0u8; 32],
        reserved_critical_slots: 0,
        allow_out_of_order_entries: false,
    }
}

fn make_entry(seq: u64, severity: AlertSeverity) -> TelemetryEntry {
    TelemetryEntry::new(
        seq,
        1_000_000 + seq, // strictly monotonic, well below MAX_REASONABLE_TS_US
        0x01,
        severity,
        b"x",
    )
    .expect("entry construction must succeed at this payload size")
}

// -----------------------------------------------------------------------
// audit-MED-2: when occupancy is at or above the reserved-critical
// high-water mark, lower-severity entries are dropped and
// `dropped_count` increments by exactly one per dropped submit.
// `Critical` / `High` are still admitted.
// -----------------------------------------------------------------------

#[test]
fn reserved_critical_slots_gate_advances_dropped_count() {
    let mut cfg = base_config();
    cfg.reserved_critical_slots = 8;

    let mut uplink: TelemetryUplink<InertCrypto> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device())
            .expect("uplink must restore from fresh-device counter");

    // Fill the non-reserved region with Info entries. Capacity is 64,
    // reserved = 8, so the high-water mark is at occupancy = 56.
    for i in 0..56u64 {
        uplink
            .submit_entry(make_entry(i, AlertSeverity::Info))
            .expect("Info admit below high-water must succeed");
    }
    assert_eq!(
        uplink.dropped_count(),
        0,
        "no drops should have happened while occupancy was below the high-water mark"
    );

    // The 57th Info hits the gate and must be dropped without
    // disturbing the queue.
    uplink
        .submit_entry(make_entry(100, AlertSeverity::Info))
        .expect("submit_entry returns Ok even when the entry is dropped at the gate");
    assert_eq!(
        uplink.dropped_count(),
        1,
        "an Info-at-high-water drop must bump dropped_count by 1"
    );

    // Critical at the boundary must still be admitted — it bypasses
    // the reserved-slot gate.
    uplink
        .submit_entry(make_entry(101, AlertSeverity::Critical))
        .expect("Critical must always be admitted while reserved slots are available");
    assert_eq!(
        uplink.dropped_count(),
        1,
        "admitting a Critical entry must NOT advance dropped_count"
    );

    // A second Info drop bumps the count again — confirming the
    // counter is genuinely monotonic, not a stuck-at-1 sentinel.
    uplink
        .submit_entry(make_entry(102, AlertSeverity::Low))
        .expect("submit_entry returns Ok even when the entry is dropped at the gate");
    assert_eq!(
        uplink.dropped_count(),
        2,
        "a Low-at-high-water drop must bump dropped_count to 2"
    );
}

// -----------------------------------------------------------------------
// audit-INFO-1: when the ring buffer is genuinely full (no reserved
// slots, occupancy == 64), the OLDEST entry is evicted and
// `dropped_count` advances. The newly-submitted entry takes the
// freed slot and the queue depth stays at capacity.
// -----------------------------------------------------------------------

#[test]
fn ring_overflow_eviction_advances_dropped_count() {
    let mut cfg = base_config();
    cfg.reserved_critical_slots = 0; // disable the high-water gate

    let mut uplink: TelemetryUplink<InertCrypto> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device())
            .expect("uplink must restore from fresh-device counter");

    // Fill the ring buffer exactly to capacity with High entries
    // (admitted because the gate is disabled).
    for i in 0..64u64 {
        uplink
            .submit_entry(make_entry(i, AlertSeverity::High))
            .expect("High admit below capacity must succeed");
    }
    assert_eq!(
        uplink.queued(),
        64,
        "ring buffer should be exactly at capacity"
    );
    assert_eq!(
        uplink.dropped_count(),
        0,
        "no drops should occur while there is room in the buffer"
    );

    // Submit one more — eviction path. Queue stays at capacity,
    // dropped_count advances by 1.
    uplink
        .submit_entry(make_entry(100, AlertSeverity::High))
        .expect("submit_entry must accept the overflow entry and evict the oldest slot");
    assert_eq!(
        uplink.queued(),
        64,
        "ring buffer occupancy stays at capacity through eviction"
    );
    assert_eq!(
        uplink.dropped_count(),
        1,
        "ring-overflow eviction must bump dropped_count by exactly 1"
    );

    // Five more — dropped_count should reach 6 (1 + 5 evictions).
    for i in 0..5u64 {
        uplink
            .submit_entry(make_entry(200 + i, AlertSeverity::Critical))
            .expect("submit_entry must keep accepting overflow entries");
    }
    assert_eq!(
        uplink.queued(),
        64,
        "ring buffer occupancy still capped at capacity"
    );
    assert_eq!(
        uplink.dropped_count(),
        6,
        "five additional evictions must add five to dropped_count"
    );
}

// -----------------------------------------------------------------------
// Cross-severity smoke: both drop paths (reserved-slots gate and
// ring-overflow) contribute to the SAME `dropped_count`. The
// receiver-facing scalar must not double-count or undercount when
// the two paths interleave.
// -----------------------------------------------------------------------

#[test]
fn dropped_count_accumulates_across_both_drop_paths() {
    let mut cfg = base_config();
    cfg.reserved_critical_slots = 4;

    let mut uplink: TelemetryUplink<InertCrypto> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device())
            .expect("uplink must restore from fresh-device counter");

    // High-water mark = 64 - 4 = 60. Fill to 60 with Info.
    for i in 0..60u64 {
        uplink
            .submit_entry(make_entry(i, AlertSeverity::Info))
            .expect("Info admit below high-water must succeed");
    }
    assert_eq!(uplink.dropped_count(), 0);

    // 3 Low entries at the gate -> 3 drops via reserved-slots path.
    for i in 0..3u64 {
        uplink
            .submit_entry(make_entry(100 + i, AlertSeverity::Low))
            .expect("submit_entry returns Ok even when dropped at the gate");
    }
    assert_eq!(uplink.dropped_count(), 3);

    // 4 Critical entries to fill the reserved region (occupancy
    // climbs to 64). No drops here — Critical bypasses the gate and
    // occupancy never exceeds capacity.
    for i in 0..4u64 {
        uplink
            .submit_entry(make_entry(200 + i, AlertSeverity::Critical))
            .expect("Critical admit into reserved slots must succeed");
    }
    assert_eq!(uplink.queued(), 64, "ring should now be exactly full");
    assert_eq!(
        uplink.dropped_count(),
        3,
        "filling the reserved region must NOT contribute to dropped_count"
    );

    // 2 more Critical -> ring-overflow eviction path. dropped_count
    // climbs from 3 to 5.
    for i in 0..2u64 {
        uplink
            .submit_entry(make_entry(300 + i, AlertSeverity::Critical))
            .expect("Critical admit at-capacity must evict the head slot");
    }
    assert_eq!(uplink.queued(), 64);
    assert_eq!(
        uplink.dropped_count(),
        5,
        "two evictions must add 2 to the existing 3 gate-drops"
    );
}

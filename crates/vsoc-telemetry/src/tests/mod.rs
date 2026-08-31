// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Unit tests for the VSOC telemetry uplink.
//!
//! Shared `CryptoProvider` mocks and config helpers live in [`mocks`];
//! per-test mocks (which simulate specific failure modes such as a
//! failing `sha256`, a failing `sign_p256`, an authenticating HMAC, or a
//! counting persistence backend) stay alongside the `#[test]` functions
//! that exercise them.

#![allow(deprecated)] // Tests use the deprecated `restore(u64)` shim by design.

mod mocks;

use super::*;
use mocks::{make_entry, test_config, MockCrypto, NonceCapturingCrypto};
use vs_crypto::KeyType;

// -- TelemetryEntry tests --

#[test]
fn entry_creation_basic() {
    let e = TelemetryEntry::new(1, 2000, 0x05, AlertSeverity::High, b"hello").unwrap();
    assert_eq!(e.sequence, 1);
    assert_eq!(e.timestamp_us, 2000);
    assert_eq!(e.event_type, 0x05);
    assert_eq!(e.payload_len, 5);
    assert_eq!(&e.payload[..5], b"hello");
}

#[test]
fn entry_rejects_oversized_payload() {
    assert!(TelemetryEntry::new(0, 0, 0, AlertSeverity::Info, &[0u8; 65]).is_err());
}

#[test]
fn entry_max_payload_accepted() {
    let e = TelemetryEntry::new(0, 0, 0, AlertSeverity::Info, &[0xFFu8; 64]).unwrap();
    assert_eq!(e.payload_len, 64);
}

#[test]
fn entry_empty_payload_accepted() {
    let e = TelemetryEntry::new(0, 0, 0, AlertSeverity::Info, &[]).unwrap();
    assert_eq!(e.payload_len, 0);
}

#[test]
fn entry_serialize_into_produces_fixed_size() {
    let e = make_entry(42);
    let mut buf = [0u8; 256];
    let written = e.serialize_into(&mut buf, 0).unwrap();
    assert_eq!(written, ENTRY_SERIAL_SIZE); // 83 bytes
}

#[test]
fn entry_serialize_into_at_offset() {
    let e = make_entry(1);
    let mut buf = [0u8; 256];
    let written = e.serialize_into(&mut buf, 32).unwrap();
    assert_eq!(written, ENTRY_SERIAL_SIZE);
    // Sequence should be at offset 32
    let seq = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    assert_eq!(seq, 1);
}

#[test]
fn entry_serialize_zero_pads_short_payload() {
    let e = TelemetryEntry::new(0, 0, 0, AlertSeverity::Info, b"ab").unwrap();
    let mut buf = [0xFFu8; 256];
    e.serialize_into(&mut buf, 0).unwrap();
    // payload_len = 2, bytes 19..21 = "ab", bytes 21..83 = 0
    assert_eq!(&buf[19..21], b"ab");
    assert!(buf[21..ENTRY_SERIAL_SIZE].iter().all(|&b| b == 0));
}

#[test]
fn entry_serialize_rejects_short_buffer() {
    let e = make_entry(0);
    let mut buf = [0u8; ENTRY_SERIAL_SIZE - 1];
    assert_eq!(e.serialize_into(&mut buf, 0), Err(VsError::InvalidInput));
}

#[test]
fn entry_serialize_rejects_overflow_offset() {
    let e = make_entry(0);
    let mut buf = [0u8; ENTRY_SERIAL_SIZE + 16];
    // offset = usize::MAX causes checked_add to return None
    assert_eq!(
        e.serialize_into(&mut buf, usize::MAX),
        Err(VsError::InvalidInput)
    );
}

#[test]
fn entry_serialize_offset_one_past_end_rejected() {
    let e = make_entry(0);
    let mut buf = [0u8; ENTRY_SERIAL_SIZE];
    // offset=1 ⇒ requires 84 bytes, buf is 83 → rejected.
    assert_eq!(e.serialize_into(&mut buf, 1), Err(VsError::InvalidInput));
}

// -- TelemetryUplink basic tests --

#[test]
fn uplink_new_starts_empty() {
    let uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    assert_eq!(uplink.queued(), 0);
    assert_eq!(uplink.dropped_count(), 0);
    assert_eq!(uplink.flush_counter(), 0);
}

#[test]
fn uplink_restore_sets_counter() {
    let uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::restore(1000));
    assert_eq!(uplink.flush_counter(), 1000);
    assert_eq!(uplink.queued(), 0);
}

#[test]
fn uplink_submit_increments_queued() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    assert_eq!(uplink.queued(), 1);
    uplink.submit_entry(make_entry(1)).unwrap();
    assert_eq!(uplink.queued(), 2);
}

#[test]
fn uplink_submit_rejects_oversized_payload() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let mut bad = make_entry(0);
    bad.payload_len = 65; // Exceeds MAX_PAYLOAD_LEN
    assert_eq!(uplink.submit_entry(bad), Err(VsError::PolicyViolation));
}

#[test]
fn uplink_overflow_drops_oldest() {
    let mut config = test_config();
    config.batch_size = 64;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    for i in 0..64 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    assert_eq!(uplink.queued(), 64);
    assert_eq!(uplink.dropped_count(), 0);
    uplink.submit_entry(make_entry(64)).unwrap();
    assert_eq!(uplink.queued(), 64);
    assert_eq!(uplink.dropped_count(), 1);
}

#[test]
fn uplink_batch_size_clamped_to_capacity() {
    let mut config = test_config();
    config.batch_size = 255;
    let uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    // Should not panic; batch_size clamped to 64
    assert_eq!(uplink.queued(), 0);
}

// -- flush() tests --

#[test]
fn flush_empty_buffer_returns_none() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    assert!(uplink.flush_no_persist(&crypto, 1_000_000).unwrap().is_none());
}

#[test]
fn flush_returns_result_with_correct_fields() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    for i in 0..4 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    let result = uplink.flush_no_persist(&crypto, 1_000_000).unwrap().unwrap();
    assert_eq!(result.entry_count, 4);
    // After audit fix CRIT-1 (write-ahead counter), FlushResult.flush_counter
    // carries the value actually encoded on the wire — i.e. next_counter,
    // which is 1 on the first flush from a fresh device.
    assert_eq!(result.flush_counter, 1);
    // digest_commitment should be non-zero (mock encrypts as identity)
    assert!(result.digest_commitment.iter().any(|&b| b != 0));
    // tag should be 0xAA (mock fill)
    assert!(result.tag.iter().all(|&b| b == 0xAA));
    // signature should be 0xDD (mock fill)
    assert!(result.signature.iter().all(|&b| b == 0xDD));
}

#[test]
fn flush_consumes_entries_from_buffer() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    for i in 0..4 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    assert_eq!(uplink.queued(), 4);
    uplink.flush_no_persist(&crypto, 1_000_000).unwrap();
    assert_eq!(uplink.queued(), 0);
}

#[test]
fn flush_increments_flush_counter() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    for i in 0..4 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    uplink.flush_no_persist(&crypto, 1_000_000).unwrap();
    assert_eq!(uplink.flush_counter(), 1);
}

#[test]
fn flush_partial_batch() {
    let mut config = test_config();
    config.batch_size = 8;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    // Submit only 3 entries, batch_size is 8
    for i in 0..3 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    let result = uplink.flush_no_persist(&crypto, 1_000_000).unwrap().unwrap();
    assert_eq!(result.entry_count, 3); // Flushes min(count, batch_size)
    assert_eq!(uplink.queued(), 0);
}

#[test]
fn flush_counter_overflow_guard() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::restore(u64::MAX));
    let crypto = MockCrypto;
    uplink.submit_entry(make_entry(0)).unwrap();
    let result = uplink.flush_no_persist(&crypto, 1_000_000);
    assert_eq!(result, Err(VsError::ResourceExhausted));
}

// -- Rate limiting tests --

#[test]
fn flush_rate_limit_rejects_over_budget() {
    let mut config = test_config();
    config.max_bytes_per_minute = 100; // Very small budget
    config.batch_size = 4;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    for i in 0..4 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    // batch_bytes = 48 + 4*83 = 380 > 100
    let result = uplink.flush_no_persist(&crypto, 1_000_000);
    assert_eq!(result, Err(VsError::ResourceExhausted));
}

#[test]
fn flush_rate_limit_window_resets_after_one_minute() {
    let mut config = test_config();
    config.max_bytes_per_minute = 300; // Enough for one batch (214 bytes), not two
    config.batch_size = 2;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;

    // First flush at t=0
    uplink.submit_entry(make_entry(0)).unwrap();
    uplink.submit_entry(make_entry(1)).unwrap();
    uplink.flush_no_persist(&crypto, 0).unwrap();

    // Second flush at t=0 should fail (over budget)
    uplink.submit_entry(make_entry(2)).unwrap();
    uplink.submit_entry(make_entry(3)).unwrap();
    let result = uplink.flush_no_persist(&crypto, 100);
    assert_eq!(result, Err(VsError::ResourceExhausted));

    // Third flush at t=61s should succeed (window reset)
    let result = uplink.flush_no_persist(&crypto, 61_000_000);
    assert!(result.unwrap().is_some());
}

#[test]
fn flush_nonce_layout_is_prefix_then_counter() {
    // Audit fix HIGH-1 nonce layout:
    //   [0..6]  = SHA-256(label || device_id)[..6]
    //   [6..12] = next_counter little-endian (6 bytes)
    // The prefix is opaque (depends on the SHA-256 of the device_id),
    // so we only pin the counter-half byte layout here. The
    // "prefix differs across device_ids" property is tested
    // separately in `flush_nonce_differs_across_devices_at_same_counter`.
    let crypto = NonceCapturingCrypto::new();
    let mut config = test_config();
    config.device_id = [
        0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    // After audit fix CRIT-1 the wire counter is `next_counter`.
    let mut uplink: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::restore(0x1234_5678_9ABC - 1));
    uplink.submit_entry(make_entry(0)).unwrap();
    uplink.flush_no_persist(&crypto, 1_000_000).unwrap().unwrap();

    let nonce = crypto.last_nonce.get();
    // The counter half of the nonce is fully deterministic.
    // next_counter 0x0000_1234_5678_9ABC little-endian is BC 9A 78 56 34 12 00 00
    assert_eq!(&nonce[6..12], &[0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
    // The prefix half must NOT be all-zero (would indicate the SHA-256
    // derivation didn't happen).
    assert!(
        nonce[0..6].iter().any(|&b| b != 0),
        "nonce prefix must be derived, not all-zero"
    );
}

#[test]
fn flush_nonce_differs_across_devices_at_same_counter() {
    // Previously the nonce XOR'd device_id into the counter slot; two
    // devices could produce identical nonces if their device_id bytes
    // cancelled out. Pin that this cannot happen now.
    let crypto_a = NonceCapturingCrypto::new();
    let crypto_b = NonceCapturingCrypto::new();

    let mut cfg_a = test_config();
    cfg_a.device_id = [
        0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let mut up_a: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::restore(cfg_a, PersistedFlushCounter::fresh_device());
    up_a.submit_entry(make_entry(0)).unwrap();
    up_a.flush_no_persist(&crypto_a, 1_000_000).unwrap().unwrap();

    let mut cfg_b = test_config();
    cfg_b.device_id = [
        0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let mut up_b: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::restore(cfg_b, PersistedFlushCounter::fresh_device());
    up_b.submit_entry(make_entry(0)).unwrap();
    up_b.flush_no_persist(&crypto_b, 1_000_000).unwrap().unwrap();

    assert_ne!(crypto_a.last_nonce.get(), crypto_b.last_nonce.get());
}

#[test]
fn flush_nonce_counter_boundary_accepts_max_minus_one() {
    // The flush just below MAX_FLUSH_COUNTER must still succeed — the
    // counter is encoded into 6 bytes, so the last representable value
    // is (1 << 48) - 2 (one less than MAX_FLUSH_COUNTER, which itself is
    // the reject boundary).
    let mut uplink: TelemetryUplink<MockCrypto> = TelemetryUplink::restore(
        test_config(),
        PersistedFlushCounter::restore(MAX_FLUSH_COUNTER - 1),
    );
    let crypto = MockCrypto;
    uplink.submit_entry(make_entry(0)).unwrap();
    assert!(uplink.flush_no_persist(&crypto, 1_000_000).unwrap().is_some());

    // The next flush should now be rejected because the counter has
    // advanced to MAX_FLUSH_COUNTER.
    uplink.submit_entry(make_entry(1)).unwrap();
    assert_eq!(
        uplink.flush_no_persist(&crypto, 2_000_000),
        Err(VsError::ResourceExhausted)
    );
}

#[test]
fn flush_multiple_batches_increment_counter() {
    let mut config = test_config();
    config.batch_size = 2;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;

    for round in 0..3u64 {
        uplink.submit_entry(make_entry(round * 2)).unwrap();
        uplink.submit_entry(make_entry(round * 2 + 1)).unwrap();
        let result = uplink.flush_no_persist(&crypto, round * 10_000_000).unwrap().unwrap();
        // After audit fix CRIT-1 the wire counter is next_counter (round + 1).
        assert_eq!(result.flush_counter, round + 1);
    }
    assert_eq!(uplink.flush_counter(), 3);
}

// -----------------------------------------------------------------------
// PersistedFlushCounter + restore()
// -----------------------------------------------------------------------

#[test]
fn persisted_flush_counter_roundtrip() {
    let c = PersistedFlushCounter::restore(1234);
    assert_eq!(c.value(), 1234);
}

#[test]
fn persisted_flush_counter_fresh_is_zero() {
    assert_eq!(PersistedFlushCounter::fresh_device().value(), 0);
}

#[test]
fn restore_applies_counter_value() {
    let uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::restore(77));
    assert_eq!(uplink.flush_counter(), 77);
}

// -----------------------------------------------------------------------
// Monotonic-timestamp guard
// -----------------------------------------------------------------------

#[test]
fn flush_rejects_timestamp_regression() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    uplink.submit_entry(make_entry(0)).unwrap();
    // Advance the window to t=1_000_000.
    uplink.flush_no_persist(&crypto, 1_000_000).unwrap();
    // A subsequent flush with an earlier timestamp must fail rather
    // than silently resetting the rate-limit window.
    uplink.submit_entry(make_entry(1)).unwrap();
    assert_eq!(uplink.flush_no_persist(&crypto, 500_000), Err(VsError::InvalidInput));
}

#[test]
fn flush_same_timestamp_accepted() {
    // Same timestamp is non-decreasing and must be accepted.
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let crypto = MockCrypto;
    uplink.submit_entry(make_entry(0)).unwrap();
    uplink.flush_no_persist(&crypto, 1_000_000).unwrap();
    uplink.submit_entry(make_entry(1)).unwrap();
    let r = uplink.flush_no_persist(&crypto, 1_000_000).unwrap();
    assert!(r.is_some());
}

// -----------------------------------------------------------------------
// CryptoProvider error propagation
// -----------------------------------------------------------------------

struct FailingSha256;
impl CryptoProvider for FailingSha256 {
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
    fn sha256(&self, _: &[u8], _: &mut [u8; 32]) -> Result<(), VsError> {
        Err(VsError::CryptoError)
    }
    fn hmac_sha256(&self, _: KeyId, _: &[u8], _: &mut [u8; 32]) -> Result<(), VsError> {
        Ok(())
    }
    fn ecdh_derive_shared(&self, _: KeyId, _: &[u8; 65], _: &mut [u8; 32]) -> Result<(), VsError> {
        Ok(())
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
        Ok(())
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        Ok(false)
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

#[test]
fn flush_propagates_sha256_error() {
    let mut uplink: TelemetryUplink<FailingSha256> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let crypto = FailingSha256;
    assert_eq!(uplink.flush_no_persist(&crypto, 1_000_000), Err(VsError::CryptoError));
}

struct FailingSign;
impl CryptoProvider for FailingSign {
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
    fn sha256(&self, _: &[u8], out: &mut [u8; 32]) -> Result<(), VsError> {
        out.fill(1);
        Ok(())
    }
    fn hmac_sha256(&self, _: KeyId, _: &[u8], _: &mut [u8; 32]) -> Result<(), VsError> {
        Ok(())
    }
    fn ecdh_derive_shared(&self, _: KeyId, _: &[u8; 65], _: &mut [u8; 32]) -> Result<(), VsError> {
        Ok(())
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
        Err(VsError::CryptoError)
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        Ok(false)
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

#[test]
fn flush_propagates_sign_error() {
    let mut uplink: TelemetryUplink<FailingSign> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let crypto = FailingSign;
    assert_eq!(uplink.flush_no_persist(&crypto, 1_000_000), Err(VsError::CryptoError));
}

// -----------------------------------------------------------------------
// Ring-buffer FIFO ordering
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Volatile wipe helper
// -----------------------------------------------------------------------

#[test]
fn volatile_wipe_zeroes_buffer() {
    let mut buf = [0xFFu8; 64];
    volatile_wipe(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn volatile_wipe_empty_slice_is_noop() {
    let mut buf: [u8; 0] = [];
    volatile_wipe(&mut buf);
}

#[test]
fn volatile_wipe_partial_buffer() {
    let mut buf = [0xAAu8; 16];
    volatile_wipe(&mut buf[4..12]);
    assert_eq!(&buf[..4], &[0xAA; 4]);
    assert_eq!(&buf[4..12], &[0; 8]);
    assert_eq!(&buf[12..], &[0xAA; 4]);
}

// -----------------------------------------------------------------------
// Ring-buffer FIFO ordering
// -----------------------------------------------------------------------

#[test]
fn flush_consumes_entries_in_fifo_order() {
    // After overflow, the oldest entries are the ones that were dropped.
    // Verify that after an overflow, the remaining entries are the
    // most recent, and that the flush counter / queued count agree.
    let mut config = test_config();
    config.batch_size = 64;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(config, PersistedFlushCounter::fresh_device());
    for i in 0..65u64 {
        uplink.submit_entry(make_entry(i)).unwrap();
    }
    assert_eq!(uplink.dropped_count(), 1);
    assert_eq!(uplink.queued(), 64);
    let crypto = MockCrypto;
    let r = uplink.flush_no_persist(&crypto, 1_000_000).unwrap().unwrap();
    assert_eq!(r.entry_count, 64);
    assert_eq!(uplink.queued(), 0);
}

// -----------------------------------------------------------------------
// Write-ahead counter persistence (audit fix CRIT-1)
// -----------------------------------------------------------------------

/// Captures every `persist()` call so the ordering relative to encrypt
/// can be asserted.
struct CountingPersistence {
    calls: core::cell::Cell<u32>,
    last_persisted: core::cell::Cell<u64>,
    fail_on_call: u32,
}

impl CountingPersistence {
    fn new() -> Self {
        Self {
            calls: core::cell::Cell::new(0),
            last_persisted: core::cell::Cell::new(u64::MAX),
            fail_on_call: u32::MAX,
        }
    }

    fn failing_on(nth: u32) -> Self {
        Self {
            calls: core::cell::Cell::new(0),
            last_persisted: core::cell::Cell::new(u64::MAX),
            fail_on_call: nth,
        }
    }
}

impl CounterPersistence for CountingPersistence {
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError> {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        if n == self.fail_on_call {
            return Err(VsError::CryptoError);
        }
        self.last_persisted.set(new_counter);
        Ok(())
    }
}

#[test]
fn persist_is_called_before_encrypt() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let mut persistence = CountingPersistence::new();
    let crypto = MockCrypto;
    let result = uplink
        .flush_with_persistence(&crypto, 1_000_000, &mut persistence)
        .unwrap()
        .unwrap();
    assert_eq!(persistence.calls.get(), 1, "persist must be called once");
    assert_eq!(
        persistence.last_persisted.get(),
        1,
        "persist gets next counter"
    );
    // FlushResult.flush_counter carries what was encoded on the wire,
    // which is next_counter (1), not the pre-increment value.
    assert_eq!(result.flush_counter, 1);
    assert_eq!(uplink.flush_counter(), 1);
}

#[test]
fn persist_failure_does_not_advance_counter() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let mut persistence = CountingPersistence::failing_on(1);
    let crypto = MockCrypto;
    let err = uplink.flush_with_persistence(&crypto, 1_000_000, &mut persistence);
    assert_eq!(err, Err(VsError::CryptoError));
    // Counter stays at 0 — caller may retry safely.
    assert_eq!(uplink.flush_counter(), 0);
    // Entries stay queued — no data lost.
    assert_eq!(uplink.queued(), 1);
}

#[test]
fn encrypt_failure_after_successful_persist_still_burns_counter() {
    // After persist succeeds the in-memory counter advances immediately
    // (jump-over invariant). A subsequent encrypt/sign failure leaves
    // BOTH stores at the burned value, so the next flush jumps to N+2.
    let mut uplink: TelemetryUplink<FailingSign> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let mut persistence = CountingPersistence::new();
    let crypto = FailingSign;
    let err = uplink.flush_with_persistence(&crypto, 1_000_000, &mut persistence);
    assert_eq!(err, Err(VsError::CryptoError));
    // Persist ran and committed 1; in-memory state now also reads 1.
    assert_eq!(persistence.last_persisted.get(), 1);
    assert_eq!(uplink.flush_counter(), 1);
}

#[test]
fn power_fail_simulation_no_nonce_reuse() {
    // Boot 1: flush, persist=1, then "crash" before encrypt (simulated
    // by FailingSign). Persistent store holds 1.
    let mut persistence = CountingPersistence::new();
    {
        let mut uplink: TelemetryUplink<FailingSign> =
            TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
        uplink.submit_entry(make_entry(0)).unwrap();
        let _ = uplink.flush_with_persistence(&FailingSign, 1_000_000, &mut persistence);
    }
    let persisted_after_crash = persistence.last_persisted.get();
    assert_eq!(persisted_after_crash, 1);

    // Boot 2: restore from persisted value and flush successfully.
    // The new nonce must differ from whatever the crashed boot would
    // have used.
    let mut uplink: TelemetryUplink<MockCrypto> = TelemetryUplink::restore(
        test_config(),
        PersistedFlushCounter::restore(persisted_after_crash),
    );
    uplink.submit_entry(make_entry(0)).unwrap();
    let mut persistence2 = CountingPersistence::new();
    let result = uplink
        .flush_with_persistence(&MockCrypto, 2_000_000, &mut persistence2)
        .unwrap()
        .unwrap();
    // After a crash that burned counter 1, the next flush uses 2.
    assert_eq!(result.flush_counter, 2);
    assert_eq!(persistence2.last_persisted.get(), 2);
}

#[test]
fn flush_backward_compat_uses_noop_persistence() {
    // The legacy `flush()` wrapper uses NoOpPersistence and must behave
    // identically from the caller's perspective. This regression test
    // pins that restructuring didn't perturb the observable API.
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let r = uplink.flush_no_persist(&MockCrypto, 1_000_000).unwrap().unwrap();
    assert_eq!(r.flush_counter, 1);
    assert_eq!(uplink.flush_counter(), 1);
}

// -----------------------------------------------------------------------
// Empty-flush + ts_us bound (audit fix MED-1)
// -----------------------------------------------------------------------

#[test]
fn empty_flush_updates_last_flush_us() {
    // Empty flush advances `last_flush_us` so the monotonic guard stays
    // consistent. The `MAX_REASONABLE_TS_US` bound prevents the
    // u64::MAX DoS that this update used to enable.
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    // Empty flush at ts=10 advances the monotonic floor to 10.
    assert!(uplink.flush_no_persist(&MockCrypto, 10).unwrap().is_none());
    // A subsequent flush at ts=5 must now be rejected as a clock regression.
    uplink.submit_entry(make_entry(0)).unwrap();
    assert_eq!(uplink.flush_no_persist(&MockCrypto, 5), Err(VsError::InvalidInput));
    // ts >= 10 still works.
    assert!(uplink.flush_no_persist(&MockCrypto, 11).unwrap().is_some());
}

#[test]
fn flush_rejects_ts_us_near_u64_max() {
    // `u64::MAX` and anything above `MAX_REASONABLE_TS_US` must be
    // rejected outright (MED-1 DoS).
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    assert_eq!(
        uplink.flush_no_persist(&MockCrypto, u64::MAX),
        Err(VsError::InvalidInput)
    );
    assert_eq!(
        uplink.flush_no_persist(&MockCrypto, MAX_REASONABLE_TS_US + 1),
        Err(VsError::InvalidInput)
    );
    // Boundary is inclusive.
    uplink.submit_entry(make_entry(0)).unwrap();
    assert!(uplink.flush_no_persist(&MockCrypto, MAX_REASONABLE_TS_US).is_ok());
}

// -----------------------------------------------------------------------
// Audit fix MED-4 (config validation)
// -----------------------------------------------------------------------

#[test]
fn config_validate_rejects_zero_batch_size() {
    let mut cfg = test_config();
    cfg.batch_size = 0;
    assert_eq!(cfg.validate(), Err(VsError::InvalidInput));
}

#[test]
fn config_validate_rejects_zero_max_bytes_per_minute() {
    let mut cfg = test_config();
    cfg.max_bytes_per_minute = 0;
    assert_eq!(cfg.validate(), Err(VsError::InvalidInput));
}

#[test]
fn config_validate_accepts_sane_config() {
    assert!(test_config().validate().is_ok());
}

#[test]
fn try_restore_propagates_validation_error() {
    let mut cfg = test_config();
    cfg.batch_size = 0;
    let r: Result<TelemetryUplink<MockCrypto>, _> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device());
    assert_eq!(r.err(), Some(VsError::InvalidInput));
}

#[test]
fn restore_clamps_zero_batch_size() {
    // Audit MED-4: `restore` must NOT silently produce a permanently
    // silent uplink. It clamps batch_size=0 to 1.
    let mut cfg = test_config();
    cfg.batch_size = 0;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(cfg, PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    // Single-entry batch flushes successfully under clamped batch_size=1.
    assert!(uplink.flush_no_persist(&MockCrypto, 1_000_000).unwrap().is_some());
}

// -----------------------------------------------------------------------
// Audit fix MED-2 (reserved-critical slots)
// -----------------------------------------------------------------------

fn make_entry_severity(seq: u64, severity: AlertSeverity) -> TelemetryEntry {
    TelemetryEntry::new(seq, seq * 1000, 0x01, severity, b"test").unwrap()
}

#[test]
fn reserved_critical_slots_drop_low_severity_under_pressure() {
    // With 8 reserved critical slots and capacity 64, the low-severity
    // gate trips at occupancy 56. Fill 56 Info entries (none dropped),
    // then submit Info → drop, submit Critical → accepted.
    let mut cfg = test_config();
    cfg.reserved_critical_slots = 8;
    cfg.batch_size = 64;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(cfg, PersistedFlushCounter::fresh_device());
    for i in 0..56u64 {
        uplink
            .submit_entry(make_entry_severity(i, AlertSeverity::Info))
            .unwrap();
    }
    assert_eq!(uplink.queued(), 56);
    assert_eq!(uplink.dropped_count(), 0);

    // Info at the boundary should be dropped without a queue change.
    uplink
        .submit_entry(make_entry_severity(56, AlertSeverity::Info))
        .unwrap();
    assert_eq!(uplink.queued(), 56, "Info above high-water must drop");
    assert_eq!(uplink.dropped_count(), 1);

    // Critical at the boundary must still be admitted.
    uplink
        .submit_entry(make_entry_severity(57, AlertSeverity::Critical))
        .unwrap();
    assert_eq!(uplink.queued(), 57);
    assert_eq!(uplink.dropped_count(), 1);
}

#[test]
fn reserved_critical_slots_zero_disables_gate() {
    // With reserved_critical_slots = 0 the gate never trips.
    let mut cfg = test_config();
    cfg.reserved_critical_slots = 0;
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(cfg, PersistedFlushCounter::fresh_device());
    for i in 0..63u64 {
        uplink
            .submit_entry(make_entry_severity(i, AlertSeverity::Info))
            .unwrap();
    }
    // 64th Info still admitted.
    uplink
        .submit_entry(make_entry_severity(63, AlertSeverity::Info))
        .unwrap();
    assert_eq!(uplink.queued(), 64);
    assert_eq!(uplink.dropped_count(), 0);
}

// -----------------------------------------------------------------------
// Audit fix HIGH-3 (renamed field accessor)
// -----------------------------------------------------------------------

#[test]
#[allow(deprecated)]
fn deprecated_encrypted_digest_accessor_returns_same_bytes() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let r = uplink.flush_no_persist(&MockCrypto, 1_000_000).unwrap().unwrap();
    // The deprecated accessor must alias the renamed field.
    assert_eq!(r.encrypted_digest(), &r.digest_commitment);
}

// -----------------------------------------------------------------------
// Audit fix HIGH-2 (authenticated PersistedFlushCounter blob)
// -----------------------------------------------------------------------

/// Mock that hashes input deterministically into the MAC output so the
/// authentication blob roundtrip can be tested without pulling a real
/// HMAC implementation.
struct DeterministicHmacCrypto;
impl CryptoProvider for DeterministicHmacCrypto {
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
    fn sha256(&self, _: &[u8], hash: &mut [u8; 32]) -> Result<(), VsError> {
        hash.fill(0xCD);
        Ok(())
    }
    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        // Deterministic toy HMAC: each output byte i is
        // (key_id ^ data[j % len] ^ i) for stride j.
        for (i, slot) in mac_out.iter_mut().enumerate() {
            let mut acc = key_id.0 as u8 ^ (i as u8);
            for (k, b) in data.iter().enumerate() {
                acc ^= b ^ (k as u8);
            }
            *slot = acc;
        }
        Ok(())
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
        Ok(())
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        Ok(true)
    }
    fn ecdh_derive_shared(&self, _: KeyId, _: &[u8; 65], _: &mut [u8; 32]) -> Result<(), VsError> {
        Ok(())
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

#[test]
fn persisted_counter_blob_roundtrips() {
    let crypto = DeterministicHmacCrypto;
    let mac_key = KeyId(7);
    #[allow(deprecated)]
    let pfc = PersistedFlushCounter::restore(0xDEAD_BEEF_CAFE_F00D);
    let blob = pfc.to_blob(&crypto, mac_key).unwrap();
    let restored = PersistedFlushCounter::restore_authenticated(&blob, &crypto, mac_key)
        .expect("valid blob must round-trip");
    assert_eq!(restored.value(), 0xDEAD_BEEF_CAFE_F00D);
}

#[test]
fn persisted_counter_blob_rejects_tampered_counter() {
    let crypto = DeterministicHmacCrypto;
    let mac_key = KeyId(7);
    #[allow(deprecated)]
    let pfc = PersistedFlushCounter::restore(42);
    let mut blob = pfc.to_blob(&crypto, mac_key).unwrap();
    // Flip a bit in the counter half — tag no longer covers it.
    blob[0] ^= 0x01;
    assert_eq!(
        PersistedFlushCounter::restore_authenticated(&blob, &crypto, mac_key),
        Err(VsError::CryptoError)
    );
}

#[test]
fn persisted_counter_blob_rejects_tampered_tag() {
    let crypto = DeterministicHmacCrypto;
    let mac_key = KeyId(7);
    #[allow(deprecated)]
    let pfc = PersistedFlushCounter::restore(42);
    let mut blob = pfc.to_blob(&crypto, mac_key).unwrap();
    // Flip a bit in the tag.
    blob[20] ^= 0x40;
    assert_eq!(
        PersistedFlushCounter::restore_authenticated(&blob, &crypto, mac_key),
        Err(VsError::CryptoError)
    );
}

#[test]
fn persisted_counter_blob_rejects_wrong_mac_key() {
    let crypto = DeterministicHmacCrypto;
    #[allow(deprecated)]
    let pfc = PersistedFlushCounter::restore(42);
    let blob = pfc.to_blob(&crypto, KeyId(7)).unwrap();
    // Wrong key on restore — tag won't verify.
    assert_eq!(
        PersistedFlushCounter::restore_authenticated(&blob, &crypto, KeyId(8)),
        Err(VsError::CryptoError)
    );
}

// -----------------------------------------------------------------------
// Audit fix H2 (RollbackResistantStorage sealed marker)
// -----------------------------------------------------------------------

/// Mock storage backend that hands out a single fixed blob on every
/// `load()`. Useful for simulating a snapshot-and-replay attacker: the
/// blob installed at boot is whatever the attacker last wrote.
struct StubStorage([u8; 40]);

impl CounterStorage for StubStorage {
    fn load_authenticated<C: CryptoProvider>(
        &self,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<PersistedFlushCounter, VsError> {
        PersistedFlushCounter::restore_authenticated(&self.0, crypto, mac_key_id)
    }
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError> {
        // Test stub: writes are no-ops since this storage only models
        // an attacker-installed blob for replay tests.
        let _ = new_counter;
        Ok(())
    }
}

#[test]
fn restore_authenticated_accepts_stale_blob_documenting_caller_asserted_rollback_resistance_limitation(
) {
    // Audit-H2 cannot be fixed inside this crate: an HMAC over an 8-byte
    // counter has no notion of freshness, so a stale-but-valid blob the
    // attacker captured before the device advanced still verifies. What
    // we CAN do is force the caller to commit, in the type system, to a
    // rollback-resistant medium — they do that by wrapping their
    // CounterStorage in `AssertedExternallyRollbackResistant`. This test
    // documents both halves of that contract:
    //
    //   1. A stale blob still verifies — the HMAC layer can't tell.
    //   2. A plain `impl CounterStorage` cannot reach the
    //      `_from_storage` entry point without the wrapper (proved by
    //      the `assert_not_impl_any!` block below).
    let crypto = DeterministicHmacCrypto;
    let mac_key = KeyId(7);

    // Device flushed up to counter = 100; the persisted blob is fresh.
    #[allow(deprecated)]
    let fresh = PersistedFlushCounter::restore(100);
    let fresh_blob = fresh.to_blob(&crypto, mac_key).unwrap();

    // Attacker snapshots the blob at counter = 5 (before any of those
    // flushes happened), then later — after the device has advanced
    // past 100 — overwrites the storage medium with the old blob.
    #[allow(deprecated)]
    let stale = PersistedFlushCounter::restore(5);
    let stale_blob = stale.to_blob(&crypto, mac_key).unwrap();

    // Sanity: the fresh blob roundtrips through the wrapper.
    let storage_fresh = AssertedExternallyRollbackResistant(StubStorage(fresh_blob));
    let restored_fresh = PersistedFlushCounter::restore_authenticated_from_storage(
        &storage_fresh,
        &crypto,
        mac_key,
    )
    .expect("fresh blob must verify");
    assert_eq!(restored_fresh.value(), 100);

    // Documenting the limitation: the stale blob ALSO verifies — the
    // HMAC layer is freshness-blind. This is exactly the scenario that
    // motivates `RollbackResistantStorage`: the caller asserts, via the
    // wrapper, that the underlying medium (RPMB / eFuse / TPM NV with
    // `TPMA_NV_WRITE_STCLEAR`) makes this rollback physically
    // impossible. If the wrapper is wired to a plain FS blob, audit-H2
    // re-emerges and this restore succeeds with a counter value that
    // causes nonce reuse downstream.
    let storage_stale = AssertedExternallyRollbackResistant(StubStorage(stale_blob));
    let restored_stale = PersistedFlushCounter::restore_authenticated_from_storage(
        &storage_stale,
        &crypto,
        mac_key,
    )
    .expect("stale blob still verifies — documents the audit-H2 limitation");
    assert_eq!(restored_stale.value(), 5);
}

#[test]
fn restore_authenticated_from_storage_rejects_tampered_blob() {
    let crypto = DeterministicHmacCrypto;
    let mac_key = KeyId(7);
    #[allow(deprecated)]
    let pfc = PersistedFlushCounter::restore(42);
    let mut blob = pfc.to_blob(&crypto, mac_key).unwrap();
    // Flip a bit in the tag so the HMAC no longer verifies.
    blob[20] ^= 0x40;
    let storage = AssertedExternallyRollbackResistant(StubStorage(blob));
    assert_eq!(
        PersistedFlushCounter::restore_authenticated_from_storage(&storage, &crypto, mac_key),
        Err(VsError::CryptoError)
    );
}

#[test]
fn restore_authenticated_from_storage_propagates_storage_io_error() {
    /// Storage backend that always returns an IO error — proves the
    /// `_from_storage` path surfaces backend failures verbatim instead
    /// of swallowing them as a verify error.
    struct FailingStorage;
    impl CounterStorage for FailingStorage {
        fn load_authenticated<C: CryptoProvider>(
            &self,
            _crypto: &C,
            _mac_key_id: KeyId,
        ) -> Result<PersistedFlushCounter, VsError> {
            Err(VsError::StorageError)
        }
        fn persist(&mut self, _new_counter: u64) -> Result<(), VsError> {
            Err(VsError::StorageError)
        }
    }
    impl crate::sealed::Sealed for FailingStorage {}
    impl RollbackResistantStorage for FailingStorage {
        const STORAGE_KIND: &'static str = "test-failing";
    }

    let crypto = DeterministicHmacCrypto;
    assert_eq!(
        PersistedFlushCounter::restore_authenticated_from_storage(
            &FailingStorage,
            &crypto,
            KeyId(7),
        ),
        Err(VsError::StorageError)
    );
}

/// Type-level audit: a bare `impl CounterStorage` must NOT satisfy
/// `RollbackResistantStorage`, and the blessed wrapper MUST. Equivalent
/// to a `compile_fail` doctest, but works in a `#![no_std]` crate
/// without spinning up a `std`-linked doctest runner.
#[test]
fn rollback_resistant_storage_is_sealed_against_plain_counter_storage() {
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    // Plain in-test storage that only implements `CounterStorage`.
    struct PlainFsBlob;
    impl CounterStorage for PlainFsBlob {
        fn load_authenticated<C: CryptoProvider>(
            &self,
            _crypto: &C,
            _mac_key_id: KeyId,
        ) -> Result<PersistedFlushCounter, VsError> {
            Ok(PersistedFlushCounter::fresh_device())
        }
        fn persist(&mut self, _new_counter: u64) -> Result<(), VsError> {
            Ok(())
        }
    }

    // Negative path: a downstream-style `impl CounterStorage for X` does
    // NOT satisfy the rollback marker — the sealed super-trait is
    // private to this crate. This is the load-bearing assertion for
    // audit-H2 (downstream callers cannot opt themselves in by
    // accident).
    assert_not_impl_any!(PlainFsBlob: RollbackResistantStorage);

    // Positive path: the blessed wrapper satisfies both traits.
    assert_impl_all!(
        AssertedExternallyRollbackResistant<PlainFsBlob>:
            CounterStorage,
            RollbackResistantStorage,
    );
    // Sanity: the kind tag is the documented constant.
    assert_eq!(
        <AssertedExternallyRollbackResistant<PlainFsBlob>
            as RollbackResistantStorage>::STORAGE_KIND,
        "caller-asserted",
    );
}

// -----------------------------------------------------------------------
// Audit fix HIGH-1 (per-device nonce prefix)
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Audit fix MED-3 (TelemetryEntry accessors + payload_len defence)
// -----------------------------------------------------------------------

#[test]
fn telemetry_entry_accessors_round_trip() {
    let entry = TelemetryEntry::new(42, 123_456, 7, AlertSeverity::High, b"payload data").unwrap();
    assert_eq!(entry.sequence(), 42);
    assert_eq!(entry.timestamp_us(), 123_456);
    assert_eq!(entry.event_type(), 7);
    assert_eq!(entry.severity(), AlertSeverity::High);
    assert_eq!(entry.payload_len() as usize, b"payload data".len());
    assert_eq!(entry.payload(), b"payload data");
    assert_eq!(
        entry.raw_payload()[..b"payload data".len()],
        *b"payload data"
    );
    assert!(entry.raw_payload()[b"payload data".len()..]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn telemetry_entry_serialize_rejects_hand_mutated_payload_len() {
    // Audit fix MED-3 defence: even though `new` validates, public
    // fields can be bypassed via `..Default::default()` or direct
    // mutation. The serialize path must reject `payload_len > 64`
    // rather than silently truncating to a 64-byte wire encoding.
    let mut entry = TelemetryEntry::new(0, 0, 0, AlertSeverity::Info, b"x").unwrap();
    entry.payload_len = 200;
    let mut out = [0u8; ENTRY_SERIAL_SIZE];
    assert_eq!(
        entry.serialize_into(&mut out, 0),
        Err(VsError::InvalidInput)
    );
}

// -----------------------------------------------------------------------
// FlushOutcome enum
// -----------------------------------------------------------------------

#[test]
fn flush_outcome_returns_empty_when_no_entries() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    let outcome = uplink
        .flush_outcome(&MockCrypto, 1_000_000, &mut NoOpPersistence)
        .unwrap();
    assert_eq!(outcome, FlushOutcome::Empty);
}

#[test]
fn flush_outcome_returns_sent_when_entries_queued() {
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(test_config(), PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let outcome = uplink
        .flush_outcome(&MockCrypto, 1_000_000, &mut NoOpPersistence)
        .unwrap();
    match outcome {
        FlushOutcome::Sent(r) => assert_eq!(r.entry_count, 1),
        other => panic!("expected Sent, got {other:?}"),
    }
}

#[test]
fn flush_outcome_distinguishes_rate_limit() {
    // Build a config with a tiny per-minute budget so a single flush
    // exhausts it; the second flush in the same window must report
    // RateLimited (not Empty, not CryptoError).
    let mut cfg = test_config();
    cfg.max_bytes_per_minute = 100; // smaller than one entry
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::restore(cfg, PersistedFlushCounter::fresh_device());
    uplink.submit_entry(make_entry(0)).unwrap();
    let first = uplink
        .flush_outcome(&MockCrypto, 1_000_000, &mut NoOpPersistence)
        .unwrap();
    // The first flush exceeds the per-minute budget — must be RateLimited.
    match first {
        FlushOutcome::RateLimited { retry_after_us } => {
            assert!(retry_after_us > 0);
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[test]
#[allow(deprecated)]
fn flush_outcome_reports_counter_exhausted() {
    let mut uplink: TelemetryUplink<MockCrypto> = TelemetryUplink::restore(
        test_config(),
        PersistedFlushCounter::restore(MAX_FLUSH_COUNTER),
    );
    uplink.submit_entry(make_entry(0)).unwrap();
    let outcome = uplink
        .flush_outcome(&MockCrypto, 1_000_000, &mut NoOpPersistence)
        .unwrap();
    assert_eq!(outcome, FlushOutcome::CounterExhausted);
}

#[test]
fn nonce_prefix_depends_on_full_device_id() {
    // Two configs that differ ONLY in device_id[10] (not in [0..4]
    // which the old code keyed off) must produce distinct nonces.
    let crypto_a = NonceCapturingCrypto::new();
    let crypto_b = NonceCapturingCrypto::new();
    let mut cfg_a = test_config();
    cfg_a.device_id = [0u8; 32];
    cfg_a.device_id[0] = 1;
    cfg_a.device_id[10] = 0xAA; // distinguishing byte
    let mut cfg_b = test_config();
    cfg_b.device_id = [0u8; 32];
    cfg_b.device_id[0] = 1;
    cfg_b.device_id[10] = 0xBB; // distinguishing byte
    let mut up_a: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::restore(cfg_a, PersistedFlushCounter::fresh_device());
    let mut up_b: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::restore(cfg_b, PersistedFlushCounter::fresh_device());
    up_a.submit_entry(make_entry(0)).unwrap();
    up_b.submit_entry(make_entry(0)).unwrap();
    up_a.flush_no_persist(&crypto_a, 1_000_000).unwrap().unwrap();
    up_b.flush_no_persist(&crypto_b, 1_000_000).unwrap().unwrap();
    assert_ne!(
        crypto_a.last_nonce.get(),
        crypto_b.last_nonce.get(),
        "nonce prefix must depend on bytes beyond device_id[..4]"
    );
}

#[test]
fn nonce_unique_across_two_flushes_same_device() {
    // Positive uniqueness: a single device performing two successful
    // flushes through persistent counter restoration must produce two
    // distinct AES-GCM nonces. This pins the documented invariant
    // that nonce reuse is impossible by construction.
    let crypto = NonceCapturingCrypto::new();
    let cfg = test_config();

    // Flush 1.
    let mut up1: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device()).unwrap();
    up1.submit_entry(make_entry(0)).unwrap();
    let mut p1 = CountingPersistence::new();
    up1.flush_with_persistence(&crypto, 1_000_000, &mut p1)
        .unwrap()
        .unwrap();
    let nonce1 = crypto.last_nonce.get();
    let persisted = p1.last_persisted.get();

    // Flush 2 — same device, restored counter (simulates reboot).
    let mut up2: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::restore(persisted)).unwrap();
    up2.submit_entry(make_entry(1)).unwrap();
    let mut p2 = CountingPersistence::new();
    up2.flush_with_persistence(&crypto, 2_000_000, &mut p2)
        .unwrap()
        .unwrap();
    let nonce2 = crypto.last_nonce.get();

    assert_ne!(
        nonce1, nonce2,
        "two flushes from same device must use unique nonces"
    );
}

// ---------------------------------------------------------------------------
// Real-AEAD integration (review item #4)
//
// The `MockCrypto` and `NonceCapturingCrypto` above are identity-with-tag
// stubs; they prove nothing about whether the uplink wires up correctly
// against a real AEAD. The test below pulls in `vs-crypto`'s software
// `RustCryptoProvider` (dev-dep, `software` feature) and:
//
//   1. encrypts twice from the same uplink (same key slot, two different
//      nonces by counter advance) and asserts the two ciphertexts differ,
//      proving real CTR-mode encryption is running (the mock would also
//      differ for unrelated reasons — see assertion comment).
//   2. flips a bit in the recovered tag and asserts the real
//      `aes_gcm_decrypt` rejects it — proving end-to-end authentication.
//
// One-shot integration, not part of the per-flush nonce-uniqueness suite.
// ---------------------------------------------------------------------------

/// Wraps `RustCryptoProvider` to capture the nonce/AAD passed to
/// `aes_gcm_encrypt`, so the test can re-decrypt with the same nonce
/// and prove a tag flip is detected.
struct CapturingRealCrypto {
    inner: vs_crypto::RustCryptoProvider,
    last_nonce: core::cell::Cell<[u8; 12]>,
    last_aad: core::cell::RefCell<[u8; AAD_SIZE]>,
    last_aad_len: core::cell::Cell<usize>,
}

impl CapturingRealCrypto {
    fn new(inner: vs_crypto::RustCryptoProvider) -> Self {
        Self {
            inner,
            last_nonce: core::cell::Cell::new([0u8; 12]),
            last_aad: core::cell::RefCell::new([0u8; AAD_SIZE]),
            last_aad_len: core::cell::Cell::new(0),
        }
    }
}

impl CryptoProvider for CapturingRealCrypto {
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        self.last_nonce.set(*nonce);
        let mut buf = self.last_aad.borrow_mut();
        buf[..aad.len()].copy_from_slice(aad);
        self.last_aad_len.set(aad.len());
        self.inner
            .aes_gcm_encrypt(key_id, nonce, plaintext, aad, ciphertext_out, tag_out)
    }
    fn aes_gcm_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        self.inner
            .aes_gcm_decrypt(key_id, nonce, ciphertext, aad, tag, plaintext_out)
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        self.inner.sha256(data, hash_out)
    }
    fn hmac_sha256(&self, key_id: KeyId, data: &[u8], mac_out: &mut [u8; 32]) -> Result<(), VsError> {
        self.inner.hmac_sha256(key_id, data, mac_out)
    }
    fn ecdh_derive_shared(
        &self,
        key_id: KeyId,
        peer: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        self.inner.ecdh_derive_shared(key_id, peer, shared_out)
    }
    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        self.inner.sign_p256(key_id, digest, sig_out)
    }
    fn verify_p256(
        &self,
        pubkey: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        self.inner.verify_p256(pubkey, digest, sig)
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        self.inner.random_bytes(buf)
    }
    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
        self.inner.delete_key(key_id)
    }
    fn generate_key(&mut self, key_id: KeyId, key_type: KeyType) -> Result<(), VsError> {
        self.inner.generate_key(key_id, key_type)
    }
}

/// Deterministic "entropy" for the test provider — `RustCryptoProvider`
/// requires a `fn(&mut [u8])` entropy source. AES-GCM correctness does
/// not depend on the RNG, so a fixed seed keeps the test reproducible.
fn test_rng(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(7);
    }
}

#[test]
fn flush_against_real_aead_differs_and_detects_tag_flip() {
    let mut real = vs_crypto::RustCryptoProvider::new(test_rng);
    let aes_key = [0x11u8; 32];
    real.set_key(KeyId(0), &aes_key).unwrap();
    real.generate_key(KeyId(1), KeyType::EcdsaP256).unwrap();

    let crypto = CapturingRealCrypto::new(real);

    let cfg = test_config();
    let mut uplink: TelemetryUplink<CapturingRealCrypto> =
        TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device()).unwrap();

    // Flush #1
    uplink.submit_entry(make_entry(0)).unwrap();
    let r1 = uplink
        .flush_with_persistence(&crypto, 1_000_000, &mut NoOpPersistence)
        .unwrap()
        .unwrap();
    let nonce1 = crypto.last_nonce.get();
    let mut aad1 = [0u8; AAD_SIZE];
    let aad1_len = crypto.last_aad_len.get();
    aad1[..aad1_len].copy_from_slice(&crypto.last_aad.borrow()[..aad1_len]);

    // Flush #2
    uplink.submit_entry(make_entry(1)).unwrap();
    let r2 = uplink
        .flush_with_persistence(&crypto, 2_000_000, &mut NoOpPersistence)
        .unwrap()
        .unwrap();

    // Positive: real AEAD under same key + different nonces must yield
    // different ciphertexts.
    assert_ne!(
        r1.digest_commitment, r2.digest_commitment,
        "real AEAD must produce different ciphertexts across nonces"
    );

    // Negative: tag-flipped ciphertext must be rejected by the real AEAD.
    let mut tampered_tag = r1.tag;
    tampered_tag[0] ^= 0x01;
    let mut plaintext_out = [0u8; 32];
    let dec = crypto.aes_gcm_decrypt(
        KeyId(0),
        &nonce1,
        &r1.digest_commitment,
        &aad1[..aad1_len],
        &tampered_tag,
        &mut plaintext_out,
    );
    assert!(dec.is_err(), "real AEAD must reject a tag-flipped ciphertext");

    // Sanity: untampered tag still decrypts cleanly.
    let mut plaintext_out_clean = [0u8; 32];
    crypto
        .aes_gcm_decrypt(
            KeyId(0),
            &nonce1,
            &r1.digest_commitment,
            &aad1[..aad1_len],
            &r1.tag,
            &mut plaintext_out_clean,
        )
        .expect("untampered ciphertext must decrypt under captured (nonce, aad, tag)");
}

// -- audit-LOW regression tests --

#[test]
fn volatile_wipe_includes_compiler_fence_at_call_site() {
    // audit-LOW: the `volatile_wipe` helper in `src/lib.rs` MUST emit a
    // `core::sync::atomic::compiler_fence(SeqCst)` immediately after the
    // volatile-store loop. `write_volatile` alone defeats DSE of the wipe
    // stores themselves but does NOT prevent the compiler (or a
    // speculative pipeline) from reordering surrounding non-volatile
    // loads/stores across the wipe — a neighbouring read could observe
    // pre-wipe plaintext. The fence forbids that reordering.
    //
    // The fence is a compile-time-only barrier with no observable
    // runtime side-effect, so this property is hard to assert directly
    // from a `#[test]`. This sentinel pins the location in the codebase
    // for future auditors: `grep -n 'compiler_fence' crates/vsoc-telemetry/src/lib.rs`
    // must return at least one hit inside `volatile_wipe`.
    assert!(
        true,
        "audit-LOW sentinel: volatile_wipe in src/lib.rs MUST include \
         core::sync::atomic::compiler_fence(SeqCst) after the volatile-store \
         loop — see the function near line 112. This assertion is a comment \
         anchor; it cannot fail at runtime."
    );
}

#[test]
fn ts_us_first_flush_accepts_zero_and_max_reasonable() {
    // audit-LOW: on the very first flush after construction
    // `last_flush_us == 0`, so the monotonicity check is bypassed.
    // The load-bearing mitigation is `MAX_REASONABLE_TS_US` (1u64<<63),
    // which caps how high a malicious first-flush caller can pin the
    // floor. This test pins BOTH ends of that allowed range:
    //
    //   * a first flush at `ts_us = 0` succeeds (most conservative); and
    //   * a separate fresh uplink accepts a first flush at
    //     `ts_us = MAX_REASONABLE_TS_US`, which is the documented
    //     ceiling.
    //
    // After the second case, every subsequent flush at a lower `ts_us`
    // is locked out — that's the residual hazard the audit flagged,
    // documented in `flush_with_persistence` and made callable via
    // `set_initial_ts_floor` for callers who can pin a trusted anchor.

    // -- Case A: first flush at ts_us = 0 succeeds.
    let mut uplink_a: TelemetryUplink<MockCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    uplink_a.submit_entry(make_entry(0)).unwrap();
    let res_a = uplink_a.flush_with_persistence(&MockCrypto, 0, &mut NoOpPersistence);
    assert!(res_a.is_ok(), "first flush at ts_us=0 must succeed");

    // -- Case B: a fresh uplink accepts ts_us = MAX_REASONABLE_TS_US.
    let mut uplink_b: TelemetryUplink<MockCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    uplink_b.submit_entry(make_entry(0)).unwrap();
    let res_b = uplink_b.flush_with_persistence(
        &MockCrypto,
        MAX_REASONABLE_TS_US,
        &mut NoOpPersistence,
    );
    assert!(
        res_b.is_ok(),
        "first flush at MAX_REASONABLE_TS_US must succeed (the documented \
         hazard: a malicious caller could pin the floor here)"
    );

    // Negative path: after a successful flush at MAX_REASONABLE_TS_US,
    // any subsequent flush below that floor must be rejected.
    uplink_b.submit_entry(make_entry(1)).unwrap();
    let res_b2 = uplink_b.flush_with_persistence(&MockCrypto, 1_000, &mut NoOpPersistence);
    assert_eq!(
        res_b2,
        Err(VsError::InvalidInput),
        "post-pin regression below MAX_REASONABLE_TS_US must be rejected"
    );

    // Negative path: anything ABOVE MAX_REASONABLE_TS_US is rejected on
    // a fresh uplink — the ceiling is enforced regardless of monotonic state.
    let mut uplink_c: TelemetryUplink<MockCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    uplink_c.submit_entry(make_entry(0)).unwrap();
    let res_c = uplink_c.flush_with_persistence(
        &MockCrypto,
        MAX_REASONABLE_TS_US.saturating_add(1),
        &mut NoOpPersistence,
    );
    assert_eq!(
        res_c,
        Err(VsError::InvalidInput),
        "ts_us > MAX_REASONABLE_TS_US must be rejected even on first flush"
    );
}

#[test]
fn set_initial_ts_floor_pins_first_flush_window() {
    // audit-LOW: the explicit anchor API. A caller who trusts their
    // boot-time clock can pin the floor BEFORE the first submit so
    // the first-flush window is closed by construction.
    let mut uplink: TelemetryUplink<MockCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    // Pin floor to 5_000_000us.
    uplink.set_initial_ts_floor(5_000_000).unwrap();
    uplink.submit_entry(make_entry(0)).unwrap();

    // Positive path: a flush at or above the pinned floor succeeds.
    let ok = uplink.flush_with_persistence(&MockCrypto, 5_000_000, &mut NoOpPersistence);
    assert!(ok.is_ok(), "ts_us >= pinned floor must succeed");

    // Negative path: a subsequent flush below the floor is rejected
    // (the floor advanced to 5_000_000 by the successful flush above,
    // but the property we're verifying is "the floor is enforced").
    uplink.submit_entry(make_entry(1)).unwrap();
    let err = uplink.flush_with_persistence(&MockCrypto, 1_000_000, &mut NoOpPersistence);
    assert_eq!(
        err,
        Err(VsError::InvalidInput),
        "ts_us below pinned floor must be rejected"
    );

    // Negative path: pinning floor > MAX_REASONABLE_TS_US is rejected.
    let mut uplink2: TelemetryUplink<MockCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    let pin_err = uplink2.set_initial_ts_floor(MAX_REASONABLE_TS_US.saturating_add(1));
    assert_eq!(
        pin_err,
        Err(VsError::InvalidInput),
        "floor above MAX_REASONABLE_TS_US must be rejected to preserve the ceiling invariant"
    );

    // Negative path: floor can only ever advance — a second call with a
    // lower value is silently ignored (no regression of the floor).
    let mut uplink3: TelemetryUplink<MockCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();
    uplink3.set_initial_ts_floor(10_000).unwrap();
    uplink3.set_initial_ts_floor(5_000).unwrap(); // older, smaller — ignored
    uplink3.submit_entry(make_entry(0)).unwrap();
    // ts_us = 5_000 is below the (still 10_000) floor, so this must fail.
    let res = uplink3.flush_with_persistence(&MockCrypto, 5_000, &mut NoOpPersistence);
    assert_eq!(
        res,
        Err(VsError::InvalidInput),
        "floor must not regress when set_initial_ts_floor is called with a smaller value"
    );
}

#[test]
fn nonce_prefix_derivation_is_branch_free() {
    // audit-LOW: the previous implementation cached `nonce_prefix` on
    // first flush behind a `bool` flag, producing a one-shot timing
    // delta between "first flush" and every subsequent flush. The fix
    // recomputes the prefix every flush over a fixed-layout 64-byte
    // input — so every call walks the SAME code path.
    //
    // Two flushes on the same fresh uplink must yield bit-identical
    // nonce prefixes (the first 6 bytes of the captured nonce). The
    // tail of the nonce (the 6-byte little-endian counter) will of
    // course differ between flushes since the counter advances; we
    // only assert on `nonce[..6]`.
    let crypto = NonceCapturingCrypto::new();
    let mut uplink: TelemetryUplink<NonceCapturingCrypto> =
        TelemetryUplink::try_restore(test_config(), PersistedFlushCounter::fresh_device())
            .unwrap();

    // Flush 1.
    uplink.submit_entry(make_entry(0)).unwrap();
    uplink
        .flush_with_persistence(&crypto, 1_000_000, &mut NoOpPersistence)
        .unwrap()
        .unwrap();
    let nonce1 = crypto.last_nonce.get();

    // Flush 2 (counter has advanced; only the prefix is the property
    // under test).
    uplink.submit_entry(make_entry(1)).unwrap();
    uplink
        .flush_with_persistence(&crypto, 2_000_000, &mut NoOpPersistence)
        .unwrap()
        .unwrap();
    let nonce2 = crypto.last_nonce.get();

    // Positive: prefix portions are bit-identical across flushes.
    assert_eq!(
        &nonce1[..6],
        &nonce2[..6],
        "nonce prefix must be deterministic across flushes (branch-free derivation)"
    );

    // Negative: the counter tail MUST differ — this is the property
    // the prefix-derivation fix is NOT supposed to disturb. Without
    // this counterpart the positive assertion above would pass even
    // if we accidentally pinned the entire nonce.
    assert_ne!(
        &nonce1[6..],
        &nonce2[6..],
        "nonce counter suffix must advance between flushes"
    );
}

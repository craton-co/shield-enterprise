// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Integration coverage for audit-H2: end-to-end `CounterStorage` +
//! `AssertedExternallyRollbackResistant` round-trip from the public API
//! surface that downstream consumers actually see.
//!
//! The in-crate regression test inside `crates/vsoc-telemetry` covers
//! the audit-H2 limitation at `cfg(test)` privilege (it can reach
//! `PersistedFlushCounter::restore(u64)` without a feature flag).
//! This file re-runs the load / verify / tamper-detect contract through
//! the published API only — proving that a downstream caller can wire
//! a `CounterStorage` impl against the public surface without having
//! to reach for crate-private helpers.
//!
//! Verified against production (`git grep`):
//!   - `pub trait CounterStorage`         in `vsoc-telemetry/src/lib.rs:280`
//!   - `pub struct AssertedExternallyRollbackResistant`
//!                                        in `vsoc-telemetry/src/rollback.rs:49`
//!   - `pub fn restore_authenticated`     in `vsoc-telemetry/src/lib.rs:1240`
//!   - `pub fn restore_authenticated_from_storage`
//!                                        in `vsoc-telemetry/src/lib.rs:1285`
//!   - `pub fn to_blob`                   in `vsoc-telemetry/src/lib.rs:1109`

use core::cell::RefCell;

use vs_crypto::{CryptoProvider, KeyId, KeyType};
use vs_types::VsError;
use vs_vsoc_telemetry::{
    AssertedExternallyRollbackResistant, CounterStorage, PersistedFlushCounter,
    PERSIST_BLOB_LEN_V1,
};

// -----------------------------------------------------------------------
// Test crypto: a deterministic toy HMAC so the blob authenticates
// without dragging the `software` feature of `vs-crypto` into the
// dependency graph of this test. Mirrors the shape of
// `DeterministicHmacCrypto` in `crates/vsoc-telemetry/src/tests/mod.rs`
// but lives in this test crate so it does not depend on private items.
// -----------------------------------------------------------------------

struct ToyHmacCrypto;

impl CryptoProvider for ToyHmacCrypto {
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
        hash_out.fill(0xCD);
        Ok(())
    }
    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        // Same shape as `DeterministicHmacCrypto`: a position-and-data
        // varying XOR fold that is bound to `key_id` and is sensitive
        // to every input byte. Toy-grade but sufficient for the
        // round-trip and tamper tests below.
        for (i, slot) in mac_out.iter_mut().enumerate() {
            let mut acc = key_id.get() as u8 ^ (i as u8);
            for (k, b) in data.iter().enumerate() {
                acc ^= b ^ (k as u8);
            }
            *slot = acc;
        }
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

// -----------------------------------------------------------------------
// `CounterStorage` stub backed by a `RefCell<Option<[u8; PERSIST_BLOB_LEN_V1]>>`
// so `persist` can mutate the slot through `&mut self` and
// `load_authenticated` can read it through `&self`. Models the
// minimum durable-storage contract a real backend would satisfy.
// -----------------------------------------------------------------------

struct RefCellStorage {
    slot: RefCell<Option<[u8; PERSIST_BLOB_LEN_V1]>>,
}

impl RefCellStorage {
    fn with_blob(blob: [u8; PERSIST_BLOB_LEN_V1]) -> Self {
        Self {
            slot: RefCell::new(Some(blob)),
        }
    }
}

impl CounterStorage for RefCellStorage {
    fn load_authenticated<C: CryptoProvider>(
        &self,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<PersistedFlushCounter, VsError> {
        let borrowed = self.slot.borrow();
        let blob = borrowed.as_ref().ok_or(VsError::NotInitialized)?;
        PersistedFlushCounter::restore_authenticated(blob, crypto, mac_key_id)
    }

    fn persist(&mut self, _new_counter: u64) -> Result<(), VsError> {
        // The test fixture writes blobs directly into `slot` so the
        // load path is exercised in isolation. A real backend would
        // re-serialise via `to_blob` here; that path is exercised by
        // the in-crate `to_blob` round-trip tests, not this file.
        Ok(())
    }
}

// -----------------------------------------------------------------------
// Audit-H2 positive path: a freshly-persisted blob restores through
// the `AssertedExternallyRollbackResistant` wrapper and yields the
// same counter value.
// -----------------------------------------------------------------------

#[test]
fn restore_authenticated_round_trips_through_rollback_resistant_wrapper() {
    let crypto = ToyHmacCrypto;
    let mac_key = KeyId::new(7);

    // Construct a counter and serialise it through the public `to_blob`
    // path; the result is what a durable backend would commit.
    let pfc = PersistedFlushCounter::fresh_device();
    let blob = pfc
        .to_blob(&crypto, mac_key)
        .expect("fresh-device blob must serialise");

    // Wrap a backend holding that blob in
    // `AssertedExternallyRollbackResistant` — the only public way to
    // reach `restore_authenticated_from_storage` because the marker
    // trait `RollbackResistantStorage` is sealed.
    let storage = AssertedExternallyRollbackResistant(RefCellStorage::with_blob(blob));

    let restored =
        PersistedFlushCounter::restore_authenticated_from_storage(&storage, &crypto, mac_key)
            .expect("fresh blob must verify and restore");

    assert_eq!(restored.value(), pfc.value());
}

// -----------------------------------------------------------------------
// Audit-H2 negative path: a single-byte flip in the MAC tag must be
// rejected with `VsError::CryptoError`. The HMAC verifier is the
// trust boundary for tamper detection, so a bit-flip anywhere in the
// tag has to make the load fail closed.
// -----------------------------------------------------------------------

#[test]
fn restore_authenticated_rejects_tampered_blob_through_wrapper() {
    let crypto = ToyHmacCrypto;
    let mac_key = KeyId::new(7);

    let pfc = PersistedFlushCounter::fresh_device();
    let mut blob = pfc
        .to_blob(&crypto, mac_key)
        .expect("fresh-device blob must serialise");

    // Flip one bit in the tag region (bytes 8..40 in a V1 blob).
    blob[20] ^= 0x01;

    let storage = AssertedExternallyRollbackResistant(RefCellStorage::with_blob(blob));

    let result =
        PersistedFlushCounter::restore_authenticated_from_storage(&storage, &crypto, mac_key);
    assert_eq!(
        result,
        Err(VsError::CryptoError),
        "tampered blob must fail to verify under the HMAC tag check"
    );
}

// -----------------------------------------------------------------------
// Audit-H2 negative path #2: tampering the counter bytes (NOT the tag)
// also fails closed because the MAC covers the counter prefix.
// -----------------------------------------------------------------------

#[test]
fn restore_authenticated_rejects_counter_tamper_through_wrapper() {
    let crypto = ToyHmacCrypto;
    let mac_key = KeyId::new(7);

    let pfc = PersistedFlushCounter::fresh_device();
    let mut blob = pfc
        .to_blob(&crypto, mac_key)
        .expect("fresh-device blob must serialise");

    // Flip a counter byte (offset 0..8). The MAC is computed over the
    // counter bytes so any change there desyncs the tag.
    blob[3] ^= 0x80;

    let storage = AssertedExternallyRollbackResistant(RefCellStorage::with_blob(blob));

    let result =
        PersistedFlushCounter::restore_authenticated_from_storage(&storage, &crypto, mac_key);
    assert_eq!(
        result,
        Err(VsError::CryptoError),
        "counter-byte tamper must fail the MAC verify"
    );
}

// -----------------------------------------------------------------------
// Audit-H2 negative path #3: surfacing a backend load error. A
// `RefCellStorage` initialised without a blob returns `NotInitialized`
// from `load_authenticated`; `restore_authenticated_from_storage`
// must propagate that verbatim instead of remapping it to a
// generic crypto error.
// -----------------------------------------------------------------------

#[test]
fn restore_authenticated_propagates_storage_load_error() {
    let crypto = ToyHmacCrypto;
    let mac_key = KeyId::new(7);

    let storage = AssertedExternallyRollbackResistant(RefCellStorage {
        slot: RefCell::new(None),
    });

    let result =
        PersistedFlushCounter::restore_authenticated_from_storage(&storage, &crypto, mac_key);
    assert_eq!(
        result,
        Err(VsError::NotInitialized),
        "backend's NotInitialized must propagate verbatim, not be remapped"
    );
}

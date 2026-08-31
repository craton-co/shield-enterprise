// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.

//! Rollback-resistance markers for the counter-storage path (audit-H2).
//!
//! See [`crate::RollbackResistantStorage`] for the contract and
//! [`AssertedExternallyRollbackResistant`] for the one blessed
//! implementation this crate ships.

use crate::{sealed, CounterStorage, PersistedFlushCounter, RollbackResistantStorage};
use vs_crypto::{CryptoProvider, KeyId};
use vs_types::VsError;

/// Caller-asserted rollback-resistance wrapper.
///
/// Callers asserting they have wired the storage to a TPM NV
/// `TPMA_NV_WRITE_STCLEAR` index, an eFuse, RPMB, or equivalent.
/// Wrapping a plain filesystem in this type defeats audit-H2 and
/// re-introduces the rollback vulnerability — see crate-level docs.
///
/// # Usage
///
/// ```ignore
/// // `MyRpmbStorage` impls `CounterStorage` and is *physically* wired
/// // to an RPMB partition that the bootloader has locked. The wrapper
/// // tells the type system that the caller has audited the binding.
/// let storage = AssertedExternallyRollbackResistant(MyRpmbStorage::open()?);
/// let pfc = PersistedFlushCounter::restore_authenticated_from_storage(
///     &storage,
///     &crypto,
///     KeyId(7),
/// )?;
/// ```
///
/// # Safety note (not `unsafe` Rust, but unsafe in the audit sense)
///
/// `AssertedExternallyRollbackResistant` is a *no-op at runtime*: it
/// performs no cryptography of its own and trusts the caller's
/// hardware/firmware binding entirely. The only protection it provides
/// is making the assertion visible at the call site — every code
/// reviewer who sees `AssertedExternallyRollbackResistant(...)` must
/// chase down what guarantees the wrapped storage actually provides.
/// Wrapping a plain filesystem blob in this type compiles but
/// re-introduces audit-H2 in its entirety.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AssertedExternallyRollbackResistant<R>(pub R);

impl<R: CounterStorage> CounterStorage for AssertedExternallyRollbackResistant<R> {
    #[inline]
    fn load_authenticated<C: CryptoProvider>(
        &self,
        crypto: &C,
        mac_key_id: KeyId,
    ) -> Result<PersistedFlushCounter, VsError> {
        self.0.load_authenticated(crypto, mac_key_id)
    }

    #[inline]
    fn persist(&mut self, new_counter: u64) -> Result<(), VsError> {
        self.0.persist(new_counter)
    }
}

impl<R> sealed::Sealed for AssertedExternallyRollbackResistant<R> {}

impl<R> RollbackResistantStorage for AssertedExternallyRollbackResistant<R> {
    const STORAGE_KIND: &'static str = "caller-asserted";
}

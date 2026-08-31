// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! PKCS#11 function pointer table.
//!
//! Rather than declaring link-time `extern "C"` symbols (which would require
//! the PKCS#11 shared library at link time), this crate accepts a
//! [`Pkcs11FunctionList`] struct populated by the caller. The caller is
//! responsible for loading the library (e.g., via `dlopen`) and resolving
//! the function pointers before constructing a [`super::Pkcs11CryptoProvider`].
//!
//! This design:
//! - Keeps the crate `no_std` compatible (no `libdl` linkage).
//! - Allows runtime selection of HSM drivers without recompilation.
//! - Enables unit testing with pure-Rust mock implementations.

// Re-export types used in function pointer signatures so downstream crates
// (e.g., integration tests, mock setups) can name them without depending on
// the private `types` module.
pub use crate::types::{
    CkAttribute, CkBbool, CkByte, CkFlags, CkMechanism, CkObjectHandle, CkRv, CkSessionHandle,
    CkSlotId, CkTokenInfo, CkUlong, CkUserType,
};

/// Complete PKCS#11 function pointer table.
///
/// Equivalent to `CK_FUNCTION_LIST` from the PKCS#11 specification, but
/// holding only the subset used by [`super::Pkcs11CryptoProvider`].
///
/// # Invariants
///
/// All function pointer fields **must** point to valid, callable functions
/// before the table is passed to [`super::Pkcs11CryptoProvider::new`].
/// Passing a zero-initialized or partially populated table is undefined
/// behaviour — the caller is responsible for ensuring completeness.
///
/// # Layout
///
/// `#[repr(C)]` is required because callers may construct this table in C
/// code (e.g., a thin shim around `CK_FUNCTION_LIST`) and pass it across
/// the FFI boundary into Rust. A `#[repr(Rust)]` layout would give the
/// compiler licence to reorder fields, which would silently corrupt any
/// C-side initializer that relies on declaration order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Pkcs11FunctionList {
    // -----------------------------------------------------------------------
    // Session lifecycle
    // -----------------------------------------------------------------------
    /// `C_Initialize` — initialise the Cryptoki library.
    ///
    /// Pass `null` for `pInitArgs` to use the library defaults.
    pub c_initialize: unsafe extern "C" fn(p_init_args: *mut core::ffi::c_void) -> CkRv,

    /// `C_Finalize` — clean up library resources.
    ///
    /// Pass `null` for `pReserved`.
    pub c_finalize: unsafe extern "C" fn(p_reserved: *mut core::ffi::c_void) -> CkRv,

    /// `C_OpenSession` — open a session with the token in the given slot.
    pub c_open_session: unsafe extern "C" fn(
        slot_id: CkSlotId,
        flags: CkFlags,
        p_application: *mut core::ffi::c_void,
        notify: Option<
            unsafe extern "C" fn(
                h_session: CkSessionHandle,
                event: CkUlong,
                p_application: *mut core::ffi::c_void,
            ) -> CkRv,
        >,
        ph_session: *mut CkSessionHandle,
    ) -> CkRv,

    /// `C_CloseSession` — close the given session.
    pub c_close_session: unsafe extern "C" fn(h_session: CkSessionHandle) -> CkRv,

    /// `C_Logout` — log the user out of the token.
    ///
    /// Called best-effort on `Drop` before `c_close_session` so that the
    /// token clears any per-session authentication state. Errors are
    /// ignored on the teardown path.
    pub c_logout: unsafe extern "C" fn(h_session: CkSessionHandle) -> CkRv,

    /// `C_Login` — log the user into the token.
    pub c_login: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        user_type: CkUserType,
        p_pin: *const CkByte,
        ul_pin_len: CkUlong,
    ) -> CkRv,

    /// `C_GetTokenInfo` — retrieve token metadata (used in `self_test`).
    pub c_get_token_info: unsafe extern "C" fn(slot_id: CkSlotId, p_info: *mut CkTokenInfo) -> CkRv,

    // -----------------------------------------------------------------------
    // Object search (key discovery)
    // -----------------------------------------------------------------------
    /// `C_FindObjectsInit` — begin a search for token objects.
    pub c_find_objects_init: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_template: *const CkAttribute,
        ul_count: CkUlong,
    ) -> CkRv,

    /// `C_FindObjects` — retrieve handles for matching objects.
    pub c_find_objects: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        ph_object: *mut CkObjectHandle,
        ul_max_object_count: CkUlong,
        pul_object_count: *mut CkUlong,
    ) -> CkRv,

    /// `C_FindObjectsFinal` — terminate an object-search operation.
    pub c_find_objects_final: unsafe extern "C" fn(h_session: CkSessionHandle) -> CkRv,

    /// `C_GetAttributeValue` — read attributes from a token object.
    pub c_get_attribute_value: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        h_object: CkObjectHandle,
        p_template: *mut CkAttribute,
        ul_count: CkUlong,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // Symmetric encryption (AES-GCM)
    // -----------------------------------------------------------------------
    /// `C_EncryptInit` — initialise an encryption operation.
    pub c_encrypt_init: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_mechanism: *const CkMechanism,
        h_key: CkObjectHandle,
    ) -> CkRv,

    /// `C_Encrypt` — encrypt data in a single call.
    ///
    /// For AES-GCM, the PKCS#11 specification appends the authentication tag
    /// to the ciphertext. The caller must therefore pass a buffer of
    /// `plaintext_len + 16` bytes.
    pub c_encrypt: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_data: *const CkByte,
        ul_data_len: CkUlong,
        p_encrypted_data: *mut CkByte,
        pul_encrypted_data_len: *mut CkUlong,
    ) -> CkRv,

    /// `C_DecryptInit` — initialise a decryption operation.
    pub c_decrypt_init: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_mechanism: *const CkMechanism,
        h_key: CkObjectHandle,
    ) -> CkRv,

    /// `C_Decrypt` — decrypt data in a single call.
    ///
    /// For AES-GCM, the input is `ciphertext || tag` (tag appended).
    /// The output is plaintext only.
    pub c_decrypt: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_encrypted_data: *const CkByte,
        ul_encrypted_data_len: CkUlong,
        p_data: *mut CkByte,
        pul_data_len: *mut CkUlong,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // Digest (SHA-256)
    // -----------------------------------------------------------------------
    /// `C_DigestInit` — initialise a message digest operation.
    pub c_digest_init:
        unsafe extern "C" fn(h_session: CkSessionHandle, p_mechanism: *const CkMechanism) -> CkRv,

    /// `C_Digest` — digest data in a single call.
    pub c_digest: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_data: *const CkByte,
        ul_data_len: CkUlong,
        p_digest: *mut CkByte,
        pul_digest_len: *mut CkUlong,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // Sign (HMAC-SHA-256 + ECDSA)
    // -----------------------------------------------------------------------
    /// `C_SignInit` — initialise a sign operation.
    pub c_sign_init: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_mechanism: *const CkMechanism,
        h_key: CkObjectHandle,
    ) -> CkRv,

    /// `C_Sign` — sign data in a single call.
    pub c_sign: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_data: *const CkByte,
        ul_data_len: CkUlong,
        p_signature: *mut CkByte,
        pul_signature_len: *mut CkUlong,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // Verify (ECDSA)
    // -----------------------------------------------------------------------
    /// `C_VerifyInit` — initialise a verify operation.
    pub c_verify_init: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_mechanism: *const CkMechanism,
        h_key: CkObjectHandle,
    ) -> CkRv,

    /// `C_Verify` — verify a signature in a single call.
    pub c_verify: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_data: *const CkByte,
        ul_data_len: CkUlong,
        p_signature: *const CkByte,
        ul_signature_len: CkUlong,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // ECDH key derivation
    // -----------------------------------------------------------------------
    /// `C_DeriveKey` — derive a new key object from an existing key.
    ///
    /// Used with `CKM_ECDH1_DERIVE` to produce a transient AES key whose
    /// raw value is then extracted via `C_GetAttributeValue(CKA_VALUE)`.
    pub c_derive_key: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_mechanism: *const CkMechanism,
        h_base_key: CkObjectHandle,
        p_template: *const CkAttribute,
        ul_attribute_count: CkUlong,
        ph_key: *mut CkObjectHandle,
    ) -> CkRv,

    /// `C_DestroyObject` — destroy a token or session object.
    ///
    /// Used to clean up transient derived key objects created by
    /// `C_DeriveKey`.
    pub c_destroy_object:
        unsafe extern "C" fn(h_session: CkSessionHandle, h_object: CkObjectHandle) -> CkRv,

    // -----------------------------------------------------------------------
    // Random number generation
    // -----------------------------------------------------------------------
    /// `C_GenerateRandom` — generate random data from the token's TRNG.
    pub c_generate_random: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_random_data: *mut CkByte,
        ul_random_len: CkUlong,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // Public-key object import (for verify_p256 with raw pub key)
    // -----------------------------------------------------------------------
    /// `C_CreateObject` — create a new session or token object.
    ///
    /// Used to import a raw EC public key for `verify_p256`.
    pub c_create_object: unsafe extern "C" fn(
        h_session: CkSessionHandle,
        p_template: *const CkAttribute,
        ul_count: CkUlong,
        ph_object: *mut CkObjectHandle,
    ) -> CkRv,

    // -----------------------------------------------------------------------
    // Library-specific: token info
    // -----------------------------------------------------------------------
    /// Slot identifier that `c_open_session` was called with.
    ///
    /// Stored here so [`super::Pkcs11CryptoProvider`] can pass it to
    /// `C_GetTokenInfo` during `self_test` without a separate field.
    pub slot_id: CkSlotId,

    /// Indicates the library has already been initialised (e.g., by the
    /// caller before constructing the provider). When `true`,
    /// [`super::Pkcs11CryptoProvider::new`] skips `C_Initialize`.
    pub library_pre_initialized: CkBbool,
}

// Compile-time layout sanity checks for the FFI function table.
//
// These guard against accidentally producing a zero-sized table (which would
// indicate the struct was emptied by mistake) and against unbounded growth
// that would push the table out of the small fixed-size budget the
// no_std/no-heap architecture targets. 4 KiB is generous — the current table
// holds roughly two dozen function pointers plus two scalar fields, well
// under that ceiling on every supported target.
const _: () = {
    assert!(
        core::mem::size_of::<Pkcs11FunctionList>() > 0,
        "Pkcs11FunctionList must not be zero-sized",
    );
    assert!(
        core::mem::size_of::<Pkcs11FunctionList>() < 4096,
        "Pkcs11FunctionList exceeded 4 KiB layout budget",
    );
};

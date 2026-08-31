// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! PKCS#11 v2.40 / v3.0 C type aliases and constants.
#![allow(dead_code)] // Complete FFI type library; not every constant is used in this version.
//!
//! Only the subset required by `Pkcs11CryptoProvider` is defined here.
//! All names follow the PKCS#11 specification exactly (CamelCase structs,
//! `CK_` prefixed aliases) for easy cross-reference with the standard.

// ---------------------------------------------------------------------------
// Primitive type aliases
// ---------------------------------------------------------------------------

/// Unsigned machine word (PKCS#11 `CK_ULONG`).
///
/// PKCS#11 defines `CK_ULONG` as the platform C compiler's `unsigned long`.
/// On Windows x64 (LLP64) `unsigned long` is **4 bytes**, while on Linux/
/// macOS/QNX 64-bit (LP64) it is **8 bytes**. `usize` is NOT a safe alias —
/// it is always pointer-width and would be 8 bytes on Windows x64, causing
/// out-pointer writes from the token (4 bytes) to be read back as 8 bytes
/// with the upper 4 bytes uninitialized.
#[cfg(target_os = "windows")]
pub type CkUlong = u32;
#[cfg(not(target_os = "windows"))]
pub type CkUlong = u64;

// Compile-time guarantee that `CkUlong` matches the platform C ABI's
// `unsigned long` width. If this assertion ever fires, every out-pointer
// and length field exchanged with the PKCS#11 token is misaligned.
#[cfg(target_os = "windows")]
const _: () = assert!(core::mem::size_of::<CkUlong>() == 4);
#[cfg(not(target_os = "windows"))]
const _: () = assert!(core::mem::size_of::<CkUlong>() == 8);

/// Cryptoki return value (PKCS#11 `CK_RV`).
pub type CkRv = CkUlong;

/// Session handle (PKCS#11 `CK_SESSION_HANDLE`).
pub type CkSessionHandle = CkUlong;

/// Object handle (PKCS#11 `CK_OBJECT_HANDLE`).
pub type CkObjectHandle = CkUlong;

/// Slot identifier (PKCS#11 `CK_SLOT_ID`).
pub type CkSlotId = CkUlong;

/// Flags word (PKCS#11 `CK_FLAGS`).
pub type CkFlags = CkUlong;

/// User type (PKCS#11 `CK_USER_TYPE`).
pub type CkUserType = CkUlong;

/// Mechanism type (PKCS#11 `CK_MECHANISM_TYPE`).
pub type CkMechanismType = CkUlong;

/// Attribute type (PKCS#11 `CK_ATTRIBUTE_TYPE`).
pub type CkAttributeType = CkUlong;

/// Object class (PKCS#11 `CK_OBJECT_CLASS`).
pub type CkObjectClass = CkUlong;

/// Boolean (PKCS#11 `CK_BBOOL`): `CK_FALSE = 0`, `CK_TRUE = 1`.
pub type CkBbool = u8;

/// Single byte (PKCS#11 `CK_BYTE`).
pub type CkByte = u8;

// ---------------------------------------------------------------------------
// CK_RV return codes
// ---------------------------------------------------------------------------

pub const CKR_OK: CkRv = 0x0000_0000;
pub const CKR_CANCEL: CkRv = 0x0000_0001;
pub const CKR_HOST_MEMORY: CkRv = 0x0000_0002;
pub const CKR_SLOT_ID_INVALID: CkRv = 0x0000_0003;
pub const CKR_GENERAL_ERROR: CkRv = 0x0000_0005;
pub const CKR_FUNCTION_FAILED: CkRv = 0x0000_0006;
pub const CKR_ARGUMENTS_BAD: CkRv = 0x0000_0007;
pub const CKR_ATTRIBUTE_VALUE_INVALID: CkRv = 0x0000_0011;
pub const CKR_DATA_LEN_RANGE: CkRv = 0x0000_0021;
pub const CKR_ENCRYPTED_DATA_INVALID: CkRv = 0x0000_0040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: CkRv = 0x0000_0041;
pub const CKR_KEY_HANDLE_INVALID: CkRv = 0x0000_0060;
pub const CKR_KEY_SIZE_RANGE: CkRv = 0x0000_0062;
pub const CKR_KEY_TYPE_INCONSISTENT: CkRv = 0x0000_0063;
pub const CKR_MECHANISM_INVALID: CkRv = 0x0000_0070;
pub const CKR_MECHANISM_PARAM_INVALID: CkRv = 0x0000_0071;
pub const CKR_OBJECT_HANDLE_INVALID: CkRv = 0x0000_0082;
pub const CKR_OPERATION_ACTIVE: CkRv = 0x0000_0090;
pub const CKR_OPERATION_NOT_INITIALIZED: CkRv = 0x0000_0091;
pub const CKR_PIN_INCORRECT: CkRv = 0x0000_00A0;
pub const CKR_PIN_LOCKED: CkRv = 0x0000_00A4;
pub const CKR_SESSION_CLOSED: CkRv = 0x0000_00B0;
pub const CKR_SESSION_HANDLE_INVALID: CkRv = 0x0000_00B3;
pub const CKR_SIGNATURE_INVALID: CkRv = 0x0000_00C0;
pub const CKR_SIGNATURE_LEN_RANGE: CkRv = 0x0000_00C1;
pub const CKR_TOKEN_NOT_PRESENT: CkRv = 0x0000_00E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CkRv = 0x0000_00E1;
pub const CKR_USER_NOT_LOGGED_IN: CkRv = 0x0000_0101;
pub const CKR_USER_TYPE_INVALID: CkRv = 0x0000_0104;
pub const CKR_BUFFER_TOO_SMALL: CkRv = 0x0000_0150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CkRv = 0x0000_0190;

// ---------------------------------------------------------------------------
// CK_FLAGS values
// ---------------------------------------------------------------------------

/// Open a session (required for all sessions).
pub const CKF_SERIAL_SESSION: CkFlags = 0x0000_0004;

/// Open a read-write session (omit for read-only).
pub const CKF_RW_SESSION: CkFlags = 0x0000_0002;

// ---------------------------------------------------------------------------
// CK_USER_TYPE values
// ---------------------------------------------------------------------------

/// Security Officer login.
pub const CKU_SO: CkUserType = 0;

/// Normal user login.
pub const CKU_USER: CkUserType = 1;

// ---------------------------------------------------------------------------
// CK_MECHANISM_TYPE values used by this provider
// ---------------------------------------------------------------------------

/// AES-GCM authenticated encryption (PKCS#11 v2.40 §2.15).
pub const CKM_AES_GCM: CkMechanismType = 0x0000_1087;

/// SHA-256 message digest.
pub const CKM_SHA256: CkMechanismType = 0x0000_0250;

/// HMAC-SHA-256 message authentication.
pub const CKM_SHA256_HMAC: CkMechanismType = 0x0000_0251;

/// ECDSA signature (hash-then-sign; caller pre-hashes).
pub const CKM_ECDSA: CkMechanismType = 0x0000_1041;

/// ECDH key derivation with no cofactor (KDF = null, returns raw shared secret).
pub const CKM_ECDH1_DERIVE: CkMechanismType = 0x0000_1050;

// ---------------------------------------------------------------------------
// CK_ATTRIBUTE_TYPE values
// ---------------------------------------------------------------------------

pub const CKA_CLASS: CkAttributeType = 0x0000_0000;
pub const CKA_TOKEN: CkAttributeType = 0x0000_0001;
pub const CKA_LABEL: CkAttributeType = 0x0000_0003;
pub const CKA_VALUE: CkAttributeType = 0x0000_0011;
pub const CKA_VALUE_LEN: CkAttributeType = 0x0000_0161;
/// `CKA_VERIFY` — boolean: object may be used for signature verification.
pub const CKA_VERIFY: CkAttributeType = 0x0000_0108;
/// `CKA_EC_PARAMS` — DER-encoded named-curve OID.
pub const CKA_EC_PARAMS: CkAttributeType = 0x0000_0180;
/// `CKA_EC_POINT` — DER-encoded uncompressed EC public key octet string.
pub const CKA_EC_POINT: CkAttributeType = 0x0000_0181;

// ---------------------------------------------------------------------------
// CK_OBJECT_CLASS values
// ---------------------------------------------------------------------------

/// `CKO_PUBLIC_KEY` — public-key object class (PKCS#11 Table 6-3).
pub const CKO_PUBLIC_KEY: CkObjectClass = 0x0000_0002;
pub const CKO_SECRET_KEY: CkObjectClass = 0x0000_0003;
pub const CKO_PRIVATE_KEY: CkObjectClass = 0x0000_0004;

// ---------------------------------------------------------------------------
// Boolean
// ---------------------------------------------------------------------------

pub const CK_FALSE: CkBbool = 0;
pub const CK_TRUE: CkBbool = 1;

// ---------------------------------------------------------------------------
// C-layout structures
// ---------------------------------------------------------------------------

/// PKCS#11 `CK_MECHANISM` — identifies an algorithm and its parameters.
#[repr(C)]
pub struct CkMechanism {
    pub mechanism: CkMechanismType,
    pub p_parameter: *mut core::ffi::c_void,
    pub ul_parameter_len: CkUlong,
}

/// AES-GCM parameters (PKCS#11 v2.40 §2.15.3 `CK_GCM_PARAMS`).
#[repr(C)]
pub struct CkAesGcmParams {
    /// Pointer to the 12-byte IV.
    pub p_iv: *mut CkByte,
    /// IV length in bytes (must be 12 for GCM).
    pub ul_iv_len: CkUlong,
    /// IV length in bits (must be 96 for GCM).
    pub ul_iv_bits: CkUlong,
    /// Pointer to Additional Authenticated Data (may be null if ulAADLen == 0).
    pub p_aad: *mut CkByte,
    /// AAD length in bytes.
    pub ul_aad_len: CkUlong,
    /// Authentication tag length **in bits** (128 for 16-byte tag).
    pub ul_tag_bits: CkUlong,
}

/// PKCS#11 `CK_ATTRIBUTE` — one token-object attribute.
#[repr(C)]
pub struct CkAttribute {
    pub attribute_type: CkAttributeType,
    pub p_value: *mut core::ffi::c_void,
    pub ul_value_len: CkUlong,
}

/// ECDH1 derivation parameters (`CK_ECDH1_DERIVE_PARAMS`).
#[repr(C)]
pub struct CkEcdh1DeriveParams {
    /// Key-derivation function (0 = none, raw shared secret).
    pub kdf: CkUlong,
    /// Length of `pSharedData` in bytes (0 if unused).
    pub ul_shared_data_len: CkUlong,
    /// Shared data for KDF (null if unused).
    pub p_shared_data: *mut CkByte,
    /// Length of the peer's uncompressed EC public key in bytes (65 for P-256).
    pub ul_public_data_len: CkUlong,
    /// Pointer to the peer's uncompressed EC public key (0x04 || X || Y).
    pub p_public_data: *mut CkByte,
}

/// PKCS#11 `CK_TOKEN_INFO` — token metadata returned by `C_GetTokenInfo`.
#[repr(C)]
pub struct CkTokenInfo {
    pub label: [CkByte; 32],
    pub manufacturer_id: [CkByte; 32],
    pub model: [CkByte; 16],
    pub serial_number: [CkByte; 16],
    pub flags: CkFlags,
    pub ul_max_session_count: CkUlong,
    pub ul_session_count: CkUlong,
    pub ul_max_rw_session_count: CkUlong,
    pub ul_rw_session_count: CkUlong,
    pub ul_max_pin_len: CkUlong,
    pub ul_min_pin_len: CkUlong,
    pub ul_total_public_memory: CkUlong,
    pub ul_free_public_memory: CkUlong,
    pub ul_total_private_memory: CkUlong,
    pub ul_free_private_memory: CkUlong,
    pub hardware_version: CkVersion,
    pub firmware_version: CkVersion,
    pub utc_time: [CkByte; 16],
}

/// PKCS#11 `CK_VERSION`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CkVersion {
    pub major: u8,
    pub minor: u8,
}

/// Null object handle sentinel (PKCS#11 `CK_INVALID_HANDLE`).
pub const CK_INVALID_HANDLE: CkObjectHandle = 0;

// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! TPM 2.0 TSS2 ESAPI C type aliases and constants.
#![allow(dead_code)] // Complete FFI type library; not every constant is used in this version.
//!
//! Only the subset required by `TpmCryptoProvider` is defined here.
//! Names follow the TCG TSS 2.0 ESAPI specification exactly for easy
//! cross-reference with the standard (Part 4 of TCG TSS 2.0).

// ---------------------------------------------------------------------------
// Primitive type aliases
// ---------------------------------------------------------------------------

/// TSS2 return code (`TSS2_RC`).
pub type Tss2Rc = u32;

/// ESAPI object handle (`ESYS_TR`). Uses `u32` on all platforms.
pub type EsysTr = u32;

/// TPM2 algorithm identifier (`TPM2_ALG_ID`).
pub type Tpm2AlgId = u16;

/// TPM2 key bits (`TPMI_AES_KEY_BITS`, `TPMI_RSA_KEY_BITS`).
pub type Tpm2KeyBits = u16;

/// TPM2 session authorisation type.
pub type Tpm2Se = u8;

/// TPM2 handle (persistent, transient, NV — lower-level than `ESYS_TR`).
pub type Tpm2Handle = u32;

/// TPM2 capabilities selector (`TPM2_CAP`).
pub type Tpm2Cap = u32;

/// TPM2 properties selector (`TPM2_PT`).
pub type Tpm2Pt = u32;

// ---------------------------------------------------------------------------
// TSS2_RC values
// ---------------------------------------------------------------------------

/// Success.
pub const TSS2_RC_SUCCESS: Tss2Rc = 0x0000_0000;

/// Non-specific failure.
pub const TSS2_BASE_RC_GENERAL_FAILURE: Tss2Rc = 0x0000_0001;
/// Bad reference or null pointer.
pub const TSS2_BASE_RC_BAD_REFERENCE: Tss2Rc = 0x0000_0002;
/// Insufficient buffer size.
pub const TSS2_BASE_RC_INSUFFICIENT_BUFFER: Tss2Rc = 0x0000_0003;
/// Bad sequence of calls.
pub const TSS2_BASE_RC_BAD_SEQUENCE: Tss2Rc = 0x0000_0004;
/// No response from TPM.
pub const TSS2_BASE_RC_NO_CONNECTION: Tss2Rc = 0x0000_0005;
/// Memory allocation failed.
pub const TSS2_BASE_RC_MEMORY: Tss2Rc = 0x0000_0006;
/// Bad value supplied.
pub const TSS2_BASE_RC_BAD_VALUE: Tss2Rc = 0x0000_0007;
/// Not implemented.
pub const TSS2_BASE_RC_NOT_IMPLEMENTED: Tss2Rc = 0x0000_0008;
/// Bad context.
pub const TSS2_BASE_RC_BAD_CONTEXT: Tss2Rc = 0x0000_000B;
/// Bad (malformed or invalid) ABI version.
pub const TSS2_BASE_RC_ABI_MISMATCH: Tss2Rc = 0x0000_000C;
/// Bad key handle.
pub const TSS2_BASE_RC_BAD_TR: Tss2Rc = 0x0000_000D;
/// Multiple / invalid authorization failures.
pub const TSS2_BASE_RC_AUTHORIZATION_FAILED: Tss2Rc = 0x0000_0018;

/// Layer tag for ESAPI errors.
///
/// Per upstream `tpm2-tss` (`tss2_common.h`), each TSS2 stack layer
/// encodes its identifier in the **high byte** of `TSS2_RC` (layer 7 =
/// ESAPI ⇒ `0x0700_0000`). The base error code occupies the low 16
/// bits; the middle bits are reserved. Earlier revisions placed the
/// layer in bits 16–19 (`0x0007_0000`) and paired it with a mask of
/// `0x000F_0000`. That was internally consistent but rejected any real
/// `TSS2_RC` returned by a production `libtss2-esys.so`.
pub const TSS2_ESYS_RC_LAYER: Tss2Rc = 0x0700_0000;

/// ESAPI: bad reference.
pub const TSS2_ESYS_RC_BAD_REFERENCE: Tss2Rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_BAD_REFERENCE;
/// ESAPI: bad value.
pub const TSS2_ESYS_RC_BAD_VALUE: Tss2Rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_BAD_VALUE;
/// ESAPI: bad TR handle.
pub const TSS2_ESYS_RC_BAD_TR: Tss2Rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_BAD_TR;

// ---------------------------------------------------------------------------
// TPM2_ALG_ID algorithm constants
// ---------------------------------------------------------------------------

/// RSA.
pub const TPM2_ALG_RSA: Tpm2AlgId = 0x0001;
/// SHA-1 (deprecated; avoid for new designs).
pub const TPM2_ALG_SHA1: Tpm2AlgId = 0x0004;
/// HMAC construction.
pub const TPM2_ALG_HMAC: Tpm2AlgId = 0x0005;
/// AES symmetric cipher.
pub const TPM2_ALG_AES: Tpm2AlgId = 0x0006;
/// SHA-256 message digest.
pub const TPM2_ALG_SHA256: Tpm2AlgId = 0x000B;
/// ECDSA signature scheme.
pub const TPM2_ALG_ECDSA: Tpm2AlgId = 0x0018;
/// ECDH key agreement.
pub const TPM2_ALG_ECDH: Tpm2AlgId = 0x0019;
/// ECC (used in key templates).
pub const TPM2_ALG_ECC: Tpm2AlgId = 0x0023;
/// Null algorithm / no scheme.
pub const TPM2_ALG_NULL: Tpm2AlgId = 0x0010;
/// CFB (Cipher Feedback) symmetric mode.
pub const TPM2_ALG_CFB: Tpm2AlgId = 0x0043;
/// CTR (Counter) symmetric mode.
pub const TPM2_ALG_CTR: Tpm2AlgId = 0x0040;

// ---------------------------------------------------------------------------
// ECC curve identifiers (`TPM2_ECC_CURVE`)
// ---------------------------------------------------------------------------

/// NIST P-256 (secp256r1).
pub const TPM2_ECC_NIST_P256: u16 = 0x0003;

// ---------------------------------------------------------------------------
// TPM2_SE session type
// ---------------------------------------------------------------------------

/// HMAC (command-authorization) session.
pub const TPM2_SE_HMAC: Tpm2Se = 0x00;
/// Policy session.
pub const TPM2_SE_POLICY: Tpm2Se = 0x01;
/// Trial policy session.
pub const TPM2_SE_TRIAL: Tpm2Se = 0x03;

// ---------------------------------------------------------------------------
// Well-known ESYS_TR handles
// ---------------------------------------------------------------------------

/// No session (`ESYS_TR_NONE`).
pub const ESYS_TR_NONE: EsysTr = 0xFF00_0000;
/// Password authorization session (`ESYS_TR_PASSWORD`).
pub const ESYS_TR_PASSWORD: EsysTr = 0xFF00_0001;
/// PCR 0 handle (`ESYS_TR_PCR0`). PCR indices 0..23 are contiguous.
pub const ESYS_TR_PCR0: EsysTr = 0x0000_0000;
/// Owner / Storage Primary Seed hierarchy.
pub const ESYS_TR_RH_OWNER: EsysTr = 0x4000_0001;
/// Endorsement hierarchy.
pub const ESYS_TR_RH_ENDORSEMENT: EsysTr = 0x4000_000B;
/// Platform hierarchy.
pub const ESYS_TR_RH_PLATFORM: EsysTr = 0x4000_000C;
/// Null hierarchy.
pub const ESYS_TR_RH_NULL: EsysTr = 0x4000_0007;

// ---------------------------------------------------------------------------
// C-layout structures used by the ESAPI
// ---------------------------------------------------------------------------

/// Opaque ESAPI context type. Only used as `*mut EsysContext` via FFI.
#[repr(C)]
pub struct EsysContext {
    _opaque: [u8; 0],
}

/// Opaque TCTI context type.
#[repr(C)]
pub struct Tss2TctiContext {
    _opaque: [u8; 0],
}

/// `TPM2B_DIGEST` — a sized buffer holding a hash value (max 64 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Tpm2bDigest {
    pub size: u16,
    pub buffer: [u8; 64],
}

/// `TPM2B_DATA` — a generic sized buffer (max 64 bytes).
#[repr(C)]
pub struct Tpm2bData {
    pub size: u16,
    pub buffer: [u8; 64],
}

/// `TPM2B_MAX_BUFFER` — maximum TPM data buffer (2048 bytes).
#[repr(C)]
pub struct Tpm2bMaxBuffer {
    pub size: u16,
    pub buffer: [u8; 2048],
}

/// `TPM2B_ECC_PARAMETER` — single ECC coordinate (max 32 bytes for P-256).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Tpm2bEccParameter {
    pub size: u16,
    pub buffer: [u8; 32],
}

/// `TPMS_ECC_POINT` — (x, y) pair representing a point on an ECC curve.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

/// `TPM2B_ECC_POINT` — sized wrapper around `TPMS_ECC_POINT`.
#[repr(C)]
pub struct Tpm2bEccPoint {
    pub size: u16,
    pub point: TpmsEccPoint,
}

/// `TPMS_SIGNATURE_ECDSA` — raw (r, s) ECDSA signature.
#[repr(C)]
pub struct TpmsSignatureEcdsa {
    pub hash: Tpm2AlgId,
    pub signature_r: Tpm2bEccParameter,
    pub signature_s: Tpm2bEccParameter,
}

/// `TPMU_SIGNATURE` — union of all signature schemes per TCG TPM 2.0
/// Part 2 §11.3.3.
///
/// The union MUST be sized to the largest member — not just the one the
/// provider uses — because TSS2 can write any variant back through the
/// pointer we hand it (for example, on a policy / mechanism mismatch).
/// The largest member is `TPMS_SIGNATURE_RSASSA`, which wraps
/// `TPM2B_PUBLIC_KEY_RSA`:
///
/// ```text
///   hash:       TPMI_ALG_HASH         (u16)
///   sig:        TPM2B_PUBLIC_KEY_RSA  (u16 size + [u8; 256])
/// ```
///
/// ≈ 260 bytes. We round up to 288 for alignment headroom. A previous
/// revision used 72 bytes — sized only for ECDSA — which meant any non-
/// ECDSA response from the TPM could overwrite up to ~190 bytes of
/// caller stack. The `sig_alg` check in `verify_p256` and `sign_p256`
/// provides additional defence-in-depth but is not load-bearing anymore.
#[repr(C)]
pub union TpmuSignature {
    pub ecdsa: core::mem::ManuallyDrop<TpmsSignatureEcdsa>,
    pub _padding: [u8; 288],
}

// Compile-time size guard: if the ECDSA variant ever grows past the
// padding (e.g., via a curve-size change) the build fails loudly here.
const _: () = assert!(
    core::mem::size_of::<TpmsSignatureEcdsa>() <= 288,
    "TpmuSignature padding is smaller than the ECDSA variant"
);

/// `TPMT_SIGNATURE` — typed signature (algorithm + union).
#[repr(C)]
pub struct TpmtSignature {
    pub sig_alg: Tpm2AlgId,
    pub signature: TpmuSignature,
}

/// `TPMT_TK_VERIFIED` — verification ticket returned by `Esys_VerifySignature`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TpmtTkVerified {
    pub tag: u16,
    pub hierarchy: Tpm2Handle,
    pub digest: Tpm2bDigest,
}

/// `TPMT_TK_HASHCHECK` — ticket returned by `Esys_Hash`.
#[repr(C)]
pub struct TpmtTkHashcheck {
    pub tag: u16,
    pub hierarchy: Tpm2Handle,
    pub digest: Tpm2bDigest,
}

/// `TPMS_AUTH_COMMAND` — single command authorization.
#[repr(C)]
pub struct TpmsAuthCommand {
    pub session_handle: Tpm2Handle,
    pub nonce: Tpm2bDigest,
    pub session_attributes: u8,
    pub hmac: Tpm2bDigest,
}

/// `TPM2B_NONCE` — caller-supplied nonce passed to `Esys_StartAuthSession`.
///
/// Per TCG TPM 2.0 Part 2 §10.4.3 a `TPM2B_NONCE` is a wrapper around a
/// `TPM2B_DIGEST`; we re-use the existing 64-byte digest buffer for the
/// layout. ESAPI accepts `NULL` for an empty caller nonce, which is what
/// the bus-protection wiring uses (the TPM generates its own nonce).
pub type Tpm2bNonce = Tpm2bDigest;

/// `TPMT_SYM_DEF` — symmetric algorithm descriptor used when starting an
/// HMAC session that performs parameter encryption / decryption.
///
/// For an HMAC-integrity-only session (no parameter encryption), set
/// `algorithm = TPM2_ALG_NULL`. For an HMAC session with parameter
/// encryption use `TPM2_ALG_AES`, `key_bits = 128`, `mode = TPM2_ALG_CFB`
/// per TCG TPM 2.0 Part 1 §19.6.4 (the only mandatory combination every
/// conforming TPM must support).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtSymDef {
    pub algorithm: Tpm2AlgId,
    pub key_bits: u16,
    pub mode: Tpm2AlgId,
}

/// `TPMA_SESSION` — session-attribute bitfield (TCG TPM 2.0 Part 2 §8.4).
///
/// Carried as a single byte on the wire; defined here as a dedicated type
/// so the `Esys_TRSess_SetAttributes` FFI signature stays self-documenting
/// and so the bit constants below have a meaningful target type.
pub type TpmaSession = u8;

/// `TPMA_SESSION` attribute bits (TCG TPM 2.0 Part 2 §8.4).
///
/// Used by `Esys_TRSess_SetAttributes` after `Esys_StartAuthSession` so
/// the session persists across calls (`CONTINUE_SESSION`) and protects
/// inbound / outbound parameters (`DECRYPT` / `ENCRYPT`). Only the
/// subset required by the bus-protection wiring is defined here.
pub const TPMA_SESSION_CONTINUE_SESSION: TpmaSession = 1 << 0;
pub const TPMA_SESSION_DECRYPT: TpmaSession = 1 << 5;
pub const TPMA_SESSION_ENCRYPT: TpmaSession = 1 << 6;

/// PCR selection structure (`TPMS_PCR_SELECTION`).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TpmsPcrSelection {
    pub hash: Tpm2AlgId,
    pub sizeof_select: u8,
    pub pcr_select: [u8; 4],
}

/// `TPML_PCR_SELECTION` — list of PCR selections (we support one bank).
#[repr(C)]
pub struct TpmlPcrSelection {
    pub count: u32,
    pub pcr_selections: [TpmsPcrSelection; 16],
}

/// `TPML_DIGEST` — list of digests returned by `PCR_Read`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TpmlDigest {
    pub count: u32,
    pub digests: [Tpm2bDigest; 8],
}

/// `TPMI_YES_NO` — TPM Boolean.
pub type TpmiYesNo = u8;
pub const TPMI_YES: TpmiYesNo = 1;
pub const TPMI_NO: TpmiYesNo = 0;

/// `TPMA_OBJECT` attribute bits (TCG TPM 2.0 Part 2 §8.3). Minimal subset
/// required to construct a verify-only external public-key template.
pub const TPMA_OBJECT_SIGN: u32 = 1 << 18;
pub const TPMA_OBJECT_USERWITHAUTH: u32 = 1 << 6;
pub const TPMA_OBJECT_NO_DA: u32 = 1 << 10;

/// `TPMS_SCHEME_HASH` — a one-field scheme carrying just a hash algorithm.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsSchemeHash {
    pub hash_alg: Tpm2AlgId,
}

/// `TPMT_ECC_SCHEME` — ECC signature / key-agreement scheme plus details.
/// For `TPM2_ALG_NULL` the `details` field is still present but unused.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtEccScheme {
    pub scheme: Tpm2AlgId,
    pub details: TpmsSchemeHash,
}

/// `TPMT_KDF_SCHEME` — KDF algorithm selector.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtKdfScheme {
    pub scheme: Tpm2AlgId,
    pub details: TpmsSchemeHash,
}

/// `TPMT_SYM_DEF_OBJECT` — symmetric cipher descriptor inside a key object.
/// For an external ECC verify key this is `TPM2_ALG_NULL`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtSymDefObject {
    pub algorithm: Tpm2AlgId,
    pub key_bits: u16,
    pub mode: Tpm2AlgId,
}

/// `TPMS_ECC_PARMS` — ECC-specific parameters of a `TPMT_PUBLIC`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: u16,
    pub kdf: TpmtKdfScheme,
}

/// Padding to keep `TpmuPublicParms` the size of the largest TPMU member.
/// We only ever populate the ECC variant; other variants read as opaque
/// bytes. 512 bytes is a safe upper bound for TSS2 binary compatibility.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::pub_underscore_fields)]
pub union TpmuPublicParms {
    pub ecc_detail: TpmsEccParms,
    pub _padding: [u8; 512],
}

/// Padding to keep `TpmuPublicId` the size of the largest TPMU member.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::pub_underscore_fields)]
pub union TpmuPublicId {
    pub ecc: TpmsEccPoint,
    pub _padding: [u8; 512],
}

/// `TPMT_PUBLIC` — public-area template for `Esys_LoadExternal`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtPublic {
    pub object_type: Tpm2AlgId,
    pub name_alg: Tpm2AlgId,
    pub object_attributes: u32,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmuPublicParms,
    pub unique: TpmuPublicId,
}

/// `TPM2B_PUBLIC` — sized wrapper around `TpmtPublic`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tpm2bPublic {
    pub size: u16,
    pub public_area: TpmtPublic,
}

/// `TPM2B_SENSITIVE` — opaque sensitive-area container. `Esys_LoadExternal`
/// accepts `NULL` here to load only the public half, which is what we do
/// for verify-only external keys. Struct provided for type-level shape.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::pub_underscore_fields)]
pub struct Tpm2bSensitive {
    pub size: u16,
    pub _opaque: [u8; 256],
}

/// `TPML_DIGEST_VALUES` — list of tagged digests for PCR extend.
///
/// Simplified to a single SHA-256 digest entry, matching the common
/// Craton Shield use case (extend one PCR bank per call).
#[repr(C)]
pub struct TpmlDigestValues {
    /// Number of digest entries (always 1 for single-bank extend).
    pub count: u32,
    /// Hash algorithm for this entry (`TPM2_ALG_SHA256`).
    pub hash_alg: Tpm2AlgId,
    /// Padding to align `digest` to the next 4-byte boundary.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: u16,
    /// The 32-byte SHA-256 digest value.
    pub digest: [u8; 32],
}

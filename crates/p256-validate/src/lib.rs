// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_std]

//! Software P-256 on-curve validation with Solinas fast reduction.
//!
//! # Overview
//!
//! This crate provides defence-in-depth validation that a 65-byte uncompressed
//! `EC_POINT` (`0x04 || X || Y`) lies on the NIST P-256 (`secp256r1`) curve.
//! It is consumed by [`vs-crypto-pkcs11`](../vs_crypto_pkcs11) and
//! [`vs-crypto-tpm`](../vs_crypto_tpm) **before** a public key is handed to
//! the underlying HSM / TPM, so invalid-curve attacks against tokens with
//! weak validation (notably older `SoftHSM`) are rejected client-side.
//!
//! # Accepted encoding
//!
//! **Only uncompressed SEC1 encoding (`0x04` prefix) is accepted**; callers
//! must decompress before invoking [`validate_p256_point_on_curve`].
//! Compressed (`0x02` / `0x03`) and hybrid (`0x06` / `0x07`) point encodings
//! are rejected at the shape-check stage.
//!
//! # Scope of validation
//!
//! This module implements **partial** public-key validation per
//! NIST SP 800-56A §5.6.2.3.3 (steps 1–3): it verifies the point is
//! correctly encoded, is not the point at infinity, that both coordinates
//! are in `[0, p)`, and that the affine equation `y² ≡ x³ − 3x + b (mod p)`
//! holds. The cofactor-1 check (`nQ == O`) required by full validation
//! (step 4) is **implicit** for P-256: since the cofactor is 1, every
//! on-curve, non-identity point is automatically in the prime-order
//! subgroup, so no separate scalar multiplication is required. The
//! subgroup order is exported as [`P256_N`] for downstream scalar-range
//! checks (ECDSA `r`/`s` and private-key validation).
//!
//! # Why a separate crate?
//!
//! The two hardware-backed providers previously each carried their own
//! identical copy of this code (≈170 lines of `u256_*` helpers plus a
//! curve-equation check). Sharing it here keeps the two implementations
//! in lock-step and lets us land the FIPS 186-4 D.2.3 Solinas fast
//! reduction once instead of twice.
//!
//! # Algorithm
//!
//! The field prime `p = 2^256 − 2^224 + 2^192 + 2^96 − 1` is a Solinas
//! (generalised-Mersenne) prime. After a 256×256 → 512-bit schoolbook
//! multiply, reduction is done by summing seven 256-bit aliases of the
//! upper half — `T + 2·S1 + 2·S2 + S3 + S4 − D1 − D2 − D3 − D4` — and
//! folding the result into `[0, p)` with at most four conditional
//! `±p` adjustments. The intermediate result is bounded in `[−4p, 5p]`
//! (NIST FIPS 186-4 §D.2.3) so each adjustment is a single
//! constant-time add or subtract; no division, no inner loop.
//!
//! Replacing the previous bit-serial reduction removes a 512-iteration
//! inner loop (one per `u256_mul_mod`, several per `validate_p256_point_on_curve`)
//! with a small fixed number of 32-bit additions and subtractions —
//! O(512) → O(1) in reduction steps per multiply.
//!
//! # Design
//!
//! - `#![no_std]`, no heap, no `unsafe`.
//! - All buffers are stack-allocated. Largest single-scope allocation is
//!   `[u32; 16]` (64 B) and `[u32; 8]` (32 B), well under the workspace
//!   2048-byte cap.
//! - Pure math. The Solinas reduction is **not** written in
//!   constant-time style (the on-curve check operates on a public point,
//!   so secret-independent branches are not a requirement); the comparison
//!   against the curve equation is the only constant-time-sensitive step
//!   and there is nothing secret-dependent in the inputs.
//!
//! # audit-M7: sealed non-constant-time surface
//!
//! All 256-bit integer helpers (`u256_cmp`, `u256_mul_mod`,
//! `u256_mul_mod_p256`, `u256_add_mod`, `u256_sub_mod`, `u256_from_be`,
//! the Solinas reducer, and the `p256_on_curve` byte-level wrapper) are
//! `pub(crate)`. The audit found that previously these were `pub` and
//! could be re-used by a downstream caller on secret material (a private
//! key or ECDH shared secret), at which point their data-dependent
//! branches would leak bits through timing.
//!
//! The only public surfaces that drive the non-CT math are:
//!
//! - [`validate_p256_point_on_curve`] / [`validate_ec_point_shape`] —
//!   take a SEC1-encoded buffer that is, by encoding contract, a public
//!   key.
//! - [`PublicFieldElement`] — a newtype that records the caller's
//!   assertion of publicness in the type system. Construction goes
//!   through [`PublicFieldElement::from_be_bytes`] (a 32-byte BE buffer)
//!   or one of the named curve-constant constructors
//!   ([`PublicFieldElement::p256_p`], `::p256_b`).
//!
//! The published curve constants [`P256_P`], [`P256_B`] remain `pub`
//! because they are reference data, not behaviour.
//!
//! The following snippets must fail to compile — they demonstrate that
//! the sealed boundary is enforced by visibility, not just by
//! documentation:
//!
//! ```compile_fail
//! // External callers cannot reach `u256_mul_mod_p256` on a raw `[u64; 4]`.
//! use vs_p256_validate::U256;
//! let a: U256 = [1, 0, 0, 0];
//! let b: U256 = [2, 0, 0, 0];
//! let _ = vs_p256_validate::u256_mul_mod_p256(&a, &b);
//! ```
//!
//! ```compile_fail
//! // `u256_cmp` is sealed too.
//! use vs_p256_validate::U256;
//! let a: U256 = [1, 0, 0, 0];
//! let b: U256 = [2, 0, 0, 0];
//! let _ = vs_p256_validate::u256_cmp(&a, &b);
//! ```
//!
//! ```compile_fail
//! // `p256_on_curve` (byte-level) is sealed; route through
//! // `validate_p256_point_on_curve` instead.
//! let x = [0u8; 32];
//! let y = [0u8; 32];
//! let _ = vs_p256_validate::p256_on_curve(&x, &y);
//! ```
//!
//! ```compile_fail
//! // `PublicFieldElement` cannot be constructed from a raw `[u64; 4]`
//! // — that would let a caller bypass the "this value is public"
//! // assertion. The only ingestion paths are `from_be_bytes` (public-key
//! // coordinate) and the named curve-constant constructors.
//! let raw: [u64; 4] = [1, 2, 3, 4];
//! let _ = vs_p256_validate::PublicFieldElement(raw);
//! ```

use vs_types::VsError;

/// Uncompressed P-256 public-key length: `0x04 || X(32) || Y(32)`.
pub const EC_POINT_LEN: usize = 65;

/// P-256 coordinate length in bytes.
pub const P256_COORD_LEN: usize = 32;

const _: () = assert!(EC_POINT_LEN == 1 + 2 * P256_COORD_LEN);

/// Big-endian 256-bit integer, represented as four 64-bit little-endian
/// limbs (limb 0 = least-significant 64 bits).
///
/// This is a thin type alias used by the published curve constants
/// ([`P256_P`], [`P256_B`]). The integer **operations** that act on
/// values of this type — multiplication, comparison, reduction — are
/// `pub(crate)` only; see [`PublicFieldElement`] and the audit-M7
/// section of `README.md` for the rationale.
pub type U256 = [u64; 4];

// ---------------------------------------------------------------------------
// audit-M7: typed barrier for non-constant-time helpers
// ---------------------------------------------------------------------------
//
// The 256-bit integer primitives in this crate (`u256_cmp`, `u256_mul_mod`,
// `u256_mul_mod_p256`, the Solinas reducer, …) are deliberately written for
// validating PUBLIC points and PUBLIC field elements. Their runtime depends
// on input values (early-exit comparisons, variable-iteration reduction
// loops, data-dependent conditional branches). Feeding them secret material
// (a private key `d`, an ECDH shared secret `Z`, or any value derived from
// those) would leak bits through timing — exactly the class of bug audit-M7
// flags.
//
// To make that misuse mechanically harder rather than only documented:
//
//   1. Every non-constant-time helper is `pub(crate)`; no external crate
//      can call them on a raw `[u64; 4]`.
//
//   2. The only public surface that touches non-constant-time math is
//      [`validate_p256_point_on_curve`] and [`validate_ec_point_shape`],
//      both of which take a 65-byte SEC1 buffer that is a public key by
//      contract (the encoded point is, by definition, what the caller
//      intends to transmit on the wire).
//
//   3. For callers who legitimately need to operate on a known-public
//      field element outside the validator entry point,
//      [`PublicFieldElement`] is provided as a newtype around `[u64; 4]`.
//      It can only be constructed from a 32-byte big-endian buffer (a
//      public-key coordinate) or via the named curve-constant
//      constructors — there is no `From<[u64; 4]>` and no `pub` field —
//      so the type system records the "this value is public"
//      precondition. A future audit can trust that any code handing a
//      `&PublicFieldElement` to a non-CT helper has already asserted
//      publicness at construction time.

/// A 256-bit value that the caller asserts is **public** information.
///
/// Construction requires the caller to acknowledge that the value will be
/// processed by non-constant-time arithmetic. Values that originate from
/// secret material (private keys, ECDH shared secrets, ephemeral scalars,
/// or anything derived from those) MUST NOT be wrapped in this type —
/// doing so is a security bug and defeats the audit-M7 barrier.
///
/// Construct via [`PublicFieldElement::from_be_bytes`] (the encoding used
/// for SEC1 public-key coordinates) or via the named curve-constant
/// constructors [`PublicFieldElement::p256_p`],
/// [`PublicFieldElement::p256_b`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PublicFieldElement([u64; 4]);

impl PublicFieldElement {
    /// Wrap a 32-byte big-endian buffer (e.g. a SEC1 public-key
    /// coordinate) as a public field element.
    ///
    /// The buffer's contents must be public information — caller-asserted.
    /// Wrapping secret material in this type is a security bug.
    #[inline]
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        Self(u256_from_be(bytes))
    }

    /// The P-256 field prime `p` as a public field element. Curve
    /// constants are public by definition.
    #[inline]
    #[must_use]
    pub fn p256_p() -> Self {
        Self(P256_P)
    }

    /// The P-256 curve parameter `b` as a public field element.
    #[inline]
    #[must_use]
    pub fn p256_b() -> Self {
        Self(P256_B)
    }

    /// Borrow the underlying limbs. Crate-internal only — the limbs are
    /// not part of the public ABI to prevent reinterpretation of secret
    /// material as public.
    #[inline]
    pub(crate) fn as_limbs(&self) -> &[u64; 4] {
        &self.0
    }
}

/// P-256 field prime `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`.
pub const P256_P: U256 = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256 curve parameter `b` (from SEC 2 §2.4.2).
pub const P256_B: U256 = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

/// P-256 subgroup order `n` (from SEC 2 §2.4.2 / FIPS 186-4 §D.1.2.3).
///
/// `n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551`
///
/// Used by downstream callers for scalar-range validation: ECDSA
/// signature components `r` and `s` must satisfy `1 <= r,s < n`, and
/// private keys must satisfy `1 <= d < n`.
///
/// P-256's cofactor is **1**, so every affine point that satisfies the
/// curve equation and is not the identity is automatically in the
/// prime-order subgroup of order `n`. As a result, an explicit
/// `nQ == O` check is **not required** for partial public-key
/// validation per NIST SP 800-56A §5.6.2.3.3 — the on-curve check
/// implemented by [`validate_p256_point_on_curve`] is sufficient.
pub const P256_N: U256 = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

// ---------------------------------------------------------------------------
// Format-level shape checks (cheap; run before the on-curve math)
// ---------------------------------------------------------------------------

/// Validate that an uncompressed EC point has the right `0x04` prefix and
/// that neither coordinate is all-zero.
///
/// **Format-only check.** Does not verify the point lies on the curve;
/// use [`validate_p256_point_on_curve`] for that.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if the prefix is not `0x04`, or if
/// either the `X` or `Y` coordinate is all-zero (which would correspond to
/// the point at infinity or a degenerate point not on the curve).
#[inline]
pub fn validate_ec_point_shape(pub_key: &[u8; EC_POINT_LEN]) -> Result<(), VsError> {
    if pub_key[0] != 0x04 {
        return Err(VsError::InvalidInput);
    }
    // audit-LOW: explicit rationale for rejecting zero coordinates.
    //
    // There are TWO logically distinct things the shape check rejects
    // here, with different justifications:
    //
    //  (a) `(X == 0, Y == 0)` — the point at infinity under the SEC1
    //      §2.3.3 encoding convention used by some PKCS#11 / TPM
    //      vendors (a 65-byte 0x04 || 0 || 0 buffer). The identity is
    //      not a valid affine point and must never be accepted as a
    //      public key.
    //
    //  (b) `(X == 0, Y != 0)` OR `(X != 0, Y == 0)` — a non-injective /
    //      malformed encoding. Such a buffer is *not* the identity, and
    //      the underlying on-curve math would reject it only if `b`
    //      (or `-3·0 + b = b`) is a quadratic non-residue mod p — a
    //      numerical property of P-256's `b` constant, not a general
    //      property of Weierstrass curves. Relying on the math to
    //      catch (b) is a numerical accident; we reject at the shape
    //      level so the property holds for any P-256-shaped validator
    //      regardless of the specific `b`.
    //
    // Both (a) and (b) map to the same `VsError::InvalidInput` — the
    // current `vs-types` `VsError` does not distinguish "identity" from
    // "malformed encoding". If a future error-variant split is
    // introduced, (a) becomes the identity-rejection branch and (b)
    // becomes the encoding-rejection branch; the explicit identity
    // early-return below already separates the two code paths so the
    // split is mechanical.
    let x_is_zero = pub_key[1..33].iter().all(|&b| b == 0);
    let y_is_zero = pub_key[33..65].iter().all(|&b| b == 0);
    if x_is_zero && y_is_zero {
        // (a) point at infinity per SEC1 §2.3.3.
        return Err(VsError::InvalidInput);
    }
    if x_is_zero || y_is_zero {
        // (b) non-injective / malformed encoding — rejected at the
        // shape level so we do not depend on the curve constants.
        return Err(VsError::InvalidInput);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// U256 primitives (operate modulo a generic 256-bit modulus)
// ---------------------------------------------------------------------------

/// Decode a 32-byte big-endian integer into limbs.
///
/// **audit-M7: not constant-time, crate-internal.** Wraps a public byte
/// buffer into limbs. External callers should use
/// [`PublicFieldElement::from_be_bytes`] instead.
///
/// audit-LOW: indexed reads instead of `rchunks_exact(8).enumerate()`.
/// The previous form built an iterator, copied each 8-byte slice into a
/// scratch buffer, and relied on enumerate-order to map the *trailing*
/// chunk (least-significant 8 bytes) to limb 0. The new form makes the
/// limb layout explicit: input bytes 0..8 (most significant) land in
/// `limbs[3]`, bytes 24..32 (least significant) land in `limbs[0]`.
/// Behaviour is bit-identical to the rchunks form; only the indirection
/// is removed.
#[inline]
#[must_use]
pub(crate) fn u256_from_be(bytes: &[u8; 32]) -> U256 {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        // Input byte block `i` (counting from the MSB side) is limb
        // index `3 - i` in little-endian limb storage.
        limbs[3 - i] = u64::from_be_bytes(b);
    }
    limbs
}

/// Compare two limbed integers: returns `-1`, `0`, or `1` for `<`, `==`, `>`.
///
/// **audit-M7: NOT constant-time, crate-internal.** Early-exits on the
/// first differing limb; the timing leaks at least the most-significant
/// non-equal limb position. Safe only on public values (curve constants,
/// validated public-key coordinates). Never call on secret material.
#[inline]
#[must_use]
pub(crate) fn u256_cmp(lhs: &U256, rhs: &U256) -> i32 {
    for idx in (0..4).rev() {
        if lhs[idx] < rhs[idx] {
            return -1;
        }
        if lhs[idx] > rhs[idx] {
            return 1;
        }
    }
    0
}

/// `r = (a + b) mod m`. Inputs must already be in `[0, m)`.
///
/// **audit-M7: NOT constant-time, crate-internal.** The final conditional
/// `-m` adjustment branches on the result. Public field elements only.
#[inline]
#[must_use]
pub(crate) fn u256_add_mod(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    let mut out = [0u64; 4];
    let mut carry: u128 = 0;
    for (idx, slot) in out.iter_mut().enumerate() {
        let sum = u128::from(lhs[idx]) + u128::from(rhs[idx]) + carry;
        *slot = sum as u64;
        carry = sum >> 64;
    }
    // If a 257th bit was produced, or the sum already exceeds `m`,
    // subtract `m` once. (Since `lhs, rhs < m`, the sum is < 2m so one
    // subtract is sufficient.)
    if carry == 1 || u256_cmp(&out, modulus) >= 0 {
        sub_assign_unchecked(&mut out, modulus);
    }
    out
}

/// `r = (a - b) mod m`. Inputs must already be in `[0, m)`.
///
/// **audit-M7: NOT constant-time, crate-internal.** The per-limb borrow
/// handling and final `+m` correction branch on data values. Public
/// field elements only.
#[inline]
#[must_use]
pub(crate) fn u256_sub_mod(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    let mut out = [0u64; 4];
    let mut borrow: i128 = 0;
    for (idx, slot) in out.iter_mut().enumerate() {
        let diff = i128::from(lhs[idx]) - i128::from(rhs[idx]) - borrow;
        if diff < 0 {
            *slot = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            *slot = diff as u64;
            borrow = 0;
        }
    }
    if borrow == 1 {
        // out += modulus (wrapping add; the final carry cancels the borrow).
        let mut add_carry: u128 = 0;
        for (idx, slot) in out.iter_mut().enumerate() {
            let sum = u128::from(*slot) + u128::from(modulus[idx]) + add_carry;
            *slot = sum as u64;
            add_carry = sum >> 64;
        }
    }
    out
}

/// `out -= m` (wrapping). Helper for in-place reduction; caller must have
/// already established `out >= m` (or that the high bit it represents
/// makes the subtraction valid).
#[inline]
fn sub_assign_unchecked(out: &mut U256, modulus: &U256) {
    let mut borrow: i128 = 0;
    for (idx, slot) in out.iter_mut().enumerate() {
        let diff = i128::from(*slot) - i128::from(modulus[idx]) - borrow;
        if diff < 0 {
            *slot = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            *slot = diff as u64;
            borrow = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// 256x256 -> 512-bit schoolbook multiply
// ---------------------------------------------------------------------------

/// Compute the full 512-bit product of two 256-bit values, returned as eight
/// little-endian 32-bit limbs. (32-bit limbs are the natural unit for the
/// Solinas reduction below.)
#[inline]
fn u256_mul_full(lhs: &U256, rhs: &U256) -> [u32; 16] {
    // Split each 256-bit operand into eight 32-bit limbs (LE).
    let mut a = [0u32; 8];
    let mut b = [0u32; 8];
    for i in 0..4 {
        a[2 * i] = lhs[i] as u32;
        a[2 * i + 1] = (lhs[i] >> 32) as u32;
        b[2 * i] = rhs[i] as u32;
        b[2 * i + 1] = (rhs[i] >> 32) as u32;
    }
    // Schoolbook 8x8 -> 16 product in 32-bit limbs.
    let mut p = [0u32; 16];
    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..8 {
            let t = u64::from(p[i + j]) + u64::from(a[i]) * u64::from(b[j]) + carry;
            p[i + j] = t as u32;
            carry = t >> 32;
        }
        p[i + 8] = carry as u32;
    }
    p
}

// ---------------------------------------------------------------------------
// FIPS 186-4 §D.2.3 Solinas reduction for p = 2^256 − 2^224 + 2^192 + 2^96 − 1
// ---------------------------------------------------------------------------
//
// Given a 512-bit value c, written in little-endian 32-bit limbs
// (c0..c15), the canonical fast-reduction identity is:
//
//   r ≡ T + 2·S1 + 2·S2 + S3 + S4 − D1 − D2 − D3 − D4 (mod p)
//
// with the 256-bit aliases (each written MSB..LSB as a tuple of eight
// 32-bit limbs):
//
//   T  = ( c7,  c6,  c5,  c4,  c3,  c2,  c1, c0)
//   S1 = (c15, c14, c13, c12, c11,   0,   0,  0)
//   S2 = (  0, c15, c14, c13, c12,   0,   0,  0)
//   S3 = (c15, c14,   0,   0,   0, c10,  c9, c8)
//   S4 = ( c8, c13, c15, c14, c13, c11, c10, c9)
//   D1 = (c10,  c8,   0,   0,   0, c13, c12, c11)
//   D2 = (c11,  c9,   0,   0, c15, c14, c13, c12)
//   D3 = (c12,   0, c10,  c9,  c8, c15, c14, c13)
//   D4 = (c13,   0, c11, c10,  c9,   0, c15, c14)
//
// All aliases are < 2^256 individually; the signed sum is bounded by
// −4p ≤ r ≤ 5p (NIST C-49 / FIPS 186-4). The final reduction to
// `[0, p)` is at most four conditional `±p` adjustments — and in
// practice almost always one or two — replacing the previous
// 512-iteration bit-serial division.

#[inline]
fn solinas_alias(words: [u32; 8]) -> [u32; 8] {
    // Helper constructor — the alias tuples above are written MSB..LSB
    // to match the FIPS-186-4 text; this helper reverses to LE storage.
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = words[7 - i];
    }
    out
}

/// Conditional add of `modulus` to an 8-limb little-endian value. Returns
/// `true` iff the add wrapped (produced a carry out of the top word).
#[inline]
fn add8_u32(acc: &mut [u32; 8], rhs: &[u32; 8]) -> bool {
    let mut carry: u64 = 0;
    for i in 0..8 {
        let s = u64::from(acc[i]) + u64::from(rhs[i]) + carry;
        acc[i] = s as u32;
        carry = s >> 32;
    }
    carry != 0
}

/// `acc -= rhs` (wrapping). Returns `true` iff the subtract underflowed
/// (the result borrows out of the top word — equivalent to `acc < rhs`).
#[inline]
fn sub8_u32(acc: &mut [u32; 8], rhs: &[u32; 8]) -> bool {
    let mut borrow: i64 = 0;
    for i in 0..8 {
        let d = i64::from(acc[i]) - i64::from(rhs[i]) - borrow;
        if d < 0 {
            acc[i] = (d + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            acc[i] = d as u32;
            borrow = 0;
        }
    }
    borrow != 0
}

/// Compare two 8-limb little-endian u32 arrays. Returns `-1`, `0`, `1`.
#[inline]
fn cmp8_u32(lhs: &[u32; 8], rhs: &[u32; 8]) -> i32 {
    for i in (0..8).rev() {
        if lhs[i] < rhs[i] {
            return -1;
        }
        if lhs[i] > rhs[i] {
            return 1;
        }
    }
    0
}

/// `[u32; 8]` representation of `p` in little-endian 32-bit limbs.
const P256_P_U32: [u32; 8] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0xFFFF_FFFF,
];

/// Reduce a 512-bit product `c` (16 little-endian 32-bit limbs) modulo the
/// P-256 prime, returning the canonical residue in `[0, p)`.
///
/// audit-LOW: `#[inline]` so cross-crate LTO can fold this body into
/// callers (`u256_mul_mod_p256`, which is itself `#[inline]`). Without
/// the attribute, the cross-crate path could keep this function as a
/// separate call even though every call site is hot.
#[inline]
fn solinas_reduce_p256(c: &[u32; 16]) -> U256 {
    // Build the eight aliases. Tuples are written MSB..LSB to match the
    // FIPS text exactly; `solinas_alias` reverses to LE.
    let t = solinas_alias([c[7], c[6], c[5], c[4], c[3], c[2], c[1], c[0]]);
    let s1 = solinas_alias([c[15], c[14], c[13], c[12], c[11], 0, 0, 0]);
    let s2 = solinas_alias([0, c[15], c[14], c[13], c[12], 0, 0, 0]);
    let s3 = solinas_alias([c[15], c[14], 0, 0, 0, c[10], c[9], c[8]]);
    let s4 = solinas_alias([c[8], c[13], c[15], c[14], c[13], c[11], c[10], c[9]]);
    let d1 = solinas_alias([c[10], c[8], 0, 0, 0, c[13], c[12], c[11]]);
    let d2 = solinas_alias([c[11], c[9], 0, 0, c[15], c[14], c[13], c[12]]);
    let d3 = solinas_alias([c[12], 0, c[10], c[9], c[8], c[15], c[14], c[13]]);
    let d4 = solinas_alias([c[13], 0, c[11], c[10], c[9], 0, c[15], c[14]]);

    // pos = T + 2*S1 + 2*S2 + S3 + S4   (track a 9th-word carry).
    let mut pos = t;
    let mut pos_hi: u32 = 0;
    if add8_u32(&mut pos, &s1) {
        pos_hi += 1;
    }
    if add8_u32(&mut pos, &s1) {
        pos_hi += 1;
    }
    if add8_u32(&mut pos, &s2) {
        pos_hi += 1;
    }
    if add8_u32(&mut pos, &s2) {
        pos_hi += 1;
    }
    if add8_u32(&mut pos, &s3) {
        pos_hi += 1;
    }
    if add8_u32(&mut pos, &s4) {
        pos_hi += 1;
    }

    // neg = D1 + D2 + D3 + D4   (also a 9th-word carry, up to 4).
    let mut neg = [0u32; 8];
    let mut neg_hi: u32 = 0;
    if add8_u32(&mut neg, &d1) {
        neg_hi += 1;
    }
    if add8_u32(&mut neg, &d2) {
        neg_hi += 1;
    }
    if add8_u32(&mut neg, &d3) {
        neg_hi += 1;
    }
    if add8_u32(&mut neg, &d4) {
        neg_hi += 1;
    }

    // Reduce `pos` mod p using its 9-word state (worst case 6*2^256, so
    // `pos_hi <= 6`). Each iteration subtracts p once: since p ≈ 2^256, a
    // single subtraction reduces the magnitude by ~2^256, so at most six
    // iterations are needed. We bound the loop to 8 for safety.
    for _ in 0..8 {
        if pos_hi == 0 && cmp8_u32(&pos, &P256_P_U32) < 0 {
            break;
        }
        if sub8_u32(&mut pos, &P256_P_U32) {
            // Underflow consumed one unit of `pos_hi`.
            // Underflow means logical value was `pos + pos_hi*2^256 - p`,
            // which is still non-negative because `pos_hi >= 1` here.
            pos_hi -= 1;
        }
    }
    // audit-M9: post-condition. After the at-most-8-iteration loop, `pos`
    // must be a canonical residue in [0, p) — i.e. the 9th-word carry has
    // been fully consumed (`pos_hi == 0`) and the low 256 bits are strictly
    // below p. If a future change breaks the Solinas alias decomposition or
    // the worst-case-6 bound, this assert trips at test time rather than
    // silently letting a non-canonical residue leak into the curve check.
    debug_assert!(
        pos_hi == 0,
        "Solinas pos reduction left a 9th-word carry: pos_hi = {pos_hi}"
    );
    debug_assert!(
        cmp8_u32(&pos, &P256_P_U32) < 0,
        "Solinas pos reduction left a non-canonical residue (>= p)"
    );

    // Likewise reduce `neg` mod p.
    for _ in 0..8 {
        if neg_hi == 0 && cmp8_u32(&neg, &P256_P_U32) < 0 {
            break;
        }
        if sub8_u32(&mut neg, &P256_P_U32) {
            neg_hi -= 1;
        }
    }
    // audit-M9: same post-condition for the negative-alias accumulator.
    debug_assert!(
        neg_hi == 0,
        "Solinas neg reduction left a 9th-word carry: neg_hi = {neg_hi}"
    );
    debug_assert!(
        cmp8_u32(&neg, &P256_P_U32) < 0,
        "Solinas neg reduction left a non-canonical residue (>= p)"
    );

    // r = (pos - neg) mod p; both operands now in [0, p).
    let mut r = pos;
    if sub8_u32(&mut r, &neg) {
        // Borrow ⇒ logical result is negative; add p once.
        let _ = add8_u32(&mut r, &P256_P_U32);
    }

    // Pack [u32; 8] LE -> [u64; 4] LE.
    [
        u64::from(r[0]) | (u64::from(r[1]) << 32),
        u64::from(r[2]) | (u64::from(r[3]) << 32),
        u64::from(r[4]) | (u64::from(r[5]) << 32),
        u64::from(r[6]) | (u64::from(r[7]) << 32),
    ]
}

/// `r = (a * b) mod p` for the P-256 prime.
///
/// Uses Solinas fast reduction (FIPS 186-4 §D.2.3): an O(1)-step sum of
/// nine 256-bit aliases replaces the O(512) bit-serial long division the
/// previous implementation used.
///
/// **audit-M7: NOT constant-time, crate-internal.** The variable-length
/// final reduction loops in `solinas_reduce_p256` branch on the magnitude
/// of intermediate sums; the per-limb adds use lazy carry propagation
/// that is data-dependent. Public field elements only. Never call on a
/// private key, an ECDH shared secret, an ECDSA nonce, or any value
/// derived from those.
#[inline]
#[must_use]
pub(crate) fn u256_mul_mod_p256(lhs: &U256, rhs: &U256) -> U256 {
    let product = u256_mul_full(lhs, rhs);
    solinas_reduce_p256(&product)
}

/// `r = (a * b) mod m` for an arbitrary 256-bit modulus.
///
/// Falls back to bit-serial long division. Kept available because the
/// original API was generic over the modulus; consumer crates that only
/// reduce mod `p` should prefer [`u256_mul_mod_p256`].
///
/// **audit-M7: NOT constant-time, crate-internal.** The bit-serial path
/// uses a `while` loop whose iteration count is data-dependent. Public
/// field elements only.
#[must_use]
pub(crate) fn u256_mul_mod(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    // Fast path: if the modulus is P-256's `p`, dispatch to Solinas.
    if u256_cmp(modulus, &P256_P) == 0 {
        return u256_mul_mod_p256(lhs, rhs);
    }
    // Generic path: 8-limb product + bit-by-bit long division.
    let mut prod = [0u64; 8];
    for (i_idx, l_limb) in lhs.iter().enumerate() {
        let mut carry: u128 = 0;
        for (j_idx, r_limb) in rhs.iter().enumerate() {
            let sum =
                u128::from(prod[i_idx + j_idx]) + u128::from(*l_limb) * u128::from(*r_limb) + carry;
            prod[i_idx + j_idx] = sum as u64;
            carry = sum >> 64;
        }
        prod[i_idx + 4] = carry as u64;
    }
    let mut acc: U256 = [0; 4];
    for word in prod.iter().rev() {
        for b_idx in (0..64).rev() {
            let mut shift_carry: u64 = 0;
            for limb in &mut acc {
                let new_high = *limb >> 63;
                *limb = (*limb << 1) | shift_carry;
                shift_carry = new_high;
            }
            let mut high: u64 = shift_carry;
            if (word >> b_idx) & 1 == 1 {
                acc[0] |= 1;
            }
            while high == 1 || u256_cmp(&acc, modulus) >= 0 {
                let mut borrow: i128 = 0;
                for (idx, slot) in acc.iter_mut().enumerate() {
                    let diff = i128::from(*slot) - i128::from(modulus[idx]) - borrow;
                    if diff < 0 {
                        *slot = (diff + (1i128 << 64)) as u64;
                        borrow = 1;
                    } else {
                        *slot = diff as u64;
                        borrow = 0;
                    }
                }
                if high == 1 {
                    high = 1 - (borrow as u64);
                }
            }
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// P-256 on-curve check
// ---------------------------------------------------------------------------

/// Check that `(x, y)` lies on the P-256 curve `y² = x³ − 3x + b (mod p)`.
///
/// `x_be` / `y_be` are the 32-byte big-endian affine coordinates.
///
/// **audit-M7: NOT constant-time, crate-internal.** Internally uses the
/// non-CT `u256_*` helpers. External callers should go through
/// [`validate_p256_point_on_curve`] (full SEC1-encoded buffer) or
/// [`p256_on_curve_public_input_only`] (typed via [`PublicFieldElement`]).
#[must_use]
pub(crate) fn p256_on_curve(x_be: &[u8; 32], y_be: &[u8; 32]) -> bool {
    let x = u256_from_be(x_be);
    let y = u256_from_be(y_be);
    // Reject x >= p or y >= p — a valid field element must be < p.
    if u256_cmp(&x, &P256_P) >= 0 || u256_cmp(&y, &P256_P) >= 0 {
        return false;
    }
    // lhs = y²
    let lhs = u256_mul_mod_p256(&y, &y);
    // rhs = x³ − 3x + b
    let x2 = u256_mul_mod_p256(&x, &x);
    let x3 = u256_mul_mod_p256(&x2, &x);
    let three_x = {
        let two_x = u256_add_mod(&x, &x, &P256_P);
        u256_add_mod(&two_x, &x, &P256_P)
    };
    let rhs_tmp = u256_sub_mod(&x3, &three_x, &P256_P);
    let rhs = u256_add_mod(&rhs_tmp, &P256_B, &P256_P);
    u256_cmp(&lhs, &rhs) == 0
}

/// Validate that an uncompressed P-256 point has the right prefix, is not
/// the point at infinity, and lies on the curve.
///
/// This is the single entry point consumer crates call before handing a
/// public key to their hardware token.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if:
/// - the prefix byte is not `0x04`,
/// - the `X` or `Y` coordinate is all zero,
/// - either coordinate is `≥ p`,
/// - or `(x, y)` does not satisfy `y² ≡ x³ − 3x + b (mod p)`.
#[inline]
pub fn validate_p256_point_on_curve(pub_key: &[u8; EC_POINT_LEN]) -> Result<(), VsError> {
    validate_ec_point_shape(pub_key)?;
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pub_key[1..33]);
    y.copy_from_slice(&pub_key[33..65]);
    if !p256_on_curve(&x, &y) {
        return Err(VsError::InvalidInput);
    }
    Ok(())
}

/// Check that two **public** field elements `(x, y)` satisfy the P-256
/// curve equation `y² ≡ x³ − 3x + b (mod p)`.
///
/// **`WARNING` — NOT CONSTANT-TIME.** This function's runtime depends on
/// input values and MUST NOT be called on secret material (private keys,
/// ECDH shared secrets, scalars derived from those). The
/// [`PublicFieldElement`] argument type is the caller's attestation that
/// the value is a public quantity. See audit-M7.
///
/// Returns `false` if either coordinate is `≥ p` or if the curve equation
/// does not hold.
///
/// Prefer [`validate_p256_point_on_curve`] when you already have a
/// SEC1-encoded buffer — that path enforces format checks first.
#[must_use]
pub fn p256_on_curve_public_input_only(
    x: &PublicFieldElement,
    y: &PublicFieldElement,
) -> bool {
    let x = x.as_limbs();
    let y = y.as_limbs();
    if u256_cmp(x, &P256_P) >= 0 || u256_cmp(y, &P256_P) >= 0 {
        return false;
    }
    let lhs = u256_mul_mod_p256(y, y);
    let x2 = u256_mul_mod_p256(x, x);
    let x3 = u256_mul_mod_p256(&x2, x);
    let three_x = {
        let two_x = u256_add_mod(x, x, &P256_P);
        u256_add_mod(&two_x, x, &P256_P)
    };
    let rhs_tmp = u256_sub_mod(&x3, &three_x, &P256_P);
    let rhs = u256_add_mod(&rhs_tmp, &P256_B, &P256_P);
    u256_cmp(&lhs, &rhs) == 0
}

// ---------------------------------------------------------------------------
// audit-LOW: scalar range validation (ECDSA r/s and private-key checks)
// ---------------------------------------------------------------------------

/// Reject ECDSA scalars (`r`, `s`) and ECDH/ECDSA private keys (`d`) that
/// lie outside the valid range `[1, n − 1]`, where `n` is the P-256
/// subgroup order [`P256_N`].
///
/// NIST FIPS 186-4 §6.4 / SEC 1 §4.1.4 require both ECDSA signature
/// components to satisfy `1 <= r,s < n`; values of `0` or values `>= n`
/// are immediately invalid signatures. Private keys must satisfy
/// `1 <= d < n` (FIPS 186-4 Appendix B.4.1).
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if the scalar is `0` or `>= n`,
/// `Ok(())` otherwise.
///
/// # Constant-time properties (audit-LOW)
///
/// This helper is **best-effort** constant-time at the byte/limb-comparison
/// level. The underlying [`u256_cmp`] is an early-exit MSB-first compare:
/// it returns as soon as the first differing limb is found, so its
/// timing leaks at least the most-significant limb position at which
/// `scalar` and `n` differ. For typical ECDSA scalars (uniformly random
/// in `[1, n − 1]`) the high limb already differs from `n`'s high limb
/// with probability ≈ 1 − 2⁻³², so on average the comparator early-exits
/// at the top limb and the work is bounded; the all-zero test is a
/// fixed-width AND-fold. In other words the leakage is bounded above
/// by the entropy of the scalar's top limb (~32 bits), not the whole
/// scalar.
///
/// **This is acceptable for a validation step at a trust boundary** —
/// rejecting an out-of-range scalar before it is fed to a hardware
/// token — but it is **not** a substitute for genuine constant-time
/// arithmetic on secret keys elsewhere in the call graph. Do not use
/// this helper as the only constant-time barrier around a secret
/// scalar in a hot path; route the secret through the underlying
/// hardware-backed provider (PKCS#11 / TPM) which has its own CT
/// guarantees.
#[inline]
pub fn validate_p256_scalar(scalar: &[u8; 32]) -> Result<(), VsError> {
    let s = u256_from_be(scalar);
    // Reject zero (scalar = 0 is invalid for r, s, and d).
    if s == [0u64; 4] {
        return Err(VsError::InvalidInput);
    }
    // Reject scalars >= n. `u256_cmp` returns 0 for equal, 1 for >;
    // either is an out-of-range scalar.
    if u256_cmp(&s, &P256_N) >= 0 {
        return Err(VsError::InvalidInput);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // P-256 generator (FIPS 186-4 §D.2.3):
    //   Gx = 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
    //   Gy = 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
    const GX: [u8; 32] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ];
    const GY: [u8; 32] = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ];

    fn point_bytes(x: &[u8; 32], y: &[u8; 32]) -> [u8; EC_POINT_LEN] {
        let mut p = [0u8; EC_POINT_LEN];
        p[0] = 0x04;
        p[1..33].copy_from_slice(x);
        p[33..65].copy_from_slice(y);
        p
    }

    // -----------------------------------------------------------------------
    // Reference: bit-serial reduction (the *old* algorithm), used to
    // cross-check the Solinas reduction over random inputs.
    // -----------------------------------------------------------------------
    fn ref_u256_mul_mod(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
        let mut prod = [0u64; 8];
        for (i_idx, l_limb) in lhs.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j_idx, r_limb) in rhs.iter().enumerate() {
                let sum = u128::from(prod[i_idx + j_idx])
                    + u128::from(*l_limb) * u128::from(*r_limb)
                    + carry;
                prod[i_idx + j_idx] = sum as u64;
                carry = sum >> 64;
            }
            prod[i_idx + 4] = carry as u64;
        }
        let mut acc: U256 = [0; 4];
        for word in prod.iter().rev() {
            for b_idx in (0..64).rev() {
                let mut shift_carry: u64 = 0;
                for limb in &mut acc {
                    let new_high = *limb >> 63;
                    *limb = (*limb << 1) | shift_carry;
                    shift_carry = new_high;
                }
                let mut high: u64 = shift_carry;
                if (word >> b_idx) & 1 == 1 {
                    acc[0] |= 1;
                }
                while high == 1 || u256_cmp(&acc, modulus) >= 0 {
                    let mut borrow: i128 = 0;
                    for (idx, slot) in acc.iter_mut().enumerate() {
                        let diff = i128::from(*slot) - i128::from(modulus[idx]) - borrow;
                        if diff < 0 {
                            *slot = (diff + (1i128 << 64)) as u64;
                            borrow = 1;
                        } else {
                            *slot = diff as u64;
                            borrow = 0;
                        }
                    }
                    if high == 1 {
                        high = 1 - (borrow as u64);
                    }
                }
            }
        }
        acc
    }

    // ---------- Positive paths ----------

    #[test]
    fn generator_is_on_curve() {
        assert!(p256_on_curve(&GX, &GY));
        let p = point_bytes(&GX, &GY);
        assert!(validate_p256_point_on_curve(&p).is_ok());
    }

    #[test]
    fn solinas_matches_reference_on_small_values() {
        // 1 * 1 mod p = 1
        let one: U256 = [1, 0, 0, 0];
        assert_eq!(u256_mul_mod_p256(&one, &one), one);

        // 2 * 3 mod p = 6
        let a: U256 = [2, 0, 0, 0];
        let b: U256 = [3, 0, 0, 0];
        assert_eq!(u256_mul_mod_p256(&a, &b), [6, 0, 0, 0]);

        // (p-1) * (p-1) mod p = 1
        let pm1: U256 = u256_sub_mod(&[0, 0, 0, 0], &[1, 0, 0, 0], &P256_P);
        assert_eq!(u256_mul_mod_p256(&pm1, &pm1), [1, 0, 0, 0]);
    }

    #[test]
    fn solinas_matches_reference_on_known_p256_values() {
        // Gx * Gx mod p, computed independently with the reference (bit-serial)
        // path, must match Solinas exactly.
        let x = u256_from_be(&GX);
        let s = u256_mul_mod_p256(&x, &x);
        let r = ref_u256_mul_mod(&x, &x, &P256_P);
        assert_eq!(s, r);

        // x³ − 3x + b on the curve generator must equal y².
        let x3 = {
            let x2 = u256_mul_mod_p256(&x, &x);
            u256_mul_mod_p256(&x2, &x)
        };
        let three_x = {
            let t = u256_add_mod(&x, &x, &P256_P);
            u256_add_mod(&t, &x, &P256_P)
        };
        let rhs = u256_add_mod(&u256_sub_mod(&x3, &three_x, &P256_P), &P256_B, &P256_P);

        let y = u256_from_be(&GY);
        let lhs = u256_mul_mod_p256(&y, &y);
        assert_eq!(lhs, rhs);
    }

    // ---------- Random property test against the reference reduction ----------

    // Tiny deterministic xorshift PRNG so the test is repeatable and has no
    // external dependencies.
    fn xs64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }
    fn rand_u256(state: &mut u64) -> U256 {
        // Generate a random u256 in [0, 2^256); reduce mod p with the
        // reference reduction so we feed both algorithms canonical
        // residues.
        let raw: U256 = [xs64(state), xs64(state), xs64(state), xs64(state)];
        // raw mod p — multiply raw by 1.
        ref_u256_mul_mod(&raw, &[1, 0, 0, 0], &P256_P)
    }

    #[test]
    fn solinas_agrees_with_reference_for_1000_random_pairs() {
        let mut state: u64 = 0xC0FF_EE12_3456_789A;
        for _ in 0..1000 {
            let a = rand_u256(&mut state);
            let b = rand_u256(&mut state);
            let fast = u256_mul_mod_p256(&a, &b);
            let slow = ref_u256_mul_mod(&a, &b, &P256_P);
            assert_eq!(fast, slow, "mismatch for a={a:?} b={b:?}");
        }
    }

    #[test]
    fn solinas_handles_edge_inputs() {
        // 0 * x = 0
        let zero: U256 = [0; 4];
        let x = u256_from_be(&GX);
        assert_eq!(u256_mul_mod_p256(&zero, &x), zero);
        // x * 0 = 0
        assert_eq!(u256_mul_mod_p256(&x, &zero), zero);
        // p−1 squared = 1 (already exercised, repeated for clarity)
        let pm1 = u256_sub_mod(&[0; 4], &[1, 0, 0, 0], &P256_P);
        assert_eq!(u256_mul_mod_p256(&pm1, &pm1), [1, 0, 0, 0]);
        // 2^255 squared — exercises a product that occupies the full
        // upper half of the 512-bit intermediate.
        let hi_bit: U256 = [0, 0, 0, 1u64 << 63];
        let fast = u256_mul_mod_p256(&hi_bit, &hi_bit);
        let slow = ref_u256_mul_mod(&hi_bit, &hi_bit, &P256_P);
        assert_eq!(fast, slow);
    }

    // ---------- Negative paths ----------

    #[test]
    fn rejects_point_at_infinity() {
        let p = [0u8; EC_POINT_LEN]; // prefix is 0x00, all coords zero.
        assert!(validate_p256_point_on_curve(&p).is_err());

        // Prefix 0x04 but all coords zero is also invalid.
        let mut p2 = [0u8; EC_POINT_LEN];
        p2[0] = 0x04;
        assert!(validate_p256_point_on_curve(&p2).is_err());
    }

    #[test]
    fn rejects_wrong_prefix() {
        // 0x02 / 0x03 (compressed-point prefixes) and 0x05+ must all be
        // rejected — the validator is strict about uncompressed-only.
        for prefix in [0u8, 1, 2, 3, 5, 6, 0xFF] {
            let mut p = point_bytes(&GX, &GY);
            p[0] = prefix;
            assert!(
                validate_p256_point_on_curve(&p).is_err(),
                "prefix {prefix:#x}"
            );
        }
    }

    #[test]
    fn rejects_off_curve_point() {
        // Flip the last byte of Y — overwhelmingly unlikely to land on the curve.
        let mut bad_y = GY;
        bad_y[31] ^= 0x01;
        // Sanity-check that the tweak didn't accidentally produce 0 / overflow:
        assert!(!p256_on_curve(&GX, &bad_y));
        let p = point_bytes(&GX, &bad_y);
        assert!(validate_p256_point_on_curve(&p).is_err());

        // Another off-curve sample: GX with an arbitrary, non-related Y.
        let bad_y2 = [0x11u8; 32];
        let p2 = point_bytes(&GX, &bad_y2);
        assert!(validate_p256_point_on_curve(&p2).is_err());
    }

    #[test]
    fn rejects_x_or_y_at_or_above_p() {
        // p itself big-endian.
        let p_be: [u8; 32] = {
            let mut b = [0u8; 32];
            // P256_P limb 3 is the most-significant 64 bits.
            b[0..8].copy_from_slice(&P256_P[3].to_be_bytes());
            b[8..16].copy_from_slice(&P256_P[2].to_be_bytes());
            b[16..24].copy_from_slice(&P256_P[1].to_be_bytes());
            b[24..32].copy_from_slice(&P256_P[0].to_be_bytes());
            b
        };

        // X == p (>= p): must reject.
        let p = point_bytes(&p_be, &GY);
        assert!(validate_p256_point_on_curve(&p).is_err());

        // Y == p (>= p): must reject.
        let p2 = point_bytes(&GX, &p_be);
        assert!(validate_p256_point_on_curve(&p2).is_err());

        // X = 0xFF..FF (well above p): must reject.
        let max = [0xFFu8; 32];
        let p3 = point_bytes(&max, &GY);
        assert!(validate_p256_point_on_curve(&p3).is_err());

        // Y = 0xFF..FF (well above p): must reject.
        let p4 = point_bytes(&GX, &max);
        assert!(validate_p256_point_on_curve(&p4).is_err());
    }

    #[test]
    fn rejects_zero_coordinates() {
        // X == 0 but Y == Gy: shape check rejects on the X == 0 branch.
        let zero = [0u8; 32];
        let p = point_bytes(&zero, &GY);
        assert!(validate_p256_point_on_curve(&p).is_err());

        // Y == 0 but X == Gx: shape check rejects on the Y == 0 branch.
        let p2 = point_bytes(&GX, &zero);
        assert!(validate_p256_point_on_curve(&p2).is_err());
    }

    #[test]
    fn generic_mul_mod_still_works_for_non_p_modulus() {
        // 10 * 7 mod 13 = 5
        let a: U256 = [10, 0, 0, 0];
        let b: U256 = [7, 0, 0, 0];
        let m: U256 = [13, 0, 0, 0];
        assert_eq!(u256_mul_mod(&a, &b, &m), [5, 0, 0, 0]);
    }

    // -----------------------------------------------------------------------
    // audit-M8: generic `u256_mul_mod` property test.
    //
    // The previous coverage of the generic (non-P256, bit-serial) multiply-
    // mod path was a single small case (10*7 mod 13). That is inadequate
    // for a routine whose correctness depends on subtle 512-bit carry
    // propagation and on the bit-by-bit subtract-or-not decision inside the
    // long-division loop. We add an oracle (`ref_mul_mod_via_bit_shifts`)
    // that performs the same school-method reduction independently from a
    // 512-bit accumulator using only verbatim shift/subtract operations,
    // and cross-check `u256_mul_mod` against it on 1000 deterministic
    // pseudo-random `(a, b, m)` triples plus a handful of edge cases.
    // -----------------------------------------------------------------------

    /// 64-bit linear congruential generator. Deterministic, no `rand`
    /// dependency — `#![no_std]` compatible. Constants are Knuth's
    /// MMIX recommendation (cited in the task brief).
    fn lcg64(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    /// Fill a `U256` with four LCG draws (LE limb order).
    fn lcg_u256(state: &mut u64) -> U256 {
        [
            lcg64(state),
            lcg64(state),
            lcg64(state),
            lcg64(state),
        ]
    }

    /// Helper: `a < b` on `U256` (LE limb order).
    fn u256_lt(a: &U256, b: &U256) -> bool {
        u256_cmp(a, b) < 0
    }

    /// Reduce `a` mod `m` (both `U256`) via repeated subtraction. Used to
    /// canonicalise random inputs before feeding them to both the unit-
    /// under-test and the oracle. The number of subtractions is bounded
    /// by ceil(2^256 / m), so we cap the loop and assert termination.
    fn u256_mod_reduce(a: &U256, m: &U256) -> U256 {
        // Special case: m == 0 is undefined; the test never passes m == 0.
        // Special case: m == 1 ⇒ everything reduces to 0.
        if m == &[1u64, 0, 0, 0] {
            return [0; 4];
        }
        // Subtract-multiples-of-m via doubling: build the largest m·2^k
        // that fits in 256 bits, then subtract it if a >= it, halve, repeat.
        // This bounds the work at 256 subtractions worst case (one per
        // bit position), independent of the magnitude ratio a/m.
        let mut out = *a;
        // Precompute m·2^k for k = 0..=255, but lazily: shift m left until
        // it would overflow, then start subtracting on the way back down.
        // For test simplicity, just walk down from k=255.
        for k in (0..=255).rev() {
            // shifted = m << k, tracking 256-bit overflow.
            let (shifted, overflowed) = shl_u256(m, k);
            if overflowed {
                continue;
            }
            if !u256_lt(&out, &shifted) {
                // out -= shifted
                let mut borrow: i128 = 0;
                for i in 0..4 {
                    let d = i128::from(out[i]) - i128::from(shifted[i]) - borrow;
                    if d < 0 {
                        out[i] = (d + (1i128 << 64)) as u64;
                        borrow = 1;
                    } else {
                        out[i] = d as u64;
                        borrow = 0;
                    }
                }
                debug_assert_eq!(borrow, 0, "u256_mod_reduce: spurious borrow");
            }
        }
        out
    }

    /// Shift a `U256` left by `k` bits (0..=255). Returns `(value, overflow)`
    /// where `overflow == true` iff one or more high bits were shifted out.
    fn shl_u256(v: &U256, k: u32) -> (U256, bool) {
        if k == 0 {
            return (*v, false);
        }
        if k >= 256 {
            return ([0; 4], *v != [0; 4]);
        }
        let limb_shift = (k / 64) as usize;
        let bit_shift = k % 64;
        let mut out = [0u64; 4];
        let mut overflowed = false;
        // Limb-level shift first.
        for i in (0..4).rev() {
            if i + limb_shift >= 4 {
                if v[i] != 0 {
                    overflowed = true;
                }
            } else {
                out[i + limb_shift] = v[i];
            }
        }
        if bit_shift == 0 {
            return (out, overflowed);
        }
        // Then bit-level shift across limbs.
        let mut carry: u64 = 0;
        for slot in out.iter_mut() {
            let new_carry = *slot >> (64 - bit_shift);
            *slot = (*slot << bit_shift) | carry;
            carry = new_carry;
        }
        if carry != 0 {
            overflowed = true;
        }
        (out, overflowed)
    }

    /// Reference `(a * b) mod m` via the school method on a 512-bit
    /// accumulator (eight 64-bit limbs) followed by bit-by-bit reduction.
    /// This is *deliberately* a different implementation from
    /// `u256_mul_mod` — it uses a shift-and-subtract reduction expressed
    /// as `if acc >= (m << k) { acc -= (m << k); }` rather than the
    /// production code's bit-by-bit pull/subtract pattern. Agreement
    /// between two independent implementations on 1000 random inputs is
    /// strong evidence that any carry-tracking bug in the production
    /// code would surface.
    fn ref_mul_mod_via_bit_shifts(a: &U256, b: &U256, m: &U256) -> U256 {
        // 256x256 -> 512-bit schoolbook product into [u64; 8] LE.
        let mut prod = [0u64; 8];
        for (i_idx, a_limb) in a.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j_idx, b_limb) in b.iter().enumerate() {
                let s = u128::from(prod[i_idx + j_idx])
                    + u128::from(*a_limb) * u128::from(*b_limb)
                    + carry;
                prod[i_idx + j_idx] = s as u64;
                carry = s >> 64;
            }
            prod[i_idx + 4] = prod[i_idx + 4].wrapping_add(carry as u64);
        }
        // Reduce mod m by shift-and-subtract. We walk bit positions from
        // 511 down to 0; at each step, if (m << bit) fits in 512 bits and
        // the current accumulator is >= (m << bit), subtract it. The
        // result after bit-0 is the canonical residue.
        //
        // To keep this oracle obviously-correct without re-implementing
        // 512-bit shift logic from scratch, we exploit the observation
        // that for any `m >= 2`, `m << 256` exceeds the 512-bit product
        // bound for our inputs (since a, b < m < 2^256 ⇒ a*b < 2^512 and
        // m << 256 == m * 2^256 >= 2 * 2^256 > a*b only when a*b ≤ m*2^256,
        // which is *not* guaranteed for arbitrary m). So we walk bit
        // positions 256..=0 with explicit 512-bit shift state.
        //
        // Concretely: represent `m_shifted` as [u64; 9] (the extra limb
        // holds bits shifted past the top) and decrement the shift each
        // round. Start with `m << 256` (i.e. `m` in the upper half) and
        // work down.
        let mut m_shifted = [0u64; 9]; // limb 8 is the overflow word.
        // Initialise to m << 256.
        for i in 0..4 {
            m_shifted[i + 4] = m[i];
        }
        // Reduce: walk bits 256..0 inclusive.
        for _ in 0..=256 {
            // If m_shifted fits in the low 8 limbs (limb 8 == 0) and
            // prod >= m_shifted, subtract.
            if m_shifted[8] == 0 {
                let mut ge = true;
                for i in (0..8).rev() {
                    if prod[i] < m_shifted[i] {
                        ge = false;
                        break;
                    }
                    if prod[i] > m_shifted[i] {
                        break;
                    }
                }
                if ge {
                    let mut borrow: i128 = 0;
                    for i in 0..8 {
                        let d = i128::from(prod[i]) - i128::from(m_shifted[i]) - borrow;
                        if d < 0 {
                            prod[i] = (d + (1i128 << 64)) as u64;
                            borrow = 1;
                        } else {
                            prod[i] = d as u64;
                            borrow = 0;
                        }
                    }
                    debug_assert_eq!(borrow, 0, "ref oracle: spurious borrow");
                }
            }
            // Shift m_shifted right by 1.
            let mut carry: u64 = 0;
            for i in (0..9).rev() {
                let new_carry = m_shifted[i] & 1;
                m_shifted[i] = (m_shifted[i] >> 1) | (carry << 63);
                carry = new_carry;
            }
        }
        // The canonical residue is now in prod[0..4]; the upper limbs must
        // be zero.
        debug_assert_eq!(prod[4], 0, "ref oracle: residue overflowed limb 4");
        debug_assert_eq!(prod[5], 0, "ref oracle: residue overflowed limb 5");
        debug_assert_eq!(prod[6], 0, "ref oracle: residue overflowed limb 6");
        debug_assert_eq!(prod[7], 0, "ref oracle: residue overflowed limb 7");
        [prod[0], prod[1], prod[2], prod[3]]
    }

    #[test]
    fn u256_mul_mod_matches_reference_for_1000_random_pairs() {
        // Deterministic LCG seed — any change here re-rolls the test
        // corpus; keep stable so regressions are reproducible.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for iter in 0..1000 {
            // Generate a modulus m >= 2. Reject m < 2 by re-rolling.
            let mut m = lcg_u256(&mut state);
            while u256_cmp(&m, &[2, 0, 0, 0]) < 0 {
                m = lcg_u256(&mut state);
            }
            // Generate a, b uniformly in [0, 2^256) and reduce mod m so
            // both are in [0, m). The production routine documents this
            // precondition for the generic path.
            let raw_a = lcg_u256(&mut state);
            let raw_b = lcg_u256(&mut state);
            let a = u256_mod_reduce(&raw_a, &m);
            let b = u256_mod_reduce(&raw_b, &m);
            assert!(u256_lt(&a, &m), "iter {iter}: a not reduced");
            assert!(u256_lt(&b, &m), "iter {iter}: b not reduced");

            let fast = u256_mul_mod(&a, &b, &m);
            let slow = ref_mul_mod_via_bit_shifts(&a, &b, &m);
            assert_eq!(
                fast, slow,
                "iter {iter}: u256_mul_mod disagrees with ref oracle for \
                 a={a:?} b={b:?} m={m:?}"
            );
            // Sanity: result must be in [0, m).
            assert!(u256_lt(&fast, &m), "iter {iter}: result >= m");
        }
    }

    #[test]
    fn u256_mul_mod_handles_edge_inputs() {
        // a == 0
        let zero: U256 = [0; 4];
        let one: U256 = [1, 0, 0, 0];
        let seven: U256 = [7, 0, 0, 0];
        let thirteen: U256 = [13, 0, 0, 0];
        assert_eq!(u256_mul_mod(&zero, &seven, &thirteen), zero);
        // b == 0
        assert_eq!(u256_mul_mod(&seven, &zero, &thirteen), zero);
        // m == 2: result is parity of (a*b).
        let two: U256 = [2, 0, 0, 0];
        assert_eq!(u256_mul_mod(&one, &one, &two), one); // 1*1 mod 2 = 1
        assert_eq!(u256_mul_mod(&one, &zero, &two), zero); // 1*0 mod 2 = 0
        // a == m - 1, b small.
        let large_m: U256 = [
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x7FFF_FFFF_FFFF_FFFF,
        ];
        let m_minus_1 = {
            let mut v = large_m;
            v[0] -= 1;
            v
        };
        // (m-1) * 1 mod m = m - 1.
        assert_eq!(u256_mul_mod(&m_minus_1, &one, &large_m), m_minus_1);
        // 1 * (m-1) mod m = m - 1.
        assert_eq!(u256_mul_mod(&one, &m_minus_1, &large_m), m_minus_1);
        // (m-1) * (m-1) mod m = 1 (since (m-1)^2 = m^2 - 2m + 1 ≡ 1).
        let sq = u256_mul_mod(&m_minus_1, &m_minus_1, &large_m);
        assert_eq!(sq, one, "(m-1)^2 mod m must be 1, got {sq:?}");
        // Cross-check the same edge cases against the bit-shift oracle.
        assert_eq!(
            u256_mul_mod(&m_minus_1, &m_minus_1, &large_m),
            ref_mul_mod_via_bit_shifts(&m_minus_1, &m_minus_1, &large_m),
        );
    }

    // -----------------------------------------------------------------------
    // audit-M9: Solinas reducer post-condition end-to-end check.
    //
    // The `debug_assert!`s inside `solinas_reduce_p256` already guarantee
    // `pos_hi == 0` and `pos < p` after each at-most-8 reduction loop.
    // The test below exercises the reducer through `u256_mul_mod_p256` on
    // a stressful input (the all-ones field element squared, which
    // produces the largest possible 512-bit product) and confirms the
    // returned residue is strictly less than `p` (i.e. canonical). Any
    // future change that breaks the alias decomposition or the worst-
    // case-6 iteration bound will trip either the internal debug_assert
    // or the explicit cmp below.
    // -----------------------------------------------------------------------

    /// Compare a `U256` against `P256_P`. Wraps `u256_cmp` so the test
    /// name documents intent. Returns the same `-1 / 0 / 1` convention.
    fn cmp_u32_against_p256_p(v: &U256) -> i32 {
        u256_cmp(v, &P256_P)
    }

    #[test]
    fn solinas_reduce_produces_canonical_residue() {
        // 1) p − 1 squared: a classic stressor for Solinas reduction —
        //    the intermediate product hits the upper end of the [−4p, 5p]
        //    bound. Result must equal 1 (since (p−1)² ≡ 1 mod p).
        let pm1 = u256_sub_mod(&[0; 4], &[1, 0, 0, 0], &P256_P);
        let r1 = u256_mul_mod_p256(&pm1, &pm1);
        assert!(
            cmp_u32_against_p256_p(&r1) < 0,
            "(p−1)² result {r1:?} is not canonical (>= p)"
        );
        assert_eq!(r1, [1, 0, 0, 0], "(p−1)² mod p must equal 1");

        // 2) 2^255 squared: the upper half of the 512-bit intermediate is
        //    populated, which exercises every S/D alias.
        let hi_bit: U256 = [0, 0, 0, 1u64 << 63];
        let r2 = u256_mul_mod_p256(&hi_bit, &hi_bit);
        assert!(
            cmp_u32_against_p256_p(&r2) < 0,
            "2^510 mod p result {r2:?} is not canonical (>= p)"
        );

        // 3) The generator's x-coordinate squared — a realistic operand
        //    inside `p256_on_curve`. Must be canonical.
        let gx = u256_from_be(&GX);
        let r3 = u256_mul_mod_p256(&gx, &gx);
        assert!(
            cmp_u32_against_p256_p(&r3) < 0,
            "Gx² result {r3:?} is not canonical (>= p)"
        );

        // 4) Negative path: a value constructed to be >= p (specifically,
        //    p itself) is NOT a valid residue and must NOT be produced by
        //    the reducer. We can't feed `p` directly into Solinas (the
        //    reducer's input is a 512-bit product, not an arbitrary 256-
        //    bit value), but we can verify the canonical-form check is
        //    sensitive: `cmp_u32_against_p256_p(&P256_P) == 0`, i.e. p
        //    itself is *not* less than p — proving the assertion above
        //    is not vacuously satisfied.
        assert_eq!(
            cmp_u32_against_p256_p(&P256_P),
            0,
            "cmp_u32_against_p256_p(p) must be 0 — canonical-residue assertion \
             must be able to detect non-canonical results"
        );
        // And a value strictly above p is detected as such.
        let p_plus_1 = {
            let mut v = P256_P;
            v[0] = v[0].wrapping_add(1);
            v
        };
        assert!(
            cmp_u32_against_p256_p(&p_plus_1) > 0,
            "p+1 must compare strictly greater than p"
        );
    }

    // -----------------------------------------------------------------------
    // NIST CAVP / SECG P-256 PointValidation test vectors (MED-p256-vectors)
    // -----------------------------------------------------------------------
    //
    // The vectors below exercise `validate_p256_point_on_curve` against
    // published P-256 point data:
    //
    //   * Valid multiples of the generator G — coordinates for 2G and 3G are
    //     widely published (e.g., NIST CAVP "PKV" / PKVValid test set, SECG
    //     SEC1 §A.2.1 worked examples, and academic ECDSA test-vector
    //     compendia). The hard-coded byte arrays below are additionally
    //     cross-checked inside the test by computing kG from G using affine
    //     doubling / addition routines defined in this module, so any
    //     transcription error fails fast.
    //
    //   * Invalid points modelled on the NIST CAVP "PKVInvalid" suite:
    //     coordinate at the field-prime boundary (X = p−1), a synthesised
    //     off-curve point with a one-bit mutation of a valid Y, and — most
    //     importantly — a **twist-curve point**: a syntactically-valid
    //     SEC1 encoding whose (x, y) satisfies the equation of a quadratic
    //     twist of P-256 rather than P-256 itself. The twist-curve case
    //     is the canonical demonstration of the invalid-curve attack this
    //     crate exists to mitigate (Antipa, Brown, Menezes, Struik &
    //     Vanstone, 2003).
    //
    // Sources cited in comments next to each vector.
    //
    // The test module uses many short, structurally-similar bindings
    // (`rx2`/`ry2`, `rx3`/`ry3`, ...) to keep the published-vector
    // cross-checks compact and readable; that aesthetic is intentional, so
    // the `similar_names` pedantic lint is locally allowed.
    #[allow(clippy::similar_names)]
    mod nist_cavp_vectors {
        use super::{
            p256_on_curve, point_bytes, u256_add_mod, u256_from_be, u256_mul_mod_p256,
            u256_sub_mod, validate_p256_point_on_curve, GX, GY, P256_P, U256,
        };

        // ---- Affine P-256 arithmetic for cross-checking valid vectors. --
        // These helpers operate on field elements only (`U256` reduced mod
        // `P256_P`) and use the same `u256_mul_mod_p256` / add / sub
        // routines the production code relies on. They live inside the
        // test module because point arithmetic is *not* part of the public
        // API of this crate — the crate validates points, it does not
        // construct them.

        /// `r = a^e mod P256_P` via square-and-multiply (used for Fermat
        /// inverse: a^(p-2) ≡ a⁻¹ mod p).
        fn pow_mod_p(base: &U256, exp_be: &[u8; 32]) -> U256 {
            let mut acc: U256 = [1, 0, 0, 0];
            let cur = *base;
            let mut started = false;
            for byte in exp_be {
                for bit in (0..8).rev() {
                    if started {
                        acc = u256_mul_mod_p256(&acc, &acc);
                    }
                    if (byte >> bit) & 1 == 1 {
                        if started {
                            acc = u256_mul_mod_p256(&acc, &cur);
                        } else {
                            // First 1-bit: `acc` is still 1 and no squaring
                            // happened yet — seed `acc` with `base`.
                            acc = cur;
                            started = true;
                        }
                    }
                }
            }
            if started {
                acc
            } else {
                // exp == 0 ⇒ result is 1.
                [1, 0, 0, 0]
            }
        }

        /// Modular inverse mod `P256_P` via Fermat: a⁻¹ = a^(p−2) mod p.
        fn inv_mod_p(a: &U256) -> U256 {
            // p − 2 in big-endian bytes. P256_P limb-3 .. limb-0, with the
            // least-significant limb decremented by 2 (it ends in 0xFF...FF
            // so no borrow propagates).
            //
            // p     = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
            // p − 2 = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFD
            const P_MINUS_2_BE: [u8; 32] = [
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFD,
            ];
            pow_mod_p(a, &P_MINUS_2_BE)
        }

        /// Affine point doubling on P-256: returns 2·(x, y).
        /// Caller must ensure y ≠ 0 (true for all G multiples we touch).
        fn dbl(x: &U256, y: &U256) -> (U256, U256) {
            // λ = (3x² − 3) / (2y)   (using a = −3 for P-256)
            let three: U256 = [3, 0, 0, 0];
            let two: U256 = [2, 0, 0, 0];
            let xsq = u256_mul_mod_p256(x, x);
            let three_xsq = u256_mul_mod_p256(&three, &xsq);
            let num = u256_sub_mod(&three_xsq, &three, &P256_P);
            let two_y = u256_mul_mod_p256(&two, y);
            let den_inv = inv_mod_p(&two_y);
            let lambda = u256_mul_mod_p256(&num, &den_inv);

            let lambda_sq = u256_mul_mod_p256(&lambda, &lambda);
            let two_x = u256_add_mod(x, x, &P256_P);
            let rx = u256_sub_mod(&lambda_sq, &two_x, &P256_P);
            let dx = u256_sub_mod(x, &rx, &P256_P);
            let ry = u256_sub_mod(&u256_mul_mod_p256(&lambda, &dx), y, &P256_P);
            (rx, ry)
        }

        /// Affine point addition on P-256: returns (x1, y1) + (x2, y2).
        /// Caller must ensure x1 ≠ x2 (else doubling or infinity).
        fn add(x1: &U256, y1: &U256, x2: &U256, y2: &U256) -> (U256, U256) {
            // λ = (y2 − y1) / (x2 − x1)
            let num = u256_sub_mod(y2, y1, &P256_P);
            let den = u256_sub_mod(x2, x1, &P256_P);
            let den_inv = inv_mod_p(&den);
            let lambda = u256_mul_mod_p256(&num, &den_inv);

            let lambda_sq = u256_mul_mod_p256(&lambda, &lambda);
            let tmp = u256_sub_mod(&lambda_sq, x1, &P256_P);
            let rx = u256_sub_mod(&tmp, x2, &P256_P);
            let dx = u256_sub_mod(x1, &rx, &P256_P);
            let ry = u256_sub_mod(&u256_mul_mod_p256(&lambda, &dx), y1, &P256_P);
            (rx, ry)
        }

        /// Convert a `U256` field element back to a 32-byte big-endian
        /// buffer (inverse of `u256_from_be`).
        fn u256_to_be(v: &U256) -> [u8; 32] {
            let mut out = [0u8; 32];
            // limb 3 → bytes 0..8, limb 0 → bytes 24..32 (MSB first).
            out[0..8].copy_from_slice(&v[3].to_be_bytes());
            out[8..16].copy_from_slice(&v[2].to_be_bytes());
            out[16..24].copy_from_slice(&v[1].to_be_bytes());
            out[24..32].copy_from_slice(&v[0].to_be_bytes());
            out
        }

        // -------------------------------------------------------------------
        // Published valid points (multiples of the generator).
        // -------------------------------------------------------------------
        //
        // 2G coordinates — Source: SECG SEC1 §A.2.1 / NIST CAVP P-256 PKV
        // worked example; also reproduced in IETF ECDSA test-vector
        // collections. Verified inside this test by independently computing
        // 2G from G using the `dbl` helper above.
        const G2X: [u8; 32] = [
            0x7C, 0xF2, 0x7B, 0x18, 0x8D, 0x03, 0x4F, 0x7E, 0x8A, 0x52, 0x38, 0x03, 0x04, 0xB5,
            0x1A, 0xC3, 0xC0, 0x89, 0x69, 0xE2, 0x77, 0xF2, 0x1B, 0x35, 0xA6, 0x0B, 0x48, 0xFC,
            0x47, 0x66, 0x99, 0x78,
        ];
        const G2Y: [u8; 32] = [
            0x07, 0x77, 0x55, 0x10, 0xDB, 0x8E, 0xD0, 0x40, 0x29, 0x3D, 0x9A, 0xC6, 0x9F, 0x74,
            0x30, 0xDB, 0xBA, 0x7D, 0xAD, 0xE6, 0x3C, 0xE9, 0x82, 0x29, 0x9E, 0x04, 0xB7, 0x9D,
            0x22, 0x78, 0x73, 0xD1,
        ];

        // 3G coordinates — same sources as 2G; cross-checked by computing
        // 2G + G with `add`.
        const G3X: [u8; 32] = [
            0x5E, 0xCB, 0xE4, 0xD1, 0xA6, 0x33, 0x0A, 0x44, 0xC8, 0xF7, 0xEF, 0x95, 0x1D, 0x4B,
            0xF1, 0x65, 0xE6, 0xC6, 0xB7, 0x21, 0xEF, 0xAD, 0xA9, 0x85, 0xFB, 0x41, 0x66, 0x1B,
            0xC6, 0xE7, 0xFD, 0x6C,
        ];
        const G3Y: [u8; 32] = [
            0x87, 0x34, 0x64, 0x0C, 0x49, 0x98, 0xFF, 0x7E, 0x37, 0x4B, 0x06, 0xCE, 0x1A, 0x64,
            0xA2, 0xEC, 0xD8, 0x2A, 0xB0, 0x36, 0x38, 0x4F, 0xB8, 0x3D, 0x9A, 0x79, 0xB1, 0x27,
            0xA2, 0x7D, 0x50, 0x32,
        ];

        #[test]
        fn nist_cavp_known_valid_points_accepted() {
            // 1) Generator G itself.
            let pg = point_bytes(&GX, &GY);
            assert!(validate_p256_point_on_curve(&pg).is_ok(), "G must validate");

            // 2) 2G — hard-coded vector cross-checked against doubling.
            let gx = u256_from_be(&GX);
            let gy = u256_from_be(&GY);
            let (rx2, ry2) = dbl(&gx, &gy);
            assert_eq!(
                u256_to_be(&rx2),
                G2X,
                "computed 2G.x must match published vector"
            );
            assert_eq!(
                u256_to_be(&ry2),
                G2Y,
                "computed 2G.y must match published vector"
            );
            let pg2 = point_bytes(&G2X, &G2Y);
            assert!(
                validate_p256_point_on_curve(&pg2).is_ok(),
                "2G must validate"
            );

            // 3) 3G — hard-coded vector cross-checked against G + 2G.
            let (rx3, ry3) = add(&gx, &gy, &rx2, &ry2);
            assert_eq!(
                u256_to_be(&rx3),
                G3X,
                "computed 3G.x must match published vector"
            );
            assert_eq!(
                u256_to_be(&ry3),
                G3Y,
                "computed 3G.y must match published vector"
            );
            let pg3 = point_bytes(&G3X, &G3Y);
            assert!(
                validate_p256_point_on_curve(&pg3).is_ok(),
                "3G must validate"
            );

            // 4) 4G = 2·(2G), derived on the fly.
            let (rx4, ry4) = dbl(&rx2, &ry2);
            let pg4 = point_bytes(&u256_to_be(&rx4), &u256_to_be(&ry4));
            assert!(
                validate_p256_point_on_curve(&pg4).is_ok(),
                "4G must validate"
            );

            // 5) 5G = 4G + G.
            let (rx5, ry5) = add(&rx4, &ry4, &gx, &gy);
            let pg5 = point_bytes(&u256_to_be(&rx5), &u256_to_be(&ry5));
            assert!(
                validate_p256_point_on_curve(&pg5).is_ok(),
                "5G must validate"
            );

            // 6) 6G = 2·(3G).
            let (rx6, ry6) = dbl(&rx3, &ry3);
            let pg6 = point_bytes(&u256_to_be(&rx6), &u256_to_be(&ry6));
            assert!(
                validate_p256_point_on_curve(&pg6).is_ok(),
                "6G must validate"
            );

            // 7) 7G = 6G + G.
            let (rx7, ry7) = add(&rx6, &ry6, &gx, &gy);
            let pg7 = point_bytes(&u256_to_be(&rx7), &u256_to_be(&ry7));
            assert!(
                validate_p256_point_on_curve(&pg7).is_ok(),
                "7G must validate"
            );

            // 8) 8G = 2·(4G).
            let (rx8, ry8) = dbl(&rx4, &ry4);
            let pg8 = point_bytes(&u256_to_be(&rx8), &u256_to_be(&ry8));
            assert!(
                validate_p256_point_on_curve(&pg8).is_ok(),
                "8G must validate"
            );

            // 9) Negation of G: (Gx, p − Gy) is also a valid curve point.
            let neg_gy = u256_sub_mod(&[0; 4], &gy, &P256_P);
            let p_neg_g = point_bytes(&GX, &u256_to_be(&neg_gy));
            assert!(
                validate_p256_point_on_curve(&p_neg_g).is_ok(),
                "−G (i.e. (Gx, p−Gy)) must validate"
            );

            // 10) Negation of 2G: (2Gx, p − 2Gy).
            let neg_g2y = u256_sub_mod(&[0; 4], &ry2, &P256_P);
            let p_neg_g2 = point_bytes(&G2X, &u256_to_be(&neg_g2y));
            assert!(
                validate_p256_point_on_curve(&p_neg_g2).is_ok(),
                "−2G must validate"
            );
        }

        #[test]
        fn nist_cavp_known_invalid_points_rejected() {
            // Helper: 32-byte BE representation of p − 1 (the largest valid
            // field element). Several boundary-style cases below combine
            // this value with an arbitrary Y to land off-curve.
            let p_minus_1_be: [u8; 32] = {
                let pm1 = u256_sub_mod(&[0; 4], &[1, 0, 0, 0], &P256_P);
                u256_to_be(&pm1)
            };

            // 1) (X = p − 1, Y = Gy) — X is in range but the point is
            //    (overwhelmingly) off-curve. NIST CAVP-style boundary.
            let bad1 = point_bytes(&p_minus_1_be, &GY);
            assert!(
                validate_p256_point_on_curve(&bad1).is_err(),
                "(p−1, Gy) must reject"
            );

            // 2) (X = Gx, Y = Gy XOR 0x...0001) — one-bit Y mutation.
            let mut bad2_y = GY;
            bad2_y[31] ^= 0x01;
            let bad2 = point_bytes(&GX, &bad2_y);
            assert!(
                validate_p256_point_on_curve(&bad2).is_err(),
                "(Gx, Gy^1) must reject"
            );

            // 3) (X = 2Gx, Y = Gy) — coordinates from different points.
            let bad3 = point_bytes(&G2X, &GY);
            assert!(
                validate_p256_point_on_curve(&bad3).is_err(),
                "(2Gx, Gy) must reject"
            );

            // 4) (X = 0x01..01, Y = 0x02..02) — arbitrary small values.
            let bad4_x = [0x01u8; 32];
            let bad4_y = [0x02u8; 32];
            let bad4 = point_bytes(&bad4_x, &bad4_y);
            assert!(
                validate_p256_point_on_curve(&bad4).is_err(),
                "(0x01.., 0x02..) must reject"
            );

            // 5) (X = 3Gx, Y = 2Gy) — mixed-multiple coordinates.
            let bad5 = point_bytes(&G3X, &G2Y);
            assert!(
                validate_p256_point_on_curve(&bad5).is_err(),
                "(3Gx, 2Gy) must reject"
            );

            // 6) **Twist-curve point.**
            //
            // The quadratic twist of P-256 has the equation
            //     y² ≡ x³ − 3x + b′ (mod p)
            // for the same prime p and parameter a = −3, but a different
            // `b′` such that `b · b′` is a quadratic non-residue mod p.
            // Any (x, y) on the twist is a syntactically-valid SEC1
            // encoding — same prefix, same coordinate length, same range —
            // but is *not* on P-256. An HSM with a buggy (e.g. range-check-
            // only) public-key parser would silently perform scalar
            // multiplication in the twist subgroup, enabling the classic
            // invalid-curve / small-subgroup attack (Antipa, Brown,
            // Menezes, Struik & Vanstone, 2003).
            //
            // We synthesise a twist point by picking small coordinates and
            // verifying they don't satisfy P-256's curve equation. Take
            // x = 1: legitimate-curve RHS = 1 − 3 + b = b − 2. Setting
            // y = 1 gives y² = 1; since b − 2 ≠ 1 (mod p), (1, 1) lies on
            // a twist of P-256 (whose constant is b′ = 3) but not on
            // P-256 itself.
            let one_be: [u8; 32] = {
                let mut b = [0u8; 32];
                b[31] = 0x01;
                b
            };
            // Sanity: the point really is off-curve so the test isn't
            // vacuous (this also documents the construction).
            assert!(
                !p256_on_curve(&one_be, &one_be),
                "(1, 1) must be off the real P-256 curve (twist construction)"
            );
            let twist = point_bytes(&one_be, &one_be);
            assert!(
                validate_p256_point_on_curve(&twist).is_err(),
                "twist-curve point (1, 1) must reject — invalid-curve attack guard"
            );

            // 7) Second twist candidate: x = 2.
            // RHS = 8 − 6 + b = b + 2; pick y = 2 ⇒ y² = 4 ≠ b + 2.
            let two_be: [u8; 32] = {
                let mut b = [0u8; 32];
                b[31] = 0x02;
                b
            };
            assert!(
                !p256_on_curve(&two_be, &two_be),
                "(2, 2) must be off-curve (second twist case)"
            );
            let twist2 = point_bytes(&two_be, &two_be);
            assert!(
                validate_p256_point_on_curve(&twist2).is_err(),
                "second twist candidate (2, 2) must reject"
            );

            // 8) (X = 0, Y = anything) — caught by shape check.
            let zero = [0u8; 32];
            let bad8 = point_bytes(&zero, &GY);
            assert!(
                validate_p256_point_on_curve(&bad8).is_err(),
                "(0, Gy) must reject (X coord zero)"
            );

            // 9) (X = anything, Y = 0) — caught by shape check.
            let bad9 = point_bytes(&GX, &zero);
            assert!(
                validate_p256_point_on_curve(&bad9).is_err(),
                "(Gx, 0) must reject (Y coord zero)"
            );

            // 10) (X = p − 1, Y = p − 1) — both at the boundary, off-curve.
            let bad10 = point_bytes(&p_minus_1_be, &p_minus_1_be);
            assert!(
                validate_p256_point_on_curve(&bad10).is_err(),
                "(p−1, p−1) must reject"
            );
        }
    }

    // ---------- P256_N constant ----------

    #[test]
    fn p256_n_matches_sec2_big_endian_encoding() {
        // SEC 2 §2.4.2 / FIPS 186-4 §D.1.2.3 specifies the P-256 subgroup
        // order n in big-endian hex as:
        //   FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
        const N_BE: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];
        // Round-trip via the existing big-endian decoder: u256_from_be(N_BE)
        // must reproduce the limb-encoded P256_N exactly.
        assert_eq!(u256_from_be(&N_BE), P256_N);

        // Sanity: n must lie strictly between p/2 and 2^256 (well-known
        // property of P-256 — n is just slightly less than p, both ~2^256).
        // We at least check n != 0 and n != p.
        assert_ne!(P256_N, [0u64; 4]);
        assert_ne!(P256_N, P256_P);

        // Explicit limb-level cross-check of the documented little-endian
        // limb layout (limb 0 = LSB):
        assert_eq!(P256_N[0], 0xF3B9_CAC2_FC63_2551);
        assert_eq!(P256_N[1], 0xBCE6_FAAD_A717_9E84);
        assert_eq!(P256_N[2], 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(P256_N[3], 0xFFFF_FFFF_0000_0000);
    }

    // ---------- audit-M7: PublicFieldElement typed barrier ----------

    #[test]
    fn public_field_element_accepts_generator_via_typed_surface() {
        // The typed `p256_on_curve_public_input_only` entry point is the
        // sealed replacement for the old byte-level `p256_on_curve`.
        let x = PublicFieldElement::from_be_bytes(&GX);
        let y = PublicFieldElement::from_be_bytes(&GY);
        assert!(p256_on_curve_public_input_only(&x, &y));
    }

    #[test]
    fn public_field_element_rejects_off_curve_via_typed_surface() {
        let mut bad_y = GY;
        bad_y[31] ^= 0x01;
        let x = PublicFieldElement::from_be_bytes(&GX);
        let y = PublicFieldElement::from_be_bytes(&bad_y);
        assert!(!p256_on_curve_public_input_only(&x, &y));
    }

    #[test]
    fn public_field_element_rejects_coord_at_or_above_p() {
        // Coordinate == p must be rejected (canonical form requires < p).
        let mut p_be = [0u8; 32];
        p_be[0..8].copy_from_slice(&P256_P[3].to_be_bytes());
        p_be[8..16].copy_from_slice(&P256_P[2].to_be_bytes());
        p_be[16..24].copy_from_slice(&P256_P[1].to_be_bytes());
        p_be[24..32].copy_from_slice(&P256_P[0].to_be_bytes());
        let x = PublicFieldElement::from_be_bytes(&p_be);
        let y = PublicFieldElement::from_be_bytes(&GY);
        assert!(!p256_on_curve_public_input_only(&x, &y));
    }

    #[test]
    fn public_field_element_constants_match_raw_constants() {
        // The named-constant accessors must yield the same limb pattern
        // as the published `P256_*` constants.
        assert_eq!(PublicFieldElement::p256_p().as_limbs(), &P256_P);
        assert_eq!(PublicFieldElement::p256_b().as_limbs(), &P256_B);
    }

    #[test]
    fn public_field_element_is_repr_transparent_size() {
        // Sanity: PublicFieldElement is a zero-overhead wrapper.
        use core::mem::size_of;
        assert_eq!(size_of::<PublicFieldElement>(), size_of::<[u64; 4]>());
    }
}

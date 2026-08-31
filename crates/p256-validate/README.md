# vs-p256-validate

Defensive software-side validation that a NIST P-256 (`secp256r1`) public
key is well-formed and lies on the curve. Consumed as defence-in-depth by
`vs-crypto-pkcs11` and `vs-crypto-tpm` before a caller-supplied
`EC_POINT` is handed to the underlying HSM or TPM.

## Purpose

Invalid-curve attacks (Biehl–Meyer–Müller, 2000) exploit cryptographic
tokens that accept off-curve points for ECDH or signature verification:
the attacker recovers private-key bits by observing the result of
operations carried out on a low-order point from a related curve. Cited
in `docs/threat-model.md` as a mitigation for **T3** (key compromise via
malformed public input) and **S1** (spoofed key material). See also
NIST SP 800-56A §5.6.2.3 for the underlying validation requirement.

This crate is the client-side guard: every uncompressed P-256 public
key that crosses the FFI boundary is validated here first, so an HSM or
TPM with weak or buggy on-curve checks (notably some older `SoftHSM`
builds) cannot be tricked into operating on attacker-chosen points.

## Scope

Implements the *partial* public-key validation routine of NIST
SP 800-56A §5.6.2.3.3 (steps 1–3):

1. Point is not the identity (`X = 0` and `Y = 0`).
2. Both affine coordinates lie in `[0, p)`.
3. `(x, y)` satisfies `y² ≡ x³ − 3x + b (mod p)`.

Step 4 (the cofactor / `nQ = O` check) is **not** required: P-256 has
cofactor 1, so every point that passes steps 1–3 has order `n`.

## API

- `validate_p256_point_on_curve(&[u8; 65]) -> Result<(), VsError>` —
  full shape + on-curve check. The single entry point consumer crates
  should call.
- `validate_ec_point_shape(&[u8; 65]) -> Result<(), VsError>` — cheap
  format-only check (prefix byte, non-zero coordinates). Useful when
  the on-curve math will be done elsewhere.
- `p256_on_curve(&[u8; 32], &[u8; 32]) -> bool` — pure curve-equation
  check on already-decoded `(X, Y)` big-endian bytes.
- Constants: `P256_P` (field prime), `P256_B` (curve parameter `b`),
  `EC_POINT_LEN = 65`, `P256_COORD_LEN = 32`.
- Helpers: `u256_from_be`, `u256_cmp`, `u256_add_mod`, `u256_sub_mod`,
  `u256_mul_mod_p256` (Solinas fast path), `u256_mul_mod` (generic
  modulus).

The Solinas reduction (FIPS 186-4 §D.2.3) replaces a 512-iteration
bit-serial long-division with an O(1) sum of nine 256-bit aliases.

## Encoding policy

Only **uncompressed SEC 1** encoding is accepted: a 65-byte buffer
beginning with `0x04`, followed by 32-byte big-endian `X` and `Y`. Any
other prefix — `0x00`, `0x02`/`0x03` (compressed), `0x06`/`0x07`
(hybrid), or arbitrary garbage — is rejected with
`VsError::InvalidInput`. Callers that hold compressed points must
decompress them before validation.

## Constant-time stance

The validator is **not** constant-time. Inputs are public keys; both
the Solinas reduction and the curve-equation comparison contain
data-dependent branches. This is acceptable here because no secret
material flows through these paths.

**Do not** reuse the low-level `u256_*` helpers on secret scalars
(private keys, ECDH shared secrets) — leak-free scalar arithmetic must
come from a constant-time implementation such as the HSM/TPM itself.

### Sealed surface (audit-M7)

The low-level 256-bit integer helpers — `u256_cmp`, `u256_mul_mod`,
`u256_mul_mod_p256`, `u256_add_mod`, `u256_sub_mod`, `u256_from_be`,
the Solinas reducer, and the byte-level `p256_on_curve` — are
`pub(crate)`. A previous version exposed them as `pub`, which the
2026 security audit (finding M7) flagged because every one of them
contains data-dependent branches (early-exit comparisons,
variable-iteration reduction loops, lazy carry propagation). Running
them on a secret value (a private key, an ECDH shared secret, an
ECDSA nonce, or any value derived from those) leaks bits through
timing.

The only public non-CT surface is `p256_on_curve_public_input_only`,
which takes a `PublicFieldElement` newtype. `PublicFieldElement` has
no `From<[u64; 4]>` and no public field; construction is via
`PublicFieldElement::from_be_bytes(&[u8; 32])` or the named
curve-constant constructors `PublicFieldElement::p256_p()` / `::p256_b()`.
The type records the "publicness" precondition in the type system
rather than only in prose.

## Relationship to HSM/TPM on-curve checks

PKCS#11 tokens and TPM 2.0 stacks vary widely in how strictly they
validate caller-supplied EC points: some perform full SP 800-56A
checks, others accept any byte string with the right length, and a few
have had silent firmware regressions. Even when the vendor check is
correct, it runs *after* the point has been parsed by token-side code
that has historically been a source of side-channel leakage.

Performing the on-curve check in software before the FFI call gives:

- a known-correct baseline independent of vendor firmware versions,
- early rejection (no `C_DeriveKey` / `TPM2_ECDH_ZGen` is issued for
  invalid input), reducing attack surface on the token,
- a single audit point for the entire enterprise build.

This is strict defence-in-depth; the vendor check is not removed.

## Test vectors

The in-crate tests use the P-256 generator from FIPS 186-4 §D.2.3, a
1000-pair randomised cross-check of the Solinas fast path against the
bit-serial reference, and explicit edge cases (`X = 0`, `Y = 0`,
`X = p`, `Y = p`, `X = Y = 0xFF…FF`, point at infinity, wrong prefix
bytes, off-curve point produced by flipping the low byte of `Y`).

For external CAVP coverage, run the NIST ECDSA `PKV` (public-key
validation) vectors from the Cryptographic Algorithm Validation Program
through `validate_p256_point_on_curve`; the partial-validation subset
is exhaustive for the checks this crate performs.

## Status

Production-ready. `#![no_std]`, no heap allocation, no `unsafe`. All
buffers are stack-allocated; the largest single-scope buffer is
`[u32; 16]` (64 B), well under the workspace 2048-byte cap. Licensed
under BSL-1.1, converting to Apache-2.0 on 2030-09-01 — see `LICENSE`
at the workspace root.

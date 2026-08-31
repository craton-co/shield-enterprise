# Cryptographic Agility & Lifecycle

This document is the authoritative record of every primitive Craton Shield
Enterprise relies on, which hardware / firmware provider validates it, the
sunset trigger that would retire it, and the migration path once it is
retired.

The matrix is reviewed every six months and at every major release. Audit
evidence is produced from this document plus the SBOMs attached to each
release tag.

## 1. Primitive matrix

| Primitive | Used for | Provider module | FIPS 140 status | Expected sunset trigger | Migration target |
|---|---|---|---|---|---|
| **AES-256-GCM** | Telemetry batch encryption; generic AEAD on HSMs | `vs-crypto-pkcs11::aes_gcm_encrypt` | FIPS 140-3 approved (see [`docs/hardware-compatibility.md`](hardware-compatibility.md) for current FIPS certificate IDs by vendor/product) | CVAE break ≥ 2^64 queries under a single key OR NIST SP 800-38D deprecation | **AES-256-GCM-SIV** or **XChaCha20-Poly1305** (software fallback) |
| **AES-256-CFB + HMAC-SHA-256 (EtM)** | Authenticated encryption when the target TPM 2.0 lacks a native AEAD | `vs-crypto-tpm::aes_gcm_encrypt` | FIPS 140-3 approved (Infineon SLB 9670 cert #4260, STMicro ST33TPHF2ESPI cert #4351) | TPM 2.0 gains a native AEAD command OR HMAC-SHA-256 cryptanalytic break | Native TPM AES-GCM once available; see TCG TPM 2.0 Library Spec Rev 2.0 errata |
| **SHA-256** | Batch digest chain; canary self-test; ECDSA pre-hash | All providers | FIPS 180-4 approved, present in every listed HSM / TPM | NIST deprecation of SHA-2 family (currently scheduled post-2030) | **SHA-384** in the short term, **SHA-3-256** once transition date is set |
| **HMAC-SHA-256** | Integrity tag in the EtM construction; key derivation checks | `vs-crypto-pkcs11::hmac_sha256`, `vs-crypto-tpm::hmac_sha256` | FIPS 198-1 approved | Follows SHA-256 sunset | HMAC-SHA-384 |
| **ECDSA P-256** | Telemetry signature; device attestation | `vs-crypto-pkcs11::sign_p256`, `vs-crypto-tpm::sign_p256` | FIPS 186-5 approved (all listed HSMs) | Practical attack on P-256 OR NIST deprecation | **Ed25519** (software), **ECDSA P-384** (HSM) |
| **ECDH P-256** | Pairwise key agreement for secure-channel bootstrap | `vs-crypto-pkcs11::ecdh_derive_shared`, `vs-crypto-tpm::ecdh_derive_shared` | FIPS 140-3 Ref SP 800-56A Rev 3 | Follows ECDSA P-256 sunset | ECDH P-384, ML-KEM-768 (PQ) |

### Post-quantum

Craton Shield Enterprise does not yet ship a post-quantum algorithm. The
roadmap commits to:

- **2027 Q4:** Expose a `hybrid_kem` trait fed by ML-KEM-768 (FIPS 203) in
  parallel with ECDH P-256 for session-key establishment.
- **2028 Q2:** Ship ML-DSA-65 (FIPS 204) alongside ECDSA P-256 for
  telemetry signatures once at least two of the supported HSMs ship
  FIPS-validated firmware for ML-DSA.

Trigger to bring this forward: any peer-reviewed publication lowering
P-256 / P-384 security margin below 112 bits, or a CNSA 2.0 mandate.

## 2. Lifecycle controls

1. **Algorithm lookup is indirected.** Every cipher/hash is selected by a
   mechanism constant (`CKM_*` in PKCS#11, `TPM2_ALG_*` in TPM). A future
   migration adds a new mechanism ID without touching any caller.
2. **Per-key algorithm policy.** `KeyId` carries a type (`KeyType` in
   `vs-crypto`). Consumers should refuse to use a key with an algorithm its
   type does not support, preventing cross-use attacks.
3. **Nonce management is per-provider.** Both `aes_gcm_encrypt`
   implementations accept caller-supplied nonces and explicitly document
   the uniqueness contract. Telemetry's `PersistedFlushCounter` (and the
   optional `strict-nonce` feature) enforces non-reuse across reboots.
4. **Deprecation policy.** A primitive marked for sunset here gets a 12-
   month deprecation window, gated by a crate feature (`legacy-sha2`,
   `legacy-ecdsa-p256`, etc.) whose default flips off at the release
   immediately following the sunset trigger.

## 3. FIPS / Common Criteria mapping

The matrix in §1 lists the primary FIPS certificate that covers each
algorithm on each target HSM. The mapping is kept in sync with
[`docs/operational-security.md`](operational-security.md) §4 (HSM
provisioning) and re-checked at release time by the `verify` job in
[`release.yml`](../.github/workflows/release.yml).

When a cert expires or is revoked:

1. Monitor `https://csrc.nist.gov/projects/cryptographic-module-validation-program`.
2. Replace the HSM or upgrade its firmware to a successor cert.
3. Re-run the provisioning procedure (§4 of `operational-security.md`).
4. Bump the `craton-shield-enterprise` minor version.

## 4. PQC-readiness test vectors

`tests/pqc_vectors/` (reserved; populated in the 2027 Q4 milestone) will
host the NIST KATs for ML-KEM-768 and ML-DSA-65. Until that milestone,
consumers should treat PQC hooks as preview-only.

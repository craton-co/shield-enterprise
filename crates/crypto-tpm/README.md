# vs-crypto-tpm

TPM 2.0 TSS2 ESAPI-backed implementation of the `vs-crypto` [`CryptoProvider`] trait.

**License:** BSL-1.1 (converts to Apache-2.0 on 2030-09-01)

---

## What this is

A Trusted Platform Module (TPM 2.0) crypto backend for Craton Shield.
Implements every method of the `CryptoProvider` trait by forwarding calls to
the TPM via caller-supplied TSS2 ESAPI function pointers.

Compatible with: **hardware TPM 2.0** (dTPM), **swtpm** (development / CI),
**fTPM** (firmware TPM on ARM TrustZone, Intel TXT), **QNX TPM resource
manager**.

## What it provides

| CryptoProvider method | TPM 2.0 command |
|:---|:---|
| `aes_gcm_encrypt` | `EncryptDecrypt2` (AES-CFB) + `HMAC` tag |
| `aes_gcm_decrypt` | HMAC verify + `EncryptDecrypt2` (AES-CFB) |
| `sha256` | `Hash(TPM2_ALG_SHA256)` |
| `hmac_sha256` | `HMAC(TPM2_ALG_SHA256)` |
| `ecdh_derive_shared` | `ECDH_ZGen` → x-coordinate |
| `sign_p256` | `Sign(ECDSA, SHA-256)` |
| `verify_p256` | `VerifySignature` |
| `random_bytes` | `GetRandom` (looped for > 32 bytes) |
| `self_test` | `SelfTest(fullTest=YES)` + SHA-256 canary |

### TPM-specific extensions

| Method | Description |
|:---|:---|
| `pcr_extend(index, measurement)` | Extend PCR[index] with SHA-256 digest |
| `pcr_read(index, value)` | Read current SHA-256 value of PCR[index] |

## AES-GCM note

TPM 2.0 does not support AES-GCM natively. This provider uses an
**Encrypt-then-MAC** construction with AES-256-CFB + HMAC-SHA-256:

```
Encrypt:
  CT  ← EncryptDecrypt2(k_enc, AES-CFB, IV=nonce[0..12]‖0x00000000, PT)
  TAG ← HMAC(k_mac, SHA-256,
             "VS-ETM01" ‖ nonce(12B)
                        ‖ aad_len(LE u64) ‖ ct_len(LE u64)
                        ‖ AAD ‖ CT)[0..16]

Decrypt:
  TAG' ← HMAC(k_mac, SHA-256, <same framed input as encrypt>)[0..16]
  verify TAG == TAG'  (constant-time)
  PT   ← EncryptDecrypt2(k_enc, AES-CFB, IV=..., CT)
```

This is IND-CCA2 secure (Encrypt-then-MAC over a length-prefixed framing
that prevents `(AAD, CT)` canonicalisation attacks). `k_enc` and `k_mac`
are distinct TPM objects — see audit C1 below. The `tag_out` field carries
the HMAC-SHA-256 truncated to 16 bytes. The construction is documented in
the source; callers using vs-crypto interoperability across providers
should note the difference (`vs-crypto-pkcs11` produces wire-compatible
AES-GCM ciphertexts).

## Design

The crate is `#![no_std]` with zero heap allocations on the Rust side. The
TSS2 ESAPI allocates output buffers internally; this provider copies each
result to a stack buffer immediately and frees the ESAPI allocation via
`Esys_Free`.

The ESAPI library is **not** linked at compile time. The caller resolves
function pointers and passes a fully populated `TpmFunctionList` to
`TpmCryptoProvider::new`.

## Quick start

```rust
// (Pseudocode — adapt to your platform's TSS2 loading.)

let fn_list = TpmFunctionList {
    esys_initialize:       tss2.resolve("Esys_Initialize"),
    esys_finalize:         tss2.resolve("Esys_Finalize"),
    esys_hash:             tss2.resolve("Esys_Hash"),
    // ... all fields required
};

// Create the provider (connects to TPM via system TCTI).
let mut provider = TpmCryptoProvider::new(fn_list)?;

// Register persistent key handles (TPM2_HANDLE → ESYS_TR).
let mut tr: u32 = 0;
(fn_list.esys_tr_from_tpm_public)(ctx, 0x8100_0001, ..., &mut tr);
provider.register_key_handle(KeyId(0), tr)?;        // AES cipher key
provider.register_mac_key_handle(KeyId(0), tr_mac)?; // distinct HMAC key (audit C1)
provider.register_key_handle(KeyId(1), tr2)?;       // ECC key

// verify_p256 does NOT require pre-registration: the caller-supplied
// uncompressed pubkey is loaded transiently via Esys_LoadExternal and
// flushed before return (audit C4).

// Pass to CratonShield.
let shield = CratonShield::init(provider, ...)?;
```

## Security limitations

- **TPM-bus integrity is opt-in; confidentiality is NOT provided.** By
  default the provider uses `ESYS_TR_PASSWORD` for command authorisation,
  meaning the LPC/SPI/I2C bus between the host SoC and a discrete TPM
  carries plaintext command payloads (PCR-extend digests, HMAC/sign
  inputs, AEAD ciphertexts). Callers can opt in to an HMAC **integrity**
  session by calling `enable_bus_integrity()` (and `disable_bus_integrity()`
  to tear it down). The session:
  - Sets `TPMA_SESSION_CONTINUE_SESSION` via `Esys_TRSess_SetAttributes`
    so it survives past one command.
  - Supplies a 32-byte caller nonce drawn from the TPM TRNG; the buffer
    is volatile-wiped immediately after the session-start call returns.
  - Uses `TpmtSymDef { algorithm: TPM2_ALG_NULL, .. }` and **does NOT**
    set `TPMA_SESSION_ENCRYPT` / `TPMA_SESSION_DECRYPT` — per TCG TPM
    2.0 Library §19.6 this delivers integrity but not confidentiality.
    **A bus-tap can still recover plaintext command and response
    parameters.**
  See [`threat-model.md`](../../threat-model.md) (audit findings **M1**,
  **H1**, **M3**) for the full analysis.
- **Naming.** The methods were renamed from `enable_bus_protection` /
  `disable_bus_protection` (which oversold what the wiring delivers) to
  `enable_bus_integrity` / `disable_bus_integrity`. The old names remain
  as `#[deprecated]` aliases so existing callers keep compiling, but new
  code MUST use the integrity-named methods.
- **Mitigation for the confidentiality gap:** deploy with a TPM in a
  tamper-resistant package (fTPM on ARM TrustZone, Intel PTT) or
  physically protect the TPM bus traces; alternatively layer
  parameter-encryption above this crate (e.g., wrap sensitive plaintext
  with a host-side AEAD before sending to the TPM). A future extension
  may attach a salt key to the bus-integrity session and request
  `TPMA_SESSION_ENCRYPT` / `TPMA_SESSION_DECRYPT`; the public API of
  `enable_bus_integrity` is stable so that change does not break callers.
- **AEAD construction is EtM, not AES-GCM** — see the AES-GCM note above.
  Callers that need wire-compatible AES-GCM ciphertexts must use a
  different provider.

## Recent audit fixes (C1, C4, CRIT-7, M1-M5)

- **C1** — AEAD now requires a distinct MAC key handle registered via
  `register_mac_key_handle`; cipher and MAC keys must reference different
  TPM objects.
- **C4** — `verify_p256` no longer requires a pre-registered pubkey slot;
  the caller-supplied uncompressed point is validated on-curve in software
  and loaded transiently via `Esys_LoadExternal`.
- **CRIT-7** — `register_mac_key_handle` runs a runtime key-separation
  canary that encrypts a fixed plaintext under the cipher handle, HMACs
  the same plaintext under the MAC handle, and rejects the registration
  (with `VsError::PolicyViolation`) if the outputs collide or either is
  stuck-zero. This is a backstop against accidental key reuse — it does
  NOT replace HKDF-based key derivation, which operators MUST still
  perform during provisioning.
- **M1 / H1 / M3** — TPM-bus **integrity** session now wired via
  `enable_bus_integrity` (`Esys_StartAuthSession` + `Esys_TRSess_SetAttributes`
  with `TPMA_SESSION_CONTINUE_SESSION` + 32-byte caller nonce from the
  TPM TRNG). Confidentiality gap remains and is documented above.
- **M2** — `pcr_extend` is `&self` (no Rust state mutated).
- **M3** — full P-256 on-curve check before `ECDH_ZGen`.
- **M4** — `TPMT_TK_VERIFIED` ticket tag and hierarchy validated after
  `Esys_VerifySignature`.
- **M5** — `register_mac_key_handle` rejects handles equal to the slot's
  cipher key handle.

## PCR-based secure boot integration

`TpmCryptoProvider` pairs naturally with `vs-secure-boot`. Use `pcr_extend`
after each boot stage measurement to mirror what `BootVerifier` records in
software, then seal sensitive keys to the expected PCR values.

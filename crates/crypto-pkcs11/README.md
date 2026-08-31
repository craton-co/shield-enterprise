# vs-crypto-pkcs11

PKCS#11 HSM-backed implementation of the `vs-crypto` [`CryptoProvider`] trait.

**License:** BSL-1.1 (converts to Apache-2.0 on 2030-09-01)

---

## What this is

A hardware security module (HSM) crypto backend for Craton Shield. Implements
every method of the `CryptoProvider` trait by forwarding calls to a PKCS#11
v2.40 / v3.0 compliant token via caller-supplied function pointers.

Compatible with: **SoftHSM2** (development / CI), **Thales Luna**, **Utimaco
SecurityServer**, **Microchip ATECC**, **NXP SE050**, and any other PKCS#11
token.

## What it provides

| CryptoProvider method | PKCS#11 mechanism |
|:---|:---|
| `aes_gcm_encrypt` | `CKM_AES_GCM` |
| `aes_gcm_decrypt` | `CKM_AES_GCM` |
| `sha256` | `CKM_SHA256` |
| `hmac_sha256` | `CKM_SHA256_HMAC` |
| `ecdh_derive_shared` | `CKM_ECDH1_DERIVE` |
| `sign_p256` | `CKM_ECDSA` |
| `verify_p256` | `CKM_ECDSA` + transient key import |
| `random_bytes` | `C_GenerateRandom` |
| `self_test` | SHA-256 canary + `C_GetTokenInfo` liveness |

## Design

The crate is `#![no_std]` with zero heap allocations. All crypto buffers are
stack-allocated. The PKCS#11 library is **not** linked at compile time — the
caller resolves function pointers (e.g., via `dlopen` on Linux / QNX, or
static linking for embedded targets) and passes a fully populated
`Pkcs11FunctionList` to `Pkcs11CryptoProvider::new`.

Key identity uses the same 64-slot `KeyId` scheme as `vs-key-manager`. Call
`register_key_handle(key_id, ck_object_handle)` to map logical key IDs to
PKCS#11 object handles after locating keys on the token.

## Quick start

```rust
// (Pseudocode — adapt to your platform's PKCS#11 loading mechanism.)

// 1. Load the PKCS#11 library and resolve the function list.
let fn_list = Pkcs11FunctionList {
    c_initialize:    pkcs11_lib.resolve("C_Initialize"),
    c_finalize:      pkcs11_lib.resolve("C_Finalize"),
    c_open_session:  pkcs11_lib.resolve("C_OpenSession"),
    // ... all fields required
    slot_id: 0,
    library_pre_initialized: 0,
};

// 2. Create the provider (opens session + logs in).
let mut provider = Pkcs11CryptoProvider::new(fn_list, b"user-pin")?;

// 3. Register the key handles you need.
provider.register_key_handle(KeyId(0), my_aes_key_handle)?;
provider.register_key_handle(KeyId(1), my_ec_key_handle)?;

// 4. Pass to CratonShield.
let shield = CratonShield::init(provider, ...)?;
```

## Nonce-cache and `try_clone`

As defence-in-depth against AES-GCM nonce reuse, the provider remembers the
last nonce used per `KeyId` and rejects a verbatim repeat with
`VsError::CryptoError` (constant-time compare).

This cache is per-provider and is **not** shared with clones. To prevent a
clone from silently re-issuing a nonce already used by the parent,
`try_clone` returns `Err(VsError::InvalidState)` once any `aes_gcm_encrypt`
has occurred on the parent. Open all needed clones **before** performing
any encryption, or construct a fresh provider with `Pkcs11CryptoProvider::new`.

## Provider cloning

`try_clone` (and `try_clone_with_pin_buffer`) returns a new
`Pkcs11CryptoProvider` that opens a **fresh** PKCS#11 session on the same
token and re-authenticates with the supplied PIN. Two contracts apply to
the result:

1. **The nonce cache is empty.** As described above, `try_clone` is gated
   on `has_encrypted == false` to keep the per-provider AES-GCM
   defence-in-depth cache meaningful.

2. **The `KeyId → CK_OBJECT_HANDLE` map is empty (audit-M6).** Cloned
   providers start with **no registered key handles**. Callers must call
   `register_key_handle` on the clone for every `KeyId` they intend to
   use, even if the parent had that slot registered. This is deliberate:

   - With an external nonce-persistence backend keyed solely by `KeyId`
     (e.g. `CountingPersistence` in `vsoc-telemetry`), two providers that
     shared a `KeyId` row would silently fail the monotonicity check on
     the second `persist` call — each has its own `nonce_device_prefix`,
     so the persistence row sees the prefixes interleave non-monotonically.
   - PKCS#11 sessions are not coordinated by the token. Two providers
     issuing different cryptographic operations under the same logical
     `KeyId` against the same hardware token can produce results that
     neither side expects.

   Dropping the inherited `key_map` forces the caller to acknowledge the
   re-registration on the clone, which makes the inheritance explicit
   and prevents silent aliasing.

```rust
let mut clone = parent.try_clone(b"user-pin")?;
// Re-register every KeyId the clone will use.
clone.register_key_handle(KeyId(0), parent_aes_handle)?;
clone.register_key_handle(KeyId(1), parent_ec_handle)?;
```

## AES-GCM tag handling

The PKCS#11 spec appends the authentication tag to the ciphertext output of
`C_Encrypt`. This provider splits the combined output buffer into separate
ciphertext and tag slices matching the `CryptoProvider` interface.

## Key deletion semantics (audit-M4)

The `CryptoProvider` trait declares `delete_key(&mut self, KeyId)`, and the
software providers in the same trait family genuinely destroy the underlying
key material on return. This PKCS#11 provider **cannot** match that
contract for free: the token-side key object lives on the HSM, and any
destruction goes through `C_DestroyObject` plus the HSM's audit / dual-
control ceremony — exactly the work this trait method elides.

To avoid silently lying to callers (a previous revision performed a local-
only "forget the handle" while leaving the token key intact, which let
callers re-bind the same `CKA_ID` / `CKA_LABEL` later and resume using the
same cryptographic identity — defeating any forward-secrecy assumption),
the implementation now exposes two distinct operations:

| Operation | Method | What it does |
|:---|:---|:---|
| **Local-forget** | `Pkcs11CryptoProvider::forget_local_handle(KeyId)` (inherent) | Clears the in-memory slot in the provider's handle map and resets the per-slot nonce cache. Does **not** contact the token. Re-registering a different handle in the same slot is supported. |
| **Token destruction** | `<Pkcs11CryptoProvider as CryptoProvider>::delete_key(KeyId)` (trait) | **Default:** returns `VsError::PolicyViolation`. **With the `policy-allow-token-destroy` feature:** issues `C_DestroyObject` against the registered handle, then forgets it locally. Destructive and irreversible. |

The recommended workflow for safety-critical deployments is:

1. Call `forget_local_handle` to remove the handle from the in-memory map.
2. Use vendor tooling (`pkcs11-tool --delete-object`, the KMS UI, the
   HSM's audit-logged "delete key" ceremony) to destroy the token object
   under dual control.
3. On the next boot, do not re-register the destroyed handle.

The `policy-allow-token-destroy` feature is provided for deployments
whose threat model and audit posture explicitly authorise in-band
destruction. **It is not the recommended path** — leaving it disabled
forces callers to go through the HSM's ceremony, which is exactly what
the trait contract's "delete" implies but cannot guarantee on its own.

## Feature flags

| Feature     | Default | Effect                                                                                                                       |
|:------------|:--------|:-----------------------------------------------------------------------------------------------------------------------------|
| `strict-rng` | **on**  | `random_bytes` pre-fills the output with a sentinel pattern and rejects the call if the token returns `CKR_OK` without overwriting every byte. Defends against tokens whose TRNG silently fails. |
| `policy-allow-token-destroy` | off | Lets `<Pkcs11CryptoProvider as CryptoProvider>::delete_key` issue `C_DestroyObject` against the token (then forget the handle locally). Destructive and irreversible. Off by default so the trait method refuses with `VsError::PolicyViolation` rather than bypass the HSM's dual-control destruction ceremony. See "Key deletion semantics (audit-M4)" above. |

Disable `strict-rng` only in audited contexts (e.g. fuzz harnesses that
drive a known-good in-process generator) by depending on this crate with
`default-features = false`. Disabling on a production target is
unsupported for automotive deployments — a silent-failure TRNG would
otherwise feed deterministic bytes into every downstream key/nonce.

## Token key labelling convention

When populating the token before deployment, label keys as `vs-key-NN` where
`NN` is the zero-padded `KeyId` (e.g., `vs-key-00`, `vs-key-01`). Use
`C_FindObjects` with `CKA_LABEL` to resolve handles at startup:

```c
CK_ATTRIBUTE template[] = {{ CKA_LABEL, "vs-key-00", 9 }};
C_FindObjectsInit(session, template, 1);
C_FindObjects(session, &handle, 1, &count);
C_FindObjectsFinal(session);
```

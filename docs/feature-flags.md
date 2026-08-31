# Feature Flags Reference

Last reviewed: **2026-05-10**.

This document covers features in both `craton-shield-core` and
`craton-shield-enterprise`. Features marked **[core]** live in the
sibling core repo (`../craton-shield/core/`) and are documented here
only for convenience — they are not exposed by any enterprise-workspace
crate and cannot be enabled via the enterprise root `Cargo.toml`.

Real enterprise-workspace features today are `strict-nonce`
(`vs-vsoc-telemetry`), `strict-rng` (`vs-crypto-pkcs11`,
`vs-crypto-tpm`), and `fuzz` (`vs-hal-qnx`, if/when added — see
[docs/fuzzing.md](fuzzing.md)).

## Enterprise-specific flags

### `strict-nonce`

**Crate:** `vs-vsoc-telemetry`
**Default:** No
**Stability:** Stable

Seals the convenience `TelemetryUplink::new()` constructor so that every
caller is forced to produce a `PersistedFlushCounter` before constructing
an uplink. Production deployments that share an AES-GCM encryption key
across reboots **must** enable this feature: it eliminates the last
footgun that could lead to catastrophic nonce reuse after a warm-start.

Enable via `--features vs-vsoc-telemetry/strict-nonce` or by listing the
flag in the consuming crate's feature set.

### `strict-rng`

**Crate:** `vs-crypto-pkcs11`, `vs-crypto-tpm`
**Default:** No
**Stability:** Stable

Enables tamper-evidence on `random_bytes()`: the provider pre-fills the
output buffer with a sentinel pattern and rejects the call if the token
returns success without overwriting every byte. Defends against faulty
or malicious TRNG backends that claim success while emitting nothing.

Recommended for any build that processes secret-bearing randomness
(session keys, nonces, signature `k`-values).

## `mock-hsm` **[core]**

**Crate:** `vs-crypto` (core repo)
**Default:** No
**Stability:** Stable

Enables a compile-time software mock of the `CryptoProvider` trait. The mock
provides full implementations of AES-256-GCM, SHA-256, HMAC-SHA-256,
ECDSA P-256, and ECDH P-256 using `ring` / `RustCrypto` crates.

This feature is intended for development, CI, and integration testing.
A `cfg` assertion prevents it from compiling under the `release` profile:

```rust
#[cfg(all(feature = "mock-hsm", not(debug_assertions)))]
compile_error!("mock-hsm must not be used in release builds");
```

## `pq-software` **[core]**

**Crate:** `vs-crypto` (core repo)
**Default:** No
**Stability:** Experimental

Activates the post-quantum software providers:

- **ML-KEM-768** -- key encapsulation (FIPS 203)
- **ML-DSA-65** -- digital signatures (FIPS 204)

These providers are software-only and are not backed by HSM hardware. They
are suitable for prototyping post-quantum migration strategies but have not
undergone safety certification. Performance on constrained targets has not
been validated.

## `json` **[core]**

**Crate:** `vs-ota-validator` (core repo)
**Default:** No
**Stability:** Beta

Enables the TUF / Uptane canonical JSON parser used for metadata
verification. When enabled, the crate can parse `TufRoot`, `TufTimestamp`,
`TufSnapshot`, and `TufTargets` structures from canonical JSON, and compute
SHA-256 content hashes over the signed portion via
`parse_tuf_root_with_hash()`.

Without this feature, TUF metadata must be supplied as pre-parsed Rust
structs.

## `wcet` **[core]**

**Crate:** `vs-bench` (binary target, core repo)
**Default:** No
**Stability:** Experimental

Builds the worst-case execution time (WCET) measurement harness. This
produces a standalone binary that exercises critical code paths and records
cycle counts via the platform `Timer` implementation.

Results are written to a fixed-size buffer and can be extracted via
semihosting (QEMU) or a debug probe (hardware). This feature is used
during safety certification to demonstrate bounded execution time.

## `std`

**Crate:** workspace-wide
**Default:** No (the workspace is `no_std` by default)
**Stability:** Stable

Enables `std`-dependent test utilities: richer assertion messages, thread-
based test parallelism, and filesystem-backed test fixtures. This feature
is available only for host-target test builds and is not compatible with
bare-metal or RTOS targets.

Production builds must never enable this feature. The CI matrix enforces
that all `--target` builds (Cortex-M, AArch64, QNX) compile without `std`.

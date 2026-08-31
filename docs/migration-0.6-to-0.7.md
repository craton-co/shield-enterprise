# Migration Guide: 0.6.x → 0.7.x

This document describes every API change an integrator needs to know
about when moving from `craton-shield-enterprise` 0.6.x to 0.7.x.

0.7 is the last release series before the 0.8 API-freeze push toward
1.0; changes after 0.7.1 are documented in the CHANGELOG's
`[Unreleased]` section.

## At a glance

| Area | 0.6.x | 0.7.x | Action |
|:---|:---|:---|:---|
| Compliance report crates | `crates/reports/*` shipped in enterprise | Moved to [Craton Shield Core](https://github.com/craton-co/craton-shield) (Apache-2.0) | Add `vs-report-*` deps to `core/`, remove from enterprise `Cargo.toml`. |
| Telemetry flush | `TelemetryUplink::flush(&mut self)` returned `()` | Returns `FlushResult { ciphertext, tag, signature, flush_counter }` | Store `flush_counter` to NVRAM before ack. |
| Telemetry nonce counter | `new_with_counter(u64)` | `restore(PersistedFlushCounter)` — `new_with_counter` is `#[deprecated]` | Switch to `restore` + `PersistedFlushCounter::restore(u64)` / `::fresh_device()`. |
| PKCS#11 clone | `impl Clone for Pkcs11CryptoProvider` | Removed (was unsound) + `try_clone(&self, pin) -> Result` | Replace `.clone()` with `.try_clone(pin)?`. |
| TPM clone | `impl Clone` + `unsafe impl Send` | Removed + `try_clone(&self) -> Result` | Replace `.clone()` with `.try_clone()?`; the `Send` bound is gone. |
| PCR extend | Used a type-punning cast to `TpmlPcrSelection` | New `TpmlDigestValues` FFI type | Callers who built PCR extend args by hand must switch struct. |
| PKCS#11 PIN handling | Raw `&[u8]` PIN passed everywhere | `PinBuffer` fixed-size holder, volatile-wipes on drop | Use `PinBuffer::new(...)?` and the `_with_pin_buffer` constructors. |
| MSRV | Rust 1.76 | Rust 1.82 | Bump toolchain. |

## 1. `FlushResult` return shape

The old API:

```rust
uplink.flush(ts_us)?;     // -> Result<(), VsError>
```

The new API:

```rust
let FlushResult { ciphertext, tag, signature, flush_counter } =
    uplink.flush(ts_us)?;
transport.send(&ciphertext, &tag, &signature)?;
nvram_write_flush_counter(flush_counter)?;  // <-- BEFORE acking
```

This is the **ordering invariant that prevents nonce reuse**: persist
`flush_counter` before telling upstream the batch was delivered. See
[operational-security.md §3.3](operational-security.md) for the
compromise playbook if that ordering is violated.

## 2. `PersistedFlushCounter` and `TelemetryUplink::restore`

### Before

```rust
let mut uplink = TelemetryUplink::new_with_counter(
    provider, KeyId(0), KeyId(1), nonce_domain,
    42,                            // raw u64, provenance lost here
);
```

### After

```rust
let counter = match nvram_read_flush_counter()? {
    Some(n) => PersistedFlushCounter::restore(n),
    None    => PersistedFlushCounter::fresh_device(),
};
let mut uplink = TelemetryUplink::restore(
    provider, KeyId(0), KeyId(1), nonce_domain, counter,
);
```

`TelemetryUplink::new_with_counter` is retained with `#[deprecated]`
for one additional minor release. It will be removed in 0.8.0 per
[docs/api-stability.md §Deprecation Process](api-stability.md).

A call to `TelemetryUplink::new()` (zero counter) is only safe on the
**very first boot** of a fresh provisioning — and even then only if the
integrator can prove the device never shipped before. Under the
`strict-nonce` feature flag, `new()` is removed at compile time.

## 3. Clone → `try_clone`

`Pkcs11CryptoProvider` and `TpmCryptoProvider` no longer implement
`Clone`. The 0.6 impls aliased FFI handles in ways that produced
double-close / double-free on drop.

```rust
// 0.6.x
let p2 = provider.clone();                       // UB on drop

// 0.7.x, PKCS#11:
let p2 = provider.try_clone(b"1234")?;           // fresh session, same slot
// 0.7.x, TPM:
let p2 = provider.try_clone()?;                  // fresh ESAPI context
```

The TPM provider is additionally **no longer `Send`**. If you were
sharing it across threads, wrap in a `Mutex` (host Rust), or carry one
provider per task (no_std). See
[crates/crypto-tpm/README.md](../crates/crypto-tpm/README.md) §
Threading.

## 4. PIN hygiene: `PinBuffer`

Raw `&[u8]` PINs were passed through the 0.6 API and could linger in
caller-controlled stack frames after login. 0.7 introduces a
dedicated `PinBuffer` that volatile-wipes in `Drop`:

```rust
use vs_crypto_pkcs11::PinBuffer;

let pin = PinBuffer::new(b"1234")?;                          // validated length
let p   = Pkcs11CryptoProvider::new_with_pin_buffer(fn_list, pin)?;
// `pin` has been consumed and wiped.
```

The raw `&[u8]` constructors (`new`, `try_clone`) are still available
for callers who already manage PIN lifetime in hardware (HSM pinpad,
secure display). Prefer the `PinBuffer` variants for any software path.

## 5. PCR extend

0.6 used a type-punning cast:

```rust
// 0.6.x — wrong layout, undefined behaviour on some TPMs
let sel: TpmlPcrSelection = unsafe { mem::transmute(digests) };
tpm.pcr_extend(pcr, &sel)?;
```

0.7 introduces `TpmlDigestValues` with the correct layout:

```rust
let digests = TpmlDigestValues::with_sha256(&hash)?;
tpm.pcr_extend(pcr, &digests)?;
```

If you were calling the 0.6 PCR extend path directly, the fix is
mechanical: build a `TpmlDigestValues` instead of a `TpmlPcrSelection`.

## 6. Compliance report crates have moved

`vs-report-iec62443`, `vs-report-iso21434`, and `vs-report-iec62304`
were re-licensed to Apache-2.0 and moved to Craton Shield Core.
Integrators who depended on them should:

1. Remove them from `[workspace.dependencies]` in the enterprise root
   `Cargo.toml`.
2. Add them from the core repository:
   ```toml
   vs-report-iec62443 = { path = "../craton-shield/core/report-iec62443" }
   ```
3. Update any examples that live in `core/examples/`.

Nothing in the report crate API changed across the move.

## 7. Fixed security issues that may affect callers

See CHANGELOG entries for 0.7.0 — the ones most likely to surface as a
behavioural difference in calling code are:

- `default_rng()` now rejects all-zero entropy with
  `VsError::CryptoError`. A caller that was relying on the old
  behaviour to boot a test harness must inject a proper RNG or build
  with the `mock-hsm` feature.
- `import_key()` no longer silently drops the `material` argument; a
  caller passing invalid material now receives `VsError::InvalidInput`.
- Boot verification enforces `BootFailurePolicy`; explicit
  `Halt | Rollback | ReportAndContinue` is now required.

## 8. MSRV bump

0.7 requires Rust 1.82 (up from 1.76). Update your `rust-toolchain.toml`
(or CI image) before the enterprise update.

## 9. CI and packaging

- The release workflow now GPG-signs tags and generates SLSA v1.0
  provenance. Packaging scripts that consumed the old unsigned tag
  archives must be updated to verify signatures — see
  [docs/supply-chain.md §5](supply-chain.md).
- The SBOM artifact is now CycloneDX JSON (previously SPDX tag-value);
  `cargo-audit` policy is enforced at push time.

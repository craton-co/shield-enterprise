# API Stability Policy

This document describes the stability guarantees and versioning policy for
Craton Shield Enterprise.

## Semantic Versioning

Craton Shield follows [Semantic Versioning 2.0.0](https://semver.org/).

While the project is at **0.x**, breaking changes may occur between minor
releases (e.g., 0.5 to 0.6). Each breaking change is documented in the
CHANGELOG under a dedicated "Changed" or "Removed" heading. Users should
pin to exact minor versions in safety-critical deployments.

Once the project reaches 1.0, the standard semver contract applies: breaking
changes require a major version bump.

## Stability Tiers

Every public API item belongs to one of three tiers.

### Stable

Items that will not change in backwards-incompatible ways within a major
version (or within a minor version during the 0.x series, barring security
fixes).

- `CryptoProvider` trait and its associated types
- `VsError` enum variants present in the current release
- `HalProvider` traits (`CanBus`, `Timer`, `EthernetPhy`)
- C FFI functions exported in `craton_shield.h`
- `EventLogger` append and verify API
- `PolicyEngine` rule evaluation interface

### Beta

Items that are functional and tested but whose API surface may change based
on user feedback. At least one minor release of deprecation warning will be
provided before removal.

- Report generators (`vs-report`)
- TUF metadata builder utilities
- IDS correlation rule DSL

### Experimental

Items that are under active development and may change or be removed without
prior deprecation. They are gated behind non-default feature flags.

- Post-quantum providers (`pq-software` feature) **[core repo]**: ML-KEM-768, ML-DSA-65
- WCET measurement harness (`wcet` feature) **[core repo]**
- Upcoming V2X protocol support

Experimental items are excluded from semver guarantees entirely. Do not use
them in production without accepting the risk of breaking changes.

## Deprecation Process

1. The item is marked `#[deprecated(since = "...", note = "...")]` with a
   message describing the replacement.
2. The deprecation is listed in the CHANGELOG for the release.
3. The deprecated item remains functional for at least one additional minor
   release.
4. The item is removed in a subsequent minor (0.x) or major (1.x+) release,
   documented under "Removed" in the CHANGELOG.

Deprecations triggered by security vulnerabilities may bypass the one-release
grace period if continued use poses a safety risk. Such cases will be
documented in a security advisory.

## FFI ABI Stability

The C FFI surface (`vs-ffi` (defined in `craton-shield-core`)) provides the following guarantees:

> **Note:** The `vs-ffi` crate and `craton_shield.h` header are part of
> [Craton Shield Core](https://github.com/craton-co/craton-shield), not this
> enterprise repository. The guarantees below apply to the core FFI surface.
> Enterprise crates expose their functionality through the same `CryptoProvider`
> trait and are consumed indirectly via `vs-ffi`.

- Function signatures in `craton_shield.h` are stable within a minor version.
- Struct layout uses `#[repr(C)]` and will not change within a minor version.
- Enum discriminant values are fixed once published.
- New functions may be added in minor releases without breaking existing
  callers.
- Symbol visibility follows the export list in the linker script; internal
  symbols are not part of the ABI.

Callers linking against the shared library should use the versioned soname
(e.g., `libcraton_shield.so.0.6`) to avoid loading an incompatible version
at runtime.

## Enterprise-Local FFI Types

Enterprise crates do **not** export their own C shared library, but they
publish a small number of `#[repr(C)]` types that are part of an
in-process ABI between the integrator binary and the Rust provider. The
same semver rules as the core `vs-ffi` surface apply.

| Type | Crate | Role |
|:---|:---|:---|
| `Pkcs11FunctionList` | `vs-crypto-pkcs11` | Holds caller-supplied PKCS#11 `C_*` function pointers. |
| `TpmFunctionList` | `vs-crypto-tpm` | Holds caller-supplied TSS2 ESAPI `Esys_*` function pointers. |
| `PinBuffer` | `vs-crypto-pkcs11` | Fixed-size PIN container with volatile drop. |
| `TelemetryEntry` | `vs-vsoc-telemetry` | Fixed-layout entry written to the uplink chain. |
| `FlushResult` | `vs-vsoc-telemetry` | Return shape of `TelemetryUplink::flush`. |
| `PersistedFlushCounter` | `vs-vsoc-telemetry` | Newtype over the persisted nonce counter. |

### Guarantees

Within a minor (0.x) release:

- Field order is frozen; no new fields are added to existing structs.
- Field sizes are frozen; a `u32` does not widen to `u64`.
- Function-pointer signatures in `Pkcs11FunctionList` / `TpmFunctionList`
  are frozen. If a new mechanism requires a new entry point, it is added
  as a new field at the end of the struct in a **minor** release; older
  callers that ignore the trailing field continue to link and run. Struct
  size is therefore non-decreasing across minor versions within a major
  release; integrators should size the struct via `mem::size_of` at
  assembly time and check it against `const _: () = assert!(size == N)`
  upstream.

### What is not covered

- Rust symbol names (Rust has no stable Rust-ABI). All cross-FFI callers
  must reach these types through the `#[repr(C)]` layout and explicit
  `extern "C"` function pointers, not through linkname.
- Internal field values inside opaque handles (`EsysTr`, `CkSessionHandle`)
  are owned by the HSM/TPM and have no stability contract beyond "opaque
  integer that the token understands."

### Bumping the ABI

A breaking change to any of the types above — removing a field,
reordering, narrowing a type, or changing a function-pointer signature —
requires a minor version bump during 0.x (a major bump post-1.0) and a
`### Removed` / `### Changed` entry in the CHANGELOG that calls out the
exact struct and field.

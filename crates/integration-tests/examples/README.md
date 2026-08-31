# Examples

Short orientation programs for the Craton Shield Enterprise workspace.
They print a walkthrough of the production integration steps and report
the on-stack sizes of the provider / function-list types, so readers can
budget memory before wiring up real hardware. They are orientation
material — not executable end-to-end demonstrations.

The executable tests live in the crate test suites
(`cargo test --workspace`), which exercise the full provider API through
the same in-process mocks used by these examples' authors.

## What each example prints

| Example | What it prints | Run |
|:---|:---|:---|
| `pkcs11_mock_setup` | The steps a real caller performs to load a PKCS#11 library via `dlopen` / `dlsym`, populate a `Pkcs11FunctionList`, and construct a `Pkcs11CryptoProvider`. Reports `size_of::<Pkcs11CryptoProvider>` and `size_of::<Pkcs11FunctionList>`. | `cargo run --example pkcs11_mock_setup` |
| `tpm_mock_setup` | The steps a real caller performs to bind TSS2 ESAPI entry points into a `TpmFunctionList` and construct a `TpmCryptoProvider`. Reports `size_of::<TpmCryptoProvider>` and `size_of::<TpmFunctionList>`. | `cargo run --example tpm_mock_setup` |
| `telemetry_uplink` | The shape of a `TelemetryEntry` and the production flow around `TelemetryUplink::restore` / `submit` / `flush`. Reports the `size_of` for those types. | `cargo run --example telemetry_uplink` |

## Why orientation and not end-to-end demos?

The real HSM, TPM and QNX integrations are hardware-bound. The
workspace's unit-test suites already exercise every provider code path
through in-process mocks, so duplicating that coverage in the examples
directory would add noise without insight. Integrators should read
these examples first to understand the shape of the API, then follow
[INSTALL.md](../INSTALL.md) and
[docs/getting-started.md](../docs/getting-started.md) to wire up
SoftHSM2 / swtpm / QNX SDP. For the open-source detection, firewall,
IDS, and compliance-report crates see the
[Craton Shield Core](https://github.com/craton-co/craton-shield)
repository (Apache-2.0).

## Core compliance-report examples

The compliance-report examples (`tara_report`, `iec62443_assessment`,
`iec62304_traceability`) moved with the open-source report crates to
[Craton Shield Core](https://github.com/craton-co/craton-shield) under
the Apache-2.0 licence. See that repository's
[`ARCHITECTURE.md`](https://github.com/craton-co/craton-shield/blob/main/ARCHITECTURE.md)
for the crate layout and
[`examples/README.md`](https://github.com/craton-co/craton-shield/tree/main/examples)
for runnable demos of the detection and report pipelines.

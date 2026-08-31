# Fuzzing

Last reviewed: **2026-05-10**.

Craton Shield Enterprise uses [`cargo-fuzz`](https://rust-fuzz.github.io/book/)
(libFuzzer) to harden the parsers and state machines that sit on a
trust boundary. This document covers how to install the tooling, run
a target, manage corpora, and triage crashes — plus a current
inventory of targets and known gaps.

## 1. Install

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

`cargo-fuzz` requires a nightly toolchain because libFuzzer is
distributed as a sanitizer-instrumented runtime that needs nightly
codegen flags.

## 2. Run a target

```bash
cd fuzz
cargo +nightly fuzz run telemetry_entry
```

To bound the run:

```bash
cargo +nightly fuzz run telemetry_entry -- -max_total_time=300 -rss_limit_mb=4096
```

CI runs each target for 5 minutes per push and 60 minutes per nightly
(see [docs/build-matrix.md §6](build-matrix.md)).

## 3. Corpora

Seed corpora live next to the targets:

```
fuzz/corpus/<target>/
```

To add a seed input by hand:

```bash
printf '\x00\x01\x02' > fuzz/corpus/telemetry_entry/seed-001
```

To minimise a corpus after a long run:

```bash
cargo +nightly fuzz cmin telemetry_entry
```

Coverage-guided merging into the upstream seed set should be done as
a separate commit, with the merged corpus pushed under
`fuzz/corpus/<target>/` so subsequent CI runs benefit from it.

## 4. Triaging a crash

When libFuzzer finds an input that crashes the target, it writes the
input to `fuzz/artifacts/<target>/crash-<hash>` and aborts. To
reproduce:

```bash
cargo +nightly fuzz run telemetry_entry fuzz/artifacts/telemetry_entry/crash-<hash>
```

To minimise the reproducer:

```bash
cargo +nightly fuzz tmin telemetry_entry fuzz/artifacts/telemetry_entry/crash-<hash>
```

Open a security advisory via the
[GitHub Security Advisory form](https://github.com/craton-co/craton-shield-enterprise/security/advisories/new)
before pushing the crash artefact to a public branch — see
[SECURITY.md](../SECURITY.md).

## 5. Current targets

| Target | Coverage |
|:---|:---|
| `can_frame` | CAN frame parser (`vs-hal`). |
| `eth_packet` | Ethernet frame parser (`vs-hal`). |
| `ota_metadata` | TUF root JSON (core). |
| `tara_input` | TARA report generator input (core). |
| `iec62304_input` | IEC 62304 report input (core). |
| `iec62443_capabilities` | IEC 62443 capabilities (core). |
| `telemetry_entry` | `TelemetryEntry` ser/deser path. |
| `uds_request` | UDS diagnostic frame parser. |
| `pkcs11_mock_crypto` | `PinBuffer` and PKCS#11 mock surface. |
| `tpm_ec_point` | P-256 uncompressed-point shape handling. |

## 6. Known gaps

- The PKCS#11 attribute parser (`C_GetAttributeValue` response
  decoding inside `vs-crypto-pkcs11`) is not yet fuzzed. Adding a
  `pkcs11_attribute` target is tracked in the backlog.
- The telemetry flush state machine (counter advance, AAD assembly,
  back-pressure transitions in `vs-vsoc-telemetry`) is exercised only
  through the `telemetry_entry` ser/deser surface; a stateful target
  driving the `flush()` machine end-to-end is planned.
- TSS2 ESAPI response decoding in `vs-crypto-tpm` is not fuzzed — the
  parsed structures come from a trusted local TPM, but a stateful
  target that injects arbitrary `Esys_*` return shapes would catch
  layout regressions.

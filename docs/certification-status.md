# Certification Status

This document tracks Craton Shield Enterprise's posture against the
standards it is **designed to support**. It is not a claim of
certification — certification applies to finished products, not to
components — but it records which clauses the codebase implements, which
are the integrator's responsibility, and where independent audit
evidence exists.

Last reviewed: **2026-05-23**, against release **`v0.7.2` — audit-fixes
closed**. The 0.7.2 release closes the CRIT-/HIGH-/MED-/LOW-tier
findings from the internal certification-readiness audit; see the
CHANGELOG `[0.7.2]` section for the per-finding mapping.

## Reading the tables

| Mark | Meaning |
|:---|:---|
| ✅ Implemented | In-tree code or process demonstrably satisfies the clause. |
| 🟡 Partial | Implemented for the common case; edge cases or non-software clauses left to integrator. |
| ⚪ Integrator | Clause is inherently product-level; the component ships the hooks but the finished system must claim it. |
| ❌ Not yet | Planned; see ROADMAP. |
| N/A | Out of scope for a software component. |

## 1. ISO/SAE 21434 — Road vehicles cybersecurity engineering

The primary standard for automotive. Craton Shield Enterprise is
designed to drop into a 21434-aligned OEM process.

| Clause | Topic | Status | Evidence |
|:---|:---|:---|:---|
| 5 | Organizational cybersecurity management | N/A | Integrator process. |
| 6 | Project-dependent cybersecurity management | ⚪ Integrator | Component interface. |
| 7 | Continual cybersecurity activities | 🟡 Partial | [SECURITY.md](../SECURITY.md) vulnerability process, [docs/supply-chain.md](supply-chain.md) monitoring. |
| 8 | Risk assessment methods | ✅ Implemented | [docs/threat-model.md](threat-model.md) STRIDE + TARA generator in core. |
| 9 | Concept | ⚪ Integrator | Vehicle-level concept. |
| 10 | Product development | ✅ Implemented | no_std codebase, unit + fuzz + fault-injection, CI gates. |
| 11 | Cybersecurity validation | 🟡 Partial | Unit + integration + fuzz covers component; vehicle-level validation on integrator. |
| 12 | Production | ⚪ Integrator | Provisioning ceremony documented in [docs/operational-security.md §1](operational-security.md). |
| 13 | Operations and maintenance | 🟡 Partial | Key rotation + IR runbooks in [docs/operational-security.md](operational-security.md). |
| 14 | End of cybersecurity support | 🟡 Partial | Support window in [docs/release-process.md §2](release-process.md). |
| 15 | Threat analysis and risk assessment (TARA) | ✅ Implemented | TARA report generator ships in core, consumed by fuzz target `tara_input`. |

**Audit evidence:** No third-party ISO 21434 audit has been completed on
Craton Shield as of 2026-05-10. Independent audits are planned with
reputable third parties; specific engagements will be announced after
contracts execute.

## 2. UN-R155 (Type approval for cybersecurity management)

Regulatory approval applies to vehicles, not components. The
enterprise crates provide the technical controls the OEM cites in its
CSMS submission:

| Annex 5 threat class | Control shipped |
|:---|:---|
| Back-end server threats | TLS/mTLS handled by transport layer; telemetry signs with ECDSA before send. |
| Communication channel threats | AES-GCM + HMAC-SHA-256 (ETM on TPM path). |
| Update procedure threats | TUF metadata validation (core), PCR-bound attestation (TPM). |
| Unintended human action threats | N/A (HMI). |
| External connectivity threats | Firewall, IDS, policy engine (core). |
| Vehicle data integrity threats | Tamper-evident HMAC chain event logger (core). |

No type-approval claim is made by Craton.

## 3. ISO 26262 — Functional safety

Cybersecurity components are not themselves ASIL-rated, but Craton
Shield targets **ASIL-B integration guarantees** (freedom from
interference with the safety path).

| Clause | Topic | Status | Evidence |
|:---|:---|:---|:---|
| Part 6 §5 | Software unit design and implementation | ✅ Implemented | `#![no_std]`, fixed-size buffers (max 2048), no heap, no `.unwrap()`, every `unsafe` has `// SAFETY:`. |
| Part 6 §6 | Software unit verification | ✅ Implemented | 432+ unit + integration tests across the enterprise crates after the 0.7.2 audit fixes (HIGH-Y, HIGH-PKCS11, HIGH-TPM, HAL-QNX HIGH batches each added negative-path tests); 85% per-crate coverage floor via `cargo-llvm-cov`. |
| Part 6 §7 | Software integration and verification | ⚪ Integrator | Integrator assembles and tests the safety-critical binary. |
| Part 6 §8 | Testing of the embedded software | 🟡 Partial | Fuzz suite (`can_frame`, `eth_packet`, `ota_metadata`, `tara_input`, `iec62304_input`, `iec62443_capabilities`, `telemetry_entry`, `uds_request`, `pkcs11_mock_crypto`, `tpm_ec_point` (MED-9: real `validate_ec_point` harness, commit `5b565c8`), `qnx_can_parse`, `qnx_eth_parse` (MED-10: wired into CI matrix, commit `4a246c9`)). |
| Part 6 §9 | Static aspects | ✅ Implemented | `clippy -D warnings` + `cargo deny check` (now pinned in workflows per MED-3 / MED-8, commits `026427f`/`cce31af`; `deny.toml` policy refreshed with the 0.7.2 audit-fix release). |
| Part 6 §10 | Dynamic aspects | 🟡 Partial | Fuzz + reproducible builds + nightly `cargo miri test` for `unsafe`-FFI UB detection (LOW-8, commit `4e3ad11`); HIL-level WCET validation pending (see [docs/wcet.md](wcet.md)). |
| Part 11 §6 | MCU-specific considerations | 🟡 Partial | `thumbv7em-none-eabihf` build validated; no official Cortex-M integration tests. |

**Freedom from interference:** No enterprise crate allocates, runs
unbounded loops, or panics in production; see [CLAUDE.md](../CLAUDE.md)
for the invariants the CI enforces.

## 4. AUTOSAR Adaptive (AP) R22-11

| Stereotype | Status |
|:---|:---|
| AUTOSAR manifest (ARXML) | ✅ Ships in core. |
| `ara::crypto::CryptoProvider` mapping | ✅ Implemented via `Pkcs11CryptoProvider` / `TpmCryptoProvider`. |
| `ara::com` (SOME/IP) transport | ⚪ Integrator |
| `ara::log` adapter | ⚪ Integrator |

## 5. IEC 62443 — Industrial IoT / OT

Targeting **IEC 62443-4-1 (secure development lifecycle)** and
**IEC 62443-4-2 (technical security requirements for components)** in
Q4 2027.

| Requirement family | Status | Notes |
|:---|:---|:---|
| SDR (secure dev. requirements) | 🟡 Partial | [docs/supply-chain.md](supply-chain.md), [CONTRIBUTING.md](../CONTRIBUTING.md). |
| CR 1 (identification & auth) | ✅ Implemented | HSM/TPM-backed identities. |
| CR 2 (use control) | ⚪ Integrator | Application-layer. |
| CR 3 (system integrity) | ✅ Implemented | Secure boot, PCR attestation, event log. |
| CR 4 (data confidentiality) | ✅ Implemented | AES-GCM (HSM) / AES-CFB+HMAC (TPM). |
| CR 5 (restricted data flow) | ⚪ Integrator | Firewall and policy engine (core) provide primitives. |
| CR 6 (timely response to events) | ✅ Implemented | Tamper-evident event logger, telemetry uplink. |
| CR 7 (resource availability) | ✅ Implemented | Rate-limited flush, bounded buffers. |

## 6. IEC 62304 — Medical device software

Targeting **Class B** in Q3 2027.

| Clause | Topic | Status |
|:---|:---|:---|
| 5.1 Software development planning | ⚪ Integrator | Document integrator plan. |
| 5.2 Software requirements analysis | 🟡 Partial | Per-crate READMEs, trait docs. |
| 5.3 Software architectural design | ✅ Implemented | [ARCHITECTURE.md](../ARCHITECTURE.md). |
| 5.4 Detailed design | ✅ Implemented | Rustdoc per item. |
| 5.5 Implementation | ✅ Implemented | no_std, unit-tested. |
| 5.6 Integration and integration testing | 🟡 Partial | Mock-based integration in `fuzz/` and crate tests. |
| 5.7 System testing | ⚪ Integrator | |
| 5.8 Release | ✅ Implemented | [docs/release-process.md](release-process.md). |
| 7 Risk management | ✅ Implemented | [docs/threat-model.md](threat-model.md). |
| 8 Configuration management | ✅ Implemented | Signed tags, locked `Cargo.lock`. |
| 9 Problem resolution | ✅ Implemented | Security advisories, CHANGELOG. |

## 7. FDA Cybersecurity Guidance (2023)

Targeting compliance alongside IEC 62304 Class B in Q3 2027.

Key asks (SBOM, vulnerability disclosure, update plan, secure
communications) are already satisfied by
[docs/supply-chain.md](supply-chain.md) and
[SECURITY.md](../SECURITY.md).

## 8. IEC 61508 — Industrial functional safety

Targeting **SIL 2** in Q1 2028. Uses the same
`#![no_std]`-no-heap-no-panic invariants as the ISO 26262 effort; the
main additional work is producing compiler qualification evidence for
the selected `rustc` version. We pin MSRV to 1.82 for the certification
baseline; updates are batched and tested on a rolling schedule per
[docs/release-process.md](release-process.md). (Rust upstream does not
designate formal LTS releases; we treat 1.82 as our internal
long-stability target rather than relying on any upstream LTS status.)

## 9. DO-178C — Airborne software

Targeting **DAL C** in Q2 2028. Rust for avionics is an emerging
story; Craton is tracking the
[Ferrocene](https://ferrous-systems.com/ferrocene/) qualification
effort and will reuse whichever artifact set is accepted by the
certifier at the time.

## 10. TUF / Uptane

| Role | Status |
|:---|:---|
| Root metadata validation | ✅ Implemented (core). |
| Timestamp / snapshot / targets delegation | ✅ Implemented (core). |
| Content hash verification | ✅ Implemented (core, `parse_tuf_root_with_hash`). |
| Director + image repo split (Uptane) | ⚪ Integrator | Update server topology. |

## 11. Third-party audits

Independent audits are planned with reputable third parties; specific
engagements (firm, scope, and dates) will be announced after contracts
execute. Results will be linked from this document as they become
available.

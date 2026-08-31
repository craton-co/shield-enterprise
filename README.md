# Craton Shield Enterprise

**Production hardening for Craton Shield: hardware-backed cryptography, QNX RTOS, and fleet telemetry.**

[![License](https://img.shields.io/badge/license-BSL--1.1-orange.svg)](LICENSE)
[![CI](https://github.com/craton-co/craton-shield-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/craton-co/craton-shield-enterprise/actions/workflows/ci.yml)
[![Security](https://github.com/craton-co/craton-shield-enterprise/actions/workflows/security.yml/badge.svg)](https://github.com/craton-co/craton-shield-enterprise/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/craton-co/craton-shield-enterprise/badge)](https://api.securityscorecards.dev/projects/github.com/craton-co/craton-shield-enterprise)

<!-- The OpenSSF Scorecard badge will be live only after the Scorecard
     workflow has run at least once on the public repository. -->


> ⚠️ **License: Business Source License 1.1 — NOT an OSI-approved open-source licence.**
> Non-production use (evaluation, research, development) is free; production
> use requires a commercial licence until **2030-09-01**, when the code
> automatically re-licenses under Apache-2.0. See [LICENSE](LICENSE),
> [`docs/licensing.md`](docs/licensing.md), or contact
> [license@craton.com.ar](mailto:license@craton.com.ar). The open-source core
> of the platform lives in [Craton Shield Core](https://github.com/craton-co/craton-shield)
> under Apache-2.0.

> **Status:** v0.7.1

## What's Included

Everything in [Craton Shield Core](https://github.com/craton-co/craton-shield)
(Apache-2.0, 21 crates including software crypto and compliance reports), plus:

| Module | Crate | Capability |
|:---|:---|:---|
| **PKCS#11 Crypto Provider** | vs-crypto-pkcs11 | AES-256-GCM, SHA-256, ECDSA P-256, HMAC, ECDH via any PKCS#11 HSM (SoftHSM2, Thales Luna, Utimaco, NXP SE050) |
| **TPM 2.0 Crypto Provider** | vs-crypto-tpm | AES-CFB+HMAC, SHA-256, ECDSA P-256, ECDH, TRNG via TPM 2.0 (hardware TPM, swtpm, fTPM); PCR extend/read extensions |
| **QNX HAL** | vs-hal-qnx | QNX Neutrino RTOS integration — Timer, CAN, Ethernet (production on QNX 7.1 aarch64) |
| **Telemetry Uplink** | vs-vsoc-telemetry | AES-GCM + ECDSA encrypted batch, VSOC protocol |

### Free vs Enterprise

| Capability | Free (Apache-2.0) | Enterprise (BSL-1.1) |
|:---|:---|:---|
| **Crypto** | `RustCryptoProvider` — software AES-GCM, ECDSA, ECDH | `Pkcs11CryptoProvider`, `TpmCryptoProvider` — hardware HSM/TPM |
| **Compliance** | IEC 62443, ISO 21434, IEC 62304 report generators | — |
| **Platform** | Linux HAL, all detection/monitoring/policy crates | QNX HAL, VSOC telemetry |
| **Fleet ops** | — | SIEM connectors, fleet correlator (roadmap) |

## Licensing

This software is licensed under the **Business Source License 1.1** (BSL).

- **Non-production use** is free (evaluation, testing, research, development).
- **Production use** requires a commercial license from Craton Software Company.
- On **2030-09-01**, the license automatically converts to **Apache-2.0**.

### Commercial License

Contact [license@craton.com.ar](mailto:license@craton.com.ar) for commercial licensing,
integration consulting, and certification support.

## Quick Start

```bash
# Build all enterprise crates
cargo build --release --workspace

# Run all tests
cargo test --workspace
```

## Standards Alignment

### Automotive (Current)

| Standard | Status |
|:---|:---|
| **ISO/SAE 21434** | Designed to support (not certified) |
| **UN R155** | Technical controls implemented (no type approval claimed) |
| **ISO 26262 ASIL-B** | Targeting ASIL-B; no formal certification achieved yet |
| **AUTOSAR AP R22-11** | ARXML manifest provided |
| **ISO 14229** | SecurityAccess (0x27) |
| **TUF/Uptane** | Canonical JSON via `json` feature **[core repo]** |

### Multi-Domain (Planned)

| Standard | Domain | Target |
|:---|:---|:---|
| **IEC 62304 Class B** | Medical devices | Q3 2027 |
| **FDA Cybersecurity Guidance** | Medical devices | Q3 2027 |
| **IEC 62443-4-1/-4-2** | Industrial IoT / OT | Q4 2027 |
| **IEC 61508 SIL 2** | Industrial functional safety | Q1 2028 |
| **DO-178C DAL C** | Avionics / defense | Q2 2028 |

## Documentation

### Start here

- [docs/getting-started.md](docs/getting-started.md) — single linear walkthrough from a clean machine to a live SoftHSM2 + swtpm + telemetry loop
- [INSTALL.md](INSTALL.md) — per-platform build & deployment instructions
- [ARCHITECTURE.md](ARCHITECTURE.md) — component diagram and crate boundaries
- [examples/README.md](examples/README.md) — orientation programs

### Operate

- [docs/operational-security.md](docs/operational-security.md) — key-rotation and IR playbooks
- [docs/hardware-compatibility.md](docs/hardware-compatibility.md) — tested HSMs, TPMs, and BSPs
- [docs/release-process.md](docs/release-process.md) — release runbook and support window
- [docs/migration-0.6-to-0.7.md](docs/migration-0.6-to-0.7.md) — upgrade notes for 0.6.x callers
- [SUPPORT.md](SUPPORT.md) — support tiers and contacts

### Secure & comply

- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [docs/threat-model.md](docs/threat-model.md) — STRIDE threat model
- [docs/supply-chain.md](docs/supply-chain.md) — SBOM, deny policy, release signing
- [docs/crypto-agility.md](docs/crypto-agility.md) — primitive matrix, FIPS mapping, PQC plan
- [docs/certification-status.md](docs/certification-status.md) — posture against ISO 21434, ISO 26262, IEC 62443, IEC 62304, DO-178C
- [docs/licensing.md](docs/licensing.md) — licence terms, change date, commercial use

### Reference

- [ROADMAP.md](ROADMAP.md) — delivered work and planned milestones
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [docs/api-stability.md](docs/api-stability.md) — API stability tiers and ABI rules
- [docs/feature-flags.md](docs/feature-flags.md) — Cargo feature flags
- [docs/build-matrix.md](docs/build-matrix.md) — CI matrix, MSRV, target triples
- [docs/porting-guide.md](docs/porting-guide.md) — porting to new platforms
- [docs/performance.md](docs/performance.md) — performance reference
- [docs/wcet.md](docs/wcet.md) — WCET analysis

## Performance

The benchmarks below are measured on the **[Craton Shield Core](https://github.com/craton-co/craton-shield)**
detection, firewall, policy, and runtime crates (Apache-2.0). They are
reproduced here because those crates are the hot path on any vehicle that
also deploys the enterprise crypto / HAL / telemetry layers. Enterprise-
specific measurements (PKCS#11 roundtrip, TPM ETM tag, telemetry flush)
are platform-bound and tracked in [docs/wcet.md](docs/wcet.md) and
[docs/performance.md](docs/performance.md).

| Benchmark (core) | x86_64 | QEMU aarch64 |
|:---|---:|---:|
| CAN frame (5 detectors) | ~464 ns | ~1,960 ns |
| Firewall (128 rules) | ~1,286 ns | ~4,290 ns |
| Policy engine (64 rules) | ~469 ns | ~5,391 ns |
| Runtime tick | ~76 ns | ~243 ns |

*QEMU aarch64 numbers are approximate (non-deterministic instruction-timing emulation); use only for trend analysis, never for WCET safety cases. See [docs/performance.md](docs/performance.md) for methodology.*

All operations within 10 us CAN gateway budget.

## License

```
Copyright 2026 Craton Software Company
SPDX-License-Identifier: BSL-1.1
Change-Date: 2030-09-01
Change-License: Apache-2.0
```

# Enterprise Roadmap

Planned enterprise crates (BSL-1.1). Enterprise adds production hardening
(hardware HSM/TPM crypto), fleet operations, and SIEM integration on top
of the free Apache-2.0 core (which includes software crypto, compliance
reports, and all detection/monitoring modules).

---

## Phase E1 — Real Crypto Providers ✓ Shipped v0.7.0

| Crate | Description | Status |
|:---|:---|:---|
| **vs-crypto-pkcs11** | PKCS#11 backend for vs-crypto: AES-GCM, ECDSA P-256, ECDH via hardware HSM tokens (SoftHSM, Thales Luna, Utimaco) | **Done** |
| **vs-crypto-tpm** | TPM 2.0 backend for vs-crypto: AES-CFB+HMAC, ECDSA P-256, ECDH, PCR extend/read via TSS2 ESAPI | **Done** |

**Rationale:** The free tier includes `RustCryptoProvider` (software-only,
production-safe). Enterprise adds hardware-backed crypto for deployments
requiring FIPS 140-2/3 compliance or tamper-resistant key storage.

**Priority:** High — blocks every other production deployment.

---

## Phase E2 — Compliance Report Generators → Moved to Core (Apache-2.0)

The three compliance report crates (vs-report-iec62443, vs-report-iso21434,
vs-report-iec62304) have been moved to the free tier in `craton-shield-core`
to drive adoption. They are now Apache-2.0 licensed.

See [craton-shield-core](https://github.com/craton-co/craton-shield) for these crates.

---

## Phase E3 — SIEM / SOC Connectors

| Crate | Description |
|:---|:---|
| **vs-siem-splunk** | Splunk HTTP Event Collector (HEC) adapter. Transforms `SecurityAlert` into Splunk CIM-compliant JSON, batched delivery with backpressure. |
| **vs-siem-sentinel** | Azure Sentinel / Microsoft Defender for IoT connector. CEF-formatted syslog output for OT environments. |
| **vs-siem-syslog** | RFC 5424 syslog-ng / rsyslog adapter. Structured data with IETF SD-IDs for alert metadata. |
| **vs-siem-kafka** | MQTT-to-Kafka bridge for fleet-scale telemetry pipelines. Avro-serialized alert streams with schema registry support. |

**Rationale:** Single-device telemetry (vs-vsoc-telemetry) is included in
the base enterprise tier.  Fleet-scale observability integration into
existing SOC tooling is what enterprises actually purchase.

**Priority:** Medium — needed for fleet deployments but not for initial
single-device sales.

---

## Phase E4 — Multi-Device Correlation

| Crate | Description |
|:---|:---|
| **vs-fleet-correlator** | Cross-device alert correlation engine. Aggregates `SecurityAlert` streams from multiple devices, detects fleet-wide anomaly patterns (e.g., coordinated CAN injection across vehicles, widespread firmware rollback attempts). Statistical clustering with configurable time windows. |

**Rationale:** `vs-ids-engine` correlates CAN + Ethernet on a single device.
Fleet operators need to detect coordinated attacks that only become visible
across multiple endpoints.  This is clearly enterprise-scale functionality.

**Priority:** Medium — requires SIEM connectors (Phase E3) as transport
layer.

---

## Phase E5 — Encrypted Storage Provider

| Crate | Description |
|:---|:---|
| **vs-storage-encrypted** | Encrypted backend for `vs-storage`. AES-256-GCM at-rest encryption for key-value store, key-wrapping via `CryptoProvider`, secure erase on zeroization. |

**Rationale:** `vs-storage` is "unencrypted by default, optional encryption."
The encrypted backend depends on a real `CryptoProvider` (Phase E1) and is
a natural enterprise add-on.

**Priority:** Medium — depends on Phase E1.

---

## Phase E6 — AUTOSAR Adaptive Integration

| Crate | Description |
|:---|:---|
| **vs-autosar-adaptive** | Full AUTOSAR Adaptive Platform (AP R22-11) integration: `ara::com` service discovery and method/event/field bindings, `ara::diag` diagnostic management, `ara::per` persistency integration. Extends the existing AUTOSAR Classic stubs in the free automotive tier. |

**Rationale:** The free tier includes AUTOSAR Classic SecOC stubs.  Full
Adaptive platform integration requires significant engineering effort and
targets OEMs / Tier-1s who are already committed to AUTOSAR AP — a purely
enterprise audience.

**Priority:** Low — niche audience, high engineering cost.  Build on demand
when a customer requires it.

---

## Existing Enterprise Crates

| Crate | Status | Notes |
|:---|:---|:---|
| **vs-hal-qnx** | Production (QNX 7.1 aarch64) | QNX Neutrino RTOS HAL — Timer, CAN, Ethernet I/O. CAN bus-off / link-state detection is gated behind the `qnx-link-detect` cargo feature pending caller-supplied SDP-verified devctl numbers. |
| **vs-vsoc-telemetry** | Functional | VSOC telemetry uplink with ring-buffer batching, rate limiting, AES-GCM encryption, and ECDSA signing. Transport layer is caller-provided. SIEM connectors (Phase E3) extend this. |

---

## Ordering Summary

| Phase | Crates | Priority | Target | Depends On |
|:---|:---|:---|:---|:---|
| E1 | vs-crypto-pkcs11, vs-crypto-tpm | ✓ Done | Q1 2026 (shipped v0.7.0) | — |
| E2 | ~~vs-report-*~~ | Moved to core | N/A | — |
| E3 | vs-siem-splunk, vs-siem-sentinel, vs-siem-syslog, vs-siem-kafka | Medium | Q4 2026 | vs-vsoc-telemetry |
| E4 | vs-fleet-correlator | Medium | Q1 2027 | E3 |
| E5 | vs-storage-encrypted | Medium | Q2 2027 | E1 |
| E6 | vs-autosar-adaptive | Low | On demand | — |

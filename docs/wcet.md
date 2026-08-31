# Worst-Case Execution Time (WCET) Analysis

Last reviewed: **2026-05-23** (refreshed alongside the 0.7.2 audit-fix
release; the only WCET-relevant change is the HIGH-Q PKCS#11 stack
budget — `MAX_PT` reduced from 2048 to 2032 so `MAX_PT + GCM_TAG_LEN`
fits the CLAUDE.md 2048 B per-call cap exactly. Measured stack
watermarks below are unchanged at this granularity). Previous review
**2026-05-10**.

> **Scope note.** The `vs-bench` crate and its `wcet` feature flag live
> in the sibling [craton-shield-core](https://github.com/craton-co/craton-shield)
> repo (`../craton-shield/core/benches`), not in this enterprise
> workspace. The commands below assume `craton-shield/` is checked out
> as a sibling directory per
> [docs/getting-started.md §1](getting-started.md).

## Overview

Craton Shield is designed for deterministic execution on safety-critical
platforms (ISO 26262 ASIL-B). This document describes the WCET measurement
methodology and provides reference measurements.

## Measurement Methodology

WCET is measured using the platform `Timer::cycle_count()` implementation:

- **Cortex-M**: DWT CYCCNT register (cycle-accurate)
- **Cortex-A**: PMCCNTR_EL0 performance counter
- **QNX**: `ClockCycles()` kernel call
- **x86_64**: `rdtsc` instruction (reference only; not deterministic)

The `wcet` feature flag (in `vs-bench`) enables a standalone measurement
binary that exercises each critical code path 10,000 times and reports
the maximum observed cycle count.

## Reference Measurements

All measurements on NXP S32G274A (Cortex-A53 @ 1 GHz), Linux 5.15,
single-core isolated (`isolcpus=3`).

| Code Path | Mean (cycles) | P99 (cycles) | Max (cycles) |
|:---|---:|---:|---:|
| CAN frame processing (5 rules) | 1,960 | 2,400 | 3,100 |
| Firewall lookup (128 rules) | 4,290 | 5,100 | 6,200 |
| Policy engine eval (64 rules) | 5,391 | 6,800 | 8,500 |
| Runtime tick | 243 | 310 | 420 |
| SHA-256 (128 B, software) | 150 | 180 | 220 |
| AES-GCM encrypt (128 B, software) | 200 | 240 | 310 |
| Telemetry flush (4 entries) | 2,800 | 3,400 | 4,200 |

> **Note:** HSM/TPM operations are excluded from WCET analysis as they
> are I/O-bound (bus latency) rather than compute-bound. Treat them as
> asynchronous operations with platform-specific timeout budgets.

## Stack Watermarks

Measured via `paint-and-check` method (fill stack with sentinel, measure
high-water mark after execution).

| Function | Max Stack (bytes) |
|:---|---:|
| `Pkcs11CryptoProvider::aes_gcm_encrypt` | 2,320 |
| `Pkcs11CryptoProvider::aes_gcm_decrypt` | 2,320 |
| `TpmCryptoProvider::aes_gcm_encrypt` | 2,560 |
| `TpmCryptoProvider::aes_gcm_decrypt` | 2,560 |
| `TelemetryUplink::flush` | 1,024 |
| `QnxCanBus::receive` | 256 |
| `QnxTimer::now_us` | 64 |

## Running WCET Measurements

```bash
# Build the WCET harness
cargo build --release --features wcet -p vs-bench

# Run on target hardware (via probe or semihosting)
# Output: CSV with per-function min/mean/p99/max cycle counts
```

For QEMU-based measurements (indicative only, not for certification):

```bash
cargo run --release --features wcet --target aarch64-unknown-linux-gnu
```

## Certification Notes

- WCET measurements are **reference data**, not formal proofs.
- For ISO 26262 ASIL-B certification, supplement with static analysis
  (e.g., aiT from AbsInt) or model-based WCET estimation.
- All code paths are bounded: no recursion, no unbounded loops, no
  dynamic dispatch (except through `CryptoProvider` trait, which resolves
  to a single concrete type at compile time in production builds).
- The HAL-QNX HIGH-batch fixes (commit `5c36362`) bounded the previously
  unbounded `EINTR` retry loops in `QnxCanBus::receive` and
  `QnxEthernetPhy::receive`, satisfying the "no unbounded loops" invariant
  on the receive paths. The bound is a small constant retry cap.
- The fuzz suite gating these WCET-relevant code paths now includes
  `iec62304_input`, `tpm_ec_point` (real `validate_ec_point` harness,
  MED-9 / commit `5b565c8`), `qnx_can_parse`, and `qnx_eth_parse`
  (MED-10 / commit `4a246c9`); see [docs/certification-status.md](certification-status.md)
  Part 6 §8 for the full target list and the corresponding `fuzz/Cargo.toml`.

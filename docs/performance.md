# Performance Guide

## Build Profiles

The workspace provides three release profiles for different deployment scenarios:

| Profile | Command | Optimization | Use Case |
|:---|:---|:---|:---|
| `release` | `cargo build --release` | `opt-level = "z"` (size) | Size-constrained ECUs, flash-limited targets |
| `release-perf` | `cargo build --profile release-perf` | `opt-level = 3` (speed) | Gateway ECUs, crypto-heavy workloads |
| `release-safe` | `cargo build --profile release-safe` | `opt-level = "z"` + overflow checks | Safety-critical paths (ISO 26262) |

**Recommendation:** Use `release-perf` for crypto providers (`vs-crypto-pkcs11`,
`vs-crypto-tpm`) and telemetry processing. The 10-30% throughput improvement from
`opt-level = 3` is significant for SHA-256 digest chaining and AES-GCM operations.
Use `release` for code deployed to flash-constrained microcontrollers.

## Crypto Provider Performance

### PKCS#11 vs TPM vs Software

| Operation | Software (RustCrypto) | PKCS#11 (SoftHSM2) | TPM 2.0 (swtpm) |
|:---|:---|:---|:---|
| AES-256-GCM (128 B) | ~200 ns | ~50 us | ~500 us |
| SHA-256 (128 B) | ~150 ns | ~30 us | ~300 us |
| ECDSA P-256 Sign | ~50 us | ~5 ms | ~50 ms |
| ECDSA P-256 Verify | ~80 us | ~8 ms | ~80 ms |

> **Note:** Hardware HSM/TPM latency is dominated by bus transfer (I2C/SPI)
> and command processing, not algorithm speed. Batch operations where possible.

### Optimization Strategies

#### 1. Minimize HSM/TPM Round-Trips

Each crypto operation is a full FFI round-trip. For the telemetry flush path:

```
Current: N entries x (SHA-256 chain) + 1 AES-GCM + 1 ECDSA sign
         = (N + 2) HSM calls per flush
```

**Recommendation:** Increase `TelemetryConfig::batch_size` to reduce flush
frequency. Larger batches amortize the fixed-cost ECDSA signature across more
entries.

#### 2. Pre-compute Digest Chains on the Host

For software crypto (`RustCryptoProvider`), the SHA-256 digest chain runs
entirely in Rust at native speed. For HSM/TPM providers, each SHA-256 call
crosses the FFI boundary. Consider computing the digest chain using software
SHA-256 (which is not security-sensitive — only integrity) and reserving HSM
calls for the final AES-GCM encryption and ECDSA signature.

#### 3. Key Slot Locality

Both `Pkcs11CryptoProvider` and `TpmCryptoProvider` use array-indexed key
lookup (`key_map[key_id.0]`). This is O(1) and cache-friendly. No optimization
needed for key lookup.

#### 4. Stack Allocation Sizes

All crypto buffers are stack-allocated with a 2048-byte maximum (`MAX_BUF`/`MAX_PT`).
On deeply-nested call stacks, this may consume significant stack space. For
Cortex-M targets with 8 KB stacks, ensure crypto operations are not called
from deeply nested contexts.

**Recommendation for constrained stacks:** Process data in smaller chunks
(512 B) instead of the full 2048-byte maximum.

#### 5. TPM Random Byte Batching

`TpmCryptoProvider::random_bytes` loops with 32-byte chunks from `Esys_GetRandom`.
For large random fills (e.g., 256 bytes for nonce pools), this means 8 TPM calls.

**Recommendation:** Pre-fill a random nonce pool at initialization if your
use case requires many random values.

## Telemetry Uplink Performance

### Rate Limiting

The `TelemetryUplink` enforces `max_bytes_per_minute`. Set this based on your
uplink bandwidth:

| Network | Recommended Rate | Batch Size |
|:---|:---|:---|
| CAN bus (500 kbit/s) | 2048 B/min | 4 |
| LTE-M (300 kbit/s) | 8192 B/min | 16 |
| Ethernet (1 Gbit/s) | 65536 B/min | 64 |

### Ring Buffer Overflow

When the 64-entry ring buffer fills, oldest entries are dropped. Monitor
`uplink.dropped_count()` to detect overflow. If drops are frequent, either
increase flush frequency or reduce event generation rate.

## Binary Size

With `opt-level = "z"` and LTO enabled:

| Crate | Approximate .text Size |
|:---|:---|
| vs-crypto-pkcs11 | ~8 KB |
| vs-crypto-tpm | ~12 KB |
| vs-hal-qnx | ~2 KB |
| vs-vsoc-telemetry | ~4 KB |

The `strip = "symbols"` setting in the release profile further reduces binary
size by removing debug symbols from the final artefact.

## Benchmarking

Run benchmarks on your target hardware:

```bash
# ARM cross-compilation benchmarks
./scripts/bench-arm.sh

# Host benchmarks (x86_64)
cargo bench --workspace
```

For accurate HSM/TPM benchmarks, use real hardware (not SoftHSM2/swtpm)
as software simulators do not reflect actual bus latency.

# vs-hal-qnx

Craton Shield Enterprise QNX Neutrino RTOS HAL implementation.

**License:** BSL-1.1 (converts to Apache-2.0 on 2030-09-01)

**Status:** Production (Timer, CAN, Ethernet — all wired on QNX Neutrino 7.1 aarch64)

---

## Overview

Implements the `vs-hal` hardware abstraction traits for the QNX Neutrino RTOS:

| Trait | Implementation | QNX API |
|:---|:---|:---|
| `Timer` | `QnxTimer` | `clock_gettime(CLOCK_MONOTONIC)`, `ClockCycles()` |
| `CanBus` | `QnxCanBus` | `/dev/can*` resource manager via `read()`, `write()`, `devctl()` |
| `EthernetPhy` | `QnxEthernetPhy` | `io-pkt` BPF raw sockets via `/dev/bpf*` |

## Platform Requirements

- **QNX SDP 7.1+** (Neutrino RTOS)
- CAN: `dev-can-<driver>` resource manager started (e.g., `dev-can-mx6x -b500000`)
- Ethernet: `io-pkt-v6-hc` network stack started
- Build target: `aarch64-unknown-nto-qnx710`

## Cross-Platform Behaviour

On non-QNX platforms (Linux, macOS, Windows), the crate compiles and all I/O
operations return `VsError::NotInitialized`. This allows the full workspace to
build and test on development hosts without QNX SDP. Frame parsing and
serialisation helpers (`parse_can_frame`, `serialize_can_frame`,
`parse_eth_frame`) are pure functions and are exercised by unit tests on
every target — failure modes on malformed input are therefore validated
without QNX hardware.

| Method | QNX | Non-QNX |
|:---|:---|:---|
| `QnxTimer::now_us()` | Microsecond monotonic clock | Returns `u64::MAX` (clock-unavailable sentinel) |
| `QnxTimer::cycle_count()` | CPU cycle counter | Returns `None` |
| `QnxCanBus::receive/transmit` | CAN I/O via resource manager | Returns `NotInitialized` |
| `QnxEthernetPhy::receive/transmit` | Ethernet I/O via BPF | Returns `NotInitialized` |

## Third-party headers

All FFI signatures in `qnx_ffi` are derived from POSIX.1-2008 (`open`,
`close`, `read`, `write`, `clock_gettime`, `ioctl`) and the publicly
documented BSD BPF interface (`bpf_hdr`, `BIOCGHDRLEN`). No QNX-private
SDP headers are reproduced in this crate.

The QNX-specific devctl/ioctl command numbers needed for accurate bus-
off and link-up reporting (`CAN_DEVCTL_GET_BUS_STATE` from `<dev/can.h>`
and `SIOCGIFFLAGS` from `<sys/sockio.h>`) are SDP- and driver-version
specific. They are gated behind the `qnx-link-detect` cargo feature,
which fires a `compile_error!` until a downstream crate supplies the
correct constants via `build.rs` or a local patch.

## CAN ID admission filter

`QnxCanBus` carries a fixed-size, in-process admission filter that runs
at the HAL boundary on every successful `receive()`. Frames whose
arbitration ID is rejected by the filter are silently dropped (the
internal `dropped_by_filter` counter is incremented) and the receive
path loops to fetch the next frame, subject to a per-call cap so a
flood of rejected IDs cannot pin the receive task.

The filter is a list of up to `CAN_FILTER_SLOTS` (16) `CanIdFilter`
entries. Each entry is an `(id, mask, accept)` triple. The compare
predicate is `(incoming_id & mask) == (id & mask)`. Slots are evaluated
in insertion order and the **first** match wins.

If no slot matches, the bus's `default_policy` decides:

| Policy | Behaviour |
|:---|:---|
| `CanAdmissionPolicy::AcceptUnmatched` (default) | Unmatched frame passes through. Backwards-compatible. |
| `CanAdmissionPolicy::RejectUnmatched` | Unmatched frame is dropped; `dropped_by_filter` is incremented. |

A freshly-constructed bus starts with an empty filter table and the
`AcceptUnmatched` default, so callers that do **not** opt into filtering
see exactly the pre-audit-M10 behaviour: every kernel-delivered frame
reaches the consumer untouched.

### Safety-critical deployments — fail-closed contract

Safety-critical consumers (engine, brake, steering) **must** call
`set_default_policy(CanAdmissionPolicy::RejectUnmatched)` and then
explicitly `add_id_accept` the IDs they expect. Doing so converts the
HAL into a fail-closed admission point: arbitration IDs the consumer
did not allow-list never surface above the HAL. Leaving the default
`AcceptUnmatched` policy in place on a safety-critical deployment
means that engine, brake, and other safety-critical IDs reach the
consumer untouched — which is the behaviour audit-M10 was filed to
constrain.

### Mask validation

`add_id_accept` / `add_id_reject` reject masks that set bits above bit
28 (only the lower 29 bits of a CAN-ID are meaningful per ISO 11898-1),
masks of zero (would match every frame and collide with the
"unused slot" sentinel), and IDs above the 29-bit extended-ID max.
A full filter table also rejects further inserts with
`VsError::InvalidInput`; callers must call `clear_id_filters` first.

### Example

```rust
use vs_hal_qnx::{QnxCanBus, CanAdmissionPolicy};

let mut can = QnxCanBus::new(500_000);

// Fail-closed default: drop everything the caller did not allow-list.
can.set_default_policy(CanAdmissionPolicy::RejectUnmatched);

// OBD-II diagnostic range 0x7E0..=0x7EF.
can.add_id_accept(0x7E0, 0x7F0).expect("valid slot");

// Specific safety message.
can.add_id_accept(0x100, 0x1FFF_FFFF).expect("valid slot");

// Observability: count how many frames were dropped.
let dropped = can.filter_drop_count();
```

## `is_bus_off()` — safety-critical-shutdown warning

With `qnx-link-detect` **disabled** (the default), `QnxCanBus::is_bus_off`
relies on a TX-error heuristic only: it flips `true` after
`MAX_CONSECUTIVE_TX_ERRORS_FOR_BUS_OFF` consecutive transmit failures
(currently 16, defined as a named constant near
`MAX_PARTIAL_WRITE_RETRIES` in `lib.rs::transmit`) and resets on any
successful TX. Callers that depend on bus-off for safety-critical
shutdown (e.g., disabling actuator commands when the wire is dead)
**must** enable `qnx-link-detect` with verified SDP-specific constants,
or arrange an out-of-band signal. The heuristic default will
under-report a bus that is failing only on RX. See the in-source comment
on `update_bus_off_state` for details. Callers may clear a latched
heuristic bus-off via `QnxCanBus::recover_bus_off`, which also resets
the consecutive-error counter.

## Bus-off recovery

`QnxCanBus::recover_bus_off` clears the heuristic in-process bus-off
state (and, with `qnx-link-detect`, issues a `CAN_DEVCTL_SET_BUS_STATE`
devctl asking the controller to transition back to
`CAN_STATE_ERROR_ACTIVE`). The call is rate-limited.

**Rate limit (audit-M11).** Two consecutive recovery attempts within
`RECOVER_BUS_OFF_MIN_INTERVAL_US` (20 ms) return
`VsError::ResourceExhausted` **without** issuing the devctl or
touching in-process state. The 20 ms floor enforces the CAN-spec
128×11 recessive-bit recovery window mandated by ISO 11898-1:

| Bit rate | 128×11 bits | Floor headroom |
|:---|:---|:---|
| 1 Mbit/s   | 1408 µs   | ≈ 14× |
| 500 kbit/s | 2816 µs   | ≈ 7×  |
| 125 kbit/s | 11264 µs  | ≈ 1.8× |

The 20 ms value covers bit rates down to ~70 kbit/s with margin and
gives the controller firmware time to finish its internal recovery
state machine. A `now_us == u64::MAX` clock-failure sentinel from
`QnxTimer::now_us` lets the call through unconditionally: a CAN
driver stuck in bus-off is a safety-critical fault, and blocking
recovery on a missing monotonic clock would convert one fault into
two.

## Thread Safety

Neither `QnxCanBus` nor `QnxEthernetPhy` is `Sync`. The cached file
descriptor and link / bus-off state are mutated by `receive()` and
`transmit()`, so callers must synchronise external access (mutex or
single-owner pattern) when sharing handles across threads. Typical
deployments use one task per bus or PHY, which needs no extra locking.

## Known Limitations

- Only tested on QNX 7.1 aarch64. QNX 8.0 support is planned.
- `BPF_HEADER_SIZE` is hardcoded to 18 (QNX 7.x `bpf_hdr`). Ports to
  platforms with a different BPF header layout must update the constant
  or query `BIOCGHDRLEN` at open time.

## Usage

```rust
use vs_hal_qnx::{QnxCanBus, QnxTimer, QnxEthernetPhy};

let timer = QnxTimer::new();
let us = timer.now_us(); // Microseconds since boot (QNX) or 0 (other)

let mut can = QnxCanBus::new(500_000); // 500 kbit/s on /dev/can0
let mut eth = QnxEthernetPhy::new(1000); // 1 Gbit/s on /dev/bpf
```

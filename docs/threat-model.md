# Threat Model — Craton Shield Enterprise

STRIDE-based threat model for the enterprise crates. Complements the
open-source core threat model published with `craton-shield-core`.

> Scope: `vs-crypto-pkcs11`, `vs-crypto-tpm`, `vs-hal-qnx`,
> `vs-vsoc-telemetry`. Out of scope: anything in `craton-shield-core`,
> the HSM / TPM firmware itself, the underlying QNX kernel, and
> user-supplied cryptographic key material.

## 1. System overview

```
┌────────────────────────────────────────┐
│ Application (core + enterprise)         │
│                                         │
│  ┌─────────────┐     ┌───────────────┐  │
│  │CryptoProvider│    │TelemetryUplink│  │
│  └─────┬───────┘     └──────┬────────┘  │
└────────┼───────────────────────┼──────────┘
         │ FFI                   │ calls
         ▼                       ▼
   ┌───────────┐           ┌──────────┐
   │ HSM / TPM │           │  VSOC    │
   │ (device)  │           │  backend │
   └───────────┘           └──────────┘
```

Trust boundaries:

- **TB-1** Rust ↔ C FFI (PKCS#11 / TSS2 / libc).
- **TB-2** Host ↔ HSM / TPM (secure-element or discrete chip interface).
- **TB-3** Device ↔ VSOC backend (network).

## 2. Assets

| ID | Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|---|
| A1 | AES-GCM encryption key material (kept inside HSM / TPM) | H | H | M |
| A2 | ECDSA signing private key (HSM / TPM) | H | H | M |
| A3 | Batched telemetry plaintext (stack-resident during `flush`) | H | H | L |
| A4 | `flush_counter` (persisted across reboots) | L | **H** | **H** |
| A5 | Peer public key passed to `ecdh_derive_shared` / `verify_p256` | L | H | L |
| A6 | CAN / Ethernet frame payloads | M | H | M |
| A7 | User PIN for PKCS#11 login | H | H | L |

## 3. STRIDE matrix

| Asset | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| A1 key material | — | **T1** | — | **I1** | — | **E1** |
| A2 signing key | — | T1 | — | **I2** | — | — |
| A3 telemetry PT | — | — | — | **I3** | — | — |
| A4 flush counter | — | **T2** | **R1** | — | **D1** | — |
| A5 peer key | **S1** | **T3** | — | — | — | — |
| A7 PIN | — | — | — | **I4** | — | — |

Legend: **T**ampering, **S**poofing, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege.

## 4. Specific threats & mitigations

### T1 — Hostile replacement of the PKCS#11 / TSS2 library

An attacker who can replace the shared library the caller resolves its
function pointers from (or substitute pointers in `Pkcs11FunctionList` /
`TpmFunctionList`) can exfiltrate keys on any call.

**Mitigations.** (a) Library integrity is the caller's responsibility —
verify the shared object signature before `dlopen`; (b) on QNX, install
the PKCS#11 / TSS2 binaries in a trusted-path directory owned by root;
(c) prefer static linking in production builds; (d) **HIGH-L (commit
`72f0cd3`)** — `Pkcs11CryptoProvider::try_clone` now marks the clone's
view of `library_pre_initialized` so only the parent (the real caller
of `C_Initialize`) ever invokes `C_Finalize` on `Drop`. The original
double-finalize race could be turned into a use-after-finalize by a
hostile library that re-issued handles between the two `C_Finalize`
calls; the fix closes that window.

### T1a — Token-state leakage through ambiguous lookups or failed object destruction

The PKCS#11 lookup `C_FindObjects` can return arbitrary matches when
two on-token objects share a `CKA_LABEL` and class. The transient
session objects created by `ecdh_derive_shared` and `verify_p256` hold
key material (shared secret / peer public point); a `C_DestroyObject`
that silently fails leaves that material on the token until the
session closes.

**Mitigations.** (a) **HIGH-N (commit `72f0cd3`)** — the lookup now
requests up to two matches and refuses the call with `CryptoError`
when `count > 1`, forcing the operator to deduplicate rather than
silently selecting whichever the token enumerated first;
(b) **HIGH-O (commit `72f0cd3`)** — both `ecdh_derive_shared` and
`verify_p256` capture the `C_DestroyObject` return value, record it
in `LAST_DESTROY_ERROR` for operational tooling, and escalate any
non-`CKR_OK` to `VsError::CryptoError` so the caller cannot silently
proceed with key material still resident on the token.

### T1b — Token "CKR_OK with partial output" misbehaviour

A misbehaving token that returns `CKR_OK` from a SHA-256, HMAC,
ECDSA-sign, or `C_GenerateRandom` call without writing the full
output buffer would historically slip past a constant-sentinel
pre-fill check (the unwritten tail still matched the sentinel and
satisfied `iter().all(|&b| b == SENTINEL)`).

**Mitigation.** **HIGH-M (commit `72f0cd3`)** — every sentinel pre-fill
in `crypto-pkcs11` now uses a position-varying pattern
(`SENTINEL ^ (i as u8)`). Every byte has a position-unique pre-fill,
so a token that writes only a prefix of the output is detected on
the post-call comparison and the buffer is wiped + `CryptoError`
returned.

### T2 / D1 — Nonce reuse via `flush_counter` regression

If `flush_counter` is reset (fresh `new()` instead of `restore()`, disk
corruption, hostile rollback) the AES-GCM nonce repeats under the same
key, which is catastrophic.

**Mitigations.** (a) `PersistedFlushCounter::restore` is the only
non-deprecated constructor signalling nonce safety; (b) the zero-counter
constructor is `#[doc(hidden)]`-like in intent and documented as a
hazard; (c) the uplink refuses a monotonic-clock regression in
`flush()`, removing a side channel for window reset; (d) the
`TelemetryUplink::restore_authenticated` constructor (MED-3 fix in
`vs-vsoc-telemetry`) binds the persisted counter to an HMAC over the
device-unique key material, so a rollback that replays an old NVRAM
blob is detected and rejected at boot rather than silently producing a
nonce collision; (e) **HIGH-Y (commit `1822052`)** — `flush()` now
validates every entry's per-entry sequence number against the previous
entry's sequence, and rejects any timestamp older than the monotonic
floor stored on the uplink. A merged batch built from a stale entry
log is therefore caught before the AAD is committed, blocking a class
of "stale-entry replay during batch construction" attacks that the
batch-level counter alone did not cover.

**Residual risk.** A caller can still misuse `TelemetryUplink::new()`.
See the operational-security playbook for provisioning guidance.

**AUDIT-INFO-2 — `restore_authenticated` proves authenticity, not
freshness.** `PersistedFlushCounter::restore_authenticated` validates
the HMAC over the counter blob in constant time, which proves the blob
was produced by a holder of `mac_key_id`. It does **not** prove the
blob is the *current* persisted counter: a blob that was validly
produced at, say, counter=42 will continue to verify successfully even
after the live device has flushed past counter=42, because the MAC
covers the counter *value* not its *recency*. An attacker with
read/write access to the persistence layer can therefore capture an old
blob, wait for the device to advance, and replay the snapshot to force
AES-GCM nonce reuse. This is a documented limitation (see the rustdoc
on `restore_authenticated` and the
`restore_authenticated_accepts_stale_blob_documenting_rollback_limitation`
test in `crates/vsoc-telemetry/src/tests/mod.rs`). **Operator
obligation:** the 40-byte authenticated blob MUST be persisted in
rollback-resistant storage — a TPM 2.0 NV index with
`TPMA_NV_WRITE_STCLEAR` / monotonic-counter attributes, a secure-element
`CKM_*_MONOTONIC_COUNTER`-style primitive, or a vendor anti-replay
facility (eFuse / RPMB). Plain authenticated-filesystem persistence is
insufficient against the snapshot-and-restore adversary modelled here.

### I1 / I2 — Residual secrets on the stack

AES-GCM plaintext, HMAC tags, ECDSA signatures, and ECDH shared secrets
live briefly on the Rust stack before being copied to caller buffers.

**Mitigations.** Every primitive in the two crypto crates now wipes the
relevant stack buffer with `core::ptr::write_volatile` on both the
success and error paths. The telemetry uplink wipes the plaintext batch
chain after digesting.

**Residual risk.** Rust stack unwinding on panic may still leave a
partial copy. The workspace uses `panic = "abort"` in release profile
to remove this path.

### I3 — Telemetry plaintext leakage via debug logging

Not a code-level threat: an application that logs `TelemetryEntry` via
`Debug` before submission leaks the payload.

**Mitigation.** `TelemetryEntry` does not implement `Display`;
callers are instructed to use opaque event IDs in logs.

### I4 — PIN residue after `Pkcs11CryptoProvider::new`

The PIN is passed into `C_Login` as a slice and then forgotten — the
provider does not take ownership. A careless caller who leaves the PIN
in a `Vec<u8>` leaks it.

**Mitigation.** The `new()` / `try_clone()` docs explicitly tell the
caller to zeroise the PIN buffer (e.g., via the `zeroize` crate).

### T3 / S1 — Malformed / attacker-chosen EC points

Compressed or point-at-infinity inputs can cause the HSM / TPM to leak
information or return incorrect results.

**Mitigation.** Both `verify_p256` and `ecdh_derive_shared` reject any
point that is not uncompressed (`0x04 || X || Y`) or has all-zero
coordinates, before invoking the hardware. Full on-curve validation is
then delegated to the device.

### R1 — Flush repudiation

A VSOC operator cannot repudiate a batch whose ECDSA signature verifies
and whose tag is authentic: both cover the `flush_counter`, `device_id`,
and `ts_us` in AAD.

**Mitigation design.** Non-repudiation relies on (a) ECDSA signing key
never leaving the HSM / TPM, and (b) the counter monotonicity invariant.

### D2 — Uplink rate-limit bypass via backdated timestamps

Rejected in `flush()`; see T2/D1.

### D3 — CAN / Ethernet read-loop DoS

A flood of malformed CAN frames with `dlc > 64` or truncated payloads
could stall higher-layer parsing.

**Mitigation.** `parse_can_frame` rejects oversized DLC and short
payloads up front, unit-tested on every host. **HAL-QNX HIGH batch
(R/S/T fixes, commit `5c36362`)** bounds the EINTR retry loop in both
`QnxCanBus::receive` and `QnxEthernetPhy::receive` so a signal-storm
attacker that triggers repeated `EINTR` cannot stall the receive
thread indefinitely; the loop returns `WouldBlock` after a fixed
retry cap. **U fix (commit `c8c6133`)** replaces the 4-byte
`SIOCGIFFLAGS` argument with a proper `IfReq` buffer, removing a
stack-overflow / out-of-bounds-read footgun on the link-status path.

### D4 — VLAN-frame truncation and CAN-FD DLC misparse

VLAN-tagged Ethernet frames extend the L2 header by 4 bytes; the
historical hal-qnx parser did not account for the shift and could
truncate or misalign the upper-layer payload. ISO 11898-1 CAN-FD
encodes the data-length code as a 4-bit nibble whose value maps
non-linearly to byte counts (8–64); the original linear mapping could
under- or over-report frame length.

**Mitigation.** VLAN-truncation HIGH (commit `c558482`) reshapes the
Ethernet parser to honour the 802.1Q tag; CAN-FD DLC fix
(commit `d5f0855`) implements the proper nibble-to-byte table.

## 5. Non-threats (out of scope)

- Physical side-channel attacks on the HSM / TPM device.
- Supply-chain attacks on the Rust compiler toolchain — see
  [`docs/supply-chain.md`](supply-chain.md) for partial mitigations.
- Confidentiality of timing or EM emissions from the host CPU.
- Denial of service via OS-level resource exhaustion (all data
  structures in these crates are bounded).

## 6. Review cadence

Review this document at each minor release and whenever a new FFI
surface is added. The current version corresponds to Craton Shield
Enterprise **v0.7.2 — audit-fix release** (HIGH-Y per-entry sequence
validation, HIGH-L/M/N/O/P/Q PKCS#11 batch, HIGH-G/J/K/W TPM batch,
HAL-QNX HIGH R/S/T/U/V batch, all landed 2026-05-23).

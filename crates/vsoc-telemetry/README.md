# vs-vsoc-telemetry

Craton Shield Enterprise VSOC telemetry uplink.

**License:** BSL-1.1 (converts to Apache-2.0 on 2030-09-01)

**Status:** Functional (core buffering, encryption, and signing implemented)

---

## Overview

This crate provides the telemetry uplink for forwarding security events to a
Vehicle Security Operations Centre (VSOC) backend. It implements:

- **Ring-buffer entry queueing** with configurable batch sizes (up to 64 entries)
- **Per-minute rate limiting** on uplink bandwidth
- **Cryptographic digest chaining** (SHA-256) over batch headers and entries
- **AES-GCM authenticated digest commitment** with monotonic nonce generation
- **ECDSA P-256 signing** of the plaintext digest for authenticity
- **Write-ahead `flush_counter` persistence** via the `CounterPersistence` trait
  for nonce-reuse safety across reboots

## Key Types

| Type | Description |
|:---|:---|
| `TelemetryUplink<C>` | Buffered, rate-limited telemetry uplink with authenticated digest commitments |
| `TelemetryConfig` | Uplink configuration: rate limits, batch size, encryption/signing keys, device ID |
| `TelemetryEntry` | A single telemetry observation (sequence, timestamp, severity, payload) |
| `FlushResult` | `digest_commitment`, AES-GCM tag, ECDSA signature, entry count, and flush counter |
| `FlushOutcome` | Discriminated outcome: `Sent`, `Empty`, `RateLimited`, `CounterExhausted` |
| `CounterPersistence` | Trait for durably persisting the monotonic `flush_counter` before encryption |
| `CounterStorage` | Trait for loading the HMAC-authenticated counter blob at boot |
| `RollbackResistantStorage` | Sealed marker trait advertising a rollback-resistant storage medium (audit-H2) |
| `AssertedExternallyRollbackResistant<R>` | Caller-asserted rollback-resistance wrapper around a `CounterStorage` impl |
| `PersistedFlushCounter` | Authenticated wrapper around the restored counter value |

## What this crate does NOT transmit

This crate produces a **commitment** to a batch, not the batch itself. The
`FlushResult::digest_commitment` field is the AES-GCM ciphertext of a SHA-256
digest chained over the batch header and entries. **Plaintext telemetry
entries are never emitted by `flush_with_persistence`** — callers that need
the receiver to see the original entries must transmit them through a
separate confidential channel (TLS, MQTT-over-TLS, etc.) and use the
commitment to authenticate the batch end-to-end.

## AAD layout (wire-format compatibility)

The AES-GCM AAD covers every non-secret value the receiver must trust. As of
the most recent audit fix the layout is:

```text
device_id            (32 bytes)   // matches header[0..32]
flush_counter        ( 8 bytes)   // little-endian
entry_count          ( 8 bytes)   // little-endian
ts_us                ( 8 bytes)   // little-endian
dropped_count        ( 8 bytes)   // little-endian
severity_dist        ( 8 bytes)   // admitted: [u16; 4] LE — Critical, High, Medium, Low
dropped_per_severity ( 8 bytes)   // dropped:  [u16; 4] LE — Critical, High, Medium, Low  ← NEW
                      ----------
total                (80 bytes)
```

The `dropped_count` field was added so the receiver can detect ring-buffer
eviction floods. A misbehaving sender (or an attacker that flooded
low-severity events to evict genuine alerts) advances `dropped_count`
locally; binding it into the AAD makes the change observable end-to-end.

The `severity_dist` field (audit fix MED-vsoc-AAD-sev) binds a
fixed-layout little-endian histogram of the batch's **admitted** alert
severities — `[u16; 4]` covering Critical, High, Medium, Low. `Info` is
intentionally excluded because it is not an alert. Without this
commitment, a targeted "drop all Critical, retain Info" rewrite of the
ring buffer would be detectable only by the absence of expected alerts;
binding the histogram makes any silent admitted-severity rewrite fail
authentication end-to-end.

The `dropped_per_severity` field (audit fix INFO-1) binds the parallel
`[u16; 4]` little-endian histogram of *dropped* entries indexed
`[Critical, High, Medium, Low]` (Info excluded for the same reason as
above). `dropped_count` alone tells the receiver "how many" but not
"which tier was suppressed"; binding the tier-resolved histogram lets
the receiver distinguish "attacker flooded Info events and the ring
evicted Critical alerts" from "caller emitted too many Info events of
their own". Per-bump saturation prevents silent wrap-around at
`u16::MAX`.

**Receiver contract:** decoded `dropped_count` MUST be validated against
the previously observed value from the same device and MUST be
monotonically non-decreasing. A regression indicates rollback, replay of
an earlier batch under a newer counter, or persistence-store tamper.
Each slot of `dropped_per_severity` MUST also be monotonically
non-decreasing across flushes from the same device, and the receiver
MUST validate that
`sum(dropped_per_severity[0..4]) <= dropped_count` (Info-tier drops are
excluded from the histogram so the inequality is strict when Info drops
are present). The receiver SHOULD also cross-check the admitted
`severity_dist` histogram against any plaintext entries it receives on
the confidential side channel; a mismatch indicates a tampered or
partially delivered batch.

This is a wire-format change. Receivers on the previous AAD layouts
(`... || dropped_count`, 64 bytes; or `... || dropped_count ||
severity_dist`, 72 bytes) will fail to authenticate batches from updated
senders until they extend their AAD-builder by the trailing 8-byte
per-severity dropped histogram.

## Nonce Safety

The `flush_with_persistence()` method derives AES-GCM nonces from a hashed
per-device prefix combined with the monotonically increasing `flush_counter`.
This guarantees nonce uniqueness across all flushes for a given key,
satisfying the nonce-reuse safety requirements of `vs-crypto-pkcs11` and
`vs-crypto-tpm`.

The counter is **write-ahead persisted** through the caller-supplied
`CounterPersistence` impl *before* any encryption runs. On a persist-success
the in-memory counter advances immediately (jump-over invariant): a
subsequent encrypt failure leaves both stores at the burned value so retries
never re-derive the same nonce. Use `restore_authenticated` on the
`PersistedFlushCounter` builder when the persistence store provides an
authenticator that the uplink should re-validate before trusting the value.

<<<<<<< HEAD
## Rollback resistance (audit-H2)

`PersistedFlushCounter::restore_authenticated(blob, …)` verifies an
HMAC-SHA-256 tag over the 40-byte counter blob. **The HMAC verifies
authenticity, not freshness.** An attacker who captures the blob at
counter value `N` and later overwrites the persistence medium with that
old blob — after the device has flushed past `N` — will pass the HMAC
check and re-install a stale counter. AES-GCM then reuses a previously
emitted nonce under the same key, which is catastrophic.

This crate cannot make rollback impossible on its own; the property has
to come from the storage medium. What it can do is force callers to say
out loud, in the type system, that they have wired the storage to a
medium that *is* rollback-resistant. The contract:

- `CounterStorage` — load path: returns the 40-byte blob produced by
  `PersistedFlushCounter::to_blob` from durable storage.
- `RollbackResistantStorage` — **sealed** marker trait; a downstream
  crate cannot implement it on its own types because its `Sealed`
  super-trait is private to `vs-vsoc-telemetry`.
- `PersistedFlushCounter::restore_authenticated_from_storage<C, R>`
  requires `R: CounterStorage + RollbackResistantStorage`. A bare
  `impl CounterStorage for MyFsBlob {}` therefore cannot be passed to
  this method.

The crate ships exactly one blessed implementer:
`AssertedExternallyRollbackResistant<R>` (in the `rollback` module).
It is a no-op wrapper that delegates `CounterStorage` to the inner `R`
and asserts the marker. Wrapping is an explicit acknowledgement that
the caller has audited the binding between `R` and a rollback-resistant
medium — examples that warrant the wrapper:

| Medium | Property | `STORAGE_KIND` (recommended) |
|:---|:---|:---|
| TPM 2.0 NV index with `TPMA_NV_WRITE_STCLEAR` | NV index is write-locked for the rest of the boot cycle after the first write — a same-boot rollback attacker cannot stomp on it. | `"tpm-nv-write-stclear"` |
| eFuse monotonic counter | One-way physically; cells cannot un-burn. | `"efuse-counter"` |
| eMMC RPMB partition | Replay-protected via per-write keyed authentication; writes carry a counter the controller enforces. | `"rpmb"` |
| Secure-element monotonic counter | Vendor-attested non-decrement guarantee. | vendor-specific |

```rust,ignore
use vs_vsoc_telemetry::{
    AssertedExternallyRollbackResistant, CounterStorage,
    PersistedFlushCounter, RollbackResistantStorage,
};

// `RpmbCounterStorage` is your own type wrapping the kernel's RPMB
// device node. It implements `CounterStorage`, but NOT
// `RollbackResistantStorage` (sealed). To pass it to
// `restore_authenticated_from_storage`, wrap it.
let storage = AssertedExternallyRollbackResistant(RpmbCounterStorage::open()?);
let pfc = PersistedFlushCounter::restore_authenticated_from_storage(
    &storage,
    &crypto,
    mac_key_id,
)?;
```

**Wrapping a plain filesystem blob in `AssertedExternallyRollbackResistant`
defeats audit-H2 and re-introduces the rollback vulnerability.** The
wrapper compiles either way — the only safeguard is the doc-comment and
the visible call-site assertion that a code reviewer can grep for.
Treat every `AssertedExternallyRollbackResistant(...)` occurrence as a
security-review obligation: chase down what guarantees the inner
storage really provides.

The legacy `restore_authenticated(blob, …)` entry point is retained for
back-compat (existing in-crate roundtrip and tamper tests use it) but
is documented as audit-H2-limited. New call sites should use
`restore_authenticated_from_storage`.
=======
## Counter persistence (V1 / V2 blob formats)

`PersistedFlushCounter` is the authenticated wrapper around a
`flush_counter` value that has been (or will be) written to durable
storage. The on-disk blob carries an HMAC-SHA-256 tag so a tampered or
forged counter can be rejected before it is ever fed into the AES-GCM
nonce.

There are two on-disk formats:

| Field | V1 (legacy) | V2 (current — audit-H4) |
|:---|:---|:---|
| `version` | (implicit `0x01`) | `0x02` (1 byte) |
| `counter_le` | 8 bytes (LE) | 8 bytes (LE) |
| `encryption_key_id_le` | — | 4 bytes (LE, `KeyId::get() as u32`) |
| `tag` | HMAC-SHA-256 over `counter_le` | HMAC-SHA-256 over `version \|\| counter_le \|\| encryption_key_id_le` |
| **Total length** | **40 bytes** (`PERSIST_BLOB_LEN_V1`) | **45 bytes** (`PERSIST_BLOB_LEN_V2`) |

The HMAC key is `mac_key_id` in both versions; it stays implicit (it IS
the HMAC key, not part of the MAC input). V2 additionally feeds
`encryption_key_id` into the MAC input *after* `mac_key_id`'s implicit
position so the persisted counter is bound to the AES key it will
ultimately be used under.

### What V2 defends against (audit-H4)

V1 binds the counter to `mac_key_id` only. If the deployment rotates
the AES encryption key while keeping the MAC key stable (a common
operational shape — MAC keys live in long-lived NV slots, AES keys
rotate on a tighter cadence), an old V1 counter blob still
authenticates under the unchanged MAC key. The loaded counter is
then used to derive an AES-GCM nonce under the *new* encryption key —
even though the new key has already advanced past this counter value,
causing nonce reuse. AES-GCM nonce reuse leaks plaintext and forges
forgeries; this is catastrophic.

V2 closes the window by including `encryption_key_id` in the HMAC
input. A blob persisted under `encryption_key_id = KeyId(7)` no
longer verifies when loaded with `encryption_key_id = KeyId(8)` —
the audit-H4 hazard surface becomes a loud `CryptoError` instead of
a silent nonce collision.

### V1 -> V2 upgrade window

`PersistedFlushCounter::restore_authenticated_versioned` accepts both
40-byte V1 blobs and 45-byte V2 blobs on load:

- A 40-byte V1 blob is verified by the legacy path (no
  `encryption_key_id` binding). The next `flush_with_persistence`
  call writes a V2 blob back through the storage layer, closing the
  audit-H4 window after at most one boot.
- A 45-byte V2 blob with version byte `0x02` is verified by the V2
  path, requiring `encryption_key_id` to match the persist-time value.
- A 45-byte blob with an unknown version byte is rejected as
  `CryptoError`.
- Any other length is rejected as `CryptoError`.

This is a **one-way upgrade**. Once storage has been rewritten as V2,
the device will not emit V1 again. Operators planning a fleet-wide
rollout should validate that all devices have been seen at least once
under the V2 code path before retiring V1-aware verifiers from the
backend.
>>>>>>> de6d879 (fix(vsoc-telemetry): bind persisted counter to encryption_key_id (audit-H4))

## Usage

```rust
use vs_vsoc_telemetry::{
    TelemetryUplink, TelemetryConfig, TelemetryEntry,
    PersistedFlushCounter, FlushOutcome,
};
use vs_crypto::KeyId;

let config = TelemetryConfig {
    max_bytes_per_minute: 8192,
    batch_size: 16,
    encryption_key_id: KeyId(0),
    signing_key_id: KeyId(1),
    device_id: [0u8; 32],
    reserved_critical_slots: 8,
    allow_out_of_order_entries: false,
};
let mut uplink: TelemetryUplink<MyCryptoProvider> =
    TelemetryUplink::try_restore(config, PersistedFlushCounter::fresh_device())?;

let entry = TelemetryEntry::new(1, timestamp_us, 0x01, severity, payload)?;
uplink.submit_entry(entry)?;

match uplink.flush_outcome(&crypto, timestamp_us, &mut persistence)? {
    FlushOutcome::Sent(result) => {
        // result.digest_commitment, result.tag, result.signature
        // authenticate the batch; transmit entries via a confidential channel.
    }
    FlushOutcome::Empty => {}
    FlushOutcome::RateLimited { retry_after_us: _ } => {}
    FlushOutcome::CounterExhausted => {}
}
```

## Design

- `#![no_std]`; zero heap allocations; fixed-size ring buffer (64 entries)
- The crate is otherwise `unsafe`-free. The single exception is `volatile_wipe`
  (`src/lib.rs`), which uses `core::ptr::write_volatile` to defeat dead-store
  elimination when scrubbing transient plaintext buffers. Every `unsafe` block
  in that helper carries a `// SAFETY:` justification at the call site.
- Transport-agnostic: the caller is responsible for network I/O
- Rate limiting prevents bandwidth exhaustion on constrained uplinks
- SIEM connectors (Phase E3 on the [Roadmap](../../ROADMAP.md)) will extend this crate

## audit-H3: dangerous test-only features

Two Cargo features expose unauthenticated rollback paths and must
**never** be active in a release-profile build:

| Feature                    | What it ungates                                                                 |
|:---------------------------|:--------------------------------------------------------------------------------|
| `unauthenticated-restore`  | `PersistedFlushCounter::restore(u64)` — unauthenticated counter restore shim    |
| `test-only`                | Reserved for additional in-crate test-fixture surface; same hazard class        |

### Why these are dangerous

Both features let a caller short-circuit the write-ahead persistence
contract that guards the AES-GCM `flush_counter`. If the counter rolls
back (e.g. a caller restores `0` after dropping the on-disk file), the
next flush reuses a nonce under the same encryption key. AES-GCM
nonce reuse is catastrophic: it leaks XOR-of-plaintexts and lets an
attacker forge arbitrary GCM tags.

Cargo's feature unification merges feature sets across the dependency
graph. A workspace dev-dependency that activates one of these features
for its integration tests will silently re-expose it to every release
build that links the same crate version — exactly the silent-reactivation
hazard audit-H3 flagged.

### The compile-fail guard

`src/lib.rs` carries a `compile_error!` macro that fires whenever either
feature is active in a build where `cfg(test)` and `cfg(debug_assertions)`
are both false. `debug_assertions` is `true` in the `dev` and `test`
cargo profiles and `false` in `release` (and any profile that inherits
from it) per the Cargo Book's Profiles chapter, so the guard correctly
discriminates "release-shaped builds" from "dev / test".

A single deliberate escape hatch exists for security engineers running a
hand-audited forensic build: enabling the
`deliberately-unsafe-release-acknowledged` feature suppresses the
`compile_error!`. This feature must never be set in a shipping artefact;
its name is intentionally awkward so that any CI grep or release-build
audit flags it immediately.

### Auditing a release binary

To confirm that the guard has not been bypassed, run:

```bash
cargo build --release -p vs-vsoc-telemetry
```

The build must succeed with the default feature set. Then run the same
command with each dangerous feature in turn — both must **fail to
compile** with the audit-H3 `compile_error!` message:

```bash
cargo build --release -p vs-vsoc-telemetry --features unauthenticated-restore
cargo build --release -p vs-vsoc-telemetry --features test-only
```

If either succeeds, the guard has been compromised (most likely the
escape-hatch feature is active somewhere in the dep graph); treat the
artefact as non-shippable and inspect `cargo tree -e features` to find
the source of the activation.

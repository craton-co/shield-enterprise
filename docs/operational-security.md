# Operational Security — Craton Shield Enterprise

Field operations guide for teams deploying Craton Shield Enterprise into
production vehicles and fleets. This is a living document — adjust to
your organisation's procedures and keep a signed-off revision log.

## 1. Provisioning

### 1.1 Per-device keys

Every ECU / target device must have its own AES-GCM and ECDSA keys.
Shared keys across devices break the nonce-separation argument made by
`vs-vsoc-telemetry` (see [`docs/threat-model.md`](threat-model.md) §T2)
and cause any compromise to be fleet-wide.

Recommended generation ceremony:

1. Operator logs into the HSM or opens the TPM in a tamper-evident
   clean room.
2. `pkcs11-tool --keygen --key-type AES:32 --label "vs-device-<id>"`
   (PKCS#11) or `tpm2_create -C o -G ecc256:ecdsa -c key.ctx` (TPM).
3. Record the public key / key handle in the provisioning database
   alongside the device serial.
4. Wipe any intermediate host-side buffers (`shred -u key.ctx` or
   equivalent).

### 1.2 `flush_counter` initial state

On first boot the uplink must be constructed with
`PersistedFlushCounter::fresh_device()` — this is the **only** safe
choice when no counter has yet been persisted. On every subsequent
boot the counter must be loaded from authenticated persistent storage
and passed via `PersistedFlushCounter::restore(n)`. The canonical
boot-path branch is:

```rust
let counter = match nvram_read_flush_counter()? {
    Some(n) => PersistedFlushCounter::restore(n),
    None    => PersistedFlushCounter::fresh_device(),
};
```

Suitable storage:

- Dedicated NV index on the TPM (`tpm2_nvdefine`, `tpm2_nvwrite`).
- Signed + encrypted file in the secure boot partition.
- Rollback-protected key store in the HSM.

Plain filesystem storage (no rollback protection) is acceptable on
air-gapped bench devices only.

## 2. Key rotation

| Key | Cadence | Trigger |
|---|---|---|
| AES-GCM encryption key | 12 months or 2³² batches, whichever comes first | Approaching the GCM safe-use bound |
| ECDSA signing key | 24 months | Calendar rotation |
| Device unique ID | Never | N/A |
| HSM / TPM firmware | Vendor-driven | Vendor advisory |

### 2.1 Rotation procedure (AES-GCM)

1. Provision the new key under a new `KeyId` on the HSM / TPM.
2. Call `CryptoProvider::generate_key` — returns `PolicyViolation` by
   design; re-register the handle via
   `Pkcs11CryptoProvider::register_key_handle` / equivalent.
3. Reset the `flush_counter` to 0 for the new key by calling
   `TelemetryUplink::try_restore(cfg, PersistedFlushCounter::fresh_device())`
   with the new `TelemetryConfig`. The deprecated `TelemetryUplink::new()`
   shortcut must not be used in field rotations.
4. Delete the old key via `delete_key(old_id)` once all in-flight
   batches are drained.
5. Archive the old key's public material for historical verification.

### 2.2 Rotation procedure (ECDSA)

Same as AES-GCM, plus the VSOC backend must be updated with the new
public key before the device cuts over, otherwise signature verification
fails and batches appear as a spoofing attack.

## 3. Compromise playbooks

### 3.1 Suspected host compromise (no HSM / TPM breach)

1. Rotate AES-GCM + ECDSA keys for the affected devices (see §2).
2. Revoke the old public key in the VSOC backend.
3. Force reboot and re-provisioning; discard any telemetry older than
   the compromise window.
4. Audit `flush_counter` gaps in the VSOC backend — a jump implies
   either a rollback attempt or a new provisioning.

### 3.2 Suspected HSM / TPM breach

1. Quarantine all devices sharing the token.
2. Preserve the HSM / TPM for forensic imaging where legally possible.
3. Issue CVE / security advisory per [`SECURITY.md`](../SECURITY.md).
4. Re-provision replacement tokens with new firmware and key ceremony.

### 3.3 Suspected nonce reuse (telemetry)

1. Treat all batches encrypted under the affected key as both
   unconfidential and unauthentic.
2. Rotate the AES-GCM key (§2.1).
3. Ingest the device's local audit log to determine the offending
   counter range.
4. File a CVE if the root cause is a defect in the crate itself.

## 4. Monitoring

| Signal | Source | Action |
|---|---|---|
| `dropped_count` increasing | `TelemetryUplink::dropped_count()` | Backend not draining — investigate transport |
| `flush_counter` gap at VSOC | VSOC ingestion | Possible rollback or compromise |
| `flush()` returns `ResourceExhausted` | Application log | Rate-limit budget exceeded — adjust `max_bytes_per_minute` or investigate event storm |
| `flush()` returns `InvalidInput` | Application log | Clock regression — inspect RTC source |
| `self_test()` fails | Startup | HSM / TPM malfunction — quarantine device |

## 5. Revocation

Public keys are revoked at the VSOC backend, not on-device. The device
does not cache trust decisions, so revocation propagates at the next
flush attempt (the VSOC refuses the batch). No on-device revocation
list is shipped.

## 6. Audit logging

Craton Shield Core provides an HMAC-chained audit log
(`vs-audit-log`). This enterprise repo forwards encrypted audit
entries through `vs-vsoc-telemetry`. Operations teams must:

- Archive VSOC-ingested batches for the statutory retention period
  (ISO 21434 recommends ≥ 24 months post end-of-support).
- Verify the HMAC chain on retrieval — any gap is an integrity
  incident.

## 7. Responsible disclosure

Send security reports to [security@craton.com.ar](mailto:security@craton.com.ar)
or via the [GitHub Security Advisory form](https://github.com/craton-co/craton-shield-enterprise/security/advisories/new).
See [`SECURITY.md`](../SECURITY.md) for full policy.

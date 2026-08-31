# Getting Started

A single linear walkthrough that takes an integrator from a clean
machine to a working Encrypt-then-MAC roundtrip through SoftHSM2 and
swtpm, and a telemetry uplink that survives a reboot.

This guide is complementary to — not a replacement for —
[INSTALL.md](../INSTALL.md) (per-platform build instructions) and
[examples/README.md](../examples/README.md) (orientation-only code
walkthroughs).

## 0. What you are building

```
┌─────────────────────────┐       ┌──────────────────────────┐
│ Your integration binary │──FFI──▶ vs-crypto-pkcs11 (HSM)  │
│  (cbindgen or pure     │       │ vs-crypto-tpm    (TPM)  │
│   Rust consumer)       │       │ vs-hal-qnx       (RTOS) │
│                         │       │ vs-vsoc-telemetry(fleet)│
└─────────────────────────┘       └──────────────────────────┘
              │                                │
              └──────── Craton Shield Core ────┘
                       (detection / policy /
                        IDS / reports — Apache-2.0)
```

By the end of the guide you will have:

1. The enterprise workspace built with `cargo build --workspace`.
2. All orientation examples running under `cargo run --example …`.
3. A SoftHSM2 token initialised with a P-256 ECDSA key and a SHA-256
   AES-GCM key, exercised through `Pkcs11CryptoProvider`.
4. A local swtpm instance producing ETM tags through
   `TpmCryptoProvider`.
5. A `TelemetryUplink::restore` loop that persists `flush_counter`
   across a simulated reboot — the canonical nonce-safe pattern.

## 1. Prerequisites

| Dependency | Minimum | Notes |
|:---|:---|:---|
| Rust toolchain | 1.82 (MSRV — see [docs/build-matrix.md](build-matrix.md)) | `rustup toolchain install 1.82` |
| A C toolchain | any | Required by `bindgen` for the ESAPI headers. |
| `pkg-config` | 0.29+ | Used by `tpm2-tss` probe. |
| SoftHSM2 | 2.6.1 | `apt install softhsm2` / `brew install softhsm` |
| OpenSC / `pkcs11-tool` | any | Not required at runtime; useful for inspecting tokens. |
| `swtpm` + `libtss2` | swtpm 0.8+, tpm2-tss 4.1+ | `apt install swtpm libtss2-dev` |
| `tpm2-tools` | 5.5+ | Optional, for inspecting the TPM. |

For sibling-repo path deps:

```bash
git clone https://github.com/craton-co/craton-shield.git
git clone https://github.com/craton-co/craton-shield-enterprise.git
# `craton-shield/` must be a sibling of `craton-shield-enterprise/`. The
# core crates live under `craton-shield/core/`, so Cargo resolves
# `../craton-shield/core/<crate>` via workspace path deps.
```

## 2. Build and test

```bash
cd craton-shield-enterprise
cargo build --workspace
cargo test  --workspace        # ~1,057 tests (923 unit + 134 integration)
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

The workspace is `#![no_std]` in production code, but tests pull in
`std` behind `#[cfg(test)]`, so a normal host test run is sufficient.

## 3. Run the orientation examples

Each example prints the provider / function-list shapes and the steps a
real caller would take; they do not touch real hardware.

```bash
cargo run --example pkcs11_mock_setup
cargo run --example tpm_mock_setup
cargo run --example telemetry_uplink
```

See [examples/README.md](../examples/README.md) for what each prints.

## 4. Wire up SoftHSM2

```bash
mkdir -p ~/.config/softhsm2 ~/.local/share/softhsm2/tokens
cat > ~/.config/softhsm2/softhsm2.conf <<'EOF'
directories.tokendir = ~/.local/share/softhsm2/tokens
objectstore.backend = file
log.level = INFO
EOF

softhsm2-util --init-token --slot 0 --label craton \
  --so-pin 3838 --pin 1234

# Generate an AES-GCM key and a P-256 ECDSA key:
pkcs11-tool --module libsofthsm2.so --login --pin 1234 \
  --keygen --key-type aes:32 --label craton-aes --id 01
pkcs11-tool --module libsofthsm2.so --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --label craton-ecc --id 02
```

Inside your Rust code:

```rust
use vs_crypto_pkcs11::{Pkcs11CryptoProvider, Pkcs11FunctionList, PinBuffer};

let fn_list: Pkcs11FunctionList = unsafe {
    // dlopen("libsofthsm2.so"), resolve C_GetFunctionList,
    // populate every field of Pkcs11FunctionList.
    load_pkcs11("libsofthsm2.so")?
};
let pin = PinBuffer::new(b"1234")?;
let mut provider = Pkcs11CryptoProvider::new_with_pin_buffer(fn_list, pin)?;
provider.register_key_handle(KeyId(0), aes_handle)?;
provider.register_key_handle(KeyId(1), ecdsa_handle)?;
```

See [crates/crypto-pkcs11/README.md](../crates/crypto-pkcs11/README.md)
for the full `Pkcs11FunctionList` layout.

## 5. Wire up swtpm

```bash
mkdir -p /tmp/craton-tpm
swtpm socket --tpm2 \
  --tpmstate dir=/tmp/craton-tpm \
  --ctrl type=unixio,path=/tmp/craton-tpm/ctrl \
  --server type=unixio,path=/tmp/craton-tpm/srv \
  --flags not-need-init,startup-clear &
export TPM2TOOLS_TCTI="swtpm:path=/tmp/craton-tpm/srv"
tpm2_startup -c
tpm2_createprimary -C o -g sha256 -G ecc256 -c /tmp/craton-tpm/primary.ctx
```

Inside your Rust code, populate a `TpmFunctionList` with resolved
`Esys_*` symbols (see
[crates/crypto-tpm/README.md](../crates/crypto-tpm/README.md)) and
construct:

```rust
let provider = TpmCryptoProvider::new(fn_list)?;
let mut tag = [0u8; 16];
let mut ciphertext = [0u8; 128];
provider.encrypt_aead(KeyId(0), &nonce, b"ad", plaintext,
                      &mut ciphertext, &mut tag)?;
```

## 6. Telemetry uplink: the nonce-safe pattern

The single most important invariant in the enterprise stack is that
`TelemetryUplink` **must not** reuse an AES-GCM nonce. The API enforces
this by requiring a `PersistedFlushCounter` that the integrator has
committed to non-volatile storage *before* the uplink is constructed.

```rust
use vs_vsoc_telemetry::{PersistedFlushCounter, TelemetryUplink};

// Boot path:
let counter = match nvram_read_flush_counter()? {
    Some(n) => PersistedFlushCounter::restore(n),
    None    => PersistedFlushCounter::fresh_device(),
};
let mut uplink = TelemetryUplink::restore(provider, KeyId(0), KeyId(1),
                                          vsoc_nonce_domain, counter);

// Production flush — write-ahead-persists the counter BEFORE encrypt/sign.
// `nvram_persistence` is your `impl CounterPersistence` writing to NVRAM.
let flush_result = uplink.flush_with_persistence(&crypto, ts_us,
                                                 &mut nvram_persistence)?;
```

Do **not** call the older `flush(&crypto, ts_us)` shape — it has been
renamed to `flush_no_persist` and marked `#[deprecated]` precisely
because it skips the counter-persistence contract above and can
cause AES-GCM nonce reuse after a reboot.

Do **not** call `TelemetryUplink::new_with_counter(raw_u64)` — it is
`#[deprecated]` because the raw-`u64` form silently encouraged
nonce-reuse accidents (see
[docs/threat-model.md](threat-model.md) §T2 and
[docs/operational-security.md](operational-security.md) §3.3).

## 7. Where to go next

| Topic | Document |
|:---|:---|
| Key rotation, IR, monitoring | [docs/operational-security.md](operational-security.md) |
| STRIDE threat model | [docs/threat-model.md](threat-model.md) |
| SBOM, signing, deny policy | [docs/supply-chain.md](supply-chain.md) |
| Porting to a new SoC / HSM | [docs/porting-guide.md](porting-guide.md) |
| Primitive matrix, FIPS mapping, PQC plan | [docs/crypto-agility.md](crypto-agility.md) |
| Tested devices and BSPs | [docs/hardware-compatibility.md](hardware-compatibility.md) |
| Certification posture | [docs/certification-status.md](certification-status.md) |
| WCET / performance | [docs/wcet.md](wcet.md), [docs/performance.md](performance.md) |
| Upgrading from 0.6.x | [docs/migration-0.6-to-0.7.md](migration-0.6-to-0.7.md) |

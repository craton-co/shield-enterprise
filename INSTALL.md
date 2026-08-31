# Installation Guide

## Prerequisites

### All Platforms

- **Rust toolchain**: 1.82 or later (`rustup update stable`)
- **cargo-audit**: `cargo install cargo-audit` (optional, for security checks)
- **cargo-deny**: `cargo install cargo-deny` (optional, for dependency policy)

### Windows

The Rust toolchain itself works natively on Windows via `rustup`, and the
`cargo build` / `cargo test` commands below run unchanged in PowerShell or
`cmd.exe`. However, several helper scripts in this repository
(`scripts/*.sh`, the SoftHSM2 / swtpm bring-up snippets, and the QNX SDP
environment file) are POSIX shell scripts. Windows users should run them
under **WSL2** (recommended) or **Git Bash**. Native `cmd.exe` /
PowerShell are not supported for those scripts.

### Craton Shield Core

This enterprise workspace depends on the Apache-2.0 core repository being
checked out as a sibling directory. The core repo's working tree contains
the crates under a top-level `core/` subdirectory:

```
<parent>/
  craton-shield/              # git clone https://github.com/craton-co/craton-shield.git
    core/                     # crates live here (types/, crypto/, hal/, ...)
  craton-shield-enterprise/   # git clone https://github.com/craton-co/craton-shield-enterprise.git
```

```bash
git clone https://github.com/craton-co/craton-shield.git
git clone https://github.com/craton-co/craton-shield-enterprise.git
```

All path dependencies in this workspace are of the form
`../craton-shield/core/<crate>`.

## Build

### Development Build (Host Platform)

```bash
cd craton-shield-enterprise
cargo build --workspace
cargo test --workspace
```

### Release Build

```bash
cargo build --release --workspace
```

### Cross-Compilation Targets

#### ARM Cortex-M (bare-metal, no_std)

```bash
rustup target add thumbv7em-none-eabihf
cargo check --target thumbv7em-none-eabihf \
  -p vs-crypto-pkcs11 \
  -p vs-crypto-tpm \
  -p vs-hal-qnx \
  -p vs-vsoc-telemetry
```

#### AArch64 Linux (e.g., NXP S32G, Raspberry Pi)

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
cargo build --target aarch64-unknown-linux-gnu --workspace
```

#### QNX Neutrino (requires QNX SDP 7.1+)

```bash
# Set up QNX SDP environment
source /path/to/qnx710/qnxsdp-env.sh

# Build for QNX aarch64
cargo build --target aarch64-unknown-nto-qnx710 -p vs-hal-qnx
```

## Platform-Specific Dependencies

### PKCS#11 (vs-crypto-pkcs11)

The PKCS#11 provider does not link against any library at compile time.
At runtime, the caller must provide function pointers from a PKCS#11 library:

| Environment | Library | Notes |
|:---|:---|:---|
| Development | SoftHSM2 | `apt install softhsm2` / `brew install softhsm` |
| Production | Thales Luna, Utimaco, NXP SE050 | Vendor-provided PKCS#11 `.so` |
| Embedded | Microchip ATECC | Static linking via vendor SDK |

**SoftHSM2 Quick Setup (Development):**

```bash
# Install
sudo apt-get install softhsm2

# Initialize a token
softhsm2-util --init-token --slot 0 --label "craton-dev" --pin 1234 --so-pin 0000

# Generate a test AES key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keygen --key-type aes:32 --label vs-key-00

# Generate a test EC key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --label vs-key-01
```

### TPM 2.0 (vs-crypto-tpm)

The TPM provider does not link against any library at compile time.
At runtime, the caller must provide TSS2 ESAPI function pointers:

| Environment | Library | Notes |
|:---|:---|:---|
| Development | swtpm + tpm2-tss | Software TPM simulator |
| Production | Hardware dTPM | Kernel driver + tpm2-tss |
| Firmware | fTPM (ARM TrustZone) | Platform-specific integration |

**swtpm Quick Setup (Development):**

```bash
# Install
sudo apt-get install swtpm tpm2-tools libtss2-dev

# Start the software TPM
mkdir /tmp/mytpm
swtpm socket --tpmstate dir=/tmp/mytpm --tpm2 \
  --ctrl type=tcp,port=2322 --server type=tcp,port=2321

# Set TCTI for tpm2-tools
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"

# Create a persistent AES key
tpm2_createprimary -C o -g sha256 -G aes256cfb -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81000001
```

### QNX Neutrino (vs-hal-qnx)

- **QNX SDP 7.1+** with `io-pkt` and `dev-can-*` drivers
- CAN: Start `dev-can-<driver> -b500000` before using CAN APIs
- Ethernet: Start `io-pkt-v6-hc` with appropriate driver before using Ethernet APIs
- No additional Rust dependencies beyond the QNX cross-compilation target

## Verification

After building, run the full verification suite:

```bash
# Unit and integration tests
cargo test --workspace

# Lint checks
cargo clippy --workspace --all-targets -- -D warnings

# Dependency audit
cargo audit

# Dependency policy
cargo deny check

# Documentation build
cargo doc --workspace --no-deps
```

## Troubleshooting

| Problem | Solution |
|:---|:---|
| `can't find crate for vs_types` | Ensure the core repository is cloned as a sibling directory named `craton-shield/` (whose working tree contains `core/`) |
| `error[E0463]: can't find crate for std` | You're building for a `no_std` target; use `cargo check` instead of `cargo test` |
| `linker 'aarch64-linux-gnu-gcc' not found` | Install cross-compilation tools: `sudo apt-get install gcc-aarch64-linux-gnu` |
| `PKCS#11 function pointer is null` | Verify all fields of `Pkcs11FunctionList` are populated before calling `new()` |
| `TPM2_RC_FAILURE` in tests | Ensure swtpm is running and TCTI environment is set |

### `error[E0433]: failed to resolve: use of undeclared crate`

Ensure the core repository is cloned as a sibling directory named
`craton-shield/` (whose working tree already exposes a top-level `core/`
folder containing the crates). All path dependencies in this workspace
use the `../craton-shield/core/<crate>` layout:

```text
<parent>/
├── craton-shield/              ← git clone https://github.com/craton-co/craton-shield.git
│   └── core/                   ← crates live here
└── craton-shield-enterprise/   ← this repo
```

### SoftHSM2 token not found

```bash
# Initialize a token for development
softhsm2-util --init-token --slot 0 --label "craton-dev" --pin 1234 --so-pin 0000
```

### swtpm fails to start

```bash
# Create state directory and start swtpm
mkdir -p /tmp/swtpm-state
swtpm socket --tpmstate dir=/tmp/swtpm-state --tpm2 \
  --ctrl type=tcp,port=2322 --server type=tcp,port=2321 &
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
```

### QNX cross-compilation fails

Ensure QNX SDP 7.1+ is installed and environment is sourced:

```bash
source /path/to/qnxsdp-env.sh
cargo build --target aarch64-unknown-nto-qnx710 --workspace
```

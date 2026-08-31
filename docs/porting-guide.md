# Porting Guide

This document describes how to port Craton Shield Enterprise to a new hardware
platform. The runtime is `no_std` Rust; porting requires implementing a small
set of HAL traits and linking the appropriate cryptographic backend.

## 1. Implement the `HalProvider` Traits

Every platform must supply concrete types for three traits defined in
`vs-hal`:

### CanBus

```rust
pub trait CanBus {
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError>;
    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError>;
    fn bitrate(&self) -> u32;
    fn is_bus_off(&self) -> bool;
}
```

Map these to your controller's mailbox or FIFO registers. On Linux targets the
reference implementation wraps SocketCAN; on QNX it calls into `devctl()`.

### Timer

```rust
pub trait Timer {
    fn now_us(&self) -> u64;
    fn cycle_count(&self) -> Option<u64>;
}
```

Use the highest-resolution monotonic clock available. On Cortex-M targets,
`DWT::CYCCNT` is typical; on QNX, use `ClockCycles()` with the
`SYSPAGE_ENTRY(qtime)->cycles_per_sec` divisor.

### EthernetPhy

```rust
pub trait EthernetPhy {
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError>;
    fn transmit(&mut self, data: &[u8]) -> Result<(), VsError>;
    fn link_speed_mbps(&self) -> u32;
    fn link_is_up(&self) -> bool;
}
```

For bare-metal targets, implement directly against the MAC/DMA descriptor ring.
For POSIX-like targets, a raw socket or TAP device is sufficient.

## 2. Platform-Specific FFI Considerations

The C FFI layer (`vs-ffi`) exposes a stable C ABI via `cbindgen`. When porting:

- Ensure your linker script exports the symbols listed in
  `vs-ffi/craton_shield.h` (provided by `craton-shield-core`).
- If the target OS provides its own libc (QNX, Linux), link against it
  normally. For bare-metal Cortex-M, use `newlib-nano` or supply your own
  `memcpy`/`memset`/`memcmp` implementations.
- All FFI functions use `#[no_mangle]` and `extern "C"`. Do not rename them.
- Stack usage is bounded; see the performance guide (`docs/performance.md`) for stack usage guidance.

## 3. Building for Target Platforms

> **Note.** There is no workspace-wide `std` feature in this enterprise
> repo. Host-target test builds pull in `std` behind `#[cfg(test)]`
> automatically; no flag needs to be passed. The feature names shown in
> the per-target commands below (`can`, `ethernet`) are illustrative of
> integrator HAL feature sets and are not exposed by any crate in this
> workspace today.


### Cortex-M (thumbv7em-none-eabihf)

Platform HALs implement the `vs-hal` traits (`CanBus`, `Timer`, `EthernetPhy`)
for the target hardware. For example, with Cortex-M:

```sh
cargo build --target thumbv7em-none-eabihf \
    --no-default-features \
    --features "can,ethernet"
```

Requires `rust-std` component for the target. Add a `.cargo/config.toml` with
your linker and `runner` (e.g., `probe-run` or `openocd`).

### AArch64 (aarch64-unknown-none)

Platform HALs implement the `vs-hal` traits for AArch64 targets:

```sh
cargo build --target aarch64-unknown-none \
    --no-default-features \
    --features "can,ethernet"
```

For Linux user-space testing, use the `aarch64-unknown-linux-gnu`
target; `std` is pulled in automatically under `#[cfg(test)]`.

### QNX (x86_64-pc-nto-qnx710 / aarch64-unknown-nto-qnx710)

```sh
source /opt/qnx710/qnxsdp-env.sh
cargo build --target x86_64-pc-nto-qnx710 \
    -p vs-hal-qnx
```

The QNX HAL uses `extern "C"` bindings to `clock_gettime`, `ClockCycles`,
and CAN driver `devctl` ioctls. The bindings are inlined as the
`mod qnx_ffi` module inside `crates/hal-qnx/src/lib.rs` (there is no
separate `ffi.rs` file). See that module for the full binding surface.

## 4. Linking Crypto Backends

### PKCS#11

The PKCS#11 provider does **not** link against any library at compile time
and does not use `dlsym`. Instead, the caller resolves PKCS#11 function
pointers (e.g., via `dlopen`/`dlsym` on Linux, or static linking on embedded
targets) and populates a `Pkcs11FunctionList` struct. This struct is passed
to `Pkcs11CryptoProvider::new()` at construction time.

Required function pointers:

- `C_Initialize`, `C_Finalize`, `C_OpenSession`, `C_CloseSession`, `C_Login`
- `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt`
- `C_DigestInit`, `C_Digest`
- `C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify`
- `C_DeriveKey`, `C_DestroyObject`, `C_GenerateRandom`
- `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`
- `C_GetAttributeValue`, `C_GetTokenInfo`, `C_CreateObject`

### TPM 2.0 (ESAPI)

The TPM 2.0 provider does **not** link against any library at compile time.
Instead, the caller resolves TSS2 ESAPI function pointers and populates a
`TpmFunctionList` struct passed to `TpmCryptoProvider::new()`.

Required function pointers:

- `Esys_Initialize`, `Esys_Finalize`, `Esys_Free`
- `Esys_SelfTest`
- `Esys_Hash`, `Esys_HMAC`
- `Esys_EncryptDecrypt2`
- `Esys_Sign`, `Esys_VerifySignature`
- `Esys_ECDH_ZGen`
- `Esys_GetRandom`
- `Esys_PCR_Extend`, `Esys_PCR_Read`
- `Esys_TR_FromTPMPublic`, `Esys_TR_Close`

### Software-Only (mock-hsm)

For development and CI, enable the `mock-hsm` feature. This compiles a
software-only `CryptoProvider` that uses `ring` or `RustCrypto` crates.
This feature is blocked from release profile builds via a `cfg` assertion.

## 5. Integration Testing with QEMU

The cross-repository integration tests live in the sibling
`craton-shield` repository (the Apache-2.0 core), not in this
enterprise workspace. They are organised as standard cargo
integration tests under `../craton-shield/core/tests/` and are
exercised by running `cargo test` from the core workspace root.

<!--
TODO(maintainers): there is no `vs-integration-tests` crate in either
this repo or the sibling `craton-shield` core repo, and there are no
`qemu-cortexm` / `qemu-aarch64` cargo features today. The QEMU
harness commands below are aspirational. Either (a) add a dedicated
integration-test crate to the core workspace that gates a QEMU
runner behind those features, or (b) replace this section with the
actual host-side `cargo test --workspace` invocation that the CI
runs. Until then this section is marked "Once available".
-->

Once available, the QEMU runs are expected to look like:

```sh
# Cortex-M (LM3S6965 machine) — not yet wired up
cargo test --target thumbv7em-none-eabihf \
    --features "qemu-cortexm"

# AArch64 (virt machine) — not yet wired up
cargo test --target aarch64-unknown-none \
    --features "qemu-aarch64"
```

QEMU semihosting is intended for test output; the test harness would
set up virtual CAN and Ethernet devices via QEMU's `-device`
options. Refer to the CI workflow (`.github/workflows/ci.yml`) for
the cross-compilation configuration that is already in place.

To validate a new port before running on real hardware:

1. Implement `HalProvider` traits against QEMU virtual peripherals.
2. Once the QEMU harness above lands, run the standard integration
   test suite under QEMU.
3. Run the `ecu_validation` test suite — it lives in the sibling
   `craton-shield` core repository at
   `../craton-shield/core/tests/ecu_validation.rs`, and is invoked
   via `cargo test --test ecu_validation` from that workspace root —
   with your HAL implementation wired into the core HAL traits.

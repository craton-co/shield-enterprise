# CLAUDE.md

Project-specific guidance for AI assistants working on this codebase.

## Project Overview

Craton Shield Enterprise provides hardware-backed cryptographic providers (PKCS#11 HSM, TPM 2.0),
QNX RTOS integration, and fleet telemetry for the Craton Shield vehicle cybersecurity platform.

## Build & Test

```bash
cargo build --workspace           # Build all crates
cargo test --workspace            # Run all tests
cargo clippy --workspace          # Lint check
cargo fmt --all -- --check        # Format check
```

## Architecture Rules

- **`#![no_std]`** is mandatory in all production code. No `Vec`, `Box`, `String`, or heap allocation.
- **`unsafe`** is only permitted at FFI boundaries (`crypto-pkcs11`, `crypto-tpm`). Every `unsafe` block must have a `// SAFETY:` comment.
- All public types must be `#[repr(C)]` and derive `Debug`, `Clone`, `Copy` where applicable.
- Use `Result<T, VsError>` for all fallible operations. No `.unwrap()` or `.expect()` in production code.
- Fixed-size buffers only. Maximum buffer size is 2048 bytes.
- All new tests require both positive and negative paths.

## Crate Dependencies

Enterprise crates depend on the Apache-2.0 core repository, which is
checked out alongside this repo under a shared `craton-shield/` parent
directory (path deps resolve to `../craton-shield/core/<crate>`):
- `vs-types` — error types, `KeyId`, `AlertSeverity`
- `vs-crypto` — `CryptoProvider` trait
- `vs-hal` — `CanBus`, `Timer`, `EthernetPhy` traits

## Key Conventions

- PKCS#11 functions are accessed via caller-supplied function pointers (`Pkcs11FunctionList`)
- TPM functions are accessed via caller-supplied function pointers (`TpmFunctionList`)
- Key slots are indexed by `KeyId(0..63)`
- AES-GCM nonces must never be reused with the same key
- The TPM crate uses AES-CFB + HMAC-SHA-256 (Encrypt-then-MAC) instead of native AES-GCM
- Telemetry `flush_counter` must be persisted across reboots to prevent nonce reuse

# Contributing to Craton Shield Enterprise

Thank you for your interest in contributing to Craton Shield Enterprise. This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/craton-co/craton-shield-enterprise.git
cd craton-shield-enterprise

# Verify the toolchain
rustup update stable
cargo --version   # 1.82+

# Build and test
cargo build --workspace
cargo test --workspace
```

## Code of Conduct

Please note that this project is released with a [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Code Quality Requirements

All contributions must pass these checks before merging:

```bash
# All tests pass
cargo test --workspace

# Zero clippy warnings (pedantic mode)
cargo clippy --workspace -- -D warnings

# Zero known vulnerabilities
cargo audit

# Zero broken doc links
cargo doc --workspace --no-deps
```

## Coding Standards

### Rust

- All crates use `#![no_std]` — no `std` library in production code
- Zero heap allocation — use fixed-size arrays, not `Vec`, `Box`, or `String`
- No `.unwrap()` or `.expect()` in production code — use `Result<T, VsError>` with `?`
- `unsafe` only at the FFI boundary (`vs-crypto-pkcs11`, `vs-crypto-tpm`) — every `unsafe` block requires a `// SAFETY:` comment
- All public types use `#[repr(C)]` for FFI compatibility
- All public types derive `Debug`, `Clone`, `Copy` where appropriate

### Lints

The workspace enforces strict linting via `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "deny"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
```

The workspace uses the default `rustfmt` configuration. Run `cargo fmt --all` before submitting.

### Tests

- Place unit tests in `#[cfg(test)] mod tests` within the same file
- Use deterministic test data — no random inputs except in fuzz targets
- Write both positive (happy path) and negative (error path) tests
- Name tests descriptively: `test_flood_detection_triggers_on_high_rate`

### Commits

- Use conventional commit messages: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- Keep commits focused — one logical change per commit
- Reference issue numbers when applicable

## Architecture Guidelines

### Adding a New Crate

1. Create under `crates/<name>/`
2. Add `#![no_std]` to `lib.rs`
3. Depend only on `vs-types` and optionally `vs-crypto`
4. Add the crate to workspace `members` in root `Cargo.toml`
5. Wire into the runtime if it needs orchestration
6. Add FFI exposure if it needs C access
7. Minimum 10 unit tests
8. Update CHANGELOG.md with the addition

### Modifying the CryptoProvider Trait

The `CryptoProvider` trait in `vs-crypto` (defined in `craton-shield-core`) is the central abstraction for all cryptographic operations. Changes to this trait affect every crate that uses cryptography, including the enterprise `vs-crypto-pkcs11` and `vs-crypto-tpm` implementations. Ensure backward compatibility or coordinate changes across all consumers.

### Deprecating Public API

Public-API removal and deprecation must follow the project's deprecation
policy — see [`docs/deprecation-policy.md`](docs/deprecation-policy.md)
<!-- created by docs agent --> for required notice periods, the
`#[deprecated]` attribute conventions, and the CHANGELOG categories used
to surface removals.

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes, following the coding standards above
3. Ensure all CI checks pass locally: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`, `cargo audit`, and `cargo doc --workspace --no-deps`. **CI gates are mandatory for all merges**.
4. Submit a pull request with a clear description of the changes
5. Address review feedback

## Reporting Issues

Use the GitHub issue tracker. Include:

- Craton Shield version and Rust toolchain version
- Target platform (OS, architecture)
- Steps to reproduce
- Expected vs actual behavior

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Developer Certificate of Origin (DCO)

By contributing to this project, you certify that each of your commits is your original work or that you have the right to submit it. All contributions must include a `Signed-off-by` line in the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

This certifies you agree to the [Developer Certificate of Origin](https://developercertificate.org/).
Use `git commit -s` to add the sign-off automatically.

## License

By contributing, you agree that your contributions will be licensed under the Business Source License 1.1 (BSL-1.1), consistent with the project's licensing. The BSL-1.1 automatically converts to Apache-2.0 on 2030-09-01.

# Build & CI Matrix

The CI configuration under `.github/workflows/ci.yml`,
`security.yml`, and `release.yml` is the source of truth. This
document explains what each job covers and why.

Last reviewed against the workflow files on `main` as of 2026-05-10.

> **Scope note.** Several feature flags below (`mock-hsm`, `pq-software`)
> live in the sibling `craton-shield-core` repo's crates, not this
> workspace. They appear in this table only because the core repo is
> built as a path dependency in CI. See
> [docs/feature-flags.md](feature-flags.md) for which features belong
> to which repo.

## 1. MSRV

| Field | Value |
|:---|:---|
| MSRV (Minimum Supported Rust Version) | **1.82** |
| Declared in | `rust-toolchain.toml` (pinned), `Cargo.toml` (`rust-version = "1.82"`) |
| Bump policy | MSRV may bump in any **minor** release during 0.x; in **major** only after 1.0. |
| Verification | The `check-msrv` CI job installs exactly `rustc 1.82` and runs `cargo check --workspace`. |

Integrators targeting long-support distros (RHEL 9, Ubuntu 22.04) can
build with the distro rustc 1.82 packages; newer toolchains are
supported but not required.

## 2. Host OS × target-triple matrix

| Host | Target | Job | Purpose |
|:---|:---|:---|:---|
| `ubuntu-24.04` | `x86_64-unknown-linux-gnu` | `test` | Primary test suite. |
| `ubuntu-24.04` | `aarch64-unknown-linux-gnu` | `check-aarch64-linux` | Cross-compile check (no runtime). |
| `ubuntu-24.04` | `aarch64-unknown-nto-qnx710` | `check-qnx` | QNX cross-compile check (requires QNX SDP in self-hosted runner). |
| `ubuntu-24.04` | `thumbv7em-none-eabihf` | `check-thumbv7em` | Cortex-M4F no_std build check. |
| `ubuntu-24.04` | `thumbv7em-none-eabi` | `check-thumbv7em-softfloat` | Cortex-M4 softfloat no_std build check. |
| `macos-14` | `x86_64-apple-darwin` / `aarch64-apple-darwin` | `test-macos` | Dev ergonomics; skipped for release artifacts. |
| `windows-2022` | `x86_64-pc-windows-msvc` | `test-windows` | Dev ergonomics. |

## 3. Feature-flag interaction matrix

The `test-all-features` CI job (added in 0.7.1) runs
`cargo test --workspace --features <combo>` across the
combinations listed below. Any new feature flag must be added here
before the PR can merge.

| Combination | Purpose |
|:---|:---|
| `default` | Baseline. |
| `strict-nonce` | Telemetry nonce-counter enforcement (removes unsafe constructor at compile time). |
| `strict-rng` | PKCS#11 + TPM sentinel-pattern TRNG checks. |
| `mock-hsm` **[core]** | Pure-software HSM for host-side CI (core repo; must not be enabled in release builds). |
| `pq-software` **[core]** | ML-KEM-768 + ML-DSA-65 experimental (core repo). |
| `strict-nonce,strict-rng` | Production profile. |
| `strict-nonce,strict-rng,pq-software` **[core+enterprise]** | Production + PQ preview (PQ is core-side). |
| `mock-hsm,strict-nonce,strict-rng` **[core+enterprise]** | Host CI profile used by `test`. |

Compile-time guard: `mock-hsm` and `std` in a release profile trigger
`compile_error!` via the feature-gate wiring in each crate. That guard
is itself tested by `check-release-feature-guards`.

## 4. CI jobs (ci.yml)

| Job | Runs on | What it enforces |
|:---|:---|:---|
| `fmt` | ubuntu-24.04 | `cargo fmt --all -- --check` |
| `clippy` | ubuntu-24.04 | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test` | ubuntu-24.04 | `cargo test --workspace` (host profile). |
| `test-all-features` | ubuntu-24.04 | Feature matrix above. |
| `check-msrv` | ubuntu-24.04 | rustc 1.82 `cargo check --workspace`. |
| `check-aarch64-linux` | ubuntu-24.04 | Cross-compile. |
| `check-thumbv7em` | ubuntu-24.04 | Cortex-M4F no_std. |
| `check-thumbv7em-softfloat` | ubuntu-24.04 | Cortex-M4 softfloat. |
| `check-qnx` | self-hosted (QNX SDP) | QNX 7.1 aarch64 cross. |
| `cargo-semver-checks` | ubuntu-24.04 | API stability vs last published crate. |
| `markdown-links` | ubuntu-24.04 | Internal doc-link check (CI badge URLs excluded). |
| `coverage` | ubuntu-24.04 | `cargo-llvm-cov` ≥ 85% workspace, ≥ 80% per crate. |
| `reproducible-build` | ubuntu-24.04 | Two clean-room release builds; hash-equal. |

## 5. Security jobs (security.yml)

| Job | Cadence | Purpose |
|:---|:---|:---|
| `cargo-audit` | Every push/PR + nightly | RustSec advisory DB scan. |
| `cargo-deny check` | Every push/PR | `deny.toml` license + ban + source allowlist. |
| `supply-chain-sbom` | Nightly + release | CycloneDX SBOM generated and archived. |
| `secret-scan` | Every push/PR | `gitleaks` against the diff. |

## 6. Fuzz jobs (fuzz.yml)

| Target | Purpose |
|:---|:---|
| `can_frame` | CAN frame parser |
| `eth_packet` | Ethernet frame parser |
| `ota_metadata` | TUF root JSON |
| `tara_input` | TARA report generator input |
| `iec62304_input` | IEC 62304 report input |
| `iec62443_capabilities` | IEC 62443 capabilities |
| `telemetry_entry` | Telemetry entry ser/deser |
| `uds_request` | UDS diagnostic frame |
| `pkcs11_mock_crypto` | `PinBuffer` and PKCS#11 mock surface |
| `tpm_ec_point` | P-256 uncompressed-point shape handling |

Fuzz corpora live in `fuzz/corpus/`; CI runs each target for 5 minutes
per push, 60 minutes per nightly.

## 7. Release workflow (release.yml)

| Stage | Purpose |
|:---|:---|
| `verify-tag-signature` | Pre-flight GPG verification; blocks later stages. |
| `build` | Release binaries, workspace-wide. |
| `sbom` | `scripts/generate-sbom.sh` → CycloneDX JSON. |
| `sign-cosign` | Artifact signing. |
| `slsa-generate` | SLSA v1.0 provenance via `slsa-github-generator`. |
| `slsa-verify` | `slsa-verifier` validates the provenance before publishing. |
| `publish-release` | Creates the GitHub Release with all artifacts. |

See [docs/release-process.md](release-process.md) for the human-side
runbook.

## 8. Known CI limitations

- QNX and Thales Luna tests rely on self-hosted runners. The public
  Actions runners cannot access either. PRs from external contributors
  skip those jobs and require a maintainer re-run post-review.
- Intel PTT and AMD fTPM are not exercised in CI; covered in
  [docs/hardware-compatibility.md](hardware-compatibility.md)
  under "Reported" status.
- DO-178C / IEC 61508 tool-qualification artifacts are **not**
  currently produced by CI; they will be added alongside the
  Ferrocene-based toolchain (see
  [docs/certification-status.md §9](certification-status.md)).

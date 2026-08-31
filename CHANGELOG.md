# Changelog

All notable changes to Craton Shield are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No unreleased changes at this time._

## [0.7.2] — 2026-05-23

### Audit Mitigation

This release closes findings from an internal certification-readiness audit
covering the enterprise crates. Aggregate counts by severity:

- **CRITICAL:** 10 findings (CRIT-1 through CRIT-10)
- **HIGH:** many (HIGH-A through HIGH-Y, plus the HIGH-PKCS11 / HIGH-TPM
  / HAL-QNX batched series)
- **MEDIUM:** many (MED-9, MED-12, MED-N, MED-RepC, and the wider MED-*
  remediation pass)
- **LOW:** many (LOW-6, LOW-7, and the broader LOW-* hygiene pass)

The release also incorporates the certification-audit remediation pass
(see grouped entries below) and a refreshed documentation set for
hardware compatibility, getting-started, migration, release process,
certification status, build matrix, threat-model, operational-security,
supply-chain, crypto-agility, and licensing.

### Added

- CI concurrency blocks, OpenSSF Scorecard workflow,
  `dependency-review` job on pull requests, and a DCO sign-off check.
- Cargo metadata enriched for crates.io publication (description,
  repository, license, categories, keywords across the workspace).
- `rv_to_err` (PKCS#11) and `rc_to_err` (TPM) helpers in the error
  modules replacing the final `.unwrap_err()` calls inside the
  `verify_p256` catch-all arms; positive/negative unit tests cover
  both helpers.
- `docs/hardware-compatibility.md` — authoritative compatibility matrix
  for PKCS#11 HSMs, TPM 2.0 devices, and QNX BSPs with tested firmware
  versions and known quirks.
- `docs/getting-started.md` — end-to-end walkthrough covering prereqs,
  workspace bring-up, the orientation examples, and a SoftHSM2 / swtpm
  integration loop.
- `docs/migration-0.6-to-0.7.md` — migration notes for callers moving
  from the v0.6.x telemetry API to the 0.7.x `PersistedFlushCounter`
  / `TelemetryUplink::restore` flow.
- `docs/release-process.md` — release runbook covering version bumps,
  backport policy, RC cadence, and the signing / provenance steps
  required for a BSL-1.1-compliant tag.
- `docs/certification-status.md` — current posture against ISO/SAE
  21434, ISO 26262, IEC 62443, IEC 62304, and DO-178C, including
  which controls are implemented in-repo vs. deferred to the host
  integrator.
- `docs/build-matrix.md` — enumerates the CI matrix (host OS × target
  triple × feature-flag set) and the MSRV validation job.
- ABI-versioning section in `docs/api-stability.md` covering the
  enterprise-local FFI types (`Pkcs11FunctionList`, `TpmFunctionList`,
  `PinBuffer`) that are **not** part of the core `vs-ffi` surface.
- Certification-audit remediation pass:
  - `strict-nonce` Cargo feature on `vs-vsoc-telemetry` that removes
    `TelemetryUplink::new()` so production builds cannot accidentally
    construct an uplink with a zero counter.
  - `strict-rng` Cargo feature on `vs-crypto-pkcs11` / `vs-crypto-tpm`
    that arms sentinel-pattern checks around the token TRNG and rejects
    the call if the token returns success without writing the buffer.
  - `PinBuffer` type (PKCS#11) — fixed-size PIN holder that volatile-
    wipes itself on `Drop`; new `new_with_pin_buffer` /
    `try_clone_with_pin_buffer` constructors accept it directly.
  - Sentinel-pattern detection across PKCS#11 `sha256`,
    `hmac_sha256`, and `sign_p256`: a token that returns `CKR_OK`
    without overwriting the output is now rejected rather than
    propagating uninitialised / stale data.
  - Checked `usize → CkUlong` conversions on every caller-controlled
    length passed through the PKCS#11 FFI, preventing silent truncation
    on 32-bit targets.
  - Volatile-wipe helper (`volatile_wipe`) in telemetry and PKCS#11
    replaces `fill(0)` on transient plaintext / nonce / AAD / digest
    buffers so the zeroing store cannot be dead-code-eliminated.
  - Expanded `// SAFETY:` comments in `vs-crypto-tpm` around ESAPI
    ownership transfer, union-variant access (`sig_alg` discriminant
    check before reading `ecdsa`), and `esys_free` uniqueness.
  - QNX device-path validator now rejects interior nul bytes in
    `QnxCanBus::new_with_device` / `QnxEthernetPhy::new_with_device`.
  - Non-QNX `Timer` / `CanBus` / `EthernetPhy` stubs now trip a
    `debug_assert!` when called outside `#[cfg(test)]`, so a
    misconfigured target triple fails loudly in debug builds.
  - `docs/crypto-agility.md` — primitive matrix with FIPS cert IDs,
    sunset triggers, and the post-quantum migration plan.
  - `docs/licensing.md` — BSL-1.1 terms, change date, commercial use
    policy.
  - Two new fuzz targets: `pkcs11_mock_crypto` (drives `PinBuffer`
    invariants) and `tpm_ec_point` (exercises P-256 uncompressed-point
    shape handling).
  - CI: reproducible-build job verifies workspace release binaries hash
    identically across two clean-room builds; `supply-chain` job runs
    `cargo audit` + `cargo deny check` on every push / PR; per-crate
    coverage floor (80%) enforced in addition to workspace 85%.
  - Release workflow verifies the git tag signature in a pre-flight
    job (before any cosign / SLSA step), installs `slsa-verifier`, and
    validates the generated provenance before publishing; SBOM
    generation is unified to `scripts/generate-sbom.sh`.
- `PersistedFlushCounter` newtype and `TelemetryUplink::restore()` constructor
  for nonce-safe telemetry bring-up after reboot. The old
  `TelemetryUplink::new_with_counter()` is now `#[deprecated]` — it silently
  accepted raw `u64` and encouraged nonce-reuse accidents.
- Pure frame parse / serialize helpers in `vs-hal-qnx`
  (`parse_can_frame`, `serialize_can_frame`, `parse_eth_frame`) exercised by
  unit tests on every host, covering short buffers, oversized DLC, truncated
  payloads, minimum / maximum Ethernet frame sizes, and BPF header handling.
- `docs/threat-model.md`, `docs/operational-security.md`, and
  `docs/supply-chain.md` for STRIDE, key-rotation playbooks, and
  SBOM/deny-policy/signing reference.
- Compile-time invariants (`const _: () = assert!(...)`) documenting and
  enforcing tag length, HMAC truncation bound, and EC-point layout in the
  TPM and PKCS#11 crates.
- Mermaid component diagram in `ARCHITECTURE.md`.
- Extensive fault-injection tests in both crypto crates: short / oversized
  out_len from the HSM, TCTI `NO_CONNECTION`, TPM2 signature-failure RCs
  across format-0 and format-1 encodings, null ESAPI return pointers,
  `C_Initialize` / `C_OpenSession` failure paths, and library pre-init
  bypass.
- CI coverage gate via `cargo-llvm-cov` with an 85% per-crate minimum.
- Release workflow now signs git tags with `--sign` and generates SLSA v1.0
  build provenance via `slsa-framework/slsa-github-generator`.

### Changed

- `deny.toml` migrated to the cargo-deny v2 schema.
- README now surfaces the TPM bus-confidentiality limitation so
  integrators do not assume parameter encryption is in scope.
- `Pkcs11CryptoProvider` and `TpmCryptoProvider` now validate the length
  reported by the HSM / TPM after every crypto primitive and wipe any
  partially-written secret output (plaintext, HMAC tag, ECDSA signature,
  ECDH shared secret) before returning an error.
- `TelemetryUplink::flush()` rejects a decreasing `ts_us` (clock regression)
  rather than silently resetting the rate-limit window, and explicitly
  zeroises the transient plaintext chain buffer before returning.
- `vs-hal-qnx`: `BPF_HEADER_SIZE` is now a crate-public constant so ports
  can verify the assumption; README status updated from "in development"
  to "production — Timer / CAN / Ethernet all wired on QNX 7.1 aarch64".
- TPM `compute_etm_tag` no longer double-buffers AAD || ciphertext
  through a second `Tpm2bMaxBuffer` on its way to `esys_hmac`; the
  concatenation and the HMAC call now share a single 2 KiB stack
  buffer via `hmac_with_buf`. Saves ~2 KiB of stack and one `memcpy`
  per Encrypt-then-MAC operation.
- README performance table now explicitly attributes the reported
  figures to Craton Shield Core, with a pointer to `docs/wcet.md` and
  `docs/performance.md` for enterprise-specific measurements.

### Fixed

- Telemetry `flush_counter` is advanced on encrypt failure so the
  persisted-state and in-memory counter remain consistent and nonce
  reuse cannot occur after a partial failure.
- Dockerfile rlib glob corrected and the in-builder `cargo test` step
  removed (tests run in the CI test job, not inside the release image).
- **[LOW]** PKCS#11 `C_Encrypt` oversized `out_len` was cast to `usize`
  without bounds-checking; now rejects values larger than the scratch
  buffer.
- **[LOW]** PKCS#11 `ecdh_derive_shared` left the peer public-key copy on
  the stack after use; now zeroised before the function returns.
- **[LOW]** PKCS#11 `sha256` / `hmac_sha256` / `sign_p256` did not validate
  the output-length reported by the token; short or long lengths now
  wipe the output and return `CryptoError`.
- **[LOW]** `.unwrap_err()` in production paths of `verify_p256` (PKCS#11
  and TPM) replaced with dedicated `rv_to_err` / `rc_to_err` helpers;
  closes the last two technical violations of the "no `.unwrap()` /
  `.expect()` in production" rule documented in CLAUDE.md.
- Stale claim in `crates/hal-qnx/README.md` that CAN and Ethernet I/O
  were stubbed on QNX.
- Stale version reference in `SECURITY.md` ("0.7.0 is current" → 0.7.1).
- CHANGELOG entries for 0.7.0 and 0.7.1 had been tagged with the same
  release date (2026-03-28); 0.7.0 now reflects its actual RC-cut
  date of 2026-03-21.

### Security

- Constant-time comparison of nonces in `vs-crypto-pkcs11` (closes a
  potential side-channel on nonce-equality checks).
- Closed nonce-reuse ergonomic hazard in `vs-vsoc-telemetry` by making
  the persisted-counter constructor the recommended API and marking the
  zero-counter constructor as a documented hazard.
- Explicit monotonic-timestamp precondition for `flush()` — a clock
  regression can no longer be used to bypass the per-minute rate limit.

## [0.7.1] — 2026-03-28

<!-- 0.7.1 is a hardening follow-up to 0.7.0 (see release below). -->


### Added

- `TpmCryptoProvider::try_clone()` — safe cloning that allocates a fresh ESAPI context
- Nonce domain separation (`"VS"` prefix) in `TelemetryUplink::flush()` to prevent cross-component nonce collisions
- `TpmlDigestValues` FFI type for correct PCR extend parameter passing
- `pub mod ffi` on both `vs-crypto-pkcs11` and `vs-crypto-tpm` for external access to function-list types
- QNX HAL: lazy device open for CAN (`/dev/can0`) and Ethernet (`/dev/bpf`) with `Drop`-based cleanup
- Integration examples: `pkcs11_mock_setup`, `tpm_mock_setup`, `telemetry_uplink`
- `Dockerfile.bench-arm` for ARM cross-compilation benchmarks
- `docs/wcet.md` — WCET analysis methodology and reference measurements
- `docs/aurix-evaluation.md` — TriCore TC3xx feasibility analysis
- `CITATION.cff` for academic citations
- `.github/FUNDING.yml` for sponsor button
- `rustfmt.toml` configuration file
- CI: `test-all-features` job for feature-flag interaction testing
- CI: `cargo-semver-checks` job for API stability enforcement
- All 8 fuzz targets wired in `fuzz/Cargo.toml` and `fuzz.yml` workflow
- Rustdoc landing page for workspace root crate

### Changed

- Compliance report crates (`vs-report-iec62443`, `vs-report-iso21434`, `vs-report-iec62304`) moved to [Craton Shield Core](https://github.com/craton-co/craton-shield) (Apache-2.0); removed from enterprise workspace
- `docs/porting-guide.md` trait signatures updated to match actual HAL code (`receive`/`transmit`, `now_us`/`cycle_count`)
- `docs/porting-guide.md` crypto backend sections updated to reflect caller-supplied function pointer design
- `SECURITY.md` scope updated to enterprise crates only (core crate vulnerabilities redirect to core repo)
- `ARCHITECTURE.md` updated to reflect current workspace contents
- `docs/feature-flags.md` scope clarified (covers core + enterprise ecosystem)
- `docs/api-stability.md` clarifies `vs-ffi` is in core repo
- `README.md` commercial license section simplified (pricing details moved off-repo)
- CI `markdown-links` exclusion narrowed to only CI badge URLs (no longer masks broken own-repo links)
- CI `check-thumbv7em` and `check-thumbv7em-softfloat` reference only enterprise crates
- Removed duplicate root `CODEOWNERS` (`.github/CODEOWNERS` is authoritative)

### Fixed

- **[HIGH]** `TpmCryptoProvider::Clone` caused double-free of ESAPI context (replaced with `try_clone()`)
- **[HIGH]** `unsafe impl Send for TpmCryptoProvider` was unsound (removed)
- **[MEDIUM]** PCR extend used incorrect type-punning cast (`TpmlDigestValues` → `TpmlPcrSelection`); replaced with proper `TpmlDigestValues` FFI type
- Fuzz `Cargo.toml` referenced non-existent local report crate paths
- Fuzz CI workflow targets did not match `fuzz/Cargo.toml` binary entries
- CI `check-thumbv7em*` jobs referenced crates not in enterprise workspace
- `examples/README.md` referenced non-existent example binaries
- PIN hygiene documentation added to `Pkcs11CryptoProvider::new()`

### Security

- Removed `unsafe impl Send` from `TpmCryptoProvider` — was unsound in multi-threaded contexts
- Fixed `TpmCryptoProvider::Clone` double-free vulnerability
- Added nonce domain separation to prevent cross-component nonce reuse
- Added PIN zeroization guidance to PKCS#11 provider documentation

## [0.7.0] — 2026-03-21

### Added

- **vs-crypto-pkcs11**: PKCS#11 HSM-backed CryptoProvider with AES-256-GCM, SHA-256, ECDSA P-256, HMAC-SHA-256, ECDH P-256 via any PKCS#11 v2.40+ token
- **vs-crypto-tpm**: TPM 2.0 TSS2 ESAPI-backed CryptoProvider with AES-CFB+HMAC Encrypt-then-MAC, SHA-256, ECDSA P-256, ECDH, PCR extend/read
- `FlushResult` return type for `TelemetryUplink::flush()` — callers now receive encrypted digest, tag, and signature
- `Pkcs11CryptoProvider::try_clone()` replaces unsafe `Clone` impl
- Nonce management documentation for PKCS#11 and TPM crypto providers
- `docs/porting-guide.md`, `docs/api-stability.md`, `docs/feature-flags.md`
- `ARCHITECTURE.md` for enterprise crate structure
- Dependabot configuration for automated dependency updates
- Release workflow for automated publishing

### Changed

- Bumped MSRV to Rust 1.82
- CI workflows updated to reference only enterprise workspace crates
- Dockerfile updated to Rust 1.82
- Compliance report crates moved to Craton Shield Core (Apache-2.0)

### Fixed

- `Pkcs11CryptoProvider::clone()` could cause double session close (replaced with `try_clone()`)
- Dockerfile referenced non-existent `wcet-harness` binary
- CI workflows referenced crates from core repo not present in enterprise workspace
- CODEOWNERS referenced non-existent paths (`crates/autosar/`, `crates/v2x/`)
- SECURITY.md linked to wrong repository for advisories
- LICENSE file had inconsistent company name

### Security

- Added nonce-reuse warnings to PKCS#11 and TPM crypto provider documentation

## [0.6.0] — 2026-03-13

### Security

- **[CRITICAL] S1**: Fixed default RNG returning all zeros — `default_rng()` now rejects zero-entropy output (vs-crypto)
- **[HIGH] S2**: HSM mock-hsm feature now provides full HMAC-SHA-256 and ECDH P-256 — no longer returns `NotInitialized` (vs-crypto)
- **[HIGH] S3**: Post-quantum ML-KEM-768 and ML-DSA-65 software providers fully operational via `pq-software` feature (vs-crypto)
- **[HIGH] S4**: Key material parameter is no longer silently discarded in `import_key()` (vs-key-manager)
- **[HIGH] S5**: TUF delegation chain complete — timestamp, snapshot, targets roles with cross-reference verification (vs-ota-validator)
- **[MEDIUM] S6**: JSON parser now computes SHA-256 content hash via `parse_tuf_root_with_hash()` — no longer returns zeros (vs-ota-validator)
- **[MEDIUM] S7**: TPM attestation extended with `extend_pcr()`, `read_pcr()`, and PCR digest computation (vs-secure-boot)
- **[LOW] S8**: Boot failure policy (`Halt`, `Rollback`, `ReportAndContinue`) now enforced via `verify_boot_chain_with_policy()` (vs-secure-boot)
- **[MEDIUM] S9**: Replaced custom constant-time comparison with `subtle::ConstantTimeEq` (vs-integrity)
- **[LOW] S10**: QNX HAL no longer panics with `todo!()` — uses proper FFI bindings with error returns (vs-hal-qnx)

### Added

- TUF metadata types: `TufTimestamp`, `TufSnapshot`, `TufTargets`, `TufTargetEntry` (vs-ota-validator)
- Per-role key delegation in `TufRoot` (targets, snapshot, timestamp keys/thresholds)
- Standalone verification functions: `verify_timestamp()`, `verify_snapshot()`, `verify_targets()`
- `find_signed_value()` JSON extractor for computing metadata hashes
- `BootVerificationOutcome` enum for policy-aware boot verification
- `PqSoftwareProvider::new_with_keys()` convenience constructor
- QNX FFI module with `clock_gettime()` and `ClockCycles()` bindings
- Hardware ECU validation test suite (`tests/ecu_validation.rs`)
- Hardware porting guide (`docs/porting-guide.md`)
- API stability and semver policy (`docs/api-stability.md`)
- Feature flags reference (`docs/feature-flags.md`)
- GitHub issue templates, PR template, CODEOWNERS
- `deny.toml` dependency policy

### Changed

- Test count: 1,057 (923 unit + 134 integration), up from 629
- Security contact email: security@craton.com.ar

### Fixed

- `ToEncodedPoint` import in HSM test module (vs-crypto)
- Missing `TufRoot` per-role key fields in runtime and integration tests

## [0.5.0] — 2026-02-01

### Added

- Initial 25-crate workspace with 4-layer architecture
- CAN bus monitoring with flood, DLC anomaly, fuzzing, and replay detection
- Ethernet packet monitoring with ARP/DHCP anomaly detection
- IDS engine with CAN/Ethernet correlation
- AES-256-GCM, SHA-256, HMAC-SHA-256, ECDSA P-256, ECDH P-256
- Network firewall with 128-rule capacity
- Policy engine with hierarchical rule evaluation
- UDS diagnostic gateway with SecurityAccess (0x27)
- HMAC-chained tamper-evident event logger
- TUF root metadata validation (root role only)
- Secure boot attestation (software TPM)
- Linux HAL (SocketCAN, raw Ethernet, clock_gettime)
- QNX HAL stubs
- C FFI layer with cbindgen header
- AUTOSAR Adaptive manifest
- CI pipeline (9 test jobs + 2 security jobs + 4 fuzz targets)

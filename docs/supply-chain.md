# Supply Chain — Craton Shield Enterprise

How the project protects what goes into a release and how downstream
consumers can verify it.

## 1. What ships in a release

Every tagged release (`v0.x.y`) publishes:

| Artefact | Tool | Location |
|---|---|---|
| Source tarball | GitHub Releases | `craton-shield-enterprise-v0.x.y.tar.gz` |
| CycloneDX SBOM (JSON) | `cyclonedx-rust-cargo` | `bom.json` in release assets |
| SLSA v1.0 provenance | `slsa-framework/slsa-github-generator` | `*.intoto.jsonl` attestation |
| Signed git tag | `git tag --sign` | `refs/tags/v0.x.y` |

The CI workflows `release.yml` and `security.yml` are the only automation
that publishes to `main` or the releases page.

## 2. Allow-list for dependencies

`deny.toml` enforces, for every dependency pulled via `cargo build`:

- License must be in **{Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0}**.
- Any copyleft license (GPL, LGPL, AGPL, MPL) denies the build.
- `tokio`, `async-std`, `reqwest`, and other async runtimes are banned
  (the project is `#![no_std]`).
- Any advisory in the RustSec Advisory Database blocks the build
  (`vulnerability = "deny"`).

To audit locally:

```bash
cargo install cargo-deny
cargo deny check
```

## 3. Vulnerability scanning

`cargo-audit` runs:

- On every push / PR via `.github/workflows/ci.yml`.
- On a weekly schedule via `.github/workflows/security.yml`.
- Manually: `cargo install cargo-audit && cargo audit`.

Any new advisory affecting a direct or transitive dependency blocks the
next release. See [`SECURITY.md`](../SECURITY.md) for the 72-hour
response SLA.

## 4. Reproducible builds

- `Cargo.lock` is committed and version-pinned in CI. `cargo build
  --locked` is enforced for release builds.
- `rust-toolchain.toml` pins the toolchain channel.
- The `Dockerfile` uses a distroless final stage so no package-manager
  state affects output.
- `panic = "abort"` in the release profile removes unwinding-table
  divergence across targets.

## 5. How to verify a release

```bash
# 1. Fetch the release + signature
gh release download v0.x.y
gpg --verify v0.x.y.tag.asc

# 2. Check the SBOM matches the source
cyclonedx-cli validate --input-file bom.json

# 3. Verify SLSA provenance
slsa-verifier verify-artifact \
  --provenance-path attestation.intoto.jsonl \
  --source-uri github.com/craton-co/craton-shield-enterprise \
  --source-tag v0.x.y \
  craton-shield-enterprise-v0.x.y.tar.gz
```

## 6. Transitive-dependency minimisation

Every production dependency is declared in the four crate manifests and
inspected by the reviewers on every PR (see `.github/CODEOWNERS`).
Current non-vendored dependencies:

| Crate | Dependency | Reason |
|---|---|---|
| vs-crypto-tpm | `subtle` | Constant-time tag comparison in `aes_gcm_decrypt` |
| vs-crypto-tpm (dev) | `serial_test` | Serialises mock-state-based unit tests |

No other third-party crates are pulled into the release binary.

## 7. Signing & provenance roadmap

| Item | Status |
|---|---|
| Git tag signing (`--sign`) | Shipped in release workflow |
| SLSA v1.0 provenance via GitHub OIDC | Shipped in release workflow |
| `cosign` keyless signing of release tarball | Shipped in release workflow |
| Publication to `docs.rs` | Pending — will land alongside the first public crates.io publish of the enterprise crates. |
| `cargo-vet` audit trail | Planned for v0.8 |

## 8. FIPS Certificate Verification

Every FIPS 140-2 / 140-3 certificate ID referenced anywhere in the
project documentation (notably
[`docs/hardware-compatibility.md`](hardware-compatibility.md) and
[`docs/crypto-agility.md`](crypto-agility.md)) **MUST** be verified
against the live NIST Cryptographic Module Validation Program (CMVP)
database before each release:

- CMVP search portal: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search>
- Per-certificate URL pattern: `https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/<NNNN>`

Release-time checklist:

1. For every cert ID cited in the docs, open the per-certificate URL
   above and confirm: (a) the certificate exists, (b) the vendor and
   module name match what we claim, (c) the certificate is still
   *Active* (not *Historical* or *Revoked*), and (d) the validated
   firmware/hardware version covers the entry in the compatibility
   matrix.
2. If any check fails, replace the cert ID (or mark the row as
   unvalidated) before the release tag is signed.
3. The `verify` job in `.github/workflows/release.yml` is the
   single source of truth; if it cannot reach the CMVP database the
   release blocks until a human signs off.

The hardware-compatibility table is the single source of truth for
cert IDs; other documents should link to it rather than restate
specific numbers.

## 9. Reporting a supply-chain concern

If you believe a dependency or build artefact is compromised, treat it
as a security issue and follow the process in
[`SECURITY.md`](../SECURITY.md). Do not open a public GitHub issue.

# Release Process

The runbook for cutting a Craton Shield Enterprise release. It
assumes read-write access to the `craton-co/craton-shield-enterprise`
repository, a GPG key published on [keybase.io/craton](https://keybase.io/craton),
and the ability to trigger the `release.yml` workflow.

## 1. Cadence

| Track | Cadence | Purpose |
|:---|:---|:---|
| **Patch (0.x.y → 0.x.y+1)** | As needed | Security fixes, critical bug fixes. 72 h ack SLA per [SECURITY.md](../SECURITY.md). |
| **Minor (0.x.y → 0.x+1.0)** | ~8 weeks | Feature work, deprecations, non-breaking ABI additions. |
| **Major (0.x → 1.0 onwards)** | After 1.0 only | Breaking changes to the stable API surface. 0.x series may break between minors, documented in the CHANGELOG. |

During 0.x a minor bump may include breaking changes; integrators should
pin to exact minor versions in safety-critical deployments — see
[docs/api-stability.md](api-stability.md).

## 2. Support / backport window

| Release line | Status | Security fixes | Feature fixes |
|:---|:---|:---|:---|
| `main` (unreleased) | Active | — | — |
| Latest minor | Active | ✅ | ✅ |
| Previous minor | Maintained | ✅ (6 mo) | ❌ |
| Older | End-of-life | ❌ | ❌ |

The support table in [SECURITY.md](../SECURITY.md) tracks the concrete
version numbers and dates. Update that table during every minor
release.

## 3. Versioning rules

Follow [SemVer 2.0.0](https://semver.org/) with the 0.x caveat above.

- **Add** → minor or patch.
- **Fix** (bug, security, doc) → patch, unless the fix requires a
  caller-visible behavioural change, in which case minor.
- **Change** to a stable-tier item ([docs/api-stability.md](api-stability.md)) → minor during 0.x, major post-1.0.
- **Remove** an item → follow the one-minor deprecation window unless a
  security advisory bypasses it.

CHANGELOG groups follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/):
`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.

## 4. Release checklist

A release is a single PR from a release branch, not a direct push to
main. Nothing below is optional.

### Pre-flight

1. **Branch.** `git switch -c release/0.x.y`.
2. **Bump the version in every `Cargo.toml`** — root workspace and all
   four crates. `cargo workspaces version --no-git` is the fast path.
3. **Move the `[Unreleased]` block in CHANGELOG.md** under a new
   `## [0.x.y] — YYYY-MM-DD` heading; create a fresh empty
   `## [Unreleased]` at the top.
4. **Regenerate Cargo.lock.** `cargo update -p craton-shield-enterprise
   --precise 0.x.y` for each published crate, commit the lock file.
5. **Run the full CI matrix locally:**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test  --workspace
   cargo deny  check
   cargo audit
   ```
6. **Confirm no `// TODO`, `// FIXME`, `todo!()`, `unimplemented!()`
   in production code** (grep the workspace excluding `tests/` and
   `fuzz/`).
7. **Reproducible build check.** CI already does this via
   `release.yml`, but for release candidates rerun locally:
   `scripts/repro-build.sh` twice in a clean-room container and diff
   the resulting binaries byte-for-byte.

### Documentation

8. **CHANGELOG complete.** Every user-visible change on main since the
   last tag has a line.
9. **Migration guide updated** (`docs/migration-0.6-to-0.7.md`,
   etc.) if any API shifted.
10. **Hardware compatibility matrix updated** if any device was tested
    during the cycle (`docs/hardware-compatibility.md`).
11. **Certification status updated** if control coverage changed
    (`docs/certification-status.md`).
12. **README status line** (`> **Status:** v0.x.y`) bumped.

### Cut

13. Open a "Release 0.x.y" PR. CI must be green; at least one
    CODEOWNERS reviewer from `@craton-co/founders` must approve.
14. Squash-merge to main with the message
    `release: 0.x.y` (no Co-Authored-By on releases).
15. **Tag a signed tag** on the merge commit:
    ```bash
    git tag --sign v0.x.y -m "Craton Shield Enterprise 0.x.y"
    git push origin v0.x.y
    ```
    The `release.yml` workflow verifies the tag signature in a
    pre-flight job before running the rest of the pipeline.

### Publish

16. The `release.yml` workflow then automatically:
    - verifies the GPG signature on the tag,
    - builds the release artifacts,
    - generates a CycloneDX SBOM via `scripts/generate-sbom.sh`,
    - signs the artifacts with cosign,
    - emits SLSA v1.0 provenance via `slsa-github-generator`,
    - validates the provenance with `slsa-verifier` before publishing.
17. **Draft GitHub Release** from the tag, body pre-populated from
    CHANGELOG. Attach: SBOM, provenance, checksums, cosign bundle.
18. **Post-release announcement** — Security-advisory crosspost to
    [SECURITY.md](../SECURITY.md) if any item in the release has a CVE
    assignment; otherwise publish a short release note.

### Post-release

19. Open a `chore: reset CHANGELOG [Unreleased]` PR if the empty block
    was not already added in step 3.
20. File a tracking issue for anything slipped; retarget roadmap.

## 5. Security-driven releases

Out-of-band security releases follow the same checklist but compress
it into 48 hours. The embargo process is in
[SECURITY.md §Responsible Disclosure](../SECURITY.md).

Security-driven minor releases are allowed to skip the one-minor
deprecation window per
[docs/api-stability.md §Deprecation Process](api-stability.md); the
CHANGELOG entry must cite the CVE.

## 6. Release candidates

For any release that touches the crypto providers or the telemetry
nonce counter, cut an `v0.x.y-rc1` tag first, announce it on GitHub
Discussions, and give integrators at least 7 calendar days before
promoting. RC tags follow the same signing / SBOM / provenance flow.

## 7. Rollback

Releases cannot be deleted (signed tags and cosign attestations are
append-only). A regression that blocks upgrade is fixed by rolling
**forward** with a patch release that either reverts the offending
change or corrects it, and a security advisory that lists affected
versions.

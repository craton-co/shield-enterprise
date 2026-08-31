# Governance

## Decision-Making

Craton Shield Enterprise is maintained by the **@craton-co/founders** team. All
technical decisions, release approvals, and breaking-change reviews are made by
this team.

### Roles

| Role | Responsibility | Current Holders |
|:---|:---|:---|
| **Maintainer** | Merge authority, release cutting, security response | @craton-co/founders |
| **Reviewer** | Code review, architecture feedback | @craton-co/founders |
| **Contributor** | Submit PRs, report issues, propose features | Anyone |

### How Decisions Are Made

1. **Day-to-day changes** (bug fixes, minor features): A single maintainer
   approval is sufficient to merge.
2. **Breaking changes** (API changes, dependency additions, ABI modifications):
   Require approval from at least two maintainers. Must be documented in
   CHANGELOG.md with migration guidance.
3. **Security fixes**: Follow the process in [SECURITY.md](SECURITY.md).
   Response within 48 hours; patches within 72 hours for critical issues.
4. **New crate additions**: Require maintainer consensus and an architecture
   review documented in the PR description.

### Release Process

1. Maintainer creates a release branch from `main`.
2. All CI checks must pass (tests, clippy, audit, coverage, doc build).
3. CHANGELOG.md is updated with the release date.
4. Cargo.toml workspace version is bumped.
5. A signed git tag is created (`v0.X.Y`).
6. The release workflow publishes artefacts.

### Dispute Resolution

If contributors disagree on a technical decision, the maintainer team makes
the final call. The reasoning is documented in the relevant PR or issue for
transparency.

## Becoming a Maintainer

Active contributors who demonstrate sustained, high-quality contributions over
at least 6 months may be invited to join the maintainer team. The existing
maintainers decide by consensus.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Violations are handled by the maintainer team as described in that document.

# Maintainers

> Individual maintainer names will be added as contributors join.
>
> This document defines the **roles, responsibilities, and incident-response
> structure** for Craton Shield Enterprise. It supports the ISO/SAE 21434
> clause 5 (organizational cybersecurity management) integrator audit by
> identifying designated owners for security triage, release signing, and
> per-crate code review.

## Roles

- **Project Lead**: ultimate decision authority for technical direction,
  roadmap, and conflict resolution. Final approver for SEMVER-MAJOR changes.
  Cross-references the governance section of
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security Lead**: triages reports submitted through the disclosure process
  in [SECURITY.md](SECURITY.md), coordinates the disclosure timeline with
  reporters and downstream integrators, and owns the CVE assignment workflow.
  Cross-reference [SECURITY.md](SECURITY.md).
- **Release Engineer**: signs release tags with the project release key, owns
  the `cargo-cyclonedx` SBOM generation step, and publishes signed artifacts
  per the release procedure documented in
  [docs/operational-security.md](docs/operational-security.md).
- **Maintainers**: per-crate code review, issue triage, and mentorship of
  new contributors. Each crate must have at least two designated maintainers
  (see Bus-Factor Mitigation below).

## Active Maintainers

> **Pre-release task (BEFORE first public release):** the maintainers MUST
> populate the table below with real identities. Each row requires a verified
> GitHub handle, a published PGP key fingerprint (matching the key referenced
> in [SECURITY.md](SECURITY.md)), the maintainer's time zone, and the hours
> during which they will respond to security pages. Until that is done, the
> placeholders below intentionally fail the ISO 21434 clause 5 audit.

| Role             | GitHub Handle                                          | PGP Key Fingerprint                                    | Time Zone                                              | Coverage Hours                                         |
|:-----------------|:-------------------------------------------------------|:-------------------------------------------------------|:-------------------------------------------------------|:-------------------------------------------------------|
| Project Lead     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     |
| Security Lead    | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     |
| Release Engineer | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     |
| Maintainer       | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     |
| Maintainer       | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     | `<TO BE FILLED — see GitHub `craton-co` org page>`     |

Until individual maintainers are designated, the
[@craton-co/founders](https://github.com/orgs/craton-co/teams/founders) team
alias holds all roles jointly. The team alias is **not** an acceptable
substitute for named contacts in the audit context.

## Incident Response Contact

- **Primary**: [security@craton.com.ar](mailto:security@craton.com.ar)
  (encrypt with the PGP key published in [SECURITY.md](SECURITY.md)).
- **Escalation**: GitHub Security Advisory private disclosure on the
  `craton-co/craton-shield-enterprise` repository.
- **Response SLA**:
  - **48 hours** to first human acknowledgement for HIGH/CRITICAL severity
    reports.
  - **14 days** target for a tested fix or documented mitigation for
    HIGH/CRITICAL severity reports.
  - Lower-severity reports follow the timelines in [SECURITY.md](SECURITY.md).

## Bus-Factor Mitigation

- **Two maintainers per crate, minimum.** No crate may be merged or released
  with a single reviewer (per the governance section of
  [CONTRIBUTING.md](CONTRIBUTING.md)).
- **Release-signing key custody.** The release-signing private key is split
  via Shamir's Secret Sharing and stored offline. See
  [docs/operational-security.md](docs/operational-security.md) for the
  share-distribution policy and recovery procedure.
- **Two-approval rule for SEMVER-MINOR and above.** All decisions at or above
  SEMVER-MINOR (new public API, dependency additions, MSRV bumps, breaking
  changes) require approval from **two** maintainers before merge.
- **Shared access to CI/CD secrets.** GitHub organization-level secrets are
  accessible to all designated maintainers; no secret is held by a single
  individual.
- **License continuity.** The BSL-1.1 license automatically converts to
  Apache-2.0 on 2030-09-01, ensuring the project remains available regardless
  of maintainer availability.

## How to Become a Maintainer

- **3+ months** of substantive contributions (code review, fixes, or
  documentation) to at least one crate.
- **Endorsement by 2 existing maintainers** via a public issue or PR
  comment, with a brief rationale.
- **Sign the DCO** on every commit (already required for all contributions
  per [CONTRIBUTING.md](CONTRIBUTING.md)).
- New maintainers are added by opening a PR against this file that fills in
  their row of the Active Maintainers table, including a published PGP key
  fingerprint.

## Triage Policy

PRs are triaged within 5 business days. Security reports follow the
disclosure process in [SECURITY.md](SECURITY.md) and the SLA in the
Incident Response Contact section above.

## Responsibilities (Summary)

- **Code review**: All PRs require at least one maintainer approval before
  merge; SEMVER-MINOR and above require two.
- **Release management**: Cutting releases, updating `CHANGELOG.md`, tagging
  versions, and generating the SBOM (owned by the Release Engineer).
- **Security response**: Triaging and resolving vulnerability reports per
  [SECURITY.md](SECURITY.md) and the SLA above (owned by the Security Lead).
- **Architecture decisions**: Approving new crates, breaking changes, and
  dependency additions (owned by the Project Lead, with two-maintainer
  approval).
- **Community health**: Responding to issues, mentoring contributors, and
  enforcing the Code of Conduct.

## Contact

- **General questions**: Open a [GitHub Issue](https://github.com/craton-co/craton-shield-enterprise/issues)
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) and the
  Incident Response Contact section above.
- **Commercial licensing**: [license@craton.com.ar](mailto:license@craton.com.ar)
- **Enterprise support**: [enterprise-support@craton.com.ar](mailto:enterprise-support@craton.com.ar)

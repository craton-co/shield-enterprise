# Security Policy

## Supported Versions

| Version | Supported |
|:---|:---:|
| 0.7.1 (current) | Yes |
| 0.6.0 | Patches until 2026-09-28 |
| < 0.6.0 | No |

> **Note:** Craton Shield Enterprise follows semantic versioning. The `0.7.1` release is
> the current actively supported version. Security patches are backported to the latest
> minor release. The previous release (0.6.0) receives critical security fixes for six
> months after the subsequent release.

## Reporting a Vulnerability

If you discover a security vulnerability in Craton Shield, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Reporting Process

**Primary channel:** Use [GitHub Security Advisories](https://github.com/craton-co/craton-shield-enterprise/security/advisories/new)
to submit a private vulnerability report. This is the preferred channel as it creates an
auditable record and enables coordinated disclosure through the GitHub CVE process.

**Secondary channel:** Email security@craton.com.ar with the subject line
`[CRATON SHIELD SECURITY] <brief description>`.

### Encrypted Reporting

Email reports to `security@craton.com.ar` may be encrypted with the project's
PGP key. The key is published at [keys.openpgp.org](https://keys.openpgp.org/search?q=security%40craton.com.ar)
under the address `security@craton.com.ar` and is rotated annually; the same
key is used to sign releases (see [docs/release-process.md](docs/release-process.md)).

**Fingerprint verification protocol.** Because a forged keyserver entry would
silently compromise encrypted disclosure, reporters MUST verify the key out of
band before use:

1. Download the key from **at least two independent keyservers** — for example
   [keys.openpgp.org](https://keys.openpgp.org/) and
   [pgp.mit.edu](https://pgp.mit.edu/) — and confirm the fingerprints match.
2. Cross-check the fingerprint against the value published on the project's
   official homepage (see the [project README](README.md)) and against the key
   used to sign the most recent release artifact.
3. Only proceed with encrypted email if all three sources agree.

**Fallback.** If the published fingerprint is unavailable from any of the
sources above, or if the values disagree, do **not** send encrypted email.
Instead, fall back to [GitHub Security Advisories](https://github.com/craton-co/craton-shield-enterprise/security/advisories/new)
for private disclosure — that channel does not depend on out-of-band key
distribution.

In your report, include:

1. Description of the vulnerability
2. Steps to reproduce
3. Affected crate(s) and version(s)
4. Potential impact assessment
5. Suggested fix (if any)

You will receive an acknowledgment within 48 hours. We will work with you to understand
and address the issue. A fix will be developed and tested before public disclosure.
Credit will be given in the security advisory (unless you prefer anonymity).

### CVE Assignment

For vulnerabilities meeting the CVE threshold, we will request a CVE identifier through
the GitHub CNA process or coordinate directly with MITRE. The CVE will be referenced in
the GitHub Security Advisory and in the relevant CHANGELOG.md entry.

### Scope

The following are in scope:

- Memory safety issues in any crate
- Cryptographic implementation flaws in `vs-crypto-pkcs11` or `vs-crypto-tpm`
- FFI safety issues in PKCS#11 or TPM function pointer handling
- Nonce reuse or key management errors in crypto providers
- Telemetry data leakage or authentication bypass in `vs-vsoc-telemetry`
- QNX HAL safety issues in `vs-hal-qnx`
- Any issue that would compromise vehicle cybersecurity

For vulnerabilities in core crates (`vs-ids-engine`, `vs-policy-engine`, `vs-ota-validator`, etc.), report to [Craton Shield Core](https://github.com/craton-co/craton-shield/security/advisories/new).

### Out of Scope

- Vulnerabilities in development dependencies only
- Issues that require physical access to the target hardware
- Denial-of-service via resource exhaustion (by design, all data structures are bounded)

## Security Design

Craton Shield is designed with security as the primary concern:

- **Memory safety**: Rust's ownership model eliminates buffer overflows, use-after-free, double-free, and data races at compile time
- **Minimal unsafe code**: All `unsafe` blocks are confined to the FFI boundary in `vs-crypto-pkcs11` and `vs-crypto-tpm`, each with documented SAFETY comments
- **No heap allocation**: Stack-only execution eliminates heap corruption and fragmentation
- **Default-deny**: Policy engine, firewall, and diagnostic gateway default to deny
- **Constant-time operations**: Integrity verification uses constant-time comparison
- **HMAC-chained logging**: Tamper-evident audit trail with cryptographic chain verification
- **Dependency minimization**: Minimal external dependencies (`subtle` for constant-time comparison)
- **Continuous auditing**: `cargo audit` and `cargo clippy --pedantic` enforced in GitHub Actions CI on every push and pull request

## Dependency Monitoring

We monitor dependencies via `cargo audit` and the RustSec Advisory Database. If a vulnerability is found in a dependency:

1. We assess whether Craton Shield is affected
2. If affected, we update the dependency and release a patch within 72 hours
3. If not affected, we update at the next regular release

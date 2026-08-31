# Licensing

Craton Shield Enterprise is distributed under the **Business Source License 1.1
(BSL-1.1)**. The full licence text is in [`LICENSE`](../LICENSE).

## Summary

- **Additional Use Grant.** You may use the software for any purpose **other
  than** offering a managed service that embeds the provider crates
  (`vs-crypto-pkcs11`, `vs-crypto-tpm`, `vs-hal-qnx`, `vs-vsoc-telemetry`) to
  third parties.
- **Change date.** `2030-09-01`. On this date, every then-released version of
  the source automatically relicenses to **Apache-2.0**.
- **Change licence.** Apache License, Version 2.0.

## What this means in practice

| Use case | Allowed today? | After 2030-09-01 |
|---|---|---|
| Evaluate, build, run on your own fleet | Yes | Yes (Apache-2.0) |
| Ship inside a vehicle product you sell | Yes | Yes (Apache-2.0) |
| Contribute fixes / features back upstream | Yes | Yes (Apache-2.0) |
| Offer a hosted Craton-Shield service to third parties | **No** — requires a commercial licence | Yes (Apache-2.0) |
| Fork and relicense | Follow BSL-1.1 terms | Yes (Apache-2.0) |

If you are uncertain whether your planned use is covered, contact
[license@craton.com.ar](mailto:license@craton.com.ar) before shipping.

## Third-party code

The full list of transitive dependencies is enumerated in the CycloneDX SBOMs
(`sbom.json` / `sbom.xml`) attached to every GitHub Release, and is rebuilt
on every push to `main` via [`.github/workflows/security.yml`](../.github/workflows/security.yml).

## SPDX identifiers

All source files carry an SPDX identifier in their top-of-file comment. The
workspace root declares `license = "BSL-1.1"` in [`Cargo.toml`](../Cargo.toml)
and each crate inherits that setting via `license.workspace = true`.

## Relationship to `craton-shield-core`

`craton-shield-core` ships separately and may be published under a different
licence for some components. Always check `craton-shield-core/LICENSE` and
`Cargo.toml` for the authoritative settings. The enterprise repository
pins a specific `craton-shield-core` revision in `Cargo.lock`; upgrading
that pin requires re-running `cargo deny check licenses` (gated in CI).

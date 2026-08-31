#!/usr/bin/env bash
set -euo pipefail

# Generate CycloneDX SBOM for Craton Shield
echo "Generating SBOM for Craton Shield..."

if ! command -v cargo-cyclonedx &> /dev/null; then
    echo "Error: cargo-cyclonedx is not installed."
    # Version 0.5.7 is the pinned baseline. The same version is installed by
    # `.github/workflows/release.yml` and `.github/workflows/security.yml`
    # via `taiki-e/install-action` so that local, CI-audit, and release SBOMs
    # are byte-identical. When bumping, update ALL THREE locations together
    # (MED-12).
    echo "Install it with: cargo install cargo-cyclonedx --version 0.5.7 --locked"
    exit 1
fi

mkdir -p artifacts
cargo cyclonedx --all-features --format json -f artifacts/sbom.json
cargo cyclonedx --all-features --format xml -f artifacts/sbom.xml

# Emit SHA256 of resulting SBOM files for reproducibility
sha256sum artifacts/sbom.json artifacts/sbom.xml > artifacts/sbom.sha256
cat artifacts/sbom.sha256

echo "SBOM generated successfully in artifacts/sbom.json and artifacts/sbom.xml"

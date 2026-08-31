# Build Stage
FROM rust:1.82-slim-bookworm AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-deny in a dedicated, cacheable RUN layer.
#
# Supply-chain gate (MED-8) — BSL-1.1 + ISO/SAE 21434 compliance:
# Every artifact-producing build must enforce the workspace's dependency
# policy (`deny.toml`: license allowlist, banned crates, vulnerability
# advisories, source allowlist) BEFORE compiling. Without this, a Docker
# image could be produced from a workspace that would fail CI's
# `cargo deny check` gate — defeating the purpose of the supply-chain
# controls documented in `docs/supply-chain.md`.
#
# Version pin (0.18.2) MUST match:
#   - .github/workflows/ci.yml
#   - .github/workflows/security.yml
#   - .github/workflows/release.yml
# so that local, CI, release, and container builds enforce an identical
# policy snapshot. When bumping, update ALL FOUR locations together.
RUN cargo install --version 0.18.2 --locked cargo-deny

WORKDIR /app

# Copy the workspace and project files
COPY . .

# Supply-chain check MUST run before `cargo build` (MED-8).
# A failure here fails the Docker build, preventing release of an image
# whose dependency graph violates `deny.toml`. See `docs/supply-chain.md`.
RUN cargo deny check

# Tests run in CI; build verifies compile only
# release-safe = release + overflow-checks=true (defence-in-depth for security crates)
RUN cargo build --workspace --profile release-safe --locked

# Final Stage — minimal image for CI artifact caching
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

# Copy built libraries from the builder stage.
# Image is for downstream integration testing of the workspace, not a runnable product.
# Cargo emits rlibs with underscored crate names (vs-* -> libvs_*.rlib).
# release-safe profile output lands in target/release-safe/, not target/release/.
COPY --from=builder /app/target/release-safe/libvs_*.rlib /usr/local/lib/

# Run as non-root user (uid 65534)
USER nonroot

# No default entrypoint — this is a library-only workspace.
# Use this image as a base for integration testing or artifact extraction.
CMD ["echo", "Craton Shield Enterprise: library-only workspace — no binary entrypoint."]

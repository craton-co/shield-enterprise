.PHONY: build test clippy fmt fmt-fix audit deny doc fuzz clean check ci build-arm build-qnx coverage check-thumbv7em

# Development build
build:
	cargo build --workspace

# Run all tests
test:
	cargo test --workspace

# Run clippy with pedantic lints
clippy:
	cargo clippy --workspace -- -D warnings

# Check formatting
fmt:
	cargo fmt --all -- --check

# Format in-place
fmt-fix:
	cargo fmt --all

# Security audit
audit:
	cargo audit

# License and dependency checks
deny:
	cargo deny check

# Build documentation
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Run all fuzz targets (5 minutes each)
fuzz:
	@for target in can_frame eth_packet ota_metadata uds_request tara_input iec62443_capabilities iec62304_input telemetry_entry qnx_can_parse qnx_eth_parse; do \
		echo "Fuzzing $$target..."; \
		cargo +nightly fuzz run $$target -- -max_total_time=300; \
	done

# Clean build artifacts
clean:
	cargo clean

# Quick pre-commit check
check: fmt clippy test

# Full CI pipeline locally
ci: fmt clippy test audit deny doc

# Cross-compile for ARM
# release-safe = release + overflow-checks=true (defence-in-depth for security crates)
build-arm:
	cargo build --workspace --target aarch64-unknown-linux-gnu --profile release-safe

# Cross-compile for QNX
# release-safe = release + overflow-checks=true (defence-in-depth for security crates)
build-qnx:
	cargo build --workspace --target aarch64-unknown-nto-qnx710 --profile release-safe

# Run coverage
coverage:
	cargo llvm-cov --workspace --lcov --output-path lcov.info

# Check no_std compliance for Cortex-M
check-thumbv7em:
	cargo check -p vs-crypto-pkcs11 --target thumbv7em-none-eabihf
	cargo check -p vs-crypto-tpm --target thumbv7em-none-eabihf
	cargo check -p vs-hal-qnx --target thumbv7em-none-eabihf
	cargo check -p vs-vsoc-telemetry --target thumbv7em-none-eabihf

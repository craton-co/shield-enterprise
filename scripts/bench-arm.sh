#!/usr/bin/env bash
# Run Craton Shield benchmarks cross-compiled for ARM aarch64 (Cortex-A53)
# via Docker + QEMU user-mode emulation.
#
# Prerequisites:
#   - Docker installed and running
#   - First run will build the Docker image (~5 min)
#
# Usage:
#   ./scripts/bench-arm.sh              # Run all benchmarks
#   ./scripts/bench-arm.sh "can_monitor" # Run only CAN monitor benchmark
#
# Output:
#   Criterion benchmark results in bencher format.
#   Note: QEMU emulation adds overhead — results are indicative of
#   relative performance, not absolute WCET. For production WCET,
#   run directly on NXP S32G3 hardware with PMCCNTR instrumentation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="cratonshield-bench-arm"

cd "$PROJECT_DIR"

# Parse --rebuild flag (must precede any filter argument)
REBUILD=0
if [ "${1:-}" = "--rebuild" ]; then
    REBUILD=1
    shift
fi

# Build the Docker image if it doesn't exist, or if --rebuild was given
if [ "$REBUILD" -eq 1 ] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building ARM benchmark Docker image..."
    docker build -f Dockerfile.bench-arm -t "$IMAGE_NAME" .
fi

# Run benchmarks
FILTER="${1:-}"
if [ -n "$FILTER" ]; then
    echo "Running ARM benchmarks (filter: $FILTER)..."
    docker run --rm "$IMAGE_NAME" \
        cargo bench --bench cratonshield_benchmarks \
        --target aarch64-unknown-linux-gnu \
        -- --noplot --output-format bencher "$FILTER"
else
    echo "Running all ARM benchmarks..."
    docker run --rm "$IMAGE_NAME" \
        cargo bench --bench cratonshield_benchmarks \
        --target aarch64-unknown-linux-gnu \
        -- --noplot --output-format bencher
fi

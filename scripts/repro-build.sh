#!/usr/bin/env bash
# repro-build.sh — Local reproducible-build helper.
#
# Runs `cargo build --profile release-safe --locked --workspace` twice into
# two separate target directories, then computes a basename-only,
# cargo-hash-stripped SHA-256 listing of every produced `.rlib`,
# `.a`, and `.so` artifact and diffs the two listings. Exits 0 when
# the two builds are bit-identical (after hash normalisation), 1
# otherwise.
#
# release-safe = release + overflow-checks=true (defence-in-depth for
# security crates); matches the profile actually shipped to production.
#
# This is the local mirror of the `reproducible-build` job in
# .github/workflows/ci.yml; CI remains the authoritative reproducer
# for release artifacts. This script exists so release-candidate
# work and pre-PR checks can be run without pushing to CI.
#
# Usage:
#   scripts/repro-build.sh                 # uses ./target-repro1 and ./target-repro2
#   TARGET_DIR_PREFIX=/tmp/foo scripts/repro-build.sh
set -euo pipefail

prefix="${TARGET_DIR_PREFIX:-target-repro}"
dir1="${prefix}1"
dir2="${prefix}2"
list1="$(mktemp)"
list2="$(mktemp)"
hashes1="$(mktemp)"
hashes2="$(mktemp)"
trap 'rm -f "${list1}" "${list2}" "${hashes1}" "${hashes2}"' EXIT

build_and_hash() {
    local target_dir="$1"
    local files_out="$2"
    local hashes_out="$3"

    echo "==> Building into ${target_dir}"
    rm -rf "${target_dir}"
    # release-safe = release + overflow-checks=true (defence-in-depth for security crates)
    CARGO_TARGET_DIR="${target_dir}" \
        cargo build --profile release-safe --locked --workspace

    # Collect reproducibility-relevant artifacts: rlibs, static libs, cdylibs.
    # Excludes *.d (dep-info embeds absolute paths) and executables (this is a
    # library workspace).
    # --profile release-safe emits into target/release-safe/, not target/release/.
    find "${target_dir}/release-safe" -maxdepth 2 -type f \
        \( -name '*.rlib' -o -name '*.a' -o -name '*.so' \) \
        -printf '%P\n' | sort > "${files_out}"

    local count
    count=$(wc -l < "${files_out}")
    echo "    produced ${count} artifact(s)"
    if [ "${count}" -lt 5 ]; then
        echo "ERROR: only ${count} artifact(s); expected at least 5" >&2
        cat "${files_out}" >&2
        return 1
    fi

    # Hash each artifact, key it by basename with the cargo-metadata
    # per-build hash stripped so listings are comparable across builds.
    : > "${hashes_out}"
    while read -r f; do
        local h key
        h=$(sha256sum "${target_dir}/release-safe/${f}" | awk '{print $1}')
        key=$(basename "${f}" | sed -E 's/-[0-9a-f]{16,}\.(rlib|a|so)$/.\1/')
        printf '%s  %s\n' "${h}" "${key}" >> "${hashes_out}"
    done < "${files_out}"
    sort -k 2 "${hashes_out}" -o "${hashes_out}"
}

build_and_hash "${dir1}" "${list1}" "${hashes1}"
build_and_hash "${dir2}" "${list2}" "${hashes2}"

echo "==> Diffing hash listings"
if diff -u "${hashes1}" "${hashes2}"; then
    echo "OK: both builds produced bit-identical artifacts."
    exit 0
else
    echo "FAIL: builds diverged. See diff above." >&2
    exit 1
fi

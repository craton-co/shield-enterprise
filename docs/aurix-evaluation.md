# TriCore TC3xx (Infineon AURIX) Evaluation

## Status: Under Evaluation (last reviewed 2026-05-23)

**Next Review Due:** 2026-08-21

For the authoritative list of platforms with confirmed support status, see
[`docs/hardware-compatibility.md`](./hardware-compatibility.md). This document
captures only the open feasibility analysis for AURIX.

The AURIX TC3xx family (TC37x, TC39x) is a common automotive microcontroller
for powertrain and chassis ECUs. This document captures the feasibility
analysis for running Craton Shield on TriCore targets.

### Gating Criteria for Status Change

Promoting AURIX out of "Under Evaluation" depends on external factors, not
on enterprise-crate work:

- **Promote to "Validated"** when Infineon SDP 1.4+ ships with PKCS#11 token
  bindings for the AURIX HSM, a customer program funds hardware-in-loop CI on
  a TC37x/TC39x evaluation board, and the HighTec TriCore Rust toolchain has
  produced a reproducible build of all enterprise crates against the
  `tricore-tc162-none-elf` target.
- **Demote to "Not Supported"** if Infineon publicly discontinues PKCS#11
  bindings for the AURIX HSM, or if no customer engagement materializes by
  the 2027 review cycle.

The Craton Shield enterprise crates themselves are not on the critical path:
all blockers are toolchain, SDK, and CI investments external to this
repository.

## Target

- **Architecture**: TriCore TC1.6.2 (TC37x) / TC1.8 (TC39x)
- **Rust target triple**: `tricore-tc162-none-elf` (not upstream; requires custom LLVM)
- **Toolchain**: HighTec TriCore GCC/LLVM or Tasking TriCore

## Feasibility Assessment

### Compiler Support

Rust does not have an upstream TriCore target. Building for AURIX requires:

1. A custom LLVM fork with TriCore backend (HighTec provides one)
2. A Rust `target.json` specification for `tricore-tc162-none-elf`
3. Linker scripts compatible with the AURIX memory map (PFLASH, DSPR, DLMU)

The `.cargo/config.toml` in this repository contains a commented-out
TriCore target configuration for use with the HighTec toolchain.

### Memory Constraints

| Memory Region | TC37x | TC39x |
|:---|:---|:---|
| Program Flash (PFLASH) | 4 MB | 16 MB |
| Data SRAM (DSPR) | 240 KB per core | 240 KB per core |
| Local Memory (DLMU) | 64 KB per core | 128 KB per core |

Craton Shield's `.text` size (all enterprise crates) is approximately 26 KB
with `opt-level = "z"`, which fits comfortably in PFLASH. Stack usage must
stay within DSPR limits; see `docs/performance.md` for per-function estimates.

### no_std Compatibility

All Craton Shield crates are `#![no_std]` with zero heap allocation,
making them compatible with bare-metal TriCore deployment. The crypto
provider function-pointer architecture avoids any link-time dependencies
on platform-specific libraries.

### Blockers

1. **No upstream Rust target**: Requires HighTec commercial toolchain
2. **Limited CI coverage**: Cannot run TriCore tests in GitHub Actions
3. **No QEMU support**: TriCore is not emulated by QEMU; testing requires
   hardware or the HighTec simulator

### Recommendation

Defer TriCore support until a customer engagement requires it. The
engineering effort is significant (custom toolchain, hardware-in-loop
testing) and benefits only AURIX-based programs. When needed:

1. Obtain HighTec TriCore Rust toolchain license
2. Create `target.json` for `tricore-tc162-none-elf`
3. Implement `vs-hal-aurix` HAL crate with HSM/SHE driver bindings
4. Set up hardware-in-loop CI with a TC37x evaluation board

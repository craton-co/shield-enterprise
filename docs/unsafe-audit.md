# `unsafe` Audit

Last reviewed: **2026-05-23** (post-0.7.2 audit-fix release; recount
performed after the HIGH-PKCS11, HIGH-TPM, and HAL-QNX batched series
landed). Previous review **2026-05-10**.

[CLAUDE.md](../CLAUDE.md) restricts `unsafe` to FFI boundaries
(`crypto-pkcs11`, `crypto-tpm`) and requires a `// SAFETY:` comment on
every block. This document inventories every `unsafe` block in the
enterprise workspace, its justification, and its current audit
status. Counts are updated each minor release alongside
[docs/threat-model.md](threat-model.md).

Counts below are for production `src/lib.rs` files only. Test
support (`src/tests/mocks.rs`, `src/tests/mod.rs`) contains additional
`unsafe { extern "C" fn ... }` blocks that synthesise PKCS#11 / TPM
callbacks; those are excluded from the production audit but covered by
the workspace tests and the LOW-8 nightly `cargo miri` job.

## Summary

| Crate | `unsafe` blocks (production) | FFI boundary? | Audit status |
|:---|---:|:---|:---|
| `vs-crypto-pkcs11` | 35 (see §1) | Yes | Reviewed 2026-05-23 |
| `vs-crypto-tpm` | 51 (see §2) | Yes (+ one volatile-wipe) | Reviewed 2026-05-23 |
| `vs-hal-qnx` | 20 (see §3) | Yes | Reviewed 2026-05-23 |
| `vs-vsoc-telemetry` | 1 (see §4) | **No** (one volatile-wipe) | Reviewed 2026-05-23, deviation documented |

## 1. `crates/crypto-pkcs11`

- **Files:** `crates/crypto-pkcs11/src/lib.rs` (35 production blocks
  as of 2026-05-23), plus the per-mechanism modules under
  `crates/crypto-pkcs11/src/`.
- **Why `unsafe`:** every call through a `Pkcs11FunctionList`
  function pointer is `extern "C"` and therefore `unsafe` by Rust's
  rules; the provider has no other unsafe surface beyond two
  `core::ptr::write_volatile` wipes (see §4 for the rationale that
  applies to those).
- **Justification (per block):** the function pointers were resolved
  by the caller from the PKCS#11 module (`dlsym`/static link). The
  provider owns no concurrent access to the session — `Send` is not
  implemented — so the only soundness obligation is that the caller
  populated a valid `Pkcs11FunctionList`. That contract is documented
  on the constructor.
- **Recent changes (HIGH-PKCS11 batch — commits `72f0cd3`, `25b9d78`):**
  the L/M/N/O/P/Q audit fixes added several new `unsafe` call sites
  but did not relax soundness — the new sites either widen an existing
  `C_FindObjects` request from one to two handles (HIGH-N) or capture
  the `CkRv` return from `C_DestroyObject` (HIGH-O) so the surrounding
  Rust code can escalate a failed destroy rather than dropping the
  error on the floor. The position-varying sentinel pattern (HIGH-M)
  is pure-Rust and adds no `unsafe`.
- **Audit status:** reviewed against the [PKCS#11 v3.0
  spec](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
  on 2026-05-23. No deviations.

## 2. `crates/crypto-tpm`

- **Files:** `crates/crypto-tpm/src/lib.rs` (51 production blocks as
  of 2026-05-23) and the AEAD / ECDSA / ECDH submodules.
- **Why `unsafe`:** identical to PKCS#11 — every `Esys_*` call is
  `extern "C"`. Additionally, blocks performing
  `core::ptr::write_volatile` stack-buffer wipes on AES-CFB
  intermediate output and HMAC scratch space after the tag has been
  computed; these are technically not FFI calls but live in the same
  `unsafe` category because the compiler is otherwise free to elide
  the writes.
- **Justification:** the wipes are necessary to discharge the I1/I2
  mitigation in [docs/threat-model.md](threat-model.md). The blocks
  are bounded to local stack buffers and run on both the success and
  error paths.
- **Recent changes (HIGH-TPM batch — commits `f67e16c`, `934151e`):**
  the G/J/K/W audit fixes touched several `Esys_*` call sites but did
  not introduce new soundness obligations — the call-site shapes are
  unchanged, only the post-call result handling (free-list ordering,
  flush-context bookkeeping). The added zeroize helper that prompted
  this audit refresh is the volatile-wipe variant noted above; it is
  counted in §2's total.
- **Audit status:** reviewed 2026-05-23; volatile-wipe deviation
  permitted by the same CLAUDE.md exception that permits FFI blocks.

## 3. `crates/hal-qnx`

- **Files:** `crates/hal-qnx/src/lib.rs` (20 production blocks as of
  2026-05-23, `mod qnx_ffi`). FFI is inlined; there is no separate
  `ffi.rs` (the older porting-guide reference has been corrected).
- **Why `unsafe`:** every call into the QNX libc / kernel
  (`ClockCycles`, `clock_gettime`, `devctl`, `read`, `write`, `open`,
  `close`) is `extern "C"`. The block count grew between 2026-05-10
  (~17) and 2026-05-23 (20) because the HAL-QNX HIGH batch (commit
  `5c36362`) added bounded-EINTR retry wraps in both CAN and Ethernet
  `receive` paths (R/S/T fixes), a proper-sized `IfReq` buffer wrap for
  `SIOCGIFFLAGS` (U fix, commit `c8c6133`), and `write()` partial-send
  loops in the TX path. Each new block is a thin wrapper around a
  single libc call.
- **Justification:** the callers either consume a `Result` that
  forwards POSIX `errno` or wrap the raw return in a HAL-typed
  enum. No `unsafe` block stores the raw pointer across calls.
- **Audit status:** reviewed 2026-05-23. No deviations.

## 4. `crates/vsoc-telemetry`

- **Files:** `crates/vsoc-telemetry/src/lib.rs`.
- **Block count:** one (production), unchanged across the 2026-05-23
  recount even after HIGH-Y added per-entry sequence/timestamp
  validation (the new logic is pure-Rust comparison).
- **Why `unsafe`:** the block performs a `core::ptr::write_volatile`
  pass over the plaintext batch buffer after the AES-GCM ciphertext
  and tag have been computed. The compiler would otherwise be free
  to elide the write because the buffer is dropped immediately
  afterwards.
- **Deviation from the CLAUDE.md rule:** the rule says `unsafe` is
  permitted only at FFI boundaries. The volatile wipe is not an FFI
  call. It is justified by the I3 mitigation in the threat model
  (residual plaintext on the stack) and by the same precedent set by
  `vs-crypto-tpm` §2.
- **Audit status:** reviewed 2026-05-23. The deviation is documented
  here and in the inline `// SAFETY:` comment.

## 5. Out of scope

Crates that do not contain `unsafe` blocks today
(`vs-vsoc-policy`, the example binaries, the fuzz targets) are
excluded from this inventory. A new `unsafe` block in any of those
crates requires an entry in §1–§4 in the same PR.

## 6. Dynamic verification

In addition to the static audit above, the nightly CI job added by
LOW-8 (commit `4e3ad11`) runs `cargo miri test` against the
workspace test suites, exercising each `unsafe` FFI shim with mock
function tables. Miri detects undefined-behaviour categories the
borrow-checker cannot (out-of-bounds reads, uninitialised-memory
reads, unaligned accesses) along the `unsafe` paths counted in
§1–§4.

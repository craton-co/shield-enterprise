# Acknowledgments

## Standards Bodies

Craton Shield Enterprise is designed with guidance from the following standards:

- **ISO/SAE 21434** — Road Vehicles: Cybersecurity Engineering
- **UN R155** — Cyber Security and Cyber Security Management System
- **ISO 26262** — Road Vehicles: Functional Safety
- **AUTOSAR** — Automotive Open System Architecture (AP R22-11)
- **ISO 14229** — Unified Diagnostic Services (UDS)
- **IEC 62443** — Security for Industrial Automation and Control Systems
- **IEC 62304** — Medical Device Software: Software Life Cycle Processes
- **TUF/Uptane** — The Update Framework for automotive OTA

## Open Source Dependencies

This project builds on the work of the Rust open-source ecosystem. The
crates below are pulled in (directly or transitively) by the workspace's
`Cargo.lock`. All licenses fall within the allow-list enumerated in
`deny.toml` (Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC,
Unicode-DFS-2016, Unicode-3.0, Zlib, CC0-1.0); refer to each crate's
own repository for the authoritative license text.

### Cryptographic Primitives (RustCrypto)

The bulk of the cryptographic surface is provided by the
[RustCrypto](https://github.com/RustCrypto) project:

- **aead** — Authenticated Encryption with Associated Data traits
- **aes** — AES block cipher implementation
- **aes-gcm** — AES-GCM AEAD construction used by `vs-crypto`
- **cipher** — Block and stream cipher traits
- **ctr** — Counter-mode block cipher wrapper (AES-CTR / AES-CFB)
- **digest** — Cryptographic hash function traits
- **sha2** — SHA-2 family hash implementations
- **hmac** — Keyed-hash message authentication used by the TPM crate
- **hkdf** — HKDF key derivation
- **ghash** — Universal hash backing AES-GCM
- **polyval** — POLYVAL universal hash
- **universal-hash** — Universal hash trait
- **block-buffer** — Fixed-size buffer used by block-based primitives
- **inout** — In-place / out-of-place buffer abstractions for ciphers
- **crypto-common** — Shared traits across RustCrypto crates
- **crypto-bigint** — Constant-time big-integer arithmetic
- **opaque-debug** — `Debug` impls that omit secret material

### Elliptic-Curve Cryptography

ECDSA / ECDH support over P-256 is layered on the RustCrypto
elliptic-curve stack:

- **elliptic-curve** — Generic elliptic-curve traits
- **ecdsa** — Generic ECDSA implementation
- **p256** — NIST P-256 curve, used by `vs-p256-validate`
- **primeorder** — Prime-order curve arithmetic helpers
- **group** — Group arithmetic traits
- **ff** — Finite-field arithmetic traits
- **sec1** — SEC1 elliptic-curve encoding
- **signature** — Generic signature traits
- **rfc6979** — Deterministic ECDSA nonce generation (RFC 6979)
- **rand_core** — RNG traits used by the curve crates

### Encoding and ASN.1

- **der** — DER encoder/decoder used for SEC1 / PKCS structures
- **const-oid** — Compile-time ASN.1 OID constants
- **base16ct** — Constant-time hex encoding/decoding

### Constant-Time and Zeroization Helpers

- **subtle** — Constant-time comparison for authentication tags
- **zeroize** — Best-effort secret zeroization on drop
- **generic-array** — Compile-time-sized arrays used across RustCrypto
- **typenum** — Type-level integers backing `generic-array`

### Platform / ABI Utilities

- **libc** — Raw `libc` type and constant definitions for the QNX HAL
- **bitflags** — Type-safe bitflag generation
- **cfg-if** — Ergonomic `#[cfg]` cascades
- **cpufeatures** — Runtime CPU feature detection for crypto backends
- **windows-link** — Windows import-library shims (host tooling only)
- **redox_syscall** — Redox `libc` shim pulled in transitively

### Procedural-Macro Infrastructure

Used at build time by the proc-macro crates listed below; not present
in any runtime binary:

- **proc-macro2** — Stable proc-macro token abstraction
- **quote** — Quasi-quoting for proc macros
- **syn** — Rust syntax tree for proc macros
- **unicode-ident** — Unicode identifier classification
- **version_check** — `rustc` version detection

### Logging / Diagnostics (host-side only)

- **log** — Logging facade used by host-side tooling

### Dev- and Test-Only Dependencies

These crates appear in `Cargo.lock` because they back the test harness
(`cratonshield-enterprise-tests`); none are linked into the
`#![no_std]` production crates:

- **serial_test** — Serialize tests that share global state
- **serial_test_derive** — Proc-macro for `serial_test`
- **parking_lot** / **parking_lot_core** — Fast synchronization primitives
- **lock_api** — Generic lock traits backing `parking_lot`
- **scopeguard** — RAII scope guards
- **once_cell** — Lazy / one-time initialization
- **smallvec** — Small-vector optimization
- **slab** — Pre-allocated object slab
- **scc** — Concurrent hash containers used by `serial_test`
- **sdd** — Scalable deferred-drop infrastructure backing `scc`
- **futures-core** — Core `Future` traits
- **futures-task** — Task plumbing for futures
- **futures-util** — Future combinators
- **futures-executor** — Minimal future executor used in tests
- **pin-project-lite** — Safe `Pin` projection without proc macros

This list is generated from the workspace's `Cargo.lock` at release time.
To regenerate, run
`cargo tree --workspace --edges normal --prefix none | sort -u`.

## Security Research

- [RustSec Advisory Database](https://rustsec.org/) — Continuous dependency vulnerability monitoring
- [MITRE CVE](https://cve.mitre.org/) — CVE identifier coordination
- [OWASP](https://owasp.org/) — Security best practices guidance

## Tools

- **Rust** and **Cargo** — The Rust programming language and build system
- **cargo-audit** — Dependency vulnerability scanning
- **cargo-deny** — Dependency license and ban policy enforcement
- **cargo-fuzz** / **libFuzzer** — Fuzz testing infrastructure
- **cargo-llvm-cov** — Code coverage measurement
- **GitHub Actions** — Continuous integration and deployment

## Contributors

We welcome contributions from the community. See [CONTRIBUTING.md](CONTRIBUTING.md)
for guidelines. Contributors will be listed here as the project grows.

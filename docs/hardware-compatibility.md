# Hardware Compatibility Matrix

This document tracks the HSMs, TPMs, host SoCs, and RTOS images against
which Craton Shield Enterprise has been exercised, either by Craton
directly or by an integrator who has reported a result back.

> **Scope.** "Tested" below means at least one full Encrypt-then-MAC or
> ECDSA-sign/verify roundtrip succeeded against a live device plus a
> clean `cargo test --workspace` run. "Reported" means a customer
> integrator has confirmed the configuration in production but Craton
> has not independently reproduced it.

Last updated: 2026-04-18. Entries are sorted alphabetically within each
section.

## 1. PKCS#11 HSMs (`vs-crypto-pkcs11`)

| Device | Firmware | Driver | Status | Notes |
|:---|:---|:---|:---|:---|
| **SoftHSM2** | 2.6.1 | libsofthsm2.so | ✅ Tested | Reference fixture for CI; `CKM_AES_GCM`, `CKM_ECDSA` (P-256), `CKM_SHA256_HMAC`, `CKM_ECDH1_DERIVE`. |
| **Thales Luna Network HSM** | 7.13.0 | libCryptoki2_64.so | ✅ Tested | Requires Crypto Officer login; ECDH requires `CKA_DERIVE` template flag. FIPS cert #4121. |
| **Utimaco SecurityServer CP5** | 5.4.1 | libcs_pkcs11_R3.so | ✅ Tested | Nonce supply is caller-side (mechanism takes explicit IV). FIPS cert #4329. <!-- TODO(maintainers): verify FIPS cert #4329 against NIST CMVP at https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4329 before publication --> |
| **NXP SE050** | v03.06 | Plug-and-Trust middleware 04.05 | ✅ Tested | Exposes PKCS#11 via `se05x_pkcs11`; only 20 concurrent sessions. CC EAL6+ cert #BSI-DSZ-CC-1107. |
| **NXP EdgeLock 2GO Managed** | 2024.09 | SE050/SE051 variants | ⚠ Reported | One integrator shipped v0.7.0 on SE051; no Craton-side CI. |
| **Microchip ATECC608B** | via cryptoauthlib 3.7.4 PKCS#11 wrapper | ⚠ Reported | Limited to SHA-256 + ECDSA; no AES-GCM (use TPM path instead). |
| **YubiHSM 2** | 2.4.0 | libyubihsm.so + PKCS#11 shim 2.5.0 | ⚠ Reported | ECDH shared-secret length check requires `sharedSecret` raw template. |
| **AWS CloudHSM** | 3.4.4 | libcloudhsm_pkcs11.so | ✅ Tested | Requires PSK bootstrapping; rate-limit `random_bytes` to <10k req/s/partition. |

### Known quirks

- **Luna**: `C_GenerateKeyPair` does not mark derived ECDH secrets as
  extractable by default; the enterprise provider issues `C_DeriveKey`
  against a transient session object and wipes the handle on exit.
- **SE050**: Returns `CKR_BUFFER_TOO_SMALL` for HMAC-SHA-256 if the
  caller requests anything other than the full 32-byte digest. The
  enterprise provider always requests the full digest.
- **SoftHSM2 < 2.6.0**: `CKM_AES_GCM` with caller-supplied IV does not
  honour `ulIvLen` correctly; upgrade to 2.6.1 or later.

## 2. TPM 2.0 Devices (`vs-crypto-tpm`)

| Device | Firmware / Revision | TSS2 | Status | Notes |
|:---|:---|:---|:---|:---|
| **Microsoft swtpm (software TPM)** | libtpms 0.9.6 | tpm2-tss 4.1.3 | ✅ Tested | Reference fixture for CI. |
| **Infineon SLB 9670** (dTPM) | 7.83.13 | tpm2-tss 4.1.3 via `tcti-device` | ✅ Tested | SPI; observe 5 ms wake from deep idle on Cortex-M. |
| **Infineon SLB 9672** (dTPM) | 15.22 | tpm2-tss 4.1.3 | ✅ Tested | Drop-in replacement for 9670 with deeper key slot count. |
| **Nuvoton NPCT75x** | 7.2.0.3 | tpm2-tss 4.1.3 | ⚠ Reported | I2C variant. |
| **STMicro ST33TPHF2E** | 74.08 | tpm2-tss 4.1.3 | ✅ Tested | Common in automotive ECUs. |
| **Intel PTT (fTPM)** | TGL/ADL CSME 18.x | tpm2-tss 4.1.3 via `tcti-device` | ⚠ Reported | Shared with Intel ME; not recommended for safety-critical keys. |
| **AMD fTPM** | PSP FW 1.0.0.AD | tpm2-tss 4.1.3 | ⚠ Reported | Known to drop commands under sustained load; rate-limit recommended. |

### Known quirks

- **SLB 9670 SPI**: First command after `S3` resume may fail with
  `TSS2_BASE_RC_NO_CONNECTION`; retry once after a 50 ms delay.
- **AMD fTPM**: `Esys_HMAC` truncates the input buffer at 1024 bytes on
  some BIOS revisions; the enterprise provider's `compute_etm_tag`
  caps total input at `MAX_BUF = 2048`, but ETM over long plaintexts
  should be split on these platforms.

## 3. Host / RTOS Platforms (`vs-hal-qnx`, workspace targets)

| Target | Host OS | Toolchain | Status | Notes |
|:---|:---|:---|:---|:---|
| **x86_64-unknown-linux-gnu** | Ubuntu 22.04 / 24.04 | rustc 1.82+ | ✅ Tested | Primary CI. |
| **aarch64-unknown-linux-gnu** | Ubuntu 24.04 (cross) | rustc 1.82+ | ✅ Tested | CI cross; QEMU user-mode runs. |
| **aarch64-unknown-nto-qnx710** | QNX SDP 7.1 | QCC 8.3.0 + rustc 1.82 (custom fork) | ✅ Tested | Production target. |
| **aarch64-unknown-nto-qnx800** | QNX SDP 8.0 (beta) | QCC 12.2.0 | 🚧 Planned v0.8 | Pending QNX 8.0 BSP availability from Craton OEM partners. |
| **thumbv7em-none-eabihf** | bare-metal | rustc 1.82 | ✅ Tested (build only) | `vs-crypto-pkcs11` and `vs-crypto-tpm` compile; no runtime CI. |
| **riscv64gc-unknown-linux-gnu** | Debian 12 (cross) | rustc 1.82 | ⚠ Reported | One integrator builds on SG2042. |

### QNX BSPs

| Board | BSP version | Kernel | Status |
|:---|:---|:---|:---|
| NXP S32G274A (GoldBox) | QNX SDP 7.1 BSP 1.0.0 Build 202404 | Neutrino 7.1 | ✅ Tested |
| Renesas R-Car V4H | QNX SDP 7.1 BSP 20240315 | Neutrino 7.1 | ⚠ Reported |
| Xilinx Zynq UltraScale+ MPSoC | QNX SDP 7.1 BSP Xilinx 202312 | Neutrino 7.1 | ⚠ Reported |

### Host OS for development

Development is supported on Linux (Ubuntu 22.04+, Debian 12+, Fedora
40+), macOS 13+ (Intel and Apple Silicon), and Windows 11 with a bash
shell. QNX SDP itself is Linux- and Windows-only.

## 4. How to add a configuration

If you have run Craton Shield Enterprise against a device not listed
above and the test suite passes, open an issue using the
`hardware-compatibility` label with:

- Device make, model, firmware version, driver version.
- Craton Shield Enterprise version (git tag or short SHA).
- Any non-default feature flags.
- Output of `cargo test -p vs-crypto-pkcs11 -p vs-crypto-tpm -p vs-vsoc-telemetry`.

Craton will reproduce the configuration where possible and upgrade the
status from ⚠ Reported to ✅ Tested in the next minor release.

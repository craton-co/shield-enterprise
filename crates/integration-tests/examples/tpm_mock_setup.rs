// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! Demonstrates the `TpmCryptoProvider` construction and capabilities.
//!
//! This example shows the TPM 2.0 provider architecture. In production,
//! the function pointers would come from linking against `libtss2-esys`.
//!
//! Run: `cargo run --example tpm_mock_setup`

fn main() {
    println!("=== Craton Shield: TPM 2.0 Mock Setup ===");
    println!();
    println!("In production, you would:");
    println!("  1. Link against libtss2-esys (or resolve at runtime)");
    println!("  2. Populate a TpmFunctionList struct with ESAPI pointers");
    println!("  3. Call TpmCryptoProvider::new(fn_list)");
    println!("  4. Register key handles via register_key_handle()");
    println!();
    println!("The TPM provider implements CryptoProvider using:");
    println!("  - AES-256-CFB + HMAC-SHA-256 (Encrypt-then-MAC, IND-CCA2)");
    println!("  - SHA-256 via Esys_Hash");
    println!("  - HMAC-SHA-256 via Esys_HMAC");
    println!("  - ECDSA P-256 via Esys_Sign / Esys_VerifySignature");
    println!("  - ECDH P-256 via Esys_ECDH_ZGen");
    println!("  - Hardware TRNG via Esys_GetRandom");
    println!();
    println!("TPM-specific extensions (beyond CryptoProvider):");
    println!("  - PCR extend (measured boot)");
    println!("  - PCR read (attestation)");
    println!();
    println!("See INSTALL.md for swtpm setup instructions.");
    println!();

    // Demonstrate type sizes (no actual TPM needed).
    println!(
        "TpmCryptoProvider size: {} bytes",
        std::mem::size_of::<vs_crypto_tpm::TpmCryptoProvider>()
    );
    println!(
        "TpmFunctionList size:   {} bytes",
        std::mem::size_of::<vs_crypto_tpm::ffi::TpmFunctionList>()
    );
}

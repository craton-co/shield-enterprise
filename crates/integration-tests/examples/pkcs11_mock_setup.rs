// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! Demonstrates constructing a `Pkcs11CryptoProvider` with mock function pointers.
//!
//! This example shows how to populate a `Pkcs11FunctionList` and create a
//! provider instance. In production, the function pointers would come from
//! `dlopen`/`dlsym` on the PKCS#11 shared library.
//!
//! Run: `cargo run --example pkcs11_mock_setup`

fn main() {
    println!("=== Craton Shield: PKCS#11 Mock Setup ===");
    println!();
    println!("In production, you would:");
    println!("  1. dlopen() the PKCS#11 shared library (e.g., libsofthsm2.so)");
    println!("  2. dlsym() each C_* function pointer");
    println!("  3. Populate a Pkcs11FunctionList struct");
    println!("  4. Call Pkcs11CryptoProvider::new(fn_list, pin)");
    println!("  5. Register key handles via register_key_handle()");
    println!();
    println!("The provider then implements CryptoProvider for:");
    println!("  - AES-256-GCM authenticated encryption/decryption");
    println!("  - SHA-256 hashing");
    println!("  - HMAC-SHA-256 message authentication");
    println!("  - ECDSA P-256 sign/verify");
    println!("  - ECDH P-256 key agreement");
    println!("  - Hardware TRNG random bytes");
    println!();
    println!("See INSTALL.md for SoftHSM2 setup instructions.");
    println!();

    // Demonstrate type sizes (no actual HSM needed).
    println!(
        "Pkcs11CryptoProvider size: {} bytes",
        std::mem::size_of::<vs_crypto_pkcs11::Pkcs11CryptoProvider>()
    );
    println!(
        "Pkcs11FunctionList size:   {} bytes",
        std::mem::size_of::<vs_crypto_pkcs11::ffi::Pkcs11FunctionList>()
    );
}

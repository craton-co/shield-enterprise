// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
#![no_main]
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vs_report_iec62443::{SecurityLevel, SystemCapabilities, assess};

/// Structured input — one bool per boolean capability, plus the
/// numeric configuration fields and a level selector. `libfuzzer-sys`
/// derives `Arbitrary` for `bool`, `u8`, `u16`, and `u32` directly,
/// which is cheaper and more shrinkable than masking raw bytes.
#[derive(Arbitrary, Debug)]
struct Input {
    // FR 1 -- Identification and Authentication Control
    has_user_authentication: bool,
    has_device_authentication: bool,
    has_multifactor_auth: bool,
    has_pki_certificates: bool,
    password_min_length: u8,
    max_failed_login_attempts: u8,
    has_login_notification: bool,
    has_untrusted_network_protection: bool,
    has_symmetric_key_auth: bool,

    // FR 2 -- Use Control
    has_authorization_enforcement: bool,
    has_session_lock: bool,
    session_timeout_seconds: u32,
    max_concurrent_sessions: u8,
    has_audit_logging: bool,
    audit_log_capacity_entries: u32,
    has_audit_failure_response: bool,
    has_timestamps: bool,
    has_non_repudiation: bool,

    // FR 3 -- System Integrity
    has_self_test: bool,
    has_software_integrity_verification: bool,
    has_input_validation: bool,
    has_session_integrity: bool,
    has_audit_protection: bool,

    // FR 4 -- Data Confidentiality
    has_data_confidentiality: bool,
    has_data_persistence_protection: bool,
    has_cryptography: bool,
    crypto_key_length_bits: u16,

    // FR 5 -- Restricted Data Flow
    has_network_segmentation: bool,
    has_zone_boundary_protection: bool,

    // FR 6 -- Timely Response to Events
    has_audit_log_accessibility: bool,
    has_continuous_monitoring: bool,

    // FR 7 -- Resource Availability
    has_dos_protection: bool,
    has_resource_management: bool,
    has_backup: bool,
    has_recovery: bool,
    has_network_config_settings: bool,
    has_least_functionality: bool,

    level_selector: u8,
}

fuzz_target!(|inp: Input| {
    let caps = SystemCapabilities {
        has_user_authentication: inp.has_user_authentication,
        has_device_authentication: inp.has_device_authentication,
        has_multifactor_auth: inp.has_multifactor_auth,
        has_pki_certificates: inp.has_pki_certificates,
        password_min_length: inp.password_min_length,
        max_failed_login_attempts: inp.max_failed_login_attempts,
        has_login_notification: inp.has_login_notification,
        has_untrusted_network_protection: inp.has_untrusted_network_protection,
        has_symmetric_key_auth: inp.has_symmetric_key_auth,

        has_authorization_enforcement: inp.has_authorization_enforcement,
        has_session_lock: inp.has_session_lock,
        session_timeout_seconds: inp.session_timeout_seconds,
        max_concurrent_sessions: inp.max_concurrent_sessions,
        has_audit_logging: inp.has_audit_logging,
        audit_log_capacity_entries: inp.audit_log_capacity_entries,
        has_audit_failure_response: inp.has_audit_failure_response,
        has_timestamps: inp.has_timestamps,
        has_non_repudiation: inp.has_non_repudiation,

        has_self_test: inp.has_self_test,
        has_software_integrity_verification: inp.has_software_integrity_verification,
        has_input_validation: inp.has_input_validation,
        has_session_integrity: inp.has_session_integrity,
        has_audit_protection: inp.has_audit_protection,

        has_data_confidentiality: inp.has_data_confidentiality,
        has_data_persistence_protection: inp.has_data_persistence_protection,
        has_cryptography: inp.has_cryptography,
        crypto_key_length_bits: inp.crypto_key_length_bits,

        has_network_segmentation: inp.has_network_segmentation,
        has_zone_boundary_protection: inp.has_zone_boundary_protection,

        has_audit_log_accessibility: inp.has_audit_log_accessibility,
        has_continuous_monitoring: inp.has_continuous_monitoring,

        has_dos_protection: inp.has_dos_protection,
        has_resource_management: inp.has_resource_management,
        has_backup: inp.has_backup,
        has_recovery: inp.has_recovery,
        has_network_config_settings: inp.has_network_config_settings,
        has_least_functionality: inp.has_least_functionality,
    };
    let level = match inp.level_selector % 4 {
        0 => SecurityLevel::Sl1,
        1 => SecurityLevel::Sl2,
        2 => SecurityLevel::Sl3,
        _ => SecurityLevel::Sl4,
    };
    let _ = assess(&caps, level);
});

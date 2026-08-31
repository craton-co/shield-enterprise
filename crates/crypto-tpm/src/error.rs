// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! `TSS2_RC` → [`VsError`] mapping.

use crate::types::{
    Tss2Rc, TSS2_BASE_RC_AUTHORIZATION_FAILED, TSS2_BASE_RC_BAD_CONTEXT,
    TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE, TSS2_BASE_RC_BAD_VALUE,
    TSS2_BASE_RC_INSUFFICIENT_BUFFER, TSS2_BASE_RC_MEMORY, TSS2_BASE_RC_NO_CONNECTION,
    TSS2_ESYS_RC_BAD_TR, TSS2_ESYS_RC_BAD_VALUE, TSS2_RC_SUCCESS,
};
use vs_types::VsError;

/// Layer mask — the high byte of `TSS2_RC` identifies the TSS2 software
/// layer (upstream `tpm2-tss` `tss2_common.h`: `TSS2_RC_LAYER_MASK =
/// 0xFF00_0000`). Earlier revisions used `0x000F_0000`, which would
/// fail to strip real ESAPI layer tags and leave the base-code match
/// permanently falling through to `CryptoError`.
const TSS2_LAYER_MASK: Tss2Rc = 0xFF00_0000;

/// Strip the layer tag and return the base return code.
#[inline]
fn base_rc(rc: Tss2Rc) -> Tss2Rc {
    rc & !TSS2_LAYER_MASK
}

/// Convert a `TSS2_RC` into a [`VsError`].
///
/// [`TSS2_RC_SUCCESS`] maps to [`Ok`]. All other codes are mapped to the
/// most semantically appropriate `VsError` variant. The mapping covers both
/// ESAPI-layer errors (with the layer tag) and raw TPM2 response codes.
pub fn tss2_rc_to_result(rc: Tss2Rc) -> Result<(), VsError> {
    if rc == TSS2_RC_SUCCESS {
        return Ok(());
    }

    // Check ESAPI-specific codes first (layer tag present).
    if rc == TSS2_ESYS_RC_BAD_TR {
        return Err(VsError::InvalidInput);
    }
    if rc == TSS2_ESYS_RC_BAD_VALUE {
        return Err(VsError::InvalidInput);
    }

    // Strip layer tag and inspect the base code.
    match base_rc(rc) {
        TSS2_BASE_RC_BAD_REFERENCE | TSS2_BASE_RC_BAD_VALUE | 0x084 | 0x184 => {
            Err(VsError::InvalidInput)
        }

        TSS2_BASE_RC_INSUFFICIENT_BUFFER | TSS2_BASE_RC_MEMORY => Err(VsError::ResourceExhausted),

        TSS2_BASE_RC_BAD_SEQUENCE | TSS2_BASE_RC_NO_CONNECTION | TSS2_BASE_RC_BAD_CONTEXT => {
            Err(VsError::NotInitialized)
        }

        // TPM2 response codes:
        //   0x09D = TPM2_RC_SIGNATURE, 0x14E = TPM2_RC_INTEGRITY → auth failure
        TSS2_BASE_RC_AUTHORIZATION_FAILED | 0x09D | 0x19D | 0x29D | 0x14E | 0x24E => {
            Err(VsError::AuthenticationFailure)
        }

        // 0x084 = TPM2_RC_KEY (handled above in InvalidInput branch)
        // All other codes including GENERAL_FAILURE and NOT_IMPLEMENTED.
        _ => Err(VsError::CryptoError),
    }
}

/// Convenience: return `Ok(())` if `rc == TSS2_RC_SUCCESS`, else map error.
#[inline]
pub fn check_rc(rc: Tss2Rc) -> Result<(), VsError> {
    tss2_rc_to_result(rc)
}

/// Map any `TSS2_RC` to a [`VsError`] without going through `Result`.
///
/// `TSS2_RC_SUCCESS` collapses to [`VsError::CryptoError`] as a defensive
/// choice: the caller invokes this only on a code that is already known to
/// be non-success (e.g. inside the catch-all arm of a `match`), so reaching
/// success here would itself be an internal contract violation. This avoids
/// the `.unwrap_err()` antipattern in production code paths.
#[inline]
pub fn rc_to_err(rc: Tss2Rc) -> VsError {
    tss2_rc_to_result(rc).err().unwrap_or(VsError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        TSS2_BASE_RC_GENERAL_FAILURE, TSS2_BASE_RC_NOT_IMPLEMENTED, TSS2_ESYS_RC_LAYER,
    };

    #[test]
    fn success_maps_to_ok() {
        assert!(check_rc(TSS2_RC_SUCCESS).is_ok());
    }

    #[test]
    fn general_failure_maps_to_crypto_error() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_GENERAL_FAILURE;
        assert_eq!(check_rc(rc), Err(VsError::CryptoError));
    }

    #[test]
    fn authorization_failed_maps_to_auth_failed() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_AUTHORIZATION_FAILED;
        assert_eq!(check_rc(rc), Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn bad_reference_maps_to_invalid_input() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_BAD_REFERENCE;
        assert_eq!(check_rc(rc), Err(VsError::InvalidInput));
    }

    #[test]
    fn insufficient_buffer_maps_to_buffer_full() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_BUFFER;
        assert_eq!(check_rc(rc), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn not_implemented_maps_to_not_supported() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_NOT_IMPLEMENTED;
        assert_eq!(check_rc(rc), Err(VsError::CryptoError));
    }

    #[test]
    fn bad_tr_maps_to_invalid_input() {
        assert_eq!(check_rc(TSS2_ESYS_RC_BAD_TR), Err(VsError::InvalidInput));
    }

    #[test]
    fn no_connection_maps_to_not_initialized() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_NO_CONNECTION;
        assert_eq!(check_rc(rc), Err(VsError::NotInitialized));
    }

    #[test]
    fn tpm_signature_rc_maps_to_auth_failed() {
        // TPM2_RC_SIGNATURE = 0x09D
        assert_eq!(check_rc(0x09D), Err(VsError::AuthenticationFailure));
    }

    #[test]
    fn unknown_code_maps_to_crypto_error() {
        assert_eq!(check_rc(0xDEAD_BEEF), Err(VsError::CryptoError));
    }

    #[test]
    fn rc_to_err_maps_known_non_success_codes() {
        let rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_AUTHORIZATION_FAILED;
        assert_eq!(rc_to_err(rc), VsError::AuthenticationFailure);
        assert_eq!(rc_to_err(TSS2_ESYS_RC_BAD_TR), VsError::InvalidInput);
        let mem = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_MEMORY;
        assert_eq!(rc_to_err(mem), VsError::ResourceExhausted);
        let nc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_NO_CONNECTION;
        assert_eq!(rc_to_err(nc), VsError::NotInitialized);
    }

    #[test]
    fn rc_to_err_unknown_code_maps_to_crypto_error() {
        assert_eq!(rc_to_err(0xDEAD_BEEF), VsError::CryptoError);
    }

    #[test]
    fn rc_to_err_success_defensively_maps_to_crypto_error() {
        // Only invoked when caller has already classified `rc` as non-OK.
        assert_eq!(rc_to_err(TSS2_RC_SUCCESS), VsError::CryptoError);
    }
}

// SPDX-License-Identifier: LicenseRef-BSL-1.1
// Copyright (c) 2026 Craton Software Company
// Licensed under the Business Source License 1.1. Converts to Apache-2.0 on 2030-09-01.
// See LICENSE at the workspace root.
//! `CK_RV` → [`VsError`] mapping.

use crate::types::{
    CkRv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_HOST_MEMORY,
    CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_PARAM_INVALID, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
    CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
};
use vs_types::VsError;

/// Convert a PKCS#11 `CK_RV` into a [`VsError`].
///
/// [`CKR_OK`] maps to [`Ok`]; every other code maps to an appropriate
/// [`VsError`] variant. Unrecognised vendor-specific codes fall through to
/// [`VsError::CryptoError`].
pub fn ck_rv_to_result(rv: CkRv) -> Result<(), VsError> {
    match rv {
        CKR_OK => Ok(()),

        // audit-LOW: `CKR_BUFFER_TOO_SMALL` is, strictly per the Cryptoki
        // spec, an output-buffer-allocation problem on the caller side
        // (the caller passed a too-short output buffer), not a
        // validation failure on input data. The current `vs-types`
        // surface (v1.0) does not expose a dedicated `BufferTooSmall` /
        // `OutputBufferTooSmall` variant, so we collapse it into
        // `InvalidInput` to keep the error class actionable. When
        // `vs-types` grows a more precise variant, move
        // `CKR_BUFFER_TOO_SMALL` out of this arm into the new mapping
        // and update the doc-comment on `ck_rv_to_result`.
        CKR_ARGUMENTS_BAD
        | CKR_DATA_LEN_RANGE
        | CKR_BUFFER_TOO_SMALL
        | CKR_MECHANISM_PARAM_INVALID
        | CKR_KEY_HANDLE_INVALID
        | CKR_KEY_SIZE_RANGE
        | CKR_KEY_TYPE_INCONSISTENT
        | CKR_OBJECT_HANDLE_INVALID
        | CKR_USER_TYPE_INVALID => Err(VsError::InvalidInput),

        CKR_PIN_INCORRECT
        | CKR_PIN_LOCKED
        | CKR_USER_NOT_LOGGED_IN
        | CKR_SIGNATURE_INVALID
        | CKR_SIGNATURE_LEN_RANGE
        | CKR_ENCRYPTED_DATA_INVALID
        | CKR_ENCRYPTED_DATA_LEN_RANGE => Err(VsError::AuthenticationFailure),

        CKR_CRYPTOKI_NOT_INITIALIZED
        | CKR_SESSION_CLOSED
        | CKR_SESSION_HANDLE_INVALID
        | CKR_TOKEN_NOT_PRESENT
        | CKR_TOKEN_NOT_RECOGNIZED
        | CKR_SLOT_ID_INVALID
        | CKR_OPERATION_ACTIVE
        | CKR_OPERATION_NOT_INITIALIZED => Err(VsError::NotInitialized),

        CKR_HOST_MEMORY => Err(VsError::ResourceExhausted),

        _ => Err(VsError::CryptoError),
    }
}

/// Convenience: return `Ok(())` if `rv == CKR_OK`, else map to `VsError`.
#[inline]
pub fn check_rv(rv: CkRv) -> Result<(), VsError> {
    ck_rv_to_result(rv)
}

/// Map any `CK_RV` to a [`VsError`] without going through `Result`.
///
/// `CKR_OK` collapses to [`VsError::CryptoError`] as a defensive choice: the
/// caller invokes this only on a code that is already known to be non-OK
/// (e.g. inside the catch-all arm of a `match` over the success codes), so
/// reaching `CKR_OK` here would itself be an internal contract violation.
/// This avoids the `.unwrap_err()` antipattern in production code paths.
#[inline]
pub fn rv_to_err(rv: CkRv) -> VsError {
    ck_rv_to_result(rv).err().unwrap_or(VsError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CKR_GENERAL_ERROR, CKR_MECHANISM_INVALID};

    #[test]
    fn ckr_ok_maps_to_ok() {
        assert!(check_rv(CKR_OK).is_ok());
    }

    #[test]
    fn ckr_pin_incorrect_maps_to_auth_failed() {
        assert_eq!(
            check_rv(CKR_PIN_INCORRECT),
            Err(VsError::AuthenticationFailure)
        );
    }

    #[test]
    fn ckr_arguments_bad_maps_to_invalid_input() {
        assert_eq!(check_rv(CKR_ARGUMENTS_BAD), Err(VsError::InvalidInput));
    }

    #[test]
    fn ckr_signature_invalid_maps_to_auth_failed() {
        assert_eq!(
            check_rv(CKR_SIGNATURE_INVALID),
            Err(VsError::AuthenticationFailure)
        );
    }

    #[test]
    fn ckr_mechanism_invalid_maps_to_crypto_error() {
        assert_eq!(check_rv(CKR_MECHANISM_INVALID), Err(VsError::CryptoError));
    }

    #[test]
    fn ckr_token_not_present_maps_to_not_initialized() {
        assert_eq!(
            check_rv(CKR_TOKEN_NOT_PRESENT),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn ckr_host_memory_maps_to_resource_exhausted() {
        assert_eq!(check_rv(CKR_HOST_MEMORY), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn ckr_general_error_maps_to_crypto_error() {
        assert_eq!(check_rv(CKR_GENERAL_ERROR), Err(VsError::CryptoError));
    }

    #[test]
    fn unknown_vendor_code_maps_to_crypto_error() {
        // Vendor-specific codes start at 0x8000_0000.
        assert_eq!(check_rv(0x8000_1234), Err(VsError::CryptoError));
    }

    #[test]
    fn ckr_key_handle_invalid_maps_to_invalid_input() {
        assert_eq!(check_rv(CKR_KEY_HANDLE_INVALID), Err(VsError::InvalidInput));
    }

    #[test]
    fn ckr_encrypted_data_invalid_maps_to_auth_failed() {
        assert_eq!(
            check_rv(CKR_ENCRYPTED_DATA_INVALID),
            Err(VsError::AuthenticationFailure)
        );
    }

    #[test]
    fn rv_to_err_maps_known_non_ok_code() {
        assert_eq!(rv_to_err(CKR_PIN_INCORRECT), VsError::AuthenticationFailure);
        assert_eq!(rv_to_err(CKR_ARGUMENTS_BAD), VsError::InvalidInput);
        assert_eq!(rv_to_err(CKR_TOKEN_NOT_PRESENT), VsError::NotInitialized);
        assert_eq!(rv_to_err(CKR_HOST_MEMORY), VsError::ResourceExhausted);
    }

    #[test]
    fn rv_to_err_unknown_vendor_code_maps_to_crypto_error() {
        assert_eq!(rv_to_err(0x8000_1234), VsError::CryptoError);
    }

    #[test]
    fn rv_to_err_ok_defensively_maps_to_crypto_error() {
        // `rv_to_err` is only invoked on codes the caller has already
        // filtered as non-OK; the defensive fallback here guards against
        // an internal contract violation rather than an expected case.
        assert_eq!(rv_to_err(CKR_OK), VsError::CryptoError);
    }
}

//! Translate `tonic::Status` + `google.rpc.ErrorInfo` → §7.5 REST errors.
//!
//! **Single source of HTTP status:** `ErrorInfo.metadata["http_status"]` from
//! the kernel. This module holds **no** reason→status table. A status that
//! lacks a well-formed `ErrorInfo` with `domain = "kernel.v1"` and a valid
//! HTTP status metadata entry is fail-closed (`500 internal_error`).

use crate::error::ApiError;
use axum::http::StatusCode;
use prost::Message;
use std::collections::HashMap;
#[cfg(test)]
use tonic::Code;
use tonic::Status;

/// Normative `ErrorInfo.domain` (§7.8).
pub const ERROR_INFO_DOMAIN: &str = "kernel.v1";

/// Wire type URL for `google.rpc.ErrorInfo` (with and without the type.googleapis.com prefix).
const ERROR_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const ERROR_INFO_TYPE_SUFFIX: &str = "google.rpc.ErrorInfo";

/// Minimal `google.rpc.ErrorInfo` (field numbers match googleapis).
#[derive(Clone, PartialEq, Message)]
pub struct ErrorInfo {
    #[prost(string, tag = "1")]
    pub reason: String,
    #[prost(string, tag = "2")]
    pub domain: String,
    #[prost(map = "string, string", tag = "3")]
    pub metadata: HashMap<String, String>,
}

/// Map a failed kernel RPC `Status` to the §7.5 REST error.
///
/// Requires exactly-decodable `ErrorInfo` in `Status.details` with:
/// - `domain == "kernel.v1"`
/// - non-empty `reason` (the §7.5 machine code)
/// - `metadata["http_status"]` a decimal integer in `400..=599` that
///   `StatusCode::from_u16` accepts
///
/// Anything else → [`ApiError::internal`] (fail-closed; no guessed status).
pub fn kernel_status_to_api_error(status: &Status) -> ApiError {
    match decode_error_info(status) {
        Ok(info) => match validate_and_build(info, status.message()) {
            Ok(err) => err,
            Err(why) => ApiError::internal(format!(
                "kernel ErrorInfo failed contract validation: {why}"
            )),
        },
        Err(why) => ApiError::internal(format!("kernel status missing usable ErrorInfo: {why}")),
    }
}

/// A transport failure (dial, broken pipe, timeout) is **not** a kernel
/// domain error. §7.5 closes unlisted conditions as `internal_error` / 500.
pub fn transport_error_to_api_error(err: &tonic::transport::Error) -> ApiError {
    ApiError::internal(format!("kernel transport error: {err}"))
}

fn validate_and_build(info: ErrorInfo, status_message: &str) -> Result<ApiError, String> {
    if info.domain != ERROR_INFO_DOMAIN {
        return Err(format!(
            "domain must be {ERROR_INFO_DOMAIN:?}, got {:?}",
            info.domain
        ));
    }
    if info.reason.is_empty() {
        return Err("reason is empty".to_string());
    }
    let http_raw = match info.metadata.get("http_status") {
        Some(v) => v.as_str(),
        None => return Err("metadata[\"http_status\"] is absent".to_string()),
    };
    if http_raw.is_empty() {
        return Err("metadata[\"http_status\"] is empty".to_string());
    }
    // Strict decimal parse — no leading '+', no whitespace, no fallback.
    let code_u16: u16 = match http_raw.parse::<u16>() {
        Ok(n) => n,
        Err(_) => {
            return Err(format!(
                "metadata[\"http_status\"] is not a u16 decimal: {http_raw:?}"
            ));
        }
    };
    // Re-check canonical form so "0400" / overflow tricks do not slip through
    // a lossy parse (u16 parse rejects overflow; reject non-canonical strings).
    if http_raw != code_u16.to_string() {
        return Err(format!(
            "metadata[\"http_status\"] is not canonical decimal: {http_raw:?}"
        ));
    }
    if !(400..=599).contains(&code_u16) {
        return Err(format!(
            "metadata[\"http_status\"] out of error range: {code_u16}"
        ));
    }
    let status = match StatusCode::from_u16(code_u16) {
        Ok(s) => s,
        Err(_) => {
            return Err(format!(
                "metadata[\"http_status\"] is not a valid HTTP status: {code_u16}"
            ));
        }
    };
    let message = if status_message.is_empty() {
        info.reason.clone()
    } else {
        status_message.to_string()
    };
    Ok(ApiError::new(status, info.reason, message))
}

fn decode_error_info(status: &Status) -> Result<ErrorInfo, String> {
    let details = status.details();
    if details.is_empty() {
        return Err("Status.details is empty".to_string());
    }
    // tonic packs a single `google.protobuf.Any` (or a repeated-Any encoding).
    // Try Any first; if the bytes are raw ErrorInfo, accept that too only when
    // the Any path fails — still one vocabulary (ErrorInfo fields), not a
    // second reason table.
    if let Ok(info) = decode_from_any(details) {
        return Ok(info);
    }
    match ErrorInfo::decode(details) {
        Ok(info) => Ok(info),
        Err(e) => Err(format!(
            "Status.details is neither google.protobuf.Any nor ErrorInfo: {e}"
        )),
    }
}

fn decode_from_any(details: &[u8]) -> Result<ErrorInfo, String> {
    let any = prost_types::Any::decode(details).map_err(|e| format!("Any decode failed: {e}"))?;
    if !type_url_is_error_info(&any.type_url) {
        return Err(format!(
            "Any type_url is not google.rpc.ErrorInfo: {:?}",
            any.type_url
        ));
    }
    ErrorInfo::decode(any.value.as_slice()).map_err(|e| format!("ErrorInfo decode failed: {e}"))
}

fn type_url_is_error_info(type_url: &str) -> bool {
    type_url == ERROR_INFO_TYPE_URL || type_url.ends_with(ERROR_INFO_TYPE_SUFFIX)
}

/// Build a `tonic::Status` carrying normative ErrorInfo (test double / helpers).
///
/// Production kernel code lives in zk-coins/node; this encoder exists so the
/// api tests can emit the **same** wire shape the REST mapper consumes — no
/// invented second vocabulary. Not compiled into non-test builds: production
/// never encodes kernel errors (only the node does).
#[cfg(test)]
pub fn encode_kernel_error_status(
    grpc_code: Code,
    message: impl Into<String>,
    reason: impl Into<String>,
    http_status: u16,
) -> Status {
    let reason = reason.into();
    let mut metadata = HashMap::new();
    metadata.insert("http_status".to_string(), http_status.to_string());
    let info = ErrorInfo {
        reason: reason.clone(),
        domain: ERROR_INFO_DOMAIN.to_string(),
        metadata,
    };
    let any = prost_types::Any {
        type_url: ERROR_INFO_TYPE_URL.to_string(),
        value: info.encode_to_vec(),
    };
    Status::with_details(grpc_code, message, any.encode_to_vec().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_job_not_found_from_error_info() {
        // Values from node/src/transport/error_contract.rs:
        // JobNotFound → reason job_not_found, http 404, gRPC NotFound.
        let st = encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.body.error, "job_not_found");
        assert_eq!(err.body.message, "Job not found");
    }

    #[test]
    fn maps_wrong_phase_from_error_info() {
        // error_contract: WrongPhase → wrong_phase / 409 / FailedPrecondition.
        let st =
            encode_kernel_error_status(Code::FailedPrecondition, "wrong phase", "wrong_phase", 409);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.body.error, "wrong_phase");
    }

    #[test]
    fn maps_bounds_exceeded_from_error_info() {
        // error_contract: BoundsExceeded → bounds_exceeded / 400 / InvalidArgument.
        let st = encode_kernel_error_status(
            Code::InvalidArgument,
            "too many inputs",
            "bounds_exceeded",
            400,
        );
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "bounds_exceeded");
        assert_eq!(err.body.message, "too many inputs");
    }

    #[test]
    fn missing_http_status_is_fail_closed_500() {
        let mut metadata = HashMap::new();
        // deliberately no http_status
        metadata.insert("other".to_string(), "x".to_string());
        let info = ErrorInfo {
            reason: "job_not_found".to_string(),
            domain: ERROR_INFO_DOMAIN.to_string(),
            metadata,
        };
        let any = prost_types::Any {
            type_url: ERROR_INFO_TYPE_URL.to_string(),
            value: info.encode_to_vec(),
        };
        let st = Status::with_details(Code::NotFound, "x", any.encode_to_vec().into());
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("http_status"),
            "message must name the missing field, got {}",
            err.body.message
        );
    }

    #[test]
    fn invalid_http_status_is_fail_closed_500() {
        let st = encode_kernel_error_status(Code::Internal, "x", "internal_error", 200);
        // encode allows any u16; mapper must reject non-error range.
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("out of error range")
                || err.body.message.contains("http_status"),
            "message must name the status problem, got {}",
            err.body.message
        );
    }

    #[test]
    fn wrong_domain_is_fail_closed_500() {
        let mut metadata = HashMap::new();
        metadata.insert("http_status".to_string(), "404".to_string());
        let info = ErrorInfo {
            reason: "job_not_found".to_string(),
            domain: "not.kernel".to_string(),
            metadata,
        };
        let any = prost_types::Any {
            type_url: ERROR_INFO_TYPE_URL.to_string(),
            value: info.encode_to_vec(),
        };
        let st = Status::with_details(Code::NotFound, "x", any.encode_to_vec().into());
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("domain"),
            "message must name domain failure, got {}",
            err.body.message
        );
    }

    #[test]
    fn empty_details_is_fail_closed_500() {
        let st = Status::new(Code::Internal, "bare status");
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("ErrorInfo"),
            "message must mention ErrorInfo, got {}",
            err.body.message
        );
    }

    #[test]
    fn non_canonical_http_status_string_is_fail_closed() {
        let mut metadata = HashMap::new();
        metadata.insert("http_status".to_string(), "0404".to_string());
        let info = ErrorInfo {
            reason: "job_not_found".to_string(),
            domain: ERROR_INFO_DOMAIN.to_string(),
            metadata,
        };
        let any = prost_types::Any {
            type_url: ERROR_INFO_TYPE_URL.to_string(),
            value: info.encode_to_vec(),
        };
        let st = Status::with_details(Code::NotFound, "x", any.encode_to_vec().into());
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("canonical"),
            "message must name canonical form, got {}",
            err.body.message
        );
    }
}

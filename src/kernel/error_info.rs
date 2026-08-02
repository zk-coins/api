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

/// Closed §7.5 `machine_code` set that a kernel `ErrorInfo.reason` **MAY**
/// carry (§7.5 jobs-family table + the additional codes closing the
/// enumeration across §7.4–§7.7, plus `feature_disabled` from the §7.5 intro).
///
/// An unknown reason is a **protocol violation by the kernel**, not a client
/// error: the API fails closed with `500 internal_error` and **never**
/// forwards a foreign code onto the public wire (same discipline as a missing
/// or non-canonical `http_status`).
///
/// ## Delivery credential (§7.5 `OutputTemplate.delivery`)
///
/// Invalid / missing / unknown-type delivery credentials are **not** a new
/// machine code. Spec §7.5 maps every failed invoice/profile check-list item
/// and every presence-rule violation to `malformed_request` / 400. The node
/// (`KernelErrorCode::MalformedRequest` → reason `malformed_request`) agrees.
/// This closed set therefore gains **no** delivery-specific reason from that
/// wire addition.
///
/// ## Alignment notes (API set vs node `KernelErrorCode::ALL`)
///
/// Node `error_contract.rs` / `KernelErrorCode` covers the 21 RPC-level codes.
/// This API set additionally accepts:
/// - `proving_failed`, `publish_rejected` — terminal **job** `JobError.error`
///   values (§7.5 jobs-family table); not `KernelErrorCode` RPC failures, but
///   listed so a kernel that ever surfaces them via `ErrorInfo` is not
///   fail-closed as foreign.
/// - `feature_disabled` — API-layer gate (§7.5 intro), never a kernel code.
///
/// Those three extras predate the delivery-credential change and are **not**
/// a Spec↔node drift for delivery.
const CLOSED_ERROR_REASONS: &[&str] = &[
    // Jobs family (§7.5 machine_code table)
    "invalid_input_coin",
    "insufficient_balance",
    "bounds_exceeded",
    "unknown_publisher",
    "stale_message",
    "invalid_signature",
    "job_not_found",
    "wrong_phase",
    "proving_failed",
    "publish_rejected",
    "circuit_digest_mismatch",
    // Additional codes closing the enumeration (§7.5 additional table)
    // `malformed_request` also covers failed/missing `OutputTemplate.delivery`
    // (§7.5 delivery check-lists + presence rule + unknown `delivery.type`).
    "malformed_request",
    "idempotency_conflict",
    "unauthorized",
    "scope_exceeded",
    "challenge_expired",
    "session_expired",
    "not_found",
    "payload_too_large",
    "retention_hold",
    "rate_limited",
    "dependency_not_final",
    "internal_error",
    // §7.5 intro: disabled feature answers `404 feature_disabled`
    "feature_disabled",
];

/// Wire type URL for `google.rpc.ErrorInfo` (with and without the type.googleapis.com prefix).
const ERROR_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const ERROR_INFO_TYPE_SUFFIX: &str = "google.rpc.ErrorInfo";

fn is_closed_error_reason(reason: &str) -> bool {
    CLOSED_ERROR_REASONS.contains(&reason)
}

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
    // Closed §7.5 machine_code set — a foreign reason is a kernel protocol
    // violation. Do not forward it as the public `error` field.
    if !is_closed_error_reason(&info.reason) {
        return Err(format!(
            "reason is not a closed §7.5 machine_code: {:?}",
            info.reason
        ));
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
    // Normative reason↔status pairs (§7.5). A kernel that sends a closed
    // reason with the wrong HTTP status is a protocol fault — fail closed
    // as 500, never invent the correct status client-side.
    match info.reason.as_str() {
        "unauthorized" if code_u16 != 401 => {
            return Err(format!(
                "reason \"unauthorized\" requires http_status 401, got {code_u16}"
            ));
        }
        "session_expired" if code_u16 != 410 => {
            return Err(format!(
                "reason \"session_expired\" requires http_status 410, got {code_u16}"
            ));
        }
        _ => {}
    }
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
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("http_status"),
            "operator cause must name the missing field, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn invalid_http_status_is_fail_closed_500() {
        let st = encode_kernel_error_status(Code::Internal, "x", "internal_error", 200);
        // encode allows any u16; mapper must reject non-error range.
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("out of error range") || cause.contains("http_status"),
            "operator cause must name the status problem, got {cause}"
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
            err.cause().unwrap_or("").contains("domain"),
            "operator cause must name domain failure, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn empty_details_is_fail_closed_500() {
        let st = Status::new(Code::Internal, "bare status");
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("ErrorInfo"),
            "operator cause must mention ErrorInfo, got {:?}",
            err.cause()
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
            err.cause().unwrap_or("").contains("canonical"),
            "operator cause must name canonical form, got {:?}",
            err.cause()
        );
    }

    /// Without the closed-set check, a non-empty foreign reason is forwarded
    /// as the public machine code. That must fail loud instead.
    #[test]
    fn unknown_error_info_reason_is_fail_closed_500_not_forwarded() {
        let st = encode_kernel_error_status(
            Code::Internal,
            "kernel invented a code",
            "totally_made_up_reason",
            500,
        );
        let err = kernel_status_to_api_error(&st);
        assert_eq!(
            err.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "unknown kernel reason is a server-side protocol fault, not a client 4xx"
        );
        assert_eq!(
            err.body.error, "internal_error",
            "foreign reason must not become the public error code"
        );
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("totally_made_up_reason")
                || cause.contains("machine_code")
                || cause.contains("closed"),
            "operator cause must name the foreign reason or the closed-set rule, got {cause}"
        );
        assert_ne!(
            err.body.error, "totally_made_up_reason",
            "foreign reason must never be echoed as the wire machine code"
        );
    }

    /// Without the pair check, `unauthorized` with http_status 403 would be
    /// forwarded as a 403. Spec binds unauthorized ↔ 401 only.
    #[test]
    fn unauthorized_with_wrong_http_status_is_fail_closed_500() {
        let st =
            encode_kernel_error_status(Code::PermissionDenied, "not allowed", "unauthorized", 403);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("401"),
            "cause must name the required 401 pairing, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn session_expired_with_wrong_http_status_is_fail_closed_500() {
        let st = encode_kernel_error_status(
            Code::FailedPrecondition,
            "session gone",
            "session_expired",
            401,
        );
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("410"),
            "cause must name the required 410 pairing, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn unauthorized_401_and_session_expired_410_are_accepted() {
        let u = encode_kernel_error_status(Code::Unauthenticated, "nope", "unauthorized", 401);
        let err = kernel_status_to_api_error(&u);
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.body.error, "unauthorized");

        let s =
            encode_kernel_error_status(Code::FailedPrecondition, "gone", "session_expired", 410);
        let err = kernel_status_to_api_error(&s);
        assert_eq!(err.status, StatusCode::GONE);
        assert_eq!(err.body.error, "session_expired");
    }

    #[test]
    fn closed_reason_set_accepts_known_machine_codes() {
        // Spot-check a few codes from each §7.5 table so the constant is not
        // accidentally empty / truncated.
        for reason in [
            "job_not_found",
            "bounds_exceeded",
            "malformed_request",
            "session_expired",
            "dependency_not_final",
            "feature_disabled",
            "internal_error",
            // Delivery credential failures reuse malformed_request — there is
            // no distinct delivery_* machine code in Spec or node.
            "proving_failed",
            "publish_rejected",
        ] {
            assert!(
                is_closed_error_reason(reason),
                "closed set must include {reason:?}"
            );
        }
        assert!(!is_closed_error_reason(""));
        assert!(!is_closed_error_reason("not_a_real_code"));
        // Delivery did not introduce a new public code.
        assert!(!is_closed_error_reason("invalid_delivery"));
        assert!(!is_closed_error_reason("delivery_required"));
        assert!(!is_closed_error_reason("invalid_invoice"));
    }
}

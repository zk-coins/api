//! Translate `tonic::Status` + `google.rpc.ErrorInfo` → §7.5 REST errors.
//!
//! **Wire shape (production):** the node packs errors via `tonic-types`
//! (`Status::with_error_details`) so `Status.details` is a `google.rpc.Status`
//! envelope whose `details` array holds **exactly one** `google.rpc.ErrorInfo`.
//! This module decodes that envelope only — bare `Any` / raw `ErrorInfo` are
//! rejected (fail-closed).
//!
//! **Single source of HTTP status:** `ErrorInfo.metadata["http_status"]` from
//! the kernel, validated against the closed `(gRPC code, reason, http_status)`
//! table. Anything else is `500 internal_error` with a neutral public message.

use crate::error::ApiError;
use axum::http::StatusCode;
use std::collections::HashMap;
use tonic::Code;
use tonic::Status;
#[cfg(test)]
use tonic_types::ErrorDetails;
use tonic_types::{ErrorDetail, StatusExt};

/// Normative `ErrorInfo.domain` (§7.8).
pub const ERROR_INFO_DOMAIN: &str = "kernel.v1";

/// One closed RPC-level `(reason, http_status, gRPC Code)` triple from
/// node `error_contract::describe` / Spec §7.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RpcErrorTriple {
    reason: &'static str,
    http_status: u16,
    grpc: Code,
}

/// Closed set of triples a kernel procedure **MAY** emit as gRPC `Status`
/// failures. Job-payload-only codes (`proving_failed`, `publish_rejected`) and
/// API-only codes (`feature_disabled`) are **not** listed — if they appear in
/// `ErrorInfo` they are protocol violations → 500.
const RPC_ERROR_TRIPLES: &[RpcErrorTriple] = &[
    RpcErrorTriple {
        reason: "malformed_request",
        http_status: 400,
        grpc: Code::InvalidArgument,
    },
    RpcErrorTriple {
        reason: "bounds_exceeded",
        http_status: 400,
        grpc: Code::InvalidArgument,
    },
    RpcErrorTriple {
        reason: "invalid_input_coin",
        http_status: 400,
        grpc: Code::InvalidArgument,
    },
    RpcErrorTriple {
        reason: "insufficient_balance",
        http_status: 400,
        grpc: Code::InvalidArgument,
    },
    RpcErrorTriple {
        reason: "unknown_publisher",
        http_status: 400,
        grpc: Code::InvalidArgument,
    },
    RpcErrorTriple {
        reason: "job_not_found",
        http_status: 404,
        grpc: Code::NotFound,
    },
    RpcErrorTriple {
        reason: "not_found",
        http_status: 404,
        grpc: Code::NotFound,
    },
    RpcErrorTriple {
        reason: "wrong_phase",
        http_status: 409,
        grpc: Code::FailedPrecondition,
    },
    RpcErrorTriple {
        reason: "stale_message",
        http_status: 409,
        grpc: Code::FailedPrecondition,
    },
    RpcErrorTriple {
        reason: "invalid_signature",
        http_status: 409,
        grpc: Code::FailedPrecondition,
    },
    // `retention_hold` removed with data permanence (Requirement 12): the
    // Blossom store is append-only; there is no DELETE refusal path.
    RpcErrorTriple {
        reason: "dependency_not_final",
        http_status: 409,
        grpc: Code::FailedPrecondition,
    },
    RpcErrorTriple {
        reason: "idempotency_conflict",
        http_status: 409,
        grpc: Code::FailedPrecondition,
    },
    RpcErrorTriple {
        reason: "unauthorized",
        http_status: 401,
        grpc: Code::Unauthenticated,
    },
    // 410 special cases: same gRPC class as unauthorized, distinct HTTP.
    RpcErrorTriple {
        reason: "challenge_expired",
        http_status: 410,
        grpc: Code::Unauthenticated,
    },
    RpcErrorTriple {
        reason: "session_expired",
        http_status: 410,
        grpc: Code::Unauthenticated,
    },
    RpcErrorTriple {
        reason: "scope_exceeded",
        http_status: 403,
        grpc: Code::PermissionDenied,
    },
    RpcErrorTriple {
        reason: "rate_limited",
        http_status: 429,
        grpc: Code::ResourceExhausted,
    },
    RpcErrorTriple {
        reason: "payload_too_large",
        http_status: 413,
        grpc: Code::ResourceExhausted,
    },
    RpcErrorTriple {
        reason: "circuit_digest_mismatch",
        http_status: 503,
        grpc: Code::Unavailable,
    },
    RpcErrorTriple {
        reason: "internal_error",
        http_status: 500,
        grpc: Code::Internal,
    },
];

/// Kernel procedure names for per-RPC allowed-error sets (§7.8 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelProcedure {
    GetInfo,
    GetAccumulator,
    ListInscriptions,
    GetNullifierPath,
    SubmitTransition,
    GetJob,
    StreamJob,
    SignTransition,
    CancelJob,
    OpenPullChallenge,
    Pull,
    GetRecord,
    GetCoinProof,
    GetAccountState,
    SubscribeReceipts,
    Publish,
    EntrustOperationalBundle,
    RevokeOperationalBundle,
    AttestBalance,
    IssueViewGrant,
}

impl KernelProcedure {
    /// Reasons this procedure **MAY** emit (always includes `internal_error`
    /// and, where the Spec allows not-ready as generic 503, that is folded
    /// into `internal_error` or procedure-specific codes only).
    fn allowed_reasons(self) -> &'static [&'static str] {
        match self {
            Self::GetInfo | Self::GetAccumulator => &["internal_error"],
            Self::ListInscriptions => &[
                "bounds_exceeded",
                "malformed_request",
                "rate_limited",
                "internal_error",
            ],
            Self::GetNullifierPath => &["malformed_request", "rate_limited", "internal_error"],
            Self::SubmitTransition => &[
                "malformed_request",
                "bounds_exceeded",
                "invalid_input_coin",
                "insufficient_balance",
                "unknown_publisher",
                "idempotency_conflict",
                "dependency_not_final",
                "rate_limited",
                "circuit_digest_mismatch",
                "internal_error",
            ],
            Self::GetJob | Self::StreamJob => &[
                "malformed_request",
                "job_not_found",
                "rate_limited",
                "internal_error",
            ],
            Self::SignTransition => &[
                "malformed_request",
                "job_not_found",
                "wrong_phase",
                "stale_message",
                "invalid_signature",
                "rate_limited",
                "internal_error",
            ],
            Self::CancelJob => &[
                "malformed_request",
                "job_not_found",
                "wrong_phase",
                "rate_limited",
                "internal_error",
            ],
            Self::OpenPullChallenge => &["malformed_request", "rate_limited", "internal_error"],
            Self::Pull => &[
                "malformed_request",
                "unauthorized",
                "challenge_expired",
                "scope_exceeded",
                "rate_limited",
                "internal_error",
            ],
            Self::GetRecord | Self::GetCoinProof => &[
                "malformed_request",
                "not_found",
                "unauthorized",
                "session_expired",
                "scope_exceeded",
                "rate_limited",
                "internal_error",
            ],
            Self::GetAccountState => &[
                "malformed_request",
                "unauthorized",
                "session_expired",
                "rate_limited",
                "internal_error",
            ],
            Self::SubscribeReceipts => &[
                "malformed_request",
                "unauthorized",
                "session_expired",
                "scope_exceeded",
                "rate_limited",
                "internal_error",
            ],
            Self::Publish => &["malformed_request", "rate_limited", "internal_error"],
            Self::EntrustOperationalBundle | Self::RevokeOperationalBundle => &[
                "malformed_request",
                "unauthorized",
                "challenge_expired",
                "rate_limited",
                "internal_error",
            ],
            Self::AttestBalance => &[
                "malformed_request",
                "unauthorized",
                "challenge_expired",
                "rate_limited",
                "circuit_digest_mismatch",
                "internal_error",
            ],
            Self::IssueViewGrant => &[
                "malformed_request",
                "unauthorized",
                "challenge_expired",
                "rate_limited",
                "internal_error",
            ],
        }
    }
}

fn lookup_triple(reason: &str) -> Option<&'static RpcErrorTriple> {
    RPC_ERROR_TRIPLES.iter().find(|t| t.reason == reason)
}

/// Decoded ErrorInfo fields used after tonic-types unpack.
struct DecodedErrorInfo {
    reason: String,
    domain: String,
    metadata: HashMap<String, String>,
}

/// Map a failed kernel RPC `Status` to the §7.5 REST error (no procedure filter).
///
/// Prefer [`kernel_status_to_api_error_for`] at production call sites so
/// procedure-foreign reasons fail closed.
pub fn kernel_status_to_api_error(status: &Status) -> ApiError {
    kernel_status_to_api_error_for(status, None)
}

/// Map a failed kernel RPC `Status`, optionally restricting to the procedure's
/// allowed reason set (§7.8 per-procedure table).
pub fn kernel_status_to_api_error_for(
    status: &Status,
    procedure: Option<KernelProcedure>,
) -> ApiError {
    match decode_error_info(status) {
        Ok(info) => match validate_and_build(info, status, procedure) {
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

fn validate_and_build(
    info: DecodedErrorInfo,
    status: &Status,
    procedure: Option<KernelProcedure>,
) -> Result<ApiError, String> {
    if info.domain != ERROR_INFO_DOMAIN {
        return Err(format!(
            "domain must be {ERROR_INFO_DOMAIN:?}, got {:?}",
            info.domain
        ));
    }
    if info.reason.is_empty() {
        return Err("reason is empty".to_string());
    }

    // Job-payload-only / API-only codes must never arrive as RPC ErrorInfo.
    if matches!(
        info.reason.as_str(),
        "proving_failed" | "publish_rejected" | "feature_disabled"
    ) {
        return Err(format!(
            "reason {:?} is not an RPC ErrorInfo code (job-payload-only or API-only)",
            info.reason
        ));
    }

    let triple = match lookup_triple(&info.reason) {
        Some(t) => t,
        None => {
            return Err(format!(
                "reason is not a closed §7.5 RPC machine_code: {:?}",
                info.reason
            ));
        }
    };

    let http_raw = match info.metadata.get("http_status") {
        Some(v) => v.as_str(),
        None => return Err("metadata[\"http_status\"] is absent".to_string()),
    };
    if http_raw.is_empty() {
        return Err("metadata[\"http_status\"] is empty".to_string());
    }
    let code_u16: u16 = match http_raw.parse::<u16>() {
        Ok(n) => n,
        Err(_) => {
            return Err(format!(
                "metadata[\"http_status\"] is not a u16 decimal: {http_raw:?}"
            ));
        }
    };
    if http_raw != code_u16.to_string() {
        return Err(format!(
            "metadata[\"http_status\"] is not canonical decimal: {http_raw:?}"
        ));
    }

    // Full triple: reason ↔ http_status ↔ gRPC code.
    if code_u16 != triple.http_status {
        return Err(format!(
            "reason {:?} requires http_status {}, got {code_u16}",
            info.reason, triple.http_status
        ));
    }
    if status.code() != triple.grpc {
        return Err(format!(
            "reason {:?} requires gRPC {:?}, got {:?}",
            info.reason,
            triple.grpc,
            status.code()
        ));
    }

    if let Some(proc) = procedure {
        if !proc.allowed_reasons().contains(&info.reason.as_str()) {
            return Err(format!(
                "reason {:?} is not allowed for procedure {:?}",
                info.reason, proc
            ));
        }
    }

    let http_status = match StatusCode::from_u16(code_u16) {
        Ok(s) => s,
        Err(_) => {
            return Err(format!(
                "metadata[\"http_status\"] is not a valid HTTP status: {code_u16}"
            ));
        }
    };

    // internal_error / 500: never forward kernel diagnostics onto the wire.
    if info.reason == "internal_error" {
        let cause = if status.message().is_empty() {
            "kernel internal_error".to_string()
        } else {
            status.message().to_string()
        };
        return Ok(ApiError::internal(cause));
    }

    let message = if status.message().is_empty() {
        info.reason.clone()
    } else {
        status.message().to_string()
    };
    Ok(ApiError::new(http_status, info.reason, message))
}

/// Decode exactly one `google.rpc.ErrorInfo` from the production
/// `google.rpc.Status` details envelope (`tonic-types`). No bare-Any or
/// raw-ErrorInfo fallback.
fn decode_error_info(status: &Status) -> Result<DecodedErrorInfo, String> {
    let details = status.details();
    if details.is_empty() {
        return Err("Status.details is empty".to_string());
    }

    let vec = status
        .check_error_details_vec()
        .map_err(|e| format!("google.rpc.Status details decode failed: {e}"))?;

    if vec.is_empty() {
        return Err("google.rpc.Status.details has zero entries".to_string());
    }
    if vec.len() != 1 {
        return Err(format!(
            "google.rpc.Status.details must hold exactly one ErrorInfo, got {} entries",
            vec.len()
        ));
    }

    match &vec[0] {
        ErrorDetail::ErrorInfo(info) => Ok(DecodedErrorInfo {
            reason: info.reason.clone(),
            domain: info.domain.clone(),
            metadata: info.metadata.clone(),
        }),
        other => Err(format!(
            "sole google.rpc.Status.details entry must be ErrorInfo, got {other:?}"
        )),
    }
}

/// Build a `tonic::Status` carrying normative ErrorInfo (test double / helpers).
///
/// Uses the **same** production encoder as the node (`tonic_types::StatusExt::
/// with_error_details`) so tests exercise the real wire shape. Not compiled
/// into non-test builds: production never encodes kernel errors.
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
    let details = ErrorDetails::with_error_info(reason, ERROR_INFO_DOMAIN, metadata);
    Status::with_error_details(grpc_code, message, details)
}

/// Minimal ErrorInfo mirror for tests that still inspect field layout.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorInfo {
    pub reason: String,
    pub domain: String,
    pub metadata: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PUBLIC_INTERNAL_MESSAGE;
    use prost::Message;
    use tonic_types::ErrorDetails;

    #[test]
    fn maps_job_not_found_from_error_info() {
        let st = encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.body.error, "job_not_found");
        assert_eq!(err.body.message, "Job not found");
    }

    #[test]
    fn maps_wrong_phase_from_error_info() {
        let st =
            encode_kernel_error_status(Code::FailedPrecondition, "wrong phase", "wrong_phase", 409);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.body.error, "wrong_phase");
    }

    #[test]
    fn maps_bounds_exceeded_from_error_info() {
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
    fn maps_challenge_expired_410() {
        let st = encode_kernel_error_status(
            Code::Unauthenticated,
            "challenge gone",
            "challenge_expired",
            410,
        );
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::GONE);
        assert_eq!(err.body.error, "challenge_expired");
        assert_eq!(err.body.message, "challenge gone");
    }

    #[test]
    fn challenge_expired_with_wrong_http_status_is_fail_closed_500() {
        let st = encode_kernel_error_status(
            Code::Unauthenticated,
            "challenge gone",
            "challenge_expired",
            401,
        );
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("410"),
            "cause must name required 410, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn wrong_grpc_code_for_reason_is_fail_closed_500() {
        // job_not_found requires NotFound, not Internal.
        let st = encode_kernel_error_status(Code::Internal, "x", "job_not_found", 404);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("gRPC")
                || err.cause().unwrap_or("").contains("NotFound"),
            "cause must name gRPC mismatch, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn job_payload_only_reason_as_rpc_is_fail_closed() {
        let st = encode_kernel_error_status(Code::Internal, "x", "proving_failed", 500);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_ne!(err.body.error, "proving_failed");
        assert!(
            err.cause().unwrap_or("").contains("proving_failed")
                || err.cause().unwrap_or("").contains("job-payload"),
            "cause must name the forbidden reason, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn feature_disabled_as_rpc_is_fail_closed() {
        let st = encode_kernel_error_status(Code::NotFound, "x", "feature_disabled", 404);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_ne!(err.body.error, "feature_disabled");
    }

    #[test]
    fn procedure_rejects_foreign_reason() {
        // job_not_found is valid globally but not for GetInfo.
        let st = encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        let err = kernel_status_to_api_error_for(&st, Some(KernelProcedure::GetInfo));
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("not allowed")
                || err.cause().unwrap_or("").contains("GetInfo"),
            "cause must name procedure filter, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn procedure_accepts_allowed_reason() {
        let st = encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        let err = kernel_status_to_api_error_for(&st, Some(KernelProcedure::GetJob));
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.body.error, "job_not_found");
    }

    #[test]
    fn missing_http_status_is_fail_closed_500() {
        let mut metadata = HashMap::new();
        metadata.insert("other".to_string(), "x".to_string());
        let details = ErrorDetails::with_error_info("job_not_found", ERROR_INFO_DOMAIN, metadata);
        let st = Status::with_error_details(Code::NotFound, "x", details);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("http_status"),
            "operator cause must name the missing field, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn invalid_http_status_is_fail_closed_500() {
        let st = encode_kernel_error_status(Code::Internal, "x", "internal_error", 200);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, PUBLIC_INTERNAL_MESSAGE);
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("requires http_status")
                || cause.contains("http_status")
                || cause.contains("500"),
            "operator cause must name the status problem, got {cause}"
        );
    }

    #[test]
    fn wrong_domain_is_fail_closed_500() {
        let mut metadata = HashMap::new();
        metadata.insert("http_status".to_string(), "404".to_string());
        let details = ErrorDetails::with_error_info("job_not_found", "not.kernel", metadata);
        let st = Status::with_error_details(Code::NotFound, "x", details);
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
            err.cause().unwrap_or("").contains("ErrorInfo")
                || err.cause().unwrap_or("").contains("details"),
            "operator cause must mention ErrorInfo/details, got {:?}",
            err.cause()
        );
    }

    /// Bare `Any(ErrorInfo)` is **not** the production wire shape and must
    /// fail closed (node uses `google.rpc.Status` envelope via tonic-types).
    #[test]
    fn bare_any_error_info_is_rejected() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct LocalErrorInfo {
            #[prost(string, tag = "1")]
            reason: String,
            #[prost(string, tag = "2")]
            domain: String,
            #[prost(map = "string, string", tag = "3")]
            metadata: HashMap<String, String>,
        }
        let mut metadata = HashMap::new();
        metadata.insert("http_status".to_string(), "404".to_string());
        let info = LocalErrorInfo {
            reason: "job_not_found".to_string(),
            domain: ERROR_INFO_DOMAIN.to_string(),
            metadata,
        };
        let any = prost_types::Any {
            type_url: "type.googleapis.com/google.rpc.ErrorInfo".to_string(),
            value: info.encode_to_vec(),
        };
        let st = Status::with_details(Code::NotFound, "x", any.encode_to_vec().into());
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, PUBLIC_INTERNAL_MESSAGE);
    }

    #[test]
    fn non_canonical_http_status_string_is_fail_closed() {
        let mut metadata = HashMap::new();
        metadata.insert("http_status".to_string(), "0404".to_string());
        let details = ErrorDetails::with_error_info("job_not_found", ERROR_INFO_DOMAIN, metadata);
        let st = Status::with_error_details(Code::NotFound, "x", details);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("canonical"),
            "operator cause must name canonical form, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn unknown_error_info_reason_is_fail_closed_500_not_forwarded() {
        let st = encode_kernel_error_status(
            Code::Internal,
            "kernel invented a code",
            "totally_made_up_reason",
            500,
        );
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_ne!(err.body.error, "totally_made_up_reason");
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("totally_made_up_reason")
                || cause.contains("machine_code")
                || cause.contains("closed"),
            "operator cause must name the foreign reason, got {cause}"
        );
    }

    #[test]
    fn unauthorized_with_wrong_http_status_is_fail_closed_500() {
        let st =
            encode_kernel_error_status(Code::PermissionDenied, "not allowed", "unauthorized", 403);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("401")
                || err.cause().unwrap_or("").contains("gRPC")
                || err.cause().unwrap_or("").contains("http_status"),
            "cause must name the pairing failure, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn session_expired_with_wrong_http_status_is_fail_closed_500() {
        let st = encode_kernel_error_status(
            Code::Unauthenticated,
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

        let s = encode_kernel_error_status(Code::Unauthenticated, "gone", "session_expired", 410);
        let err = kernel_status_to_api_error(&s);
        assert_eq!(err.status, StatusCode::GONE);
        assert_eq!(err.body.error, "session_expired");
    }

    /// Kernel `internal_error` must never leak the status message onto the wire.
    #[test]
    fn internal_error_public_message_is_neutral_secret_not_on_wire() {
        const SECRET: &str = "/var/lib/zkcoins/SECRET_DB_PATH_xyz_do_not_leak";
        let st = encode_kernel_error_status(Code::Internal, SECRET, "internal_error", 500);
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, PUBLIC_INTERNAL_MESSAGE);
        assert!(
            !err.body.message.contains("SECRET"),
            "public message must not carry secret"
        );
        assert!(
            err.cause().unwrap_or("").contains("SECRET_DB_PATH"),
            "operator cause must retain the diagnostic, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn closed_rpc_triple_table_covers_normative_codes() {
        for reason in [
            "job_not_found",
            "bounds_exceeded",
            "malformed_request",
            "session_expired",
            "challenge_expired",
            "dependency_not_final",
            "internal_error",
            "circuit_digest_mismatch",
            "rate_limited",
            "scope_exceeded",
            "unauthorized",
        ] {
            assert!(
                lookup_triple(reason).is_some(),
                "RPC triple table must include {reason:?}"
            );
        }
        // Job-payload / API-only must stay out of the RPC table.
        assert!(lookup_triple("proving_failed").is_none());
        assert!(lookup_triple("publish_rejected").is_none());
        assert!(lookup_triple("feature_disabled").is_none());
        assert!(lookup_triple("totally_made_up").is_none());
    }

    #[test]
    fn encode_uses_google_rpc_status_envelope_not_bare_any() {
        let st = encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        // Production decoder path must succeed.
        let err = kernel_status_to_api_error(&st);
        assert_eq!(err.body.error, "job_not_found");
        // Details must decode as a multi-detail google.rpc.Status envelope.
        let vec = st
            .check_error_details_vec()
            .expect("production encoder must pack google.rpc.Status details");
        assert_eq!(vec.len(), 1);
        match &vec[0] {
            ErrorDetail::ErrorInfo(info) => {
                assert_eq!(info.reason, "job_not_found");
                assert_eq!(info.domain, ERROR_INFO_DOMAIN);
            }
            other => panic!("expected ErrorInfo, got {other:?}"),
        }
    }
}

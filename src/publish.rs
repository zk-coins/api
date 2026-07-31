//! Publisher hand-off REST surface (§7.6): `POST /v1/publish/spendrecord`.
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/publish/spendrecord` | `Publish` |
//!
//! Permissionless — no OwnershipProof, no challenge. A well-formed body is
//! never answered with `401`/`403` for lack of credentials.
//!
//! ## HTTP status discipline (§7.6)
//!
//! | Condition | HTTP | Body |
//! |---|---|---|
//! | Malformed wire body (incl. any v1 fee field set) | **400** | `{ "error": "malformed_request", … }` |
//! | Crypto / policy rejection | **200** | `{ accepted: false, reason: <closed> }` |
//! | Accepted | **200** | `{ accepted: true, batch_eta: <u64 decimal string> }` |
//! | Internal failure | **500** | `{ "error": "internal_error", … }` |
//!
//! A publisher rejection is a **successful** RPC result, not a transport or
//! domain error. The REST surface mirrors that: `accepted: false` is still
//! HTTP 200.

use crate::error::ApiError;
use crate::hexutil::decode_hex_exact;
use crate::kernel::kernel_v1::{BlockAnchor, PublishRequest, PublishResult};
use crate::ownership::parse_u64_decimal;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Closed reason set (§7.6 L3079–L3089)
// ---------------------------------------------------------------------------

/// Normative closed enumeration for `PublishResult.reason` when
/// `accepted == false`. Unknown kernel tokens become `internal_error` —
/// never silently forwarded as an open string.
const PUBLISH_REJECT_REASONS: &[&str] = &[
    "invalid_signature",
    "invalid_s2c_opening",
    "invalid_fee_coinproof",
    "fee_address_mismatch",
    "ocr_mismatch",
    "fee_too_low",
    "unknown_fee_asset",
    "policy",
    "anchor_stale",
];

fn is_closed_reason(reason: &str) -> bool {
    PUBLISH_REJECT_REASONS.contains(&reason)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct BlockAnchorJson {
    pub block_hash: String,
    /// §7.1 decimal-string u32 (same wire form as other request integers).
    pub height: String,
}

#[derive(Debug, Deserialize)]
pub struct PublishSpendRecordBody {
    pub public_key: String,
    pub r: String,
    pub s: String,
    pub r_prime: String,
    pub block_anchor: BlockAnchorJson,
    /// Deferred fee fields — **MUST be absent in v1** (§7.6). Presence → 400.
    #[serde(default)]
    pub fee_blob_id: Option<String>,
    #[serde(default)]
    pub fee_blob_locators: Option<String>,
    #[serde(default)]
    pub fee_epk: Option<String>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /v1/publish/spendrecord` → `Publish`.
pub async fn post_publish_spendrecord(
    State(state): State<AppState>,
    Json(body): Json<PublishSpendRecordBody>,
) -> Result<Response, ApiError> {
    // v1 fee fields are fail-closed: any set field is malformed, never ignored.
    if body.fee_blob_id.is_some() || body.fee_blob_locators.is_some() || body.fee_epk.is_some() {
        return Err(ApiError::malformed(
            "fee_blob_id, fee_blob_locators, and fee_epk are deferred and MUST be absent in v1 \
             (§7.6 / §3.8.1); publishing is sponsored",
        ));
    }

    let public_key = decode_hex32(&body.public_key, "public_key")?;
    let r = decode_hex32(&body.r, "r")?;
    let s = decode_hex32(&body.s, "s")?;
    let r_prime = decode_hex32(&body.r_prime, "r_prime")?;
    let block_hash = decode_hex32(&body.block_anchor.block_hash, "block_anchor.block_hash")?;
    let height = parse_u32_decimal(&body.block_anchor.height, "block_anchor.height")?;

    let result: PublishResult = state
        .kernel
        .publish(PublishRequest {
            public_key,
            r,
            s,
            r_prime,
            // Empty fee fields = fee-less hand-off (v1 only shape).
            fee_blob_id: Vec::new(),
            fee_epk: Vec::new(),
            fee_blob_locators: Vec::new(),
            block_anchor: Some(BlockAnchor { block_hash, height }),
        })
        .await?;

    let body = publish_result_to_json(&result)?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

fn decode_hex32(s: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    decode_hex_exact(s, 32).map_err(|e| ApiError::malformed(format!("{field}: {e}")))
}

fn parse_u32_decimal(s: &str, field: &str) -> Result<u32, ApiError> {
    let v = parse_u64_decimal(s)
        .map_err(|e| ApiError::malformed(format!("{field}: {}", e.body.message)))?;
    u32::try_from(v).map_err(|_| {
        ApiError::malformed(format!(
            "{field} must fit in u32 (on-chain height range); got {v}"
        ))
    })
}

/// Map kernel `PublishResult` to the §7.6 JSON shape.
///
/// Presence invariants (fail-closed):
/// - `accepted == true`  ⇔  `batch_eta` present, `reason` absent
/// - `accepted == false` ⇔  `reason` present (closed), `batch_eta` absent
fn publish_result_to_json(result: &PublishResult) -> Result<Value, ApiError> {
    let mut obj = Map::new();
    obj.insert("accepted".into(), Value::Bool(result.accepted));

    if result.accepted {
        if result.reason.is_some() {
            return Err(ApiError::internal(
                "kernel PublishResult.accepted is true but reason is set",
            ));
        }
        let eta = match result.batch_eta {
            Some(v) => v,
            None => {
                return Err(ApiError::internal(
                    "kernel PublishResult.accepted is true but batch_eta is absent",
                ));
            }
        };
        // Decimal-string u64 — same JSON integer discipline as session_expiry.
        obj.insert("batch_eta".into(), Value::String(eta.to_string()));
    } else {
        if result.batch_eta.is_some() {
            return Err(ApiError::internal(
                "kernel PublishResult.accepted is false but batch_eta is set",
            ));
        }
        let reason = match &result.reason {
            Some(r) if !r.is_empty() => r.as_str(),
            Some(_) => {
                return Err(ApiError::internal(
                    "kernel PublishResult.accepted is false but reason is empty",
                ));
            }
            None => {
                return Err(ApiError::internal(
                    "kernel PublishResult.accepted is false but reason is absent",
                ));
            }
        };
        if !is_closed_reason(reason) {
            return Err(ApiError::internal(format!(
                "kernel PublishResult.reason {reason:?} is not in the §7.6 closed set"
            )));
        }
        obj.insert("reason".into(), Value::String(reason.to_string()));
    }

    Ok(Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_reason_set_matches_spec_count() {
        assert_eq!(PUBLISH_REJECT_REASONS.len(), 9);
        assert!(is_closed_reason("policy"));
        assert!(is_closed_reason("invalid_signature"));
        assert!(!is_closed_reason("not_a_reason"));
        assert!(!is_closed_reason(""));
    }

    #[test]
    fn accepted_result_json() {
        let r = PublishResult {
            accepted: true,
            reason: None,
            batch_eta: Some(30),
        };
        let json = publish_result_to_json(&r).unwrap();
        assert_eq!(json["accepted"], true);
        assert_eq!(json["batch_eta"], "30");
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn rejected_result_json() {
        let r = PublishResult {
            accepted: false,
            reason: Some("policy".into()),
            batch_eta: None,
        };
        let json = publish_result_to_json(&r).unwrap();
        assert_eq!(json["accepted"], false);
        assert_eq!(json["reason"], "policy");
        assert!(json.get("batch_eta").is_none());
    }

    #[test]
    fn accepted_with_reason_is_internal() {
        let r = PublishResult {
            accepted: true,
            reason: Some("policy".into()),
            batch_eta: Some(1),
        };
        let err = publish_result_to_json(&r).unwrap_err();
        assert_eq!(err.body.error, "internal_error");
    }

    #[test]
    fn rejected_with_unknown_reason_is_internal() {
        let r = PublishResult {
            accepted: false,
            reason: Some("invented".into()),
            batch_eta: None,
        };
        let err = publish_result_to_json(&r).unwrap_err();
        assert_eq!(err.body.error, "internal_error");
    }
}

//! View-grant REST surface (§7.5 L2895–L2896).
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/grants/challenge` | `OpenPullChallenge` action=`issue_grant` |
//! | `POST` | `/v1/grants` | `IssueViewGrant` (after OwnershipProof) |
//!
//! A GrantProof is rejected here (no-escalation). The kernel message has no
//! capability field — only the API edge can enforce this.

use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{GrantRequest, PullChallengeRequest, Scope};
use crate::ownership::{
    decode_zk_address, encode_grant_asset_ids, issue_grant_request_hash, parse_u64_decimal,
    verify_ownership_proof, ChallengeDomain, ChallengeEcho, OwnershipProofJson,
    ISSUE_GRANT_CHALLENGE_DOMAIN, SCOPE_NOT_AFTER_UNBOUNDED,
};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GrantsChallengeBody {
    pub subject: String,
}

#[derive(Debug, Deserialize)]
pub struct GrantScopeJson {
    /// Either the string `"*"` or an array of hex32 asset ids.
    pub asset_ids: Value,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IssueGrantBody {
    pub subject: String,
    pub grantee_pk: String,
    pub scope: GrantScopeJson,
    /// Grant-level expiry (§7.1 decimal-string u64) — bound into request_hash.
    pub expiry: String,
    pub challenge: ChallengeEcho,
    pub ownership_proof: OwnershipProofJson,
}

// ---------------------------------------------------------------------------
// Scope normalisation (§5.1 / §7.5)
// ---------------------------------------------------------------------------

struct NormalisedScope {
    all_assets: bool,
    asset_ids: Vec<[u8; 32]>,
    not_before: u64,
    not_after: u64,
}

/// Normalise REST scope to the single unbounded-sentinel pair **before**
/// `request_hash` and the kernel RPC (§5.1 L1918).
fn normalise_scope(scope: &GrantScopeJson) -> Result<NormalisedScope, ApiError> {
    let (all_assets, asset_ids) = match &scope.asset_ids {
        Value::String(s) if s == "*" => (true, Vec::new()),
        Value::String(s) => {
            return Err(ApiError::malformed(format!(
                "scope.asset_ids string must be \"*\", got {s:?}"
            )));
        }
        Value::Array(arr) => {
            let mut ids = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                let hex = v.as_str().ok_or_else(|| {
                    ApiError::malformed(format!("scope.asset_ids[{i}] must be a hex string"))
                })?;
                let raw = decode_hex_exact(hex, 32)
                    .map_err(|e| ApiError::malformed(format!("scope.asset_ids[{i}]: {e}")))?;
                let mut a = [0u8; 32];
                a.copy_from_slice(&raw);
                ids.push(a);
            }
            if ids.is_empty() {
                return Err(ApiError::malformed(
                    "scope.asset_ids list must be non-empty when not \"*\"",
                ));
            }
            (false, ids)
        }
        other => {
            return Err(ApiError::malformed(format!(
                "scope.asset_ids must be \"*\" or an array of hex32, got {other}"
            )));
        }
    };

    let not_before = match &scope.not_before {
        None => 0u64,
        Some(s) => parse_u64_decimal(s)
            .map_err(|e| ApiError::malformed(format!("scope.not_before: {}", e.body.message)))?,
    };
    let not_after = match &scope.not_after {
        None => SCOPE_NOT_AFTER_UNBOUNDED,
        Some(s) => parse_u64_decimal(s)
            .map_err(|e| ApiError::malformed(format!("scope.not_after: {}", e.body.message)))?,
    };

    Ok(NormalisedScope {
        all_assets,
        asset_ids,
        not_before,
        not_after,
    })
}

fn scope_to_proto(scope: &NormalisedScope) -> Scope {
    Scope {
        asset_ids: scope.asset_ids.iter().map(|a| a.to_vec()).collect(),
        all_assets: scope.all_assets,
        not_before: scope.not_before,
        not_after: scope.not_after,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/grants/challenge` → OpenPullChallenge(action=issue_grant).
pub async fn post_grants_challenge(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<GrantsChallengeBody>,
) -> Result<Response, ApiError> {
    if body.subject.is_empty() {
        return Err(ApiError::malformed("subject is required"));
    }
    let _ = decode_zk_address(&body.subject)?;

    let challenge = state
        .kernel
        .open_pull_challenge(PullChallengeRequest {
            subject: body.subject,
            requested_scope: None,
            action: "issue_grant".to_string(),
        })
        .await?;

    if challenge.nonce.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel Challenge.nonce must be 32 bytes, got {}",
            challenge.nonce.len()
        )));
    }
    if challenge.domain != ISSUE_GRANT_CHALLENGE_DOMAIN {
        return Err(ApiError::internal(format!(
            "kernel Challenge.domain must be {ISSUE_GRANT_CHALLENGE_DOMAIN:?}, got {:?}",
            challenge.domain
        )));
    }

    let body = json!({
        "nonce": encode_hex(&challenge.nonce),
        "expiry": challenge.expiry.to_string(),
        "domain": ISSUE_GRANT_CHALLENGE_DOMAIN,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /v1/grants` → verify OwnershipProof, then IssueViewGrant.
pub async fn post_grants(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<IssueGrantBody>,
) -> Result<Response, ApiError> {
    // ---- pure validation + OwnershipProof (no kernel) ----
    let subject_raw = decode_zk_address(&body.subject)?;
    let grantee_pk = {
        let v = decode_hex_exact(&body.grantee_pk, 32)
            .map_err(|e| ApiError::malformed(format!("grantee_pk: {e}")))?;
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };
    let grant_expiry = parse_u64_decimal(&body.expiry)
        .map_err(|e| ApiError::malformed(format!("expiry: {}", e.body.message)))?;
    let scope = normalise_scope(&body.scope)?;
    let asset_enc = encode_grant_asset_ids(scope.all_assets, &scope.asset_ids)?;

    // Server-computed request_hash — never a client-supplied hash field.
    let request_hash = issue_grant_request_hash(
        &subject_raw,
        &grantee_pk,
        &asset_enc,
        scope.not_before,
        scope.not_after,
        grant_expiry,
    );

    // Domain is the IssueGrant endpoint constant — not taken from body.
    let verified = verify_ownership_proof(
        ChallengeDomain::IssueGrant,
        &body.subject,
        &body.challenge,
        &body.ownership_proof,
        &request_hash,
        state.public_hosts.as_slice(),
    )?;

    // ---- only now: kernel (nonce consumption lives here) ----
    let result = state
        .kernel
        .issue_view_grant(GrantRequest {
            subject: verified.subject_bech32,
            grantee_pk: grantee_pk.to_vec(),
            scope: Some(scope_to_proto(&scope)),
            expiry: grant_expiry,
            nonce: verified.nonce.to_vec(),
            chan_bind: verified.chan_bind.to_vec(),
        })
        .await?;

    if result.grant.is_empty() {
        return Err(ApiError::internal(
            "kernel GrantResult.grant is empty on IssueViewGrant success",
        ));
    }
    let body = json!({ "grant": result.grant });
    Ok((StatusCode::OK, Json(body)).into_response())
}

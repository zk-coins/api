//! Capability-gated pull REST surface (§7.5 L3039–L3043).
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/pull/challenge` | `OpenPullChallenge` action=`pull` |
//! | `POST` | `/v1/pull` | `Pull` (after OwnershipProof; GrantProof rejected) |
//! | `GET`  | `/v1/record/<record_id>` | `GetRecord` |
//! | `GET`  | `/v1/proof/<coin_id>` | `GetCoinProof` |
//! | `GET`  | `/v1/account/state` | `GetAccountState` (ownership session only) |
//!
//! The API holds **no** session store: the bearer token is forwarded to the
//! kernel. Session authority is taken solely from the verified proof kind and
//! sent as interim metadata `x-zkcoins-session-authority` (never defaulted).

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{
    AccountStateRequest, AccountStateResult, CoinProofBlob, CoinProofRequest, PullChallengeRequest,
    PullRequest, PullResult as ProtoPullResult, RecordBlob, RecordRef, RecordRequest, Scope,
};
use crate::ownership::{
    chan_bind_for_host, decode_zk_address, parse_u64_decimal, reject_grant_proof,
    verify_pull_ownership_proof, GrantProofJson, OwnershipProofJson, SessionAuthority,
    PULL_CHALLENGE_DOMAIN, SCOPE_NOT_AFTER_UNBOUNDED,
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PullChallengeBody {
    pub subject: String,
    #[serde(default)]
    pub scope: Option<PullScopeJson>,
}

#[derive(Debug, Deserialize)]
pub struct PullScopeJson {
    /// Either the string `"*"` or an array of hex32 asset ids.
    pub asset_ids: Value,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

/// Redeem body: top-level `{ nonce, expiry, proof }` (Redeem-body `expiry`
/// normative — not nested under `challenge`).
#[derive(Debug, Deserialize)]
pub struct PullBody {
    pub nonce: String,
    /// Challenge expiry echoed from issuance (bound into signed `chal`; not
    /// trusted as a clock source — a forged value fails BIP-340).
    pub expiry: String,
    pub proof: PullProofJson,
}

/// Closed proof discriminator for `POST /v1/pull`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum PullProofJson {
    #[serde(rename = "ownership")]
    Ownership {
        subject: String,
        public_key: String,
        nk_commit: String,
        signature: String,
    },
    #[serde(rename = "grant")]
    Grant {
        grant: String,
        grantee_pk: String,
        signature: String,
    },
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

/// Unbounded scope: `asset_ids = "*"`, `not_before = 0`, `not_after = 2⁶³−1`.
fn unbounded_scope() -> NormalisedScope {
    NormalisedScope {
        all_assets: true,
        asset_ids: Vec::new(),
        not_before: 0,
        not_after: SCOPE_NOT_AFTER_UNBOUNDED,
    }
}

/// Normalise REST scope to the single unbounded-sentinel pair **before**
/// the kernel RPC (§5.1 L1918).
fn normalise_scope(scope: &PullScopeJson) -> Result<NormalisedScope, ApiError> {
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
// Closed wire vocabularies (§7.5 PullResult)
// ---------------------------------------------------------------------------

fn map_record_type(raw: &str) -> Result<&'static str, ApiError> {
    match raw {
        "coinproof" => Ok("coinproof"),
        "self_delivery" => Ok("self_delivery"),
        other => Err(ApiError::internal(format!(
            "kernel RecordRef.record_type is outside the closed set \
             (\"coinproof\"|\"self_delivery\"): {other:?}"
        ))),
    }
}

/// Map optional `transition_kind`. Empty string means absent (coinproof).
/// Required non-empty for `self_delivery`.
fn map_transition_kind(raw: &str, record_type: &str) -> Result<Option<&'static str>, ApiError> {
    if raw.is_empty() {
        if record_type == "self_delivery" {
            return Err(ApiError::internal(
                "kernel RecordRef.transition_kind is required for record_type=self_delivery",
            ));
        }
        return Ok(None);
    }
    match raw {
        "mint" => Ok(Some("mint")),
        "send" => Ok(Some("send")),
        "receive" => Ok(Some("receive")),
        other => Err(ApiError::internal(format!(
            "kernel RecordRef.transition_kind is outside the closed set \
             (\"mint\"|\"send\"|\"receive\"): {other:?}"
        ))),
    }
}

fn record_ref_to_json(r: &RecordRef) -> Result<Value, ApiError> {
    if r.record_id.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel RecordRef.record_id must be 32 bytes, got {}",
            r.record_id.len()
        )));
    }
    if r.blob_id.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel RecordRef.blob_id must be 32 bytes, got {}",
            r.blob_id.len()
        )));
    }
    let record_type = map_record_type(&r.record_type)?;
    let transition_kind = map_transition_kind(&r.transition_kind, record_type)?;

    let mut obj = serde_json::Map::new();
    obj.insert("record_id".into(), Value::String(encode_hex(&r.record_id)));
    obj.insert("record_type".into(), Value::String(record_type.to_string()));
    if let Some(kind) = transition_kind {
        obj.insert("transition_kind".into(), Value::String(kind.to_string()));
    }
    obj.insert("blob_id".into(), Value::String(encode_hex(&r.blob_id)));
    obj.insert(
        "occurred_at".into(),
        Value::String(r.occurred_at.to_string()),
    );
    Ok(Value::Object(obj))
}

// ---------------------------------------------------------------------------
// Session / bearer helpers
// ---------------------------------------------------------------------------

/// Extract `Authorization: Bearer <token>`.
///
/// Missing or malformed → `401 unauthorized` (§7.5: never collapse into
/// `session_expired` / 410).
fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(ApiError::unauthorized(
            "missing Authorization bearer token for pull session",
        ));
    };
    let s = value
        .to_str()
        .map_err(|_| ApiError::unauthorized("Authorization header is not valid UTF-8"))?;
    let Some(token) = s.strip_prefix("Bearer ") else {
        return Err(ApiError::unauthorized(
            "Authorization must be \"Bearer <token>\"",
        ));
    };
    if token.is_empty() {
        return Err(ApiError::unauthorized("bearer token is empty"));
    }
    // Whitespace or control characters are not a node-issued credential shape.
    if token.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20) {
        return Err(ApiError::unauthorized(
            "bearer token is malformed (whitespace or control bytes)",
        ));
    }
    Ok(token.to_string())
}

/// Authoritative `chan_bind` for session-bound follow-ups.
///
/// Exactly one configured public host is required: with several hosts the API
/// cannot re-select the original binding without reading the request `Host`
/// (forbidden by §5.1 / §7.8). Multi-host session routing is a documented GAP.
fn session_chan_bind(public_hosts: &[String]) -> Result<[u8; 32], ApiError> {
    match public_hosts {
        [] => Err(ApiError::internal(
            "no authoritative public hosts configured for chan_bind (ZKCOINS_PUBLIC_HOST)",
        )),
        [only] => Ok(chan_bind_for_host(only)),
        _ => Err(ApiError::internal(
            "session channel binding requires exactly one ZKCOINS_PUBLIC_HOST \
             in this stage (multi-host re-bind would need a trusted SNI path, \
             not the client Host header)",
        )),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/pull/challenge` → OpenPullChallenge(action=pull).
pub async fn post_pull_challenge(
    State(state): State<AppState>,
    Json(body): Json<PullChallengeBody>,
) -> Result<Response, ApiError> {
    if body.subject.is_empty() {
        return Err(ApiError::malformed("subject is required"));
    }
    let _ = decode_zk_address(&body.subject)?;

    let requested_scope = match &body.scope {
        None => None,
        Some(s) => Some(scope_to_proto(&normalise_scope(s)?)),
    };

    let challenge = state
        .kernel
        .open_pull_challenge(PullChallengeRequest {
            subject: body.subject,
            requested_scope,
            action: "pull".to_string(),
        })
        .await?;

    if challenge.nonce.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel Challenge.nonce must be 32 bytes, got {}",
            challenge.nonce.len()
        )));
    }
    if challenge.domain != PULL_CHALLENGE_DOMAIN {
        return Err(ApiError::internal(format!(
            "kernel Challenge.domain must be {PULL_CHALLENGE_DOMAIN:?}, got {:?}",
            challenge.domain
        )));
    }

    let body = json!({
        "nonce": encode_hex(&challenge.nonce),
        "expiry": challenge.expiry.to_string(),
        "domain": PULL_CHALLENGE_DOMAIN,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /v1/pull` → verify proof, then `Pull`.
///
/// OwnershipProof is verified pure (no kernel) so a bad signature cannot
/// consume the single-use nonce. GrantProof is rejected fail-closed (no
/// op_pubkey lookup — see [`reject_grant_proof`]).
pub async fn post_pull(
    State(state): State<AppState>,
    Json(body): Json<PullBody>,
) -> Result<Response, ApiError> {
    // ---- pure validation + capability gate (no kernel) ----
    let (verified, authority) = match body.proof {
        PullProofJson::Ownership {
            subject,
            public_key,
            nk_commit,
            signature,
        } => {
            let proof = OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject.clone(),
                public_key,
                nk_commit,
                signature,
            };
            let v = verify_pull_ownership_proof(
                &subject,
                &body.nonce,
                &body.expiry,
                &proof,
                state.public_hosts.as_slice(),
            )?;
            (v, SessionAuthority::Ownership)
        }
        PullProofJson::Grant {
            grant,
            grantee_pk,
            signature,
        } => {
            let proof = GrantProofJson {
                proof_type: "grant".into(),
                grant,
                grantee_pk,
                signature,
            };
            // Structural fail-closed: never half-check a grant.
            return Err(reject_grant_proof(&proof));
        }
    };

    // Ownership authorises the full account; resolved scope is the unbounded
    // sentinel pair. A narrower scope requested at challenge time is enforced
    // by the kernel (`resolved ⊆ requested`). Clients that open a narrow
    // challenge and then pull with unbounded resolved_scope get
    // `scope_exceeded` from the kernel — fail-closed, not silently widened.
    // GAP: a stateless API cannot recompute the exact requested scope without
    // a challenge store or a client re-echo of scope on redeem.
    let resolved = unbounded_scope();

    // ---- only now: kernel (nonce consumption lives here) ----
    let result: ProtoPullResult = state
        .kernel
        .pull(
            PullRequest {
                nonce: verified.nonce.to_vec(),
                subject: verified.subject_bech32,
                resolved_scope: Some(scope_to_proto(&resolved)),
                chan_bind: verified.chan_bind.to_vec(),
            },
            authority,
        )
        .await?;

    if result.session.is_empty() {
        return Err(ApiError::internal(
            "kernel PullResult.session is empty on Pull success",
        ));
    }

    let mut records = Vec::with_capacity(result.records.len());
    for r in &result.records {
        records.push(record_ref_to_json(r)?);
    }

    let body = json!({
        "records": records,
        "session": result.session,
        "session_expiry": result.session_expiry.to_string(),
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `GET /v1/record/<record_id>` → canonical binary (§7.5 L3041).
///
/// Content-Type: `application/octet-stream` (same binary transport class as
/// §7.4 Blossom; §7.5 names the body as canonical §7.1 bytes, not JSON).
pub async fn get_record(
    State(state): State<AppState>,
    Path(record_id_hex): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = bearer_token(&headers)?;
    let chan_bind = session_chan_bind(state.public_hosts.as_slice())?;
    let record_id = decode_hex_exact(&record_id_hex, 32)
        .map_err(|e| ApiError::malformed(format!("record_id: {e}")))?;

    let blob: RecordBlob = state
        .kernel
        .get_record(RecordRequest {
            record_id,
            session,
            chan_bind: chan_bind.to_vec(),
        })
        .await?;

    // Validate closed type metadata from the kernel even though the REST
    // response is raw bytes only — an unknown type must not be released.
    let record_type = map_record_type(&blob.record_type)?;
    let _ = map_transition_kind(&blob.transition_kind, record_type)?;

    if blob.canonical.is_empty() {
        return Err(ApiError::internal(
            "kernel RecordBlob.canonical is empty on GetRecord success",
        ));
    }

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        blob.canonical,
    )
        .into_response())
}

/// `GET /v1/proof/<coin_id>` → canonical CoinProof bytes (§7.5 L3042).
pub async fn get_proof(
    State(state): State<AppState>,
    Path(coin_id_hex): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = bearer_token(&headers)?;
    let chan_bind = session_chan_bind(state.public_hosts.as_slice())?;
    let coin_id = decode_hex_exact(&coin_id_hex, 32)
        .map_err(|e| ApiError::malformed(format!("coin_id: {e}")))?;

    let blob: CoinProofBlob = state
        .kernel
        .get_coin_proof(CoinProofRequest {
            coin_id,
            session,
            chan_bind: chan_bind.to_vec(),
        })
        .await?;

    if blob.canonical.is_empty() {
        return Err(ApiError::internal(
            "kernel CoinProofBlob.canonical is empty on GetCoinProof success",
        ));
    }

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        blob.canonical,
    )
        .into_response())
}

/// `GET /v1/account/state` → ownership-only account head (§7.5 L3043).
///
/// Consistency of `send_counter` / `current_pubkey` with the bytes inside
/// `account_state` is a **kernel** guarantee (proto comments / §7.8); the
/// API does not re-parse or recompute those fields.
pub async fn get_account_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = bearer_token(&headers)?;
    let chan_bind = session_chan_bind(state.public_hosts.as_slice())?;

    let view: AccountStateResult = state
        .kernel
        .get_account_state(AccountStateRequest {
            session,
            chan_bind: chan_bind.to_vec(),
        })
        .await?;

    if view.account_state.is_empty() {
        return Err(ApiError::internal(
            "kernel AccountStateResult.account_state is empty on success",
        ));
    }
    if view.state_head.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel AccountStateResult.state_head must be 32 bytes, got {}",
            view.state_head.len()
        )));
    }
    if view.current_pubkey.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel AccountStateResult.current_pubkey must be 32 bytes, got {}",
            view.current_pubkey.len()
        )));
    }
    // Optional head_record_id: empty = absent; otherwise exactly 32.
    if !view.head_record_id.is_empty() && view.head_record_id.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel AccountStateResult.head_record_id must be empty or 32 bytes, got {}",
            view.head_record_id.len()
        )));
    }
    // last_nullifier: both present (32B each) or both empty.
    let last_nullifier = match (
        view.last_nullifier_pk.is_empty(),
        view.last_nullifier_r.is_empty(),
    ) {
        (true, true) => None,
        (false, false) => {
            if view.last_nullifier_pk.len() != 32 || view.last_nullifier_r.len() != 32 {
                return Err(ApiError::internal(format!(
                    "kernel last_nullifier fields must be 32 bytes each when present \
                     (pk={}, r={})",
                    view.last_nullifier_pk.len(),
                    view.last_nullifier_r.len()
                )));
            }
            Some(json!({
                "pubkey": encode_hex(&view.last_nullifier_pk),
                "r": encode_hex(&view.last_nullifier_r),
            }))
        }
        _ => {
            return Err(ApiError::internal(
                "kernel last_nullifier_pk and last_nullifier_r must both be present or both empty",
            ));
        }
    };

    let mut body = serde_json::Map::new();
    body.insert(
        "account_state".into(),
        Value::String(encode_hex(&view.account_state)),
    );
    body.insert(
        "state_head".into(),
        Value::String(encode_hex(&view.state_head)),
    );
    if !view.head_record_id.is_empty() {
        body.insert(
            "head_record_id".into(),
            Value::String(encode_hex(&view.head_record_id)),
        );
    }
    body.insert(
        "send_counter".into(),
        Value::String(view.send_counter.to_string()),
    );
    body.insert(
        "current_pubkey".into(),
        Value::String(encode_hex(&view.current_pubkey)),
    );
    if let Some(nf) = last_nullifier {
        body.insert("last_nullifier".into(), nf);
    }

    Ok((StatusCode::OK, Json(Value::Object(body))).into_response())
}

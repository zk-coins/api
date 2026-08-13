//! Capability-gated pull REST surface (§7.5 L3039–L3044).
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/pull/challenge` | `OpenPullChallenge` action=`pull` |
//! | `POST` | `/v1/pull` | `Pull` (after OwnershipProof **or** GrantProof) |
//! | `GET`  | `/v1/record/<record_id>` | `GetRecord` |
//! | `GET`  | `/v1/proof/<coin_id>` | `GetCoinProof` |
//! | `GET`  | `/v1/account/state` | `GetAccountState` (ownership session only) |
//! | `GET`  | `/v1/receipts/stream` | `SubscribeReceipts` (ownership **or** grant session) |
//!
//! The API holds **no** session store: the bearer token is forwarded to the
//! kernel. Session authority is taken solely from the verified proof kind and
//! sent as interim metadata `x-zkcoins-session-authority` (never defaulted).
//! The **resolved (intersected) scope** is computed here and sent on `Pull`;
//! the kernel records it into the session and never widens it.
//!
//! `GET /v1/receipts/stream` admits **any** still-valid ownership **or** grant
//! pull session (§7.5 L2953) — unlike `GET /v1/account/state`, which is
//! ownership-only. Subject and resolved scope come from server-side session
//! state; the request carries no `subject` field.

use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{
    AccountStateRequest, AccountStateResult, CoinProofBlob, CoinProofRequest, PullChallengeRequest,
    PullRequest, PullResult as ProtoPullResult, Receipt, RecordBlob, RecordRef, RecordRequest,
    Scope, SubscribeReceiptsRequest,
};
use crate::ownership::{
    chan_bind_for_host, decode_zk_address, parse_u64_decimal, validate_resolved_scope,
    verify_grant_proof, verify_pull_ownership_proof, GrantProofJson, GrantVerificationContext,
    OwnershipProofJson, ResolvedScope, SessionAuthority, PULL_CHALLENGE_DOMAIN,
    SCOPE_NOT_AFTER_UNBOUNDED,
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::Stream;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullChallengeBody {
    pub subject: String,
    #[serde(default)]
    pub scope: Option<PullScopeJson>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullScopeJson {
    /// Either the string `"*"` or an array of hex32 asset ids.
    pub asset_ids: Value,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

/// Redeem body: top-level `{ nonce, expiry, proof, scope? }`.
///
/// Redeem-body `expiry` is normative (bound into signed `chal`). Optional
/// `scope` re-echoes the requested scope so a **stateless** API edge can
/// compute `requested ∩ capability` without a challenge store (§5.1). Omitted
/// scope normalises to the unbounded sentinel pair before intersection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullBody {
    pub nonce: String,
    /// Challenge expiry echoed from issuance (bound into signed `chal`; not
    /// trusted as a clock source — a forged value fails BIP-340).
    pub expiry: String,
    pub proof: PullProofJson,
    /// Requested scope re-echo (same shape as challenge). Omitted ⇒ unbounded.
    #[serde(default)]
    pub scope: Option<PullScopeJson>,
}

/// Closed proof discriminator for `POST /v1/pull`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
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

/// Normalise REST scope to the single unbounded-sentinel pair **before**
/// the kernel RPC and any scope intersection (§5.1 L1918).
fn normalise_scope(scope: &PullScopeJson) -> Result<ResolvedScope, ApiError> {
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

    let resolved = ResolvedScope {
        all_assets,
        asset_ids,
        not_before,
        not_after,
    };
    // Canonical form before any Challenge/Redeem kernel RPC: strictly
    // ascending unique asset ids; non-empty time interval.
    validate_resolved_scope(&resolved)?;
    Ok(resolved)
}

fn scope_to_proto(scope: &ResolvedScope) -> Scope {
    Scope {
        asset_ids: scope.asset_ids.iter().map(|a| a.to_vec()).collect(),
        all_assets: scope.all_assets,
        not_before: scope.not_before,
        not_after: scope.not_after,
    }
}

fn unix_now() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ApiError::internal("system clock is before Unix epoch"))
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
/// # Single host (this stage)
///
/// Exactly one configured public host is required here. Proof verification on
/// `POST /v1/pull` already accepts **any** of the configured hosts (try each
/// `chan_bind` until BIP-340 verifies — §5.1). Session follow-ups are different:
/// the session record stores **one** `chan_bind` from the accepting proof, and
/// the API must recompute that same value for the current connection so the
/// kernel can equality-check it.
///
/// # Why multi-host is refused (not silently left open)
///
/// Spec §5.1 forbids deriving `host` from attacker-influenceable request
/// metadata such as a forwarded `Host` header. With several authoritative
/// names the API therefore cannot know which host the client dialed on this
/// TCP/TLS connection without a **trusted** side channel (e.g. TLS SNI as
/// observed by a co-located terminator, or a single front-end name). Until
/// that path exists, multi-host session re-bind fails closed with 500 rather
/// than guessing — guessing would either reject legitimate clients or accept
/// a captured token against the wrong name.
///
/// What would close the GAP: a trusted connection-identity input (SNI /
/// local socket metadata) that selects exactly one entry of
/// `ZKCOINS_PUBLIC_HOST` per request, still never the client `Host` header.
fn session_chan_bind(public_hosts: &[String]) -> Result<[u8; 32], ApiError> {
    match public_hosts {
        [] => Err(ApiError::internal(
            "no authoritative public hosts configured for chan_bind (ZKCOINS_PUBLIC_HOST)",
        )),
        [only] => Ok(chan_bind_for_host(only)),
        _ => Err(ApiError::internal(
            "session channel binding requires exactly one ZKCOINS_PUBLIC_HOST: \
             multi-host re-bind needs a trusted SNI/connection-identity path \
             (not the client Host header; §5.1). Proof verification already \
             accepts any configured host; only follow-up session routes are restricted",
        )),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/pull/challenge` → OpenPullChallenge(action=pull).
pub async fn post_pull_challenge(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<PullChallengeBody>,
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
/// OwnershipProof and GrantProof are verified **pure** (no kernel) so a bad
/// signature cannot consume the single-use nonce. The resolved scope passed
/// to the kernel is exactly what the capability authorises after intersection
/// with the requested scope — never widened, never defaulted to unbounded
/// under a scoped grant.
pub async fn post_pull(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<PullBody>,
) -> Result<Response, ApiError> {
    // Requested scope: re-echo on redeem, or unbounded sentinels when omitted.
    let requested_scope = match &body.scope {
        None => ResolvedScope::unbounded(),
        Some(s) => normalise_scope(s)?,
    };

    // ---- pure validation + capability gate (no kernel) ----
    let (subject_bech32, nonce, chan_bind, resolved, authority) = match body.proof {
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
            // Ownership authorises the full account: resolved = requested
            // (requester may narrow; omitted/`*` ⇒ whole account). §5.1(a).
            (
                v.subject_bech32,
                v.nonce,
                v.chan_bind,
                requested_scope,
                SessionAuthority::Ownership,
            )
        }
        PullProofJson::Grant {
            grant,
            grantee_pk,
            signature,
        } => {
            let proof = GrantProofJson {
                proof_type: "grant".into(),
                grant: grant.clone(),
                grantee_pk,
                signature,
            };
            // Decode first so we know which subject's published op to load.
            let decoded = crate::ownership::decode_view_grant(&grant)?;
            let op_pubkey = match state.subject_ops.get(&decoded.subject) {
                Some(pk) => pk,
                None => {
                    return Err(ApiError::unauthorized(
                        "GrantProof rejected: subject's published op_pubkey is not available \
                         (Nostr kind-30420 profile resolution with §4.3 address binding is \
                         not wired; subject_ops directory has no entry). Half-checked grants \
                         are forbidden (§5.1(b) step 1)",
                    ));
                }
            };
            let now = unix_now()?;
            let v = verify_grant_proof(
                &body.nonce,
                &body.expiry,
                &proof,
                &op_pubkey,
                &requested_scope,
                &GrantVerificationContext {
                    public_hosts: state.public_hosts.as_slice(),
                    now,
                    revoked: state.revoked_grants.as_ref(),
                },
            )?;
            // Fail-closed belt: a grant session must never carry a fully
            // unbounded scope when the grant itself was scoped.
            if v.resolved_scope.is_fully_unbounded() && !v.grant_scope.is_fully_unbounded() {
                return Err(ApiError::internal(
                    "grant resolved_scope is fully unbounded while grant.scope is not — refuse",
                ));
            }
            (
                v.subject_bech32,
                v.nonce,
                v.chan_bind,
                v.resolved_scope,
                SessionAuthority::Grant,
            )
        }
    };

    // ---- only now: kernel (nonce consumption lives here) ----
    let result: ProtoPullResult = state
        .kernel
        .pull(
            PullRequest {
                nonce: nonce.to_vec(),
                subject: subject_bech32,
                resolved_scope: Some(scope_to_proto(&resolved)),
                chan_bind: chan_bind.to_vec(),
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
        Value::Number(view.send_counter.into()),
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

/// `GET /v1/receipts/stream` → `SubscribeReceipts` as SSE (§7.5 L2953–L2955).
///
/// Auth split (fail-closed, same as `GET /v1/proof/<coin_id>`):
/// - missing / malformed bearer → `401 unauthorized` (API edge, no kernel)
/// - unknown / expired / `chan_bind`-mismatch session → `410 session_expired`
///   (kernel `ErrorInfo`, before the SSE upgrade)
///
/// Ownership **or** grant sessions are both admissible. Subject and resolved
/// scope are **not** taken from the request — the kernel looks them up from
/// the session record. No recovery buffer, no sequence numbers: reconnect and
/// catch-up via ordinary pull are client-side (§4.9).
///
/// Pattern matches `GET /v1/jobs/<job_id>/stream`: handshake errors return as
/// HTTP status + JSON; only a successful kernel stream becomes
/// `text/event-stream`. Dropping the SSE consumer drops the gRPC stream and
/// ends the subscription.
pub async fn stream_receipts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>> + Send + 'static>, ApiError> {
    let session = bearer_token(&headers)?;
    let chan_bind = session_chan_bind(state.public_hosts.as_slice())?;

    // Await the kernel stream handshake first. On `Err`, axum maps `ApiError`
    // to a normal HTTP response (status + JSON body) and never enters SSE.
    let stream = state
        .kernel
        .subscribe_receipts(SubscribeReceiptsRequest {
            session,
            chan_bind: chan_bind.to_vec(),
        })
        .await?;

    let sse_stream = receipt_event_sse_stream(stream);
    Ok(Sse::new(sse_stream).keep_alive(KeepAlive::default()))
}

// ---------------------------------------------------------------------------
// Receipts SSE
// ---------------------------------------------------------------------------

fn receipt_event_sse_stream<S>(stream: S) -> impl Stream<Item = Result<Event, Infallible>> + Send
where
    S: Stream<Item = Result<Receipt, ApiError>> + Send + 'static,
{
    // Map each kernel receipt to one SSE frame. On stream break, emit a single
    // recognizable `error` frame then end — never hang open with silence.
    // Clean end (`None`) closes without a terminal frame (open-ended push).
    //
    // Dropping this unfold (client disconnect) drops `stream`, which drops the
    // tonic gRPC subscription — same cleanup pattern as the job stream.
    futures_util::stream::unfold((Box::pin(stream), false), |(mut stream, done)| async move {
        if done {
            return None;
        }
        match stream.next().await {
            None => None,
            Some(Ok(receipt)) => match receipt_to_sse(&receipt) {
                Ok(frame) => Some((Ok(frame), (stream, false))),
                Err(api_err) => {
                    let frame = receipt_stream_break_event(&api_err);
                    Some((Ok(frame), (stream, true)))
                }
            },
            Some(Err(api_err)) => {
                let frame = receipt_stream_break_event(&api_err);
                Some((Ok(frame), (stream, true)))
            }
        }
    })
}

fn receipt_stream_break_event(err: &ApiError) -> Event {
    let data = json!({
        "error": err.body.error,
        "message": err.body.message,
    });
    Event::default().event("error").data(data.to_string())
}

fn receipt_to_sse(r: &Receipt) -> Result<Event, ApiError> {
    let data = receipt_to_json(r)?;
    Ok(Event::default().event("receipt").data(data.to_string()))
}

/// §7.8 `Receipt` as public JSON: hex32 digests, decimal strings for
/// `amount` / `credited_at` (§7.1).
fn receipt_to_json(r: &Receipt) -> Result<Value, ApiError> {
    if r.coin_id.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel Receipt.coin_id must be 32 bytes, got {}",
            r.coin_id.len()
        )));
    }
    if r.asset_id.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel Receipt.asset_id must be 32 bytes, got {}",
            r.asset_id.len()
        )));
    }
    if r.amount.is_empty() {
        return Err(ApiError::internal(
            "kernel Receipt.amount is empty on SubscribeReceipts success",
        ));
    }
    if r.state.is_empty() {
        return Err(ApiError::internal(
            "kernel Receipt.state is empty on SubscribeReceipts success",
        ));
    }
    Ok(json!({
        "coin_id": encode_hex(&r.coin_id),
        "asset_id": encode_hex(&r.asset_id),
        "amount": r.amount,
        "state": r.state,
        "credited_at": r.credited_at.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use serde_json::{json, Value};

    fn hex32(byte: u8) -> String {
        crate::hexutil::encode_hex(&[byte; 32])
    }

    fn scope(asset_ids: Value, not_before: Option<&str>, not_after: Option<&str>) -> PullScopeJson {
        PullScopeJson {
            asset_ids,
            not_before: not_before.map(str::to_string),
            not_after: not_after.map(str::to_string),
        }
    }

    fn assert_malformed(err: &ApiError) {
        assert_eq!(err.body.error, "malformed_request");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    fn assert_internal(err: &ApiError) {
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn assert_unauthorized(err: &ApiError) {
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_ne!(err.status, StatusCode::GONE);
    }

    fn sample_record_ref(record_type: &str, transition_kind: &str) -> RecordRef {
        RecordRef {
            record_id: vec![0x11u8; 32],
            record_type: record_type.into(),
            transition_kind: transition_kind.into(),
            blob_id: vec![0x22u8; 32],
            occurred_at: 1_700_000_000,
        }
    }

    fn sample_receipt(coin_byte: u8, amount: &str, state: &str, credited_at: u64) -> Receipt {
        Receipt {
            coin_id: vec![coin_byte; 32],
            asset_id: vec![0xABu8; 32],
            amount: amount.to_string(),
            state: state.into(),
            credited_at,
        }
    }

    // -----------------------------------------------------------------------
    // normalise_scope
    // -----------------------------------------------------------------------

    #[test]
    fn normalise_scope_star_is_all_assets_empty_ids() {
        let resolved = normalise_scope(&scope(json!("*"), None, None)).expect("star");
        assert!(resolved.all_assets);
        assert!(resolved.asset_ids.is_empty());
    }

    #[test]
    fn normalise_scope_non_star_string_is_malformed() {
        let err = normalise_scope(&scope(json!("foo"), None, None)).expect_err("non-star string");
        assert_malformed(&err);
    }

    #[test]
    fn normalise_scope_empty_array_is_malformed() {
        let err = normalise_scope(&scope(json!([]), None, None)).expect_err("empty array");
        assert_malformed(&err);
    }

    #[test]
    fn normalise_scope_non_string_array_element_is_malformed() {
        let err = normalise_scope(&scope(json!([1]), None, None)).expect_err("numeric element");
        assert_malformed(&err);
        let err = normalise_scope(&scope(json!([null]), None, None)).expect_err("null element");
        assert_malformed(&err);
    }

    #[test]
    fn normalise_scope_non_hex32_element_is_malformed() {
        let err = normalise_scope(&scope(json!(["zz"]), None, None)).expect_err("non-hex");
        assert_malformed(&err);
        let short = crate::hexutil::encode_hex(&[0xABu8; 16]);
        let err = normalise_scope(&scope(json!([short]), None, None)).expect_err("16-byte hex");
        assert_malformed(&err);
    }

    #[test]
    fn normalise_scope_number_or_object_asset_ids_is_malformed() {
        let err = normalise_scope(&scope(json!(1), None, None)).expect_err("number");
        assert_malformed(&err);
        let err = normalise_scope(&scope(json!({}), None, None)).expect_err("object");
        assert_malformed(&err);
    }

    /// Unsorted ids stay malformed: validate_resolved_scope does not sort.
    #[test]
    fn normalise_scope_unsorted_hex32_pair_is_malformed() {
        let err = normalise_scope(&scope(json!([hex32(0x02), hex32(0x01)]), None, None))
            .expect_err("descending pair must stay malformed");
        assert_malformed(&err);
    }

    #[test]
    fn normalise_scope_ascending_unique_hex32_pair_is_ok() {
        let resolved = normalise_scope(&scope(json!([hex32(0x01), hex32(0x02)]), None, None))
            .expect("ascending pair");
        assert!(!resolved.all_assets);
        assert_eq!(resolved.asset_ids, vec![[0x01u8; 32], [0x02u8; 32]]);
    }

    #[test]
    fn normalise_scope_absent_bounds_are_sentinels() {
        let resolved = normalise_scope(&scope(json!("*"), None, None)).expect("sentinels");
        assert_eq!(resolved.not_before, 0);
        assert_eq!(resolved.not_after, SCOPE_NOT_AFTER_UNBOUNDED);
    }

    #[test]
    fn normalise_scope_non_decimal_bounds_are_malformed() {
        let err = normalise_scope(&scope(json!("*"), Some("abc"), None))
            .expect_err("non-decimal not_before");
        assert_malformed(&err);
        let err =
            normalise_scope(&scope(json!("*"), None, Some("-1"))).expect_err("negative not_after");
        assert_malformed(&err);
        let err = normalise_scope(&scope(json!("*"), Some("1.5"), None))
            .expect_err("fractional not_before");
        assert_malformed(&err);
        let err = normalise_scope(&scope(json!("*"), None, Some(""))).expect_err("empty not_after");
        assert_malformed(&err);
    }

    #[test]
    fn normalise_scope_empty_interval_is_malformed_without_swap() {
        let err = normalise_scope(&scope(json!("*"), Some("100"), Some("50")))
            .expect_err("not_before > not_after must not swap");
        assert_malformed(&err);
    }

    // -----------------------------------------------------------------------
    // map_record_type / map_transition_kind / record_ref_to_json
    // -----------------------------------------------------------------------

    #[test]
    fn map_record_type_coinproof_ok() {
        assert_eq!(
            map_record_type("coinproof").expect("coinproof"),
            "coinproof"
        );
    }

    #[test]
    fn map_record_type_self_delivery_ok() {
        assert_eq!(
            map_record_type("self_delivery").expect("self_delivery"),
            "self_delivery"
        );
    }

    #[test]
    fn map_record_type_unknown_is_internal_not_malformed() {
        let err = map_record_type("invoice").expect_err("unknown type");
        assert_internal(&err);
        assert_ne!(err.body.error, "malformed_request");
    }

    #[test]
    fn map_transition_kind_empty_coinproof_is_none() {
        let kind = map_transition_kind("", "coinproof").expect("empty coinproof");
        assert_eq!(kind, None);
    }

    #[test]
    fn map_transition_kind_empty_self_delivery_is_internal() {
        let err = map_transition_kind("", "self_delivery").expect_err("required kind");
        assert_internal(&err);
    }

    #[test]
    fn map_transition_kind_mint_send_receive_ok() {
        assert_eq!(
            map_transition_kind("mint", "self_delivery").expect("mint"),
            Some("mint")
        );
        assert_eq!(
            map_transition_kind("send", "self_delivery").expect("send"),
            Some("send")
        );
        assert_eq!(
            map_transition_kind("receive", "coinproof").expect("receive"),
            Some("receive")
        );
    }

    #[test]
    fn map_transition_kind_unknown_nonempty_is_internal() {
        let err = map_transition_kind("burn", "coinproof").expect_err("unknown kind");
        assert_internal(&err);
    }

    #[test]
    fn record_ref_to_json_rejects_record_id_not_32() {
        let mut r = sample_record_ref("coinproof", "");
        r.record_id = vec![0x11u8; 16];
        let err = record_ref_to_json(&r).expect_err("short record_id");
        assert_internal(&err);
    }

    #[test]
    fn record_ref_to_json_rejects_blob_id_not_32() {
        let mut r = sample_record_ref("coinproof", "");
        r.blob_id = vec![0x22u8; 16];
        let err = record_ref_to_json(&r).expect_err("short blob_id");
        assert_internal(&err);
    }

    #[test]
    fn record_ref_to_json_coinproof_omits_transition_kind() {
        let r = sample_record_ref("coinproof", "");
        let json = record_ref_to_json(&r).expect("coinproof json");
        assert_eq!(json["record_id"], hex32(0x11));
        assert_eq!(json["record_type"], "coinproof");
        assert_eq!(json["blob_id"], hex32(0x22));
        assert_eq!(json["occurred_at"], "1700000000");
        assert!(json.get("transition_kind").is_none());
    }

    #[test]
    fn record_ref_to_json_self_delivery_includes_transition_kind() {
        let r = sample_record_ref("self_delivery", "mint");
        let json = record_ref_to_json(&r).expect("self_delivery json");
        assert_eq!(json["record_type"], "self_delivery");
        assert_eq!(json["transition_kind"], "mint");
        assert_eq!(json["record_id"], hex32(0x11));
        assert_eq!(json["blob_id"], hex32(0x22));
    }

    // -----------------------------------------------------------------------
    // bearer_token
    // -----------------------------------------------------------------------

    #[test]
    fn bearer_token_missing_header_is_unauthorized() {
        let headers = HeaderMap::new();
        let err = bearer_token(&headers).expect_err("missing");
        assert_unauthorized(&err);
    }

    #[test]
    fn bearer_token_non_utf8_is_unauthorized() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("raw header bytes"),
        );
        let err = bearer_token(&headers).expect_err("non-utf8");
        assert_unauthorized(&err);
    }

    #[test]
    fn bearer_token_missing_bearer_prefix_is_unauthorized() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Token tok"));
        let err = bearer_token(&headers).expect_err("Token prefix");
        assert_unauthorized(&err);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer tok"),
        );
        let err = bearer_token(&headers).expect_err("lowercase bearer");
        assert_unauthorized(&err);
    }

    #[test]
    fn bearer_token_empty_token_is_unauthorized() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        let err = bearer_token(&headers).expect_err("empty token");
        assert_unauthorized(&err);
    }

    #[test]
    fn bearer_token_whitespace_or_control_is_unauthorized() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok en"),
        );
        let err = bearer_token(&headers).expect_err("whitespace in token");
        assert_unauthorized(&err);

        // Tab is the only ASCII control byte HeaderValue accepts (and is whitespace).
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok\t"),
        );
        let err = bearer_token(&headers).expect_err("control/whitespace byte in token");
        assert_unauthorized(&err);
    }

    #[test]
    fn bearer_token_valid_returns_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok"),
        );
        let token = bearer_token(&headers).expect("valid bearer");
        assert_eq!(token, "tok");
    }

    // -----------------------------------------------------------------------
    // session_chan_bind
    // -----------------------------------------------------------------------

    #[test]
    fn session_chan_bind_empty_hosts_is_internal() {
        let err = session_chan_bind(&[]).expect_err("empty hosts");
        assert_internal(&err);
    }

    #[test]
    fn session_chan_bind_single_host_matches_chan_bind_for_host() {
        let host = "example.com";
        let bind = session_chan_bind(&[host.to_string()]).expect("single host");
        assert_eq!(bind, chan_bind_for_host(host));
    }

    #[test]
    fn session_chan_bind_two_hosts_is_internal() {
        let hosts = vec!["a.example".to_string(), "b.example".to_string()];
        let err = session_chan_bind(&hosts).expect_err("two hosts");
        assert_internal(&err);
        // Multi-host must fail closed rather than returning either host's bind.
        assert_ne!(
            chan_bind_for_host("a.example"),
            chan_bind_for_host("b.example"),
            "fixture hosts must have distinct binds so a silent pick would be detectable"
        );
    }

    // -----------------------------------------------------------------------
    // receipt_to_json / receipt_stream_break_event
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_to_json_rejects_coin_id_not_32() {
        let mut r = sample_receipt(0x11, "100", "completed", 1_700_000_000);
        r.coin_id = vec![0x11u8; 16];
        let err = receipt_to_json(&r).expect_err("short coin_id");
        assert_internal(&err);
    }

    #[test]
    fn receipt_to_json_rejects_asset_id_not_32() {
        let mut r = sample_receipt(0x11, "100", "completed", 1_700_000_000);
        r.asset_id = vec![0xABu8; 16];
        let err = receipt_to_json(&r).expect_err("short asset_id");
        assert_internal(&err);
    }

    #[test]
    fn receipt_to_json_rejects_empty_amount() {
        let r = sample_receipt(0x11, "", "completed", 1_700_000_000);
        let err = receipt_to_json(&r).expect_err("empty amount");
        assert_internal(&err);
    }

    #[test]
    fn receipt_to_json_rejects_empty_state() {
        let r = sample_receipt(0x11, "100", "", 1_700_000_000);
        let err = receipt_to_json(&r).expect_err("empty state");
        assert_internal(&err);
    }

    #[test]
    fn receipt_to_json_valid_hex_and_decimal_credited_at() {
        let r = sample_receipt(0x11, "100", "completed", 1_700_000_000);
        let json = receipt_to_json(&r).expect("valid receipt");
        assert_eq!(json["coin_id"], hex32(0x11));
        assert_eq!(json["asset_id"], hex32(0xAB));
        assert_eq!(json["amount"], "100");
        assert_eq!(json["state"], "completed");
        assert_eq!(json["credited_at"], "1700000000");
    }

    #[test]
    fn receipt_stream_break_event_is_error_with_code_and_message() {
        let err = ApiError::unauthorized("x");
        let ev = receipt_stream_break_event(&err);
        let data = json!({
            "error": err.body.error,
            "message": err.body.message,
        });
        let expected = Event::default().event("error").data(data.to_string());
        // Event fields are private; compare reconstructed Debug text.
        assert_eq!(format!("{ev:?}"), format!("{expected:?}"));

        let err = ApiError::internal("cause");
        let ev = receipt_stream_break_event(&err);
        let data = json!({
            "error": err.body.error,
            "message": err.body.message,
        });
        let expected = Event::default().event("error").data(data.to_string());
        assert_eq!(format!("{ev:?}"), format!("{expected:?}"));
    }

    // -----------------------------------------------------------------------
    // deny_unknown_fields (closed REST request DTOs)
    // -----------------------------------------------------------------------

    #[test]
    fn pull_challenge_body_rejects_unknown_top_level_field() {
        let v = json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqun6mw",
            "not_in_spec": true,
        });
        let err = serde_json::from_value::<PullChallengeBody>(v).expect_err("deny");
        assert!(
            err.to_string().contains("not_in_spec") || err.to_string().contains("unknown field"),
            "serde must reject unknown field, got {err}"
        );
    }

    #[test]
    fn pull_challenge_body_rejects_unknown_nested_scope_field() {
        let v = json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqun6mw",
            "scope": {
                "asset_ids": "*",
                "ghost": 1,
            },
        });
        let err = serde_json::from_value::<PullChallengeBody>(v).expect_err("deny nested");
        assert!(
            err.to_string().contains("ghost") || err.to_string().contains("unknown field"),
            "nested deny_unknown_fields must fire, got {err}"
        );
    }
}

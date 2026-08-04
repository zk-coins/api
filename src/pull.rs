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

/// Redeem body: top-level `{ nonce, expiry, proof, scope? }`.
///
/// Redeem-body `expiry` is normative (bound into signed `chal`). Optional
/// `scope` re-echoes the requested scope so a **stateless** API edge can
/// compute `requested ∩ capability` without a challenge store (§5.1). Omitted
/// scope normalises to the unbounded sentinel pair before intersection.
#[derive(Debug, Deserialize)]
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

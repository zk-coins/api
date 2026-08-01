//! §7.4 Blossom blob store — API-local, content-addressed, no kernel RPC.
//!
//! Four routes, one filesystem store. Discovery keys
//! `blossom_get` / `blossom_head` / `blossom_upload` / `blossom_delete` are
//! advertised **if and only if** `ZKCOINS_BLOSSOM_STORE` is configured.
//!
//! ## `ReplicaReceiptV1` — not issued
//!
//! §4.6 dual-commit replication (delivery event + blob) is **not** implemented
//! in this process. Successful upload responses are therefore exactly
//! `{ "blob_id": <hex32> }` — the optional `receipt` field is **absent**
//! (not `null`, not `{}`). The three `X-ZkCoins-*` binding headers are still
//! validated when present (all-or-nothing, closed enum, hex width) so a broken
//! value cannot pass unnoticed; they produce no receipt and no other side
//! effect until §4.6 lands.

mod auth;
mod base64;
mod store;

#[cfg(test)]
pub use auth::sign_auth_event_base64;
pub use auth::{
    verify_blossom_auth, AuthAction, RequiredAction, VerifiedAuthEvent, CLOCK_SKEW_SECS,
    REPLAY_WINDOW_SECS,
};
pub use store::{blob_id_of, BlobStore};

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Runtime handle for the Blossom surface (store + ACL + size limit).
#[derive(Clone)]
pub struct BlossomState {
    pub store: Arc<BlobStore>,
    pub max_blob_bytes: u64,
    /// `op` keys allowed to upload (paired accounts + replication peers).
    pub allowed_upload_ops: Arc<BTreeSet<[u8; 32]>>,
}

impl BlossomState {
    pub fn from_config(cfg: &crate::config::BlossomConfig) -> Result<Self, ApiError> {
        let store = BlobStore::open(cfg.store_root.clone())?;
        Ok(Self {
            store: Arc::new(store),
            max_blob_bytes: cfg.max_blob_bytes,
            allowed_upload_ops: Arc::new(cfg.allowed_upload_ops.clone()),
        })
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Successful upload body. `receipt` is intentionally not a field — §4.6 is
/// absent, so serde never emits it (honest omission, not `null`).
#[derive(Debug, Serialize)]
struct UploadResponse {
    blob_id: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /blossom/<sha256>` — unauthenticated raw bytes.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Result<Response, ApiError> {
    let blossom = require_blossom(&state)?;
    let id = BlobStore::parse_blob_id(&sha256)?;
    let bytes = blossom
        .store
        .read(&id)?
        .ok_or_else(|| ApiError::not_found(format!("blob {sha256} not found")))?;
    let mut res = Response::new(axum::body::Body::from(bytes));
    *res.status_mut() = StatusCode::OK;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(res)
}

/// `HEAD /blossom/<sha256>` — existence / size probe.
pub async fn head_blob(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Result<Response, ApiError> {
    let blossom = require_blossom(&state)?;
    let id = BlobStore::parse_blob_id(&sha256)?;
    let size = blossom
        .store
        .size(&id)?
        .ok_or_else(|| ApiError::not_found(format!("blob {sha256} not found")))?;
    let mut res = Response::new(axum::body::Body::empty());
    *res.status_mut() = StatusCode::OK;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    res.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&size.to_string())
            .map_err(|_| ApiError::internal("content-length header value is not valid"))?,
    );
    Ok(res)
}

/// `PUT` / `POST /blossom/upload` — raw body, kind-24242 auth.
pub async fn upload_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let blossom = require_blossom(&state)?;

    // Content-Type is mandatory application/octet-stream.
    require_octet_stream(&headers)?;

    // Body size — advertised limit, no clamping.
    let max = blossom.max_blob_bytes;
    let body_len = body.len() as u64;
    if body_len > max {
        return Err(ApiError::payload_too_large(format!(
            "upload body is {body_len} bytes; advertised limit is {max} bytes"
        )));
    }

    // Binding headers: all three or none; validate when present.
    // §4.6 receipt is not issued — validation only (see module docs).
    validate_binding_headers(&headers)?;

    // Server computes blob_id = H(body); never trusts a client claim.
    let body_hash = blob_id_of(&body);

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header for blossom upload"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Authorization header is not valid UTF-8"))?;

    let now = unix_now();
    let verified = verify_blossom_auth(auth_header, RequiredAction::Upload, &body_hash, now)?;

    // ACL: op must be a paired account or configured replication peer.
    if !blossom.allowed_upload_ops.contains(&verified.op_pubkey) {
        return Err(ApiError::scope_exceeded(
            "upload op key is neither a paired account nor a configured replication peer",
        ));
    }

    let id = blossom.store.put(&body, &verified.op_pubkey)?;
    debug_assert_eq!(id, body_hash);

    // Honest response without receipt (§4.6 absent).
    Ok((
        StatusCode::OK,
        Json(UploadResponse {
            blob_id: encode_hex(&id),
        }),
    )
        .into_response())
}

/// `DELETE /blossom/<sha256>` — original uploader only.
pub async fn delete_blob(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let blossom = require_blossom(&state)?;
    let id = BlobStore::parse_blob_id(&sha256)?;

    if !blossom.store.exists(&id) {
        return Err(ApiError::not_found(format!("blob {sha256} not found")));
    }

    // Fail-closed: no uploader note ⇒ refuse DELETE (never allow).
    let original = blossom.store.read_uploader(&id)?.ok_or_else(|| {
        ApiError::scope_exceeded("blob has no uploader note; DELETE refused (fail-closed)")
    })?;

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header for blossom delete"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Authorization header is not valid UTF-8"))?;

    let now = unix_now();
    let verified = verify_blossom_auth(auth_header, RequiredAction::Delete, &id, now)?;

    if verified.op_pubkey != original {
        return Err(ApiError::scope_exceeded(
            "delete op key is not the original uploader of this blob",
        ));
    }

    let deleted = blossom.store.delete(&id)?;
    if !deleted {
        // Race: blob vanished between exists and delete.
        return Err(ApiError::not_found(format!("blob {sha256} not found")));
    }

    // Successful DELETE: 200 empty body (§7.4).
    Ok(StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_blossom(state: &AppState) -> Result<&BlossomState, ApiError> {
    state.blossom.as_ref().ok_or_else(|| {
        // Routes are only mounted when configured; this branch is a
        // programming error if reached on a live path.
        ApiError::internal("blossom surface reached without configuration")
    })
}

fn require_octet_stream(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(ct) = headers.get(header::CONTENT_TYPE) else {
        return Err(ApiError::unsupported_media_type(
            "Content-Type application/octet-stream is required for blossom upload",
        ));
    };
    let ct = ct
        .to_str()
        .map_err(|_| ApiError::unsupported_media_type("Content-Type is not valid UTF-8"))?;
    // Exact media type; parameters (e.g. charset) are not a conforming form.
    let media = ct.split(';').next().unwrap_or(ct).trim();
    if media != "application/octet-stream" {
        // Multipart / JSON called out by §7.4 as non-conforming → 415.
        return Err(ApiError::unsupported_media_type(format!(
            "Content-Type must be application/octet-stream, got {media:?} \
             (multipart and JSON are not a conforming v1 upload form)"
        )));
    }
    Ok(())
}

/// `X-ZkCoins-Event-Id`, `X-ZkCoins-Attempt-Nonce`, `X-ZkCoins-Retention` —
/// all three present, or all three absent. Partial set → 400. Invalid hex /
/// width / retention enum → 400.
///
/// When all three are valid, they are accepted and **discarded**: this process
/// does not issue `ReplicaReceiptV1` (§4.6 dual-commit is absent). Validation
/// exists so a broken value cannot pass unnoticed.
fn validate_binding_headers(headers: &HeaderMap) -> Result<(), ApiError> {
    const H_EVENT: &str = "x-zkcoins-event-id";
    const H_NONCE: &str = "x-zkcoins-attempt-nonce";
    const H_RETENTION: &str = "x-zkcoins-retention";

    let event = header_str(headers, H_EVENT)?;
    let nonce = header_str(headers, H_NONCE)?;
    let retention = header_str(headers, H_RETENTION)?;

    match (event.is_some(), nonce.is_some(), retention.is_some()) {
        (false, false, false) => Ok(()),
        (true, true, true) => {
            let event = event.expect("checked");
            let nonce = nonce.expect("checked");
            let retention = retention.expect("checked");
            parse_hex32_lower(event, "X-ZkCoins-Event-Id")?;
            parse_hex32_lower(nonce, "X-ZkCoins-Attempt-Nonce")?;
            match retention {
                "indefinite" | "policy" => {}
                other => {
                    return Err(ApiError::malformed(format!(
                        "X-ZkCoins-Retention must be \"indefinite\" or \"policy\", got {other:?}"
                    )));
                }
            }
            // Validated; no receipt follows.
            Ok(())
        }
        _ => Err(ApiError::malformed(
            "X-ZkCoins-Event-Id, X-ZkCoins-Attempt-Nonce, and X-ZkCoins-Retention \
             must be supplied all together or not at all",
        )),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ApiError> {
    match headers.get(name) {
        None => Ok(None),
        Some(v) => {
            let s = v
                .to_str()
                .map_err(|_| ApiError::malformed(format!("{name} header is not valid UTF-8")))?;
            Ok(Some(s))
        }
    }
}

fn parse_hex32_lower(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ApiError::malformed(format!(
            "{field} must be exactly 64 lowercase hex characters"
        )));
    }
    let v = decode_hex_exact(s, 32).map_err(|e| ApiError::malformed(format!("{field}: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs()
}

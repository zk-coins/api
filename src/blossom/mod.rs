//! §7.4 Blossom blob store — API-local, content-addressed, no kernel RPC.
//!
//! Three routes, one filesystem store. Discovery keys
//! `blossom_get` / `blossom_head` / `blossom_upload` are advertised **if and
//! only if** `ZKCOINS_BLOSSOM_STORE` is configured.
//!
//! ## Data permanence (Requirement 12)
//!
//! The store is **append-only**. There is **no** `DELETE` route, no retention
//! hold, and no server-side prune of received blobs. Successful upload
//! responses are exactly `{ "blob_id": <hex32> }` — there is no `receipt`
//! field (`ReplicaReceiptV1` / §4.6 dual-commit replication was removed from
//! the spec). Upload remains ACL-gated (paired accounts + configured peers).

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
use crate::extract::LimitedBytes;
use crate::hexutil::encode_hex;
use crate::state::AppState;
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

/// Successful upload body. No `receipt` field — data permanence / no §4.6
/// dual-commit; serde never emits the key (honest omission, not `null`).
#[derive(Debug, Serialize)]
struct UploadResponse {
    blob_id: String,
}

// ---------------------------------------------------------------------------
// Blocking store helpers (keep reactor threads free of sync fsync/read)
// ---------------------------------------------------------------------------

async fn store_read(store: Arc<BlobStore>, id: [u8; 32]) -> Result<Option<Vec<u8>>, ApiError> {
    tokio::task::spawn_blocking(move || store.read(&id))
        .await
        .map_err(|e| ApiError::internal(format!("blossom store read join: {e}")))?
}

async fn store_size(store: Arc<BlobStore>, id: [u8; 32]) -> Result<Option<u64>, ApiError> {
    tokio::task::spawn_blocking(move || store.size(&id))
        .await
        .map_err(|e| ApiError::internal(format!("blossom store size join: {e}")))?
}

async fn store_put(
    store: Arc<BlobStore>,
    body: axum::body::Bytes,
    uploader: [u8; 32],
) -> Result<[u8; 32], ApiError> {
    tokio::task::spawn_blocking(move || store.put(&body, &uploader))
        .await
        .map_err(|e| ApiError::internal(format!("blossom store put join: {e}")))?
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
    let bytes = store_read(Arc::clone(&blossom.store), id)
        .await?
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
    let size = store_size(Arc::clone(&blossom.store), id)
        .await?
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
    LimitedBytes(body): LimitedBytes,
) -> Result<Response, ApiError> {
    let blossom = require_blossom(&state)?;

    // Content-Type is mandatory application/octet-stream.
    require_octet_stream(&headers)?;

    // Body size — advertised limit, no clamping. The route-level body limit is
    // set to the same max so axum buffering rejects far-oversized bodies; both
    // paths map to §7.5 `payload_too_large` (handler check + LimitedBytes).
    let max = blossom.max_blob_bytes;
    let body_len = body.len() as u64;
    if body_len > max {
        return Err(ApiError::payload_too_large(format!(
            "upload body is {body_len} bytes; advertised limit is {max} bytes"
        )));
    }

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

    let id = store_put(Arc::clone(&blossom.store), body, verified.op_pubkey).await?;
    debug_assert_eq!(id, body_hash);

    Ok((
        StatusCode::OK,
        Json(UploadResponse {
            blob_id: encode_hex(&id),
        }),
    )
        .into_response())
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
    // §7.4 non-conforming upload form (JSON / multipart / missing CT) →
    // `400 malformed_request` (closed §7.5 set; no `unsupported_media_type`).
    let Some(ct) = headers.get(header::CONTENT_TYPE) else {
        return Err(ApiError::malformed(
            "Content-Type application/octet-stream is required for blossom upload",
        ));
    };
    let ct = ct
        .to_str()
        .map_err(|_| ApiError::malformed("Content-Type is not valid UTF-8"))?;
    // Exact media type; parameters (e.g. charset) are not a conforming form.
    let media = ct.split(';').next().unwrap_or(ct).trim();
    if media != "application/octet-stream" {
        return Err(ApiError::malformed(format!(
            "Content-Type must be application/octet-stream, got {media:?} \
             (multipart and JSON are not a conforming v1 upload form)"
        )));
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::connect_lazy;
    use crate::ownership::{GrantRevokeChallengeStore, RevokedGrantSet, SubjectOpDirectory};
    use crate::state::AppState;
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn dummy_state() -> AppState {
        let kernel = Arc::new(connect_lazy("http://127.0.0.1:1").expect("lazy kernel uri"));
        AppState {
            kernel,
            features: BTreeSet::new(),
            public_hosts: Arc::new(vec!["node.example.com".into()]),
            blossom: None,
            subject_ops: Arc::new(SubjectOpDirectory::new()),
            revoked_grants: Arc::new(RevokedGrantSet::new()),
            grant_revoke_challenges: Arc::new(GrantRevokeChallengeStore::new()),
        }
    }

    #[tokio::test]
    async fn require_blossom_without_configuration_is_internal() {
        let state = dummy_state();
        let result = require_blossom(&state);
        assert!(result.is_err(), "unconfigured blossom must err");
        let err = match result {
            Err(e) => e,
            Ok(_) => return,
        };
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(
            err.cause(),
            Some("blossom surface reached without configuration")
        );
    }

    #[tokio::test]
    async fn upload_blob_oversize_before_auth_is_payload_too_large() {
        let root = std::env::temp_dir().join(format!(
            "zkcoins-blossom-oversize-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Arc::new(BlobStore::open(&root).expect("temp blossom store"));
        let mut state = dummy_state();
        state.blossom = Some(BlossomState {
            store,
            max_blob_bytes: 1,
            allowed_upload_ops: Arc::new(BTreeSet::new()),
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let body = axum::body::Bytes::from_static(b"ab");
        let result = upload_blob(State(state), headers, LimitedBytes(body)).await;
        assert!(
            result.is_err(),
            "oversize body must be rejected before auth"
        );
        if let Err(err) = result {
            assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(err.body.error, "payload_too_large");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn require_octet_stream_missing_content_type_is_malformed() {
        let headers = HeaderMap::new();
        let err = require_octet_stream(&headers).expect_err("missing Content-Type");
        assert_eq!(err.body.error, "malformed_request");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn require_octet_stream_non_utf8_is_malformed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("raw header bytes"),
        );
        let err = require_octet_stream(&headers).expect_err("non-utf8 Content-Type");
        assert_eq!(err.body.error, "malformed_request");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn require_octet_stream_json_and_multipart_are_malformed() {
        for ct in ["application/json", "multipart/form-data"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
            let err = require_octet_stream(&headers).expect_err(ct);
            assert_eq!(err.body.error, "malformed_request");
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn require_octet_stream_exact_is_ok() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        require_octet_stream(&headers).expect("exact media type");
    }
}

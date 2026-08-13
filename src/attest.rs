//! Balance-attestation REST surface (§7.5 L2893–L2894).
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/attest/balance/challenge` | `OpenPullChallenge` action=`attest_balance` |
//! | `POST` | `/v1/attest/balance` | `AttestBalance` (after OwnershipProof) |
//!
//! OwnershipProof verification is API-local; the kernel receives only the
//! already-authenticated subject plus `nonce` / `chan_bind`.

use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{AttestRequest, JobHandle, PullChallengeRequest};
use crate::ownership::{
    attest_request_hash, ceiling_encoding, decode_zk_address, parse_u64_decimal,
    verify_ownership_proof, ChallengeDomain, ChallengeEcho, OwnerOnlyProofJson,
    ATTEST_BALANCE_CHALLENGE_DOMAIN,
};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AttestChallengeBody {
    pub subject: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestBalanceBody {
    pub subject: String,
    pub asset_id: String,
    #[serde(default)]
    pub nav_ceiling: Option<String>,
    /// §7.1 decimal-string u64 when present.
    #[serde(default)]
    pub size_ceiling: Option<String>,
    pub challenge: ChallengeEcho,
    pub ownership_proof: OwnerOnlyProofJson,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/attest/balance/challenge` → OpenPullChallenge(action=attest_balance).
pub async fn post_attest_balance_challenge(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<AttestChallengeBody>,
) -> Result<Response, ApiError> {
    if body.subject.is_empty() {
        return Err(ApiError::malformed("subject is required"));
    }
    // Validate Bech32m early so the API returns a clear 400 rather than
    // relying on the kernel's parse of the same string.
    let _ = decode_zk_address(&body.subject)?;

    let challenge = state
        .kernel
        .open_pull_challenge(PullChallengeRequest {
            subject: body.subject,
            requested_scope: None,
            action: "attest_balance".to_string(),
        })
        .await?;

    if challenge.nonce.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel Challenge.nonce must be 32 bytes, got {}",
            challenge.nonce.len()
        )));
    }
    // Domain is endpoint-bound: refuse a kernel that returns a foreign tag.
    if challenge.domain != ATTEST_BALANCE_CHALLENGE_DOMAIN {
        return Err(ApiError::internal(format!(
            "kernel Challenge.domain must be {ATTEST_BALANCE_CHALLENGE_DOMAIN:?}, got {:?}",
            challenge.domain
        )));
    }

    let body = json!({
        "nonce": encode_hex(&challenge.nonce),
        "expiry": challenge.expiry.to_string(),
        "domain": ATTEST_BALANCE_CHALLENGE_DOMAIN,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /v1/attest/balance` → verify OwnershipProof, then AttestBalance.
///
/// Verification runs entirely before the kernel call so a bad signature
/// cannot consume the single-use challenge nonce.
pub async fn post_attest_balance(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<AttestBalanceBody>,
) -> Result<Response, ApiError> {
    // ---- pure validation + OwnershipProof (no kernel) ----
    let nav_ceiling = match &body.nav_ceiling {
        None => None,
        Some(h) => {
            let v = decode_hex_exact(h, 32)
                .map_err(|e| ApiError::malformed(format!("nav_ceiling: {e}")))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            Some(arr)
        }
    };
    let size_ceiling = match &body.size_ceiling {
        None => None,
        Some(s) => Some(
            parse_u64_decimal(s)
                .map_err(|e| ApiError::malformed(format!("size_ceiling: {}", e.body.message)))?,
        ),
    };
    let ceiling_enc = ceiling_encoding(nav_ceiling.as_ref(), size_ceiling)?;

    let subject_raw = decode_zk_address(&body.subject)?;
    let asset_id = {
        let v = decode_hex_exact(&body.asset_id, 32)
            .map_err(|e| ApiError::malformed(format!("asset_id: {e}")))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        arr
    };

    // Server-computed request_hash — never a client-supplied hash field.
    let request_hash = attest_request_hash(&subject_raw, &asset_id, &ceiling_enc);

    // GrantProof arm → 401 before any kernel call (tagged union, not 400).
    let ownership_proof = body.ownership_proof.require_ownership()?;

    // Domain is the AttestBalance endpoint constant — not taken from body.
    let verified = verify_ownership_proof(
        ChallengeDomain::AttestBalance,
        &body.subject,
        &body.challenge,
        &ownership_proof,
        &request_hash,
        state.public_hosts.as_slice(),
    )?;

    // ---- only now: kernel (nonce consumption lives here) ----
    let (nav_bytes, size_val) = match (nav_ceiling, size_ceiling) {
        (None, None) => (Vec::new(), 0u64),
        (Some(nav), Some(size)) => (nav.to_vec(), size),
        _ => {
            // ceiling_encoding already rejected mixed presence.
            return Err(ApiError::internal(
                "ceiling pair invariant broken after encoding",
            ));
        }
    };

    let handle: JobHandle = state
        .kernel
        .attest_balance(AttestRequest {
            subject: verified.subject_bech32,
            asset_id: asset_id.to_vec(),
            nav_ceiling: nav_bytes,
            size_ceiling: size_val,
            nonce: verified.nonce.to_vec(),
            chan_bind: verified.chan_bind.to_vec(),
        })
        .await?;

    // §7.5 L2894: `202 { job_id }` — no status field on this admit response.
    // JobHandle.status must still be the admit terminal `"accepted"` (same
    // contract as POST /v1/tx); any other value is a kernel protocol fault.
    if handle.job_id.is_empty() {
        return Err(ApiError::internal(
            "kernel JobHandle.job_id is empty on AttestBalance success",
        ));
    }
    if handle.status != "accepted" {
        return Err(ApiError::internal(format!(
            "kernel JobHandle.status must be \"accepted\" on AttestBalance success, got {:?}",
            handle.status
        )));
    }
    let body = json!({ "job_id": handle.job_id });
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexutil::encode_hex;
    use crate::kernel::connect_lazy;
    use crate::ownership::{
        ChallengeEcho, GrantRevokeChallengeStore, OwnerOnlyProofJson, RevokedGrantSet,
        SubjectOpDirectory,
    };
    use crate::state::AppState;
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
    async fn valid_nav_ceiling_hex_is_copied_then_mixed_ceiling_rejected() {
        let nav = encode_hex(&[0xABu8; 32]);
        let body = AttestBalanceBody {
            subject: "unused".into(),
            asset_id: "unused".into(),
            nav_ceiling: Some(nav),
            size_ceiling: None,
            challenge: ChallengeEcho {
                nonce: "00".repeat(32),
                expiry: "1".into(),
            },
            ownership_proof: OwnerOnlyProofJson::Ownership {
                subject: "unused".into(),
                public_key: "00".repeat(32),
                nk_commit: "00".repeat(32),
                signature: "00".repeat(64),
            },
        };
        let err = post_attest_balance(State(dummy_state()), JsonBody(body))
            .await
            .expect_err("mixed ceilings");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("nav_ceiling") && err.body.message.contains("size_ceiling"),
            "mixed-presence message, got {:?}",
            err.body.message
        );
    }
}

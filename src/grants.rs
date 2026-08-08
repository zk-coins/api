//! View-grant REST surface (§7.5 L2895–L2896 / §5.2).
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/grants/challenge` | `OpenPullChallenge` action=`issue_grant` |
//! | `POST` | `/v1/grants` | `IssueViewGrant` (after OwnershipProof) |
//! | `POST` | `/v1/grants/revoke/challenge` | none (api-local store) |
//! | `POST` | `/v1/grants/revoke` | none (api-local `revoked_grants`) |
//!
//! A GrantProof is rejected here (no-escalation). The kernel message has no
//! capability field — only the API edge can enforce this.

use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{GrantRequest, PullChallengeRequest, Scope};
use crate::ownership::{
    decode_view_grant, decode_zk_address, encode_grant_asset_ids, encode_zk_address_public,
    issue_grant_request_hash, parse_u64_decimal, validate_resolved_scope, verify_ownership_proof,
    verify_simple_ownership_proof, ChallengeDomain, ChallengeEcho, OwnerOnlyProofJson,
    ResolvedScope, ISSUE_GRANT_CHALLENGE_DOMAIN, REVOKE_GRANT_CHALLENGE_DOMAIN,
    SCOPE_NOT_AFTER_UNBOUNDED,
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
    pub ownership_proof: OwnerOnlyProofJson,
}

#[derive(Debug, Deserialize)]
pub struct GrantsRevokeChallengeBody {
    pub subject: String,
}

#[derive(Debug, Deserialize)]
pub struct GrantRevokeNonce {
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct GrantsRevokeBody {
    pub challenge: GrantRevokeNonce,
    pub ownership_proof: OwnerOnlyProofJson,
    pub grant: String,
}

/// §5.1 RECOMMENDED challenge TTL, gespiegelt von
/// `node/src/kernel/bootstrap/challenges.rs::CHALLENGE_TTL_SECS` (60s) — die
/// gleiche Grössenordnung wie jede andere Challenge in diesem System, auch
/// wenn dieser Store rein api-lokal ist.
const GRANT_REVOKE_CHALLENGE_TTL_SECS: u64 = 60;

fn unix_now() -> Result<u64, ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ApiError::internal("system clock is before Unix epoch"))
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

    let resolved = ResolvedScope {
        all_assets,
        asset_ids,
        not_before,
        not_after,
    };
    validate_resolved_scope(&resolved)?;

    Ok(NormalisedScope {
        all_assets: resolved.all_assets,
        asset_ids: resolved.asset_ids,
        not_before: resolved.not_before,
        not_after: resolved.not_after,
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

    // GrantProof arm → 401 before any kernel call (tagged union, not 400).
    let ownership_proof = body.ownership_proof.require_ownership()?;

    // Domain is the IssueGrant endpoint constant — not taken from body.
    let verified = verify_ownership_proof(
        ChallengeDomain::IssueGrant,
        &body.subject,
        &body.challenge,
        &ownership_proof,
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

/// `POST /v1/grants/revoke/challenge` — issue a fresh single-use nonce for
/// grant revocation. Rein api-lokal, kein Kernel-Dial (§5.2).
pub async fn post_grants_revoke_challenge(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<GrantsRevokeChallengeBody>,
) -> Result<Response, ApiError> {
    if body.subject.is_empty() {
        return Err(ApiError::malformed("subject is required"));
    }
    let subject_raw = decode_zk_address(&body.subject)?;
    let now = unix_now()?;
    let expiry = now.saturating_add(GRANT_REVOKE_CHALLENGE_TTL_SECS);
    let nonce = state.grant_revoke_challenges.issue(subject_raw, expiry);

    let body = json!({
        "nonce": encode_hex(&nonce),
        "expiry": expiry.to_string(),
        "domain": REVOKE_GRANT_CHALLENGE_DOMAIN,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /v1/grants/revoke` — verify OwnershipProof under RevokeGrant domain
/// and grant→subject binding, then populate `revoked_grants`. Rein api-lokal,
/// KEIN Kernel-Dial an irgendeiner Stelle (§5.2).
pub async fn post_grants_revoke(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<GrantsRevokeBody>,
) -> Result<Response, ApiError> {
    // 1. Capability gate — GrantProof-Arm wird mit 401 abgewiesen, bevor der
    //    Nonce-Store überhaupt angefasst wird (no-escalation, wie überall sonst).
    let ownership_proof = body.ownership_proof.require_ownership()?;

    // 2. Single-use take — DAS ist der Single-Use-Check. Unbekannt ODER
    //    bereits verbraucht sehen von aussen identisch aus (401), keine
    //    Unterscheidung, die Existenz/Timing leakt.
    let nonce_bytes = decode_hex_exact(&body.challenge.nonce, 32)
        .map_err(|e| ApiError::malformed(format!("challenge.nonce: {e}")))?;
    let mut nonce_raw = [0u8; 32];
    nonce_raw.copy_from_slice(&nonce_bytes);
    let entry = state
        .grant_revoke_challenges
        .take(&nonce_raw)
        .ok_or_else(|| {
            ApiError::unauthorized("unknown or already-consumed grant-revoke challenge nonce")
        })?;

    // 3. Expiry — der Store ist hier der einzige Prüfer (kein Kernel dahinter).
    let now = unix_now()?;
    if now > entry.expiry {
        return Err(ApiError::unauthorized("grant-revoke challenge has expired"));
    }

    // 4. OwnershipProof unter RevokeGrant-Domain verifizieren. subject UND
    //    expiry kommen aus `entry` (dem Store), NICHT aus dem Client-Body —
    //    der Body trägt für `challenge` nur `nonce`, keine `expiry`. chan_bind
    //    bleibt server-autoritativ (state.public_hosts), wie überall sonst.
    let subject_bech32 = encode_zk_address_public(&entry.subject)?;
    let echo = ChallengeEcho {
        nonce: body.challenge.nonce.clone(),
        expiry: entry.expiry.to_string(),
    };
    let _verified = verify_simple_ownership_proof(
        ChallengeDomain::RevokeGrant,
        &subject_bech32,
        &echo,
        &ownership_proof,
        state.public_hosts.as_slice(),
    )?;

    // 5. Grant decodieren + grant→subject-Bindung (DoS-Schutz): eine fremde
    //    grant_id darf nicht revozierbar sein, nur weil jemand ein gültiges
    //    OwnershipProof für SEIN EIGENES subject vorlegt.
    let grant = decode_view_grant(&body.grant)?;
    if grant.subject != entry.subject {
        return Err(ApiError::unauthorized(
            "grant.subject does not match the authenticated revoke subject",
        ));
    }

    // 6. Population — der einzige Schreibzugriff auf revoked_grants in dieser
    //    Datei. KEIN Kernel-Dial an irgendeiner Stelle in diesem Handler.
    state.revoked_grants.revoke(grant.grant_id);

    let body = json!({ "revoked": true });
    Ok((StatusCode::OK, Json(body)).into_response())
}

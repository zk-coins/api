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
#[serde(deny_unknown_fields)]
pub struct GrantsChallengeBody {
    pub subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantScopeJson {
    /// Either the string `"*"` or an array of hex32 asset ids.
    pub asset_ids: Value,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct GrantsRevokeChallengeBody {
    pub subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevokeNonce {
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let nonce = state
        .grant_revoke_challenges
        .issue(subject_raw, expiry, now)?;

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
    // 1. Capability gate — GrantProof arm is rejected with 401 before the
    //    nonce store is touched (no-escalation, same as elsewhere).
    let ownership_proof = body.ownership_proof.require_ownership()?;

    // 2. Parse nonce hex. Malformed → 400 before any store lookup.
    let nonce_bytes = decode_hex_exact(&body.challenge.nonce, 32)
        .map_err(|e| ApiError::malformed(format!("challenge.nonce: {e}")))?;
    let mut nonce_raw = [0u8; 32];
    nonce_raw.copy_from_slice(&nonce_bytes);

    // 3. Peek — never-issued and already-consumed look identical on the wire
    //    (401). Do not consume yet: a failed proof must not burn the nonce.
    //    `get` may drop *other* expired entries; the looked-up nonce is kept
    //    even when expired so step 5 can still return 410 after a valid proof.
    let now = unix_now()?;
    let entry = state
        .grant_revoke_challenges
        .get(&nonce_raw, now)
        .ok_or_else(|| {
            ApiError::unauthorized("unknown or already-consumed grant-revoke challenge nonce")
        })?;

    // 4. OwnershipProof under RevokeGrant. subject and expiry come from
    //    `entry` (the store), not the client body — the body only carries
    //    `challenge.nonce`. chan_bind stays server-authoritative
    //    (`state.public_hosts`). On verify failure do not `take`.
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

    // 5. Expiry — immediately after a valid proof, before grant decode.
    //    Clean up the expired nonce via `take`, then 410 `challenge_expired`
    //    (malformed grant must not mask expiry). Re-sample wall clock so a
    //    slow proof does not stretch the challenge lifetime.
    let now = unix_now()?;
    if now > entry.expiry {
        let _ = state.grant_revoke_challenges.take(&nonce_raw);
        return Err(ApiError::challenge_expired(
            "grant-revoke challenge has expired",
        ));
    }

    // 6. Decode grant + grant→subject binding (DoS protection): a foreign
    //    grant_id must not be revocable merely because someone presents a
    //    valid OwnershipProof for their own subject. On mismatch do not `take`.
    let grant = decode_view_grant(&body.grant)?;
    if grant.subject != entry.subject {
        return Err(ApiError::unauthorized(
            "grant.subject does not match the authenticated revoke subject",
        ));
    }

    // 7. Single-use consume. `None` means lost the race with another redeem.
    let _entry = state
        .grant_revoke_challenges
        .take(&nonce_raw)
        .ok_or_else(|| {
            // post-peek consume race: get succeeded, concurrent take won
            #[cfg_attr(coverage_nightly, coverage(off))]
            {
                ApiError::unauthorized("unknown or already-consumed grant-revoke challenge nonce")
            }
        })?;

    // 8. Population — only write to revoked_grants in this handler. No kernel
    //    dial at any point here.
    state.revoked_grants.revoke(grant.grant_id);

    let body = json!({ "revoked": true });
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(
        asset_ids: Value,
        not_before: Option<&str>,
        not_after: Option<&str>,
    ) -> GrantScopeJson {
        GrantScopeJson {
            asset_ids,
            not_before: not_before.map(str::to_string),
            not_after: not_after.map(str::to_string),
        }
    }

    fn assert_malformed(result: Result<NormalisedScope, ApiError>, message_fragment: &str) {
        let err = result.err().expect("scope must be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains(message_fragment),
            "expected {message_fragment:?} in {:?}",
            err.body.message
        );
    }

    #[test]
    fn normalise_explicit_scope_and_convert_every_field_to_proto() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let normalised = normalise_scope(&scope(
            json!([encode_hex(&first), encode_hex(&second)]),
            Some("7"),
            Some("99"),
        ))
        .expect("valid explicit scope");
        assert!(!normalised.all_assets);
        assert_eq!(normalised.asset_ids, vec![first, second]);
        assert_eq!(normalised.not_before, 7);
        assert_eq!(normalised.not_after, 99);

        let proto = scope_to_proto(&normalised);
        assert!(!proto.all_assets);
        assert_eq!(proto.asset_ids, vec![first.to_vec(), second.to_vec()]);
        assert_eq!(proto.not_before, 7);
        assert_eq!(proto.not_after, 99);
    }

    #[test]
    fn normalise_scope_rejects_every_malformed_asset_shape() {
        assert_malformed(
            normalise_scope(&scope(json!("all"), None, None)),
            "string must be \"*\"",
        );
        assert_malformed(
            normalise_scope(&scope(json!([7]), None, None)),
            "asset_ids[0] must be a hex string",
        );
        assert_malformed(
            normalise_scope(&scope(json!(["abcd"]), None, None)),
            "asset_ids[0]",
        );
        assert_malformed(
            normalise_scope(&scope(json!([]), None, None)),
            "list must be non-empty",
        );
        assert_malformed(
            normalise_scope(&scope(json!({"asset": "x"}), None, None)),
            "must be \"*\" or an array",
        );
    }

    #[test]
    fn normalise_scope_rejects_bad_bounds_order_and_duplicates() {
        assert_malformed(
            normalise_scope(&scope(json!("*"), Some("-1"), None)),
            "scope.not_before",
        );
        assert_malformed(
            normalise_scope(&scope(json!("*"), None, Some("nope"))),
            "scope.not_after",
        );
        assert_malformed(
            normalise_scope(&scope(json!("*"), Some("10"), Some("9"))),
            "time interval is empty",
        );
        let id = encode_hex(&[0x33; 32]);
        assert_malformed(
            normalise_scope(&scope(json!([id, encode_hex(&[0x33; 32])]), None, None)),
            "strictly ascending and unique",
        );
    }

    #[test]
    fn grants_challenge_body_rejects_unknown_top_level_field() {
        let v = json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqun6mw",
            "not_in_spec": true,
        });
        let err = serde_json::from_value::<GrantsChallengeBody>(v).expect_err("deny");
        assert!(
            err.to_string().contains("not_in_spec") || err.to_string().contains("unknown field"),
            "serde must reject unknown field, got {err}"
        );
    }

    #[test]
    fn issue_grant_body_rejects_unknown_nested_scope_field() {
        let v = json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqun6mw",
            "grantee_pk": "00".repeat(32),
            "scope": {
                "asset_ids": "*",
                "ghost": 1,
            },
            "expiry": "1",
            "challenge": {
                "nonce": "00".repeat(32),
                "expiry": "1",
            },
            "ownership_proof": {
                "type": "ownership",
                "subject": "unused",
                "public_key": "00".repeat(32),
                "nk_commit": "00".repeat(32),
                "signature": "00".repeat(64),
            },
        });
        let err = serde_json::from_value::<IssueGrantBody>(v).expect_err("deny nested");
        assert!(
            err.to_string().contains("ghost") || err.to_string().contains("unknown field"),
            "nested deny_unknown_fields must fire, got {err}"
        );
    }
}

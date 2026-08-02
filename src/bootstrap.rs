//! Bootstrap REST surface (§7.7): challenge, entrust, revoke.
//!
//! | Method | Path | Kernel |
//! |---|---|---|
//! | `POST` | `/v1/bootstrap/challenge` | `OpenPullChallenge` action=`entrust`\|`revoke` |
//! | `POST` | `/v1/bootstrap/entrust` | `EntrustOperationalBundle` (after OwnershipProof) |
//! | `POST` | `/v1/bootstrap/revoke` | `RevokeOperationalBundle` (after OwnershipProof) |
//!
//! ## Domain binding
//!
//! Issuance takes `action` in the body and returns the matching domain
//! (`zkCoins/v1/EntrustChallenge` / `zkCoins/v1/RevokeChallenge`). Redeem is
//! **endpoint-bound**: `/entrust` always verifies under Entrust, `/revoke`
//! under Revoke — a proof signed for one cannot authorise the other.
//!
//! ## Secrets
//!
//! `POST /v1/bootstrap/entrust` carries `serialize(OperationalBundle)` (161
//! bytes / five 256-bit secrets). This module never logs the hex, never puts
//! it in an error message, and never includes it in `Debug` output of any
//! type that outlives the parse. Length and hex form are checked **before**
//! the kernel is dialed; a bad body fails at the edge with length/form only.

use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::hexutil::encode_hex;
use crate::kernel::kernel_v1::{
    EntrustRequest, EntrustResult, PullChallengeRequest, RevokeRequest, RevokeResult,
};
use crate::ownership::{
    decode_zk_address, verify_simple_ownership_proof, ChallengeDomain, ChallengeEcho,
    OwnerOnlyProofJson, ENTRUST_CHALLENGE_DOMAIN, REVOKE_CHALLENGE_DOMAIN,
};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

/// Normative fixed length of `serialize(OperationalBundle)` (§7.7 / node
/// `OPERATIONAL_BUNDLE_LEN`): version(1) ‖ five × 32-byte secrets = 161.
pub const OPERATIONAL_BUNDLE_LEN: usize = 161;

/// Hex character count for a 161-byte bundle (`<hex322>`).
pub const OPERATIONAL_BUNDLE_HEX_CHARS: usize = OPERATIONAL_BUNDLE_LEN * 2;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct BootstrapChallengeBody {
    pub subject: String,
    /// `"entrust"` or `"revoke"` — maps to kernel `OpenPullChallenge.action`.
    pub action: String,
}

/// Entrust redeem body. **`Debug` redacts `bundle`** so a logger that prints
/// the extractor cannot spill five operational secrets.
#[derive(Deserialize)]
pub struct BootstrapEntrustBody {
    /// Redeem-body `expiry` (§7.5 normative): `{ nonce, expiry }` from issuance.
    pub challenge: ChallengeEcho,
    pub ownership_proof: OwnerOnlyProofJson,
    /// 161-byte `serialize(OperationalBundle)` as hex (`<hex322>`).
    ///
    /// **Never log this field.** It holds five 256-bit operational secrets.
    pub bundle: String,
}

impl std::fmt::Debug for BootstrapEntrustBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapEntrustBody")
            .field("challenge", &self.challenge)
            .field("ownership_proof", &self.ownership_proof)
            .field("bundle", &"<redacted operational bundle hex>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct BootstrapRevokeBody {
    /// Redeem-body `expiry` (§7.5 normative): `{ nonce, expiry }` from issuance.
    pub challenge: ChallengeEcho,
    pub ownership_proof: OwnerOnlyProofJson,
}

// ---------------------------------------------------------------------------
// Bundle parse (no secret in errors)
// ---------------------------------------------------------------------------

/// Decode and length-check the operational bundle hex.
///
/// Error messages name only the **length** or the **form class** (odd length,
/// non-hex nibble). The raw hex string is **never** interpolated into the
/// message — a distinctive secret hex must not leak through 400 responses.
fn parse_operational_bundle_hex(hex: &str) -> Result<Vec<u8>, ApiError> {
    // Exact character count first: wrong length is the common client mistake
    // and must not fall through to a per-nibble walk that could be logged.
    if hex.len() != OPERATIONAL_BUNDLE_HEX_CHARS {
        return Err(ApiError::malformed(format!(
            "bundle must be exactly {OPERATIONAL_BUNDLE_HEX_CHARS} hex characters \
             ({OPERATIONAL_BUNDLE_LEN} bytes); got {} characters",
            hex.len()
        )));
    }
    // Manual nibble decode so we never surface the input string on failure.
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(OPERATIONAL_BUNDLE_LEN);
    let mut i = 0;
    while i < bytes.len() {
        let hi = match hex_nibble(bytes[i]) {
            Some(v) => v,
            None => {
                return Err(ApiError::malformed(
                    "bundle is not valid hex (non-hex character at even nibble offset)",
                ));
            }
        };
        let lo = match hex_nibble(bytes[i + 1]) {
            Some(v) => v,
            None => {
                return Err(ApiError::malformed(
                    "bundle is not valid hex (non-hex character at odd nibble offset)",
                ));
            }
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    debug_assert_eq!(out.len(), OPERATIONAL_BUNDLE_LEN);
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/bootstrap/challenge` → OpenPullChallenge(action=entrust|revoke).
pub async fn post_bootstrap_challenge(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<BootstrapChallengeBody>,
) -> Result<Response, ApiError> {
    if body.subject.is_empty() {
        return Err(ApiError::malformed("subject is required"));
    }
    let _ = decode_zk_address(&body.subject)?;

    let (action_wire, expected_domain) = match body.action.as_str() {
        "entrust" => ("entrust", ENTRUST_CHALLENGE_DOMAIN),
        "revoke" => ("revoke", REVOKE_CHALLENGE_DOMAIN),
        other => {
            return Err(ApiError::malformed(format!(
                "action must be \"entrust\" or \"revoke\", got {other:?}"
            )));
        }
    };

    let challenge = state
        .kernel
        .open_pull_challenge(PullChallengeRequest {
            subject: body.subject,
            requested_scope: None,
            action: action_wire.to_string(),
        })
        .await?;

    if challenge.nonce.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel Challenge.nonce must be 32 bytes, got {}",
            challenge.nonce.len()
        )));
    }
    // Domain is action-bound at issuance: refuse a kernel that returns a
    // foreign tag (would let a client sign under the wrong domain).
    if challenge.domain != expected_domain {
        return Err(ApiError::internal(format!(
            "kernel Challenge.domain must be {expected_domain:?} for action {action_wire:?}, \
             got {:?}",
            challenge.domain
        )));
    }

    let body = json!({
        "nonce": encode_hex(&challenge.nonce),
        "expiry": challenge.expiry.to_string(),
        "domain": expected_domain,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /v1/bootstrap/entrust` → verify OwnershipProof (Entrust domain), then
/// `EntrustOperationalBundle`.
///
/// Verification and bundle length/form run **before** any kernel call so a
/// bad signature cannot burn the single-use nonce and a 160/162-byte hex
/// never leaves this process as a secret-bearing RPC payload.
pub async fn post_bootstrap_entrust(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<BootstrapEntrustBody>,
) -> Result<Response, ApiError> {
    // ---- pure validation (no kernel) ----
    // Destructure so the hex `bundle` string is dropped before the kernel
    // await (only `bundle_bytes` remains).
    let BootstrapEntrustBody {
        challenge,
        ownership_proof,
        bundle,
    } = body;
    // Bundle first: reject wrong width without touching the challenge store.
    // `parse_operational_bundle_hex` never interpolates the hex into errors.
    let bundle_bytes = parse_operational_bundle_hex(&bundle)?;
    drop(bundle);

    // GrantProof arm → 401; Ownership arm carries the subject (no outer field).
    let ownership_proof = ownership_proof.require_ownership()?;
    let subject = ownership_proof.subject.clone();
    if subject.is_empty() {
        return Err(ApiError::malformed("ownership_proof.subject is required"));
    }

    // Domain is the **endpoint** constant — not body.action, not body.domain.
    let verified = verify_simple_ownership_proof(
        ChallengeDomain::Entrust,
        &subject,
        &challenge,
        &ownership_proof,
        state.public_hosts.as_slice(),
    )?;

    // ---- only now: kernel (nonce consumption lives here) ----
    let result: EntrustResult = state
        .kernel
        .entrust_operational_bundle(EntrustRequest {
            nonce: verified.nonce.to_vec(),
            subject: verified.subject_bech32,
            bundle: bundle_bytes,
            chan_bind: verified.chan_bind.to_vec(),
        })
        .await?;

    let body = json!({ "accepted": result.accepted });
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /v1/bootstrap/revoke` → verify OwnershipProof (Revoke domain), then
/// `RevokeOperationalBundle`.
pub async fn post_bootstrap_revoke(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<BootstrapRevokeBody>,
) -> Result<Response, ApiError> {
    let ownership_proof = body.ownership_proof.require_ownership()?;
    let subject = ownership_proof.subject.clone();
    if subject.is_empty() {
        return Err(ApiError::malformed("ownership_proof.subject is required"));
    }

    let verified = verify_simple_ownership_proof(
        ChallengeDomain::Revoke,
        &subject,
        &body.challenge,
        &ownership_proof,
        state.public_hosts.as_slice(),
    )?;

    let result: RevokeResult = state
        .kernel
        .revoke_operational_bundle(RevokeRequest {
            nonce: verified.nonce.to_vec(),
            subject: verified.subject_bech32,
            chan_bind: verified.chan_bind.to_vec(),
        })
        .await?;

    let body = json!({ "revoked": result.revoked });
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_len_constants_match_spec() {
        assert_eq!(OPERATIONAL_BUNDLE_LEN, 161);
        assert_eq!(OPERATIONAL_BUNDLE_HEX_CHARS, 322);
    }

    #[test]
    fn bundle_wrong_length_does_not_echo_hex() {
        // 160 bytes = 320 hex chars — distinctive secret pattern must not
        // appear in the error message.
        let secret = "ab".repeat(160);
        assert_eq!(secret.len(), 320);
        let err = parse_operational_bundle_hex(&secret).expect_err("160 bytes");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            !err.body.message.contains(&secret),
            "error must not contain the bundle hex: {}",
            err.body.message
        );
        assert!(
            err.body.message.contains("320") || err.body.message.contains("322"),
            "error should report character counts: {}",
            err.body.message
        );

        let secret162 = "cd".repeat(162);
        let err = parse_operational_bundle_hex(&secret162).expect_err("162 bytes");
        assert!(!err.body.message.contains(&secret162));
    }

    #[test]
    fn bundle_161_bytes_accepted() {
        let hex = "01".to_string() + &"00".repeat(160);
        assert_eq!(hex.len(), 322);
        let bytes = parse_operational_bundle_hex(&hex).expect("161 bytes");
        assert_eq!(bytes.len(), 161);
        assert_eq!(bytes[0], 0x01);
    }

    #[test]
    fn bundle_non_hex_does_not_echo_input() {
        let mut hex = "ee".repeat(161);
        // Force a non-hex character in the middle without changing length.
        hex.replace_range(100..102, "zz");
        let err = parse_operational_bundle_hex(&hex).expect_err("non-hex");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            !err.body.message.contains("zz"),
            "error must not echo the bad nibble context: {}",
            err.body.message
        );
        assert!(!err.body.message.contains(&hex));
    }
}

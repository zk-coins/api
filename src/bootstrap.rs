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
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
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
#[serde(deny_unknown_fields)]
pub struct BootstrapChallengeBody {
    pub subject: String,
    /// `"entrust"` or `"revoke"` — maps to kernel `OpenPullChallenge.action`.
    pub action: String,
}

/// Entrust redeem body. **`Debug` redacts `bundle`** so a logger that prints
/// the extractor cannot spill five operational secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

    // Copy out the `op` secret (§7.7 layout offset 65..97 — the operational
    // signing key, NOT the unrelated `op_secret` nav_rand field at
    // 129..161) before `bundle_bytes` moves into the kernel request below.
    // Only the derived PUBLIC key is ever installed into subject_ops, and
    // only after the kernel confirms the entrust succeeded (see below) —
    // this is just a byte copy so the value survives that move.
    let op_secret_bytes: [u8; 32] = bundle_bytes
        .get(65..97)
        .ok_or_else(|| {
            // parse_operational_bundle_hex already requires exactly 161 bytes
            #[cfg_attr(coverage_nightly, coverage(off))]
            {
                ApiError::internal("operational bundle too short to hold the op secret at [65..97]")
            }
        })?
        .try_into()
        .map_err(|_| {
            // parse_operational_bundle_hex already requires exactly 161 bytes
            #[cfg_attr(coverage_nightly, coverage(off))]
            {
                ApiError::internal("op secret slice is not exactly 32 bytes")
            }
        })?;

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

    // Population point (Requirement 9(c)): the kernel just accepted THIS
    // subject's own entrusted bundle under an authenticated OwnershipProof
    // — this is the moment the api co-located with the node legitimately
    // learns the subject's real op_pubkey. Only on success; a rejected
    // entrust must never seed the directory with an unconfirmed key.
    if result.accepted {
        let secp = Secp256k1::new();
        let op_sk = SecretKey::from_slice(&op_secret_bytes).map_err(|_| {
            ApiError::internal("entrusted bundle op field is not a valid secp256k1 secret key")
        })?;
        let op_kp = Keypair::from_secret_key(&secp, &op_sk);
        let (op_xonly, _parity) = op_kp.x_only_public_key();
        state
            .subject_ops
            .insert(verified.subject_raw, op_xonly.serialize());
    }

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

    // §7.7 cease-use: drop the cached op so grant proofs under the revoked
    // key fail closed immediately (no process restart required). Only when
    // the kernel actually revoked — a no-op revoke must not clear a live op.
    if result.revoked {
        state.subject_ops.remove(&verified.subject_raw);
    }

    let body = json!({ "revoked": result.revoked });
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::connect_lazy;
    use crate::ownership::{
        encode_zk_address, GrantRevokeChallengeStore, RevokedGrantSet, SubjectOpDirectory,
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

    /// Distinctive secret hex; Debug must never emit this substring.
    fn distinctive_bundle_marker() -> String {
        "B00B1E5C0FFEE_OPERATIONAL_BUNDLE_MARKER".to_string()
    }

    #[test]
    fn bundle_len_constants_match_spec() {
        assert_eq!(OPERATIONAL_BUNDLE_LEN, 161);
        assert_eq!(OPERATIONAL_BUNDLE_HEX_CHARS, 322);
    }

    #[test]
    fn entrust_body_debug_redacts_bundle() {
        let marker = distinctive_bundle_marker();
        let body = BootstrapEntrustBody {
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
            bundle: marker.clone(),
        };
        let rendered = format!("{body:?}");
        assert!(
            rendered.contains("redacted"),
            "Debug must use the redaction marker, got {rendered}"
        );
        assert!(
            !rendered.contains(&marker),
            "Debug must not leak the operational bundle hex: {rendered}"
        );
    }

    #[tokio::test]
    async fn challenge_unknown_action_is_malformed_before_kernel() {
        let subject = encode_zk_address(&[0u8; 32]);
        let err = post_bootstrap_challenge(
            State(dummy_state()),
            JsonBody(BootstrapChallengeBody {
                subject,
                action: "transfer".into(),
            }),
        )
        .await
        .expect_err("unknown action");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("entrust")
                && err.body.message.contains("revoke")
                && err.body.message.contains("transfer"),
            "message must name the closed set and the bad token, got {:?}",
            err.body.message
        );
    }

    #[tokio::test]
    async fn challenge_empty_subject_is_malformed_before_kernel() {
        let err = post_bootstrap_challenge(
            State(dummy_state()),
            JsonBody(BootstrapChallengeBody {
                subject: String::new(),
                action: "entrust".into(),
            }),
        )
        .await
        .expect_err("empty subject");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("subject is required"),
            "got {:?}",
            err.body.message
        );
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

    #[test]
    fn bundle_non_hex_odd_nibble_does_not_echo_input() {
        let mut hex = "ee".repeat(161);
        // Odd index: covers the second nibble of a byte pair.
        hex.replace_range(101..102, "z");
        let err = parse_operational_bundle_hex(&hex).expect_err("non-hex odd nibble");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            !err.body.message.contains("z"),
            "error must not echo the bad nibble: {}",
            err.body.message
        );
        assert!(!err.body.message.contains(&hex));
    }

    #[test]
    fn entrust_body_debug_redacts_operational_bundle_hex() {
        let secret = "ab".repeat(161);
        let body = BootstrapEntrustBody {
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
            bundle: secret.clone(),
        };
        let dbg = format!("{body:?}");
        assert!(
            dbg.contains("<redacted operational bundle hex>"),
            "Debug must show redaction marker, got {dbg}"
        );
        assert!(
            !dbg.contains(&secret),
            "Debug must not contain the real bundle hex"
        );
    }

    #[test]
    fn bootstrap_challenge_body_rejects_unknown_top_level_field() {
        let v = serde_json::json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqun6mw",
            "action": "entrust",
            "not_in_spec": true,
        });
        let err = serde_json::from_value::<BootstrapChallengeBody>(v).expect_err("deny");
        assert!(
            err.to_string().contains("not_in_spec") || err.to_string().contains("unknown field"),
            "serde must reject unknown field, got {err}"
        );
    }

    #[test]
    fn bootstrap_entrust_body_rejects_unknown_nested_challenge_field() {
        let v = serde_json::json!({
            "challenge": {
                "nonce": "00".repeat(32),
                "expiry": "1",
                "ghost": true,
            },
            "ownership_proof": {
                "type": "ownership",
                "subject": "unused",
                "public_key": "00".repeat(32),
                "nk_commit": "00".repeat(32),
                "signature": "00".repeat(64),
            },
            "bundle": "00".repeat(OPERATIONAL_BUNDLE_HEX_CHARS / 2),
        });
        let err = serde_json::from_value::<BootstrapEntrustBody>(v).expect_err("deny nested");
        assert!(
            err.to_string().contains("ghost") || err.to_string().contains("unknown field"),
            "nested deny_unknown_fields must fire, got {err}"
        );
    }
}

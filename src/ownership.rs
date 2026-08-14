//! Action-bound OwnershipProof verification at the API edge (§5.1 / §7.5).
//!
//! The kernel gRPC surface carries **no** OwnershipProof fields: this module
//! is the sole place that verifies BIP-340 ownership before any kernel call
//! that would consume a challenge nonce.
//!
//! ## Domain binding
//!
//! Challenge domains are endpoint-selected constants ([`ChallengeDomain`]).
//! Callers pass the domain of the route they are serving — never a string
//! from the request body. A proof signed under AttestBalance cannot authorise
//! IssueGrant, and vice versa.
//!
//! ## Nonce non-consumption
//!
//! Every check in [`verify_ownership_proof`] is pure. The kernel is only
//! dialed by the handler **after** this function returns `Ok`. A failed
//! signature therefore cannot burn the single-use nonce in the kernel store.

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use bitcoin::secp256k1::{
    schnorr::Signature as SchnorrSignature, Message, Secp256k1, XOnlyPublicKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Domain tags — taken from node `ChallengeAction::domain()` (sole definition
// there). Word-for-word match is the cryptographic action binding.
// ---------------------------------------------------------------------------

/// `ChallengeAction::Pull.domain()` in
/// `node/src/kernel/bootstrap/challenges.rs`.
pub const PULL_CHALLENGE_DOMAIN: &str = "zkCoins/v1/PullChallenge";

/// `ChallengeAction::AttestBalance.domain()` in
/// `node/src/kernel/bootstrap/challenges.rs`.
pub const ATTEST_BALANCE_CHALLENGE_DOMAIN: &str = "zkCoins/v1/AttestBalanceChallenge";

/// `ChallengeAction::IssueViewGrant.domain()` in
/// `node/src/kernel/bootstrap/challenges.rs`.
pub const ISSUE_GRANT_CHALLENGE_DOMAIN: &str = "zkCoins/v1/IssueGrantChallenge";

/// `ChallengeAction::Entrust.domain()` in
/// `node/src/kernel/bootstrap/challenges.rs`.
pub const ENTRUST_CHALLENGE_DOMAIN: &str = "zkCoins/v1/EntrustChallenge";

/// `ChallengeAction::Revoke.domain()` in
/// `node/src/kernel/bootstrap/challenges.rs`.
pub const REVOKE_CHALLENGE_DOMAIN: &str = "zkCoins/v1/RevokeChallenge";

/// api-local — §5.2 grant revocation has no kernel-side challenge (the
/// kernel does not know about grants). Issued and redeemed entirely by
/// `GrantRevokeChallengeStore`.
pub const REVOKE_GRANT_CHALLENGE_DOMAIN: &str = "zkCoins/v1/RevokeGrantChallenge";

/// §7.5 `request_hash` tag for `POST /v1/attest/balance`.
pub const ATTEST_BALANCE_REQUEST_TAG: &str = "zkCoins/v1/AttestBalance";

/// §7.5 `request_hash` tag for `POST /v1/grants`.
pub const ISSUE_GRANT_REQUEST_TAG: &str = "zkCoins/v1/IssueGrant";

/// §5.1 clearnet `chan_bind` host domain.
pub const PULL_HOST_DOMAIN: &str = "zkCoins/v1/PullHost";

/// Bech32m HRP for a zkCoins address (§1.7.7).
pub const ADDRESS_HRP: &str = "zk";

/// Bech32m HRP for a serialised view grant (§5.2 / §1.7.7).
pub const GRANT_HRP: &str = "zkgrant";

/// §5.2 `grant_message` domain tag (Foundations `Grant` context).
pub const GRANT_MESSAGE_TAG: &str = "zkCoins/v1/Grant";

/// §5.2 grant version byte (currently always `0x01`).
pub const GRANT_VERSION: u8 = 0x01;

/// Unbounded `not_after` sentinel: `2⁶³−1` (§5.1).
pub const SCOPE_NOT_AFTER_UNBOUNDED: u64 = 9_223_372_036_854_775_807;

// Lock the §5.1 bit-pattern: unbounded not_after is exactly i64::MAX as u64.
const _: () = assert!(SCOPE_NOT_AFTER_UNBOUNDED == i64::MAX as u64);

// Goldilocks field order — nk_commit limbs on the wire must be strictly `< p`
// (same fail-loud rule as node `digest_from_bytes`).
const GOLDILOCKS_ORDER: u64 = 0xffff_ffff_0000_0001;

/// Closed set of challenge domains this stage verifies.
///
/// The domain string is a method on the enum — callers cannot pass an
/// arbitrary domain from the request body. Entrust and Revoke are distinct
/// from Pull so a proof cannot be retargeted across bootstrap actions (§7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeDomain {
    /// `POST /v1/pull` — no `request_hash` in `chal` (§5.1 L1916).
    Pull,
    AttestBalance,
    IssueGrant,
    /// `POST /v1/bootstrap/entrust` — no `request_hash` (§7.7).
    Entrust,
    /// `POST /v1/bootstrap/revoke` — no `request_hash` (§7.7).
    Revoke,
    /// `POST /v1/grants/revoke` — api-local, no kernel Redeem (§5.2).
    RevokeGrant,
}

impl ChallengeDomain {
    /// Normative domain tag for this action (§5.1 table / node source).
    pub const fn as_str(self) -> &'static str {
        match self {
            ChallengeDomain::Pull => PULL_CHALLENGE_DOMAIN,
            ChallengeDomain::AttestBalance => ATTEST_BALANCE_CHALLENGE_DOMAIN,
            ChallengeDomain::IssueGrant => ISSUE_GRANT_CHALLENGE_DOMAIN,
            ChallengeDomain::Entrust => ENTRUST_CHALLENGE_DOMAIN,
            ChallengeDomain::Revoke => REVOKE_CHALLENGE_DOMAIN,
            ChallengeDomain::RevokeGrant => REVOKE_GRANT_CHALLENGE_DOMAIN,
        }
    }

    /// Whether `chal` omits `request_hash` (pull / bootstrap).
    pub const fn is_simple(self) -> bool {
        matches!(
            self,
            ChallengeDomain::Pull
                | ChallengeDomain::Entrust
                | ChallengeDomain::Revoke
                | ChallengeDomain::RevokeGrant
        )
    }
}

/// §7.5 / §5.1(a) `OwnershipProofJson` on the wire.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipProofJson {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub subject: String,
    pub public_key: String,
    pub nk_commit: String,
    pub signature: String,
}

/// Tagged proof union for **owner-only** endpoints (Attest, IssueGrant,
/// Entrust, Revoke). Deserialises a real GrantProof shape as the `grant` arm
/// so clients receive `401 unauthorized` (capability gate) rather than
/// `400 malformed_request` from missing Ownership fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum OwnerOnlyProofJson {
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

impl OwnerOnlyProofJson {
    /// Reject GrantProof with `401 unauthorized`; return OwnershipProof fields.
    pub fn require_ownership(self) -> Result<OwnershipProofJson, ApiError> {
        match self {
            Self::Ownership {
                subject,
                public_key,
                nk_commit,
                signature,
            } => Ok(OwnershipProofJson {
                proof_type: "ownership".into(),
                subject,
                public_key,
                nk_commit,
                signature,
            }),
            Self::Grant { .. } => Err(ApiError::unauthorized(
                "GrantProof does not authorise this owner-only action \
                 (AttestBalance / IssueViewGrant / Entrust / Revoke require OwnershipProof; \
                 no-escalation)",
            )),
        }
    }
}

/// Validate normalised scope invariants before any Challenge/Redeem RPC:
/// - explicit `asset_ids` strictly ascending and unique;
/// - time interval non-empty (`not_before <= not_after`).
pub fn validate_resolved_scope(scope: &ResolvedScope) -> Result<(), ApiError> {
    if !scope.all_assets {
        if scope.asset_ids.is_empty() {
            return Err(ApiError::malformed(
                "scope.asset_ids list must be non-empty when not \"*\"",
            ));
        }
        for window in scope.asset_ids.windows(2) {
            if window[0] >= window[1] {
                return Err(ApiError::malformed(
                    "scope.asset_ids must be strictly ascending and unique",
                ));
            }
        }
    } else if !scope.asset_ids.is_empty() {
        return Err(ApiError::internal(
            "ResolvedScope invariant: all_assets with non-empty asset_ids",
        ));
    }
    if scope.not_before > scope.not_after {
        return Err(ApiError::malformed(
            "scope time interval is empty (not_before > not_after)",
        ));
    }
    Ok(())
}

/// Challenge fields echoed by the client so the API can recompute `chal`
/// without holding challenge state.
///
/// Spec §7.5 abbreviated bodies list only `nonce` (the monlithic node looked
/// up `expiry` from its local store). On a **stateless** API edge the client
/// MUST resubmit the issued `expiry` so BIP-340 verification can run
/// **before** any kernel call that would consume the nonce.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeEcho {
    pub nonce: String,
    /// §7.1 decimal-string u64 (same wire form as the challenge response).
    pub expiry: String,
}

/// Outcome of a successful OwnershipProof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnership {
    /// Bech32m subject string as accepted on the request.
    pub subject_bech32: String,
    /// 32-byte address digest (`H(Pk₀ ‖ nk_commit)`).
    pub subject_raw: [u8; 32],
    pub nonce: [u8; 32],
    /// Challenge expiry from the client echo (bound into the signed `chal`).
    pub challenge_expiry: u64,
    /// The authoritative `chan_bind` that accepted the signature.
    pub chan_bind: [u8; 32],
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `chan_bind = H("zkCoins/v1/PullHost" ‖ host)` for clearnet (§5.1).
///
/// `host` must already be the server's canonical authority (from config),
/// never a client-supplied or `Host`-header value.
pub fn chan_bind_for_host(host: &str) -> [u8; 32] {
    let mut pre = Vec::with_capacity(PULL_HOST_DOMAIN.len() + host.len());
    pre.extend_from_slice(PULL_HOST_DOMAIN.as_bytes());
    pre.extend_from_slice(host.as_bytes());
    sha256(&pre)
}

/// `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry ‖ request_hash)`.
///
/// Spec §5.1 L1963 (AttestBalance / IssueGrant form with `request_hash`).
/// `domain` is UTF-8 of the action tag; `nonce`/`chan_bind`/`subject`/
/// `request_hash` are 32 raw bytes; `expiry` is u64 big-endian.
pub fn ownership_challenge_message(
    domain: &str,
    nonce: &[u8; 32],
    chan_bind: &[u8; 32],
    subject: &[u8; 32],
    expiry: u64,
    request_hash: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(domain.len() + 32 + 32 + 32 + 8 + 32);
    pre.extend_from_slice(domain.as_bytes());
    pre.extend_from_slice(nonce);
    pre.extend_from_slice(chan_bind);
    pre.extend_from_slice(subject);
    pre.extend_from_slice(&expiry.to_be_bytes());
    pre.extend_from_slice(request_hash);
    sha256(&pre)
}

/// `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry)` for pull / bootstrap
/// (§5.1 L1916 — no `request_hash`).
///
/// `domain` is UTF-8 of the action tag; `nonce`/`chan_bind`/`subject` are 32
/// raw bytes; `expiry` is u64 big-endian. Body `expiry` is bound into this
/// digest (Redeem-body `expiry` normative): a forged value yields a different
/// `chal` and fails signature verification.
pub fn pull_challenge_message(
    domain: &str,
    nonce: &[u8; 32],
    chan_bind: &[u8; 32],
    subject: &[u8; 32],
    expiry: u64,
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(domain.len() + 32 + 32 + 32 + 8);
    pre.extend_from_slice(domain.as_bytes());
    pre.extend_from_slice(nonce);
    pre.extend_from_slice(chan_bind);
    pre.extend_from_slice(subject);
    pre.extend_from_slice(&expiry.to_be_bytes());
    sha256(&pre)
}

/// Ceiling encoding for attest `request_hash` (§7.5 L2894):
/// - both omitted → `0x00`
/// - both present → `0x01 ‖ nav_ceiling (32B) ‖ u64-be(size_ceiling)`
/// - any other combination → `400 malformed_request`
pub fn ceiling_encoding(
    nav_ceiling: Option<&[u8; 32]>,
    size_ceiling: Option<u64>,
) -> Result<Vec<u8>, ApiError> {
    match (nav_ceiling, size_ceiling) {
        (None, None) => Ok(vec![0x00]),
        (Some(nav), Some(size)) => {
            let mut out = Vec::with_capacity(1 + 32 + 8);
            out.push(0x01);
            out.extend_from_slice(nav);
            out.extend_from_slice(&size.to_be_bytes());
            Ok(out)
        }
        _ => Err(ApiError::malformed(
            "nav_ceiling and size_ceiling must both be present or both omitted (§7.5)",
        )),
    }
}

/// `request_hash = H("zkCoins/v1/AttestBalance" ‖ subject ‖ asset_id ‖ ceiling_encoding)`.
pub fn attest_request_hash(
    subject: &[u8; 32],
    asset_id: &[u8; 32],
    ceiling_enc: &[u8],
) -> [u8; 32] {
    let mut pre =
        Vec::with_capacity(ATTEST_BALANCE_REQUEST_TAG.len() + 32 + 32 + ceiling_enc.len());
    pre.extend_from_slice(ATTEST_BALANCE_REQUEST_TAG.as_bytes());
    pre.extend_from_slice(subject);
    pre.extend_from_slice(asset_id);
    pre.extend_from_slice(ceiling_enc);
    sha256(&pre)
}

/// Encode grant `asset_ids` as in `grant_message` (§5.2): `0x00` for `*`,
/// or `0x01 ‖ u32-be count ‖ ascending 32-byte ids`.
pub fn encode_grant_asset_ids(
    all_assets: bool,
    asset_ids: &[[u8; 32]],
) -> Result<Vec<u8>, ApiError> {
    if all_assets {
        if !asset_ids.is_empty() {
            return Err(ApiError::malformed(
                "scope.asset_ids must be empty when asset_ids is \"*\"",
            ));
        }
        return Ok(vec![0x00]);
    }
    if asset_ids.is_empty() {
        return Err(ApiError::malformed(
            "scope.asset_ids list must be non-empty when not \"*\"",
        ));
    }
    for w in asset_ids.windows(2) {
        if w[0] >= w[1] {
            return Err(ApiError::malformed(
                "scope.asset_ids must be strictly ascending",
            ));
        }
    }
    let count = u32::try_from(asset_ids.len())
        .map_err(|_| ApiError::malformed("scope.asset_ids count exceeds u32"))?;
    let mut out = Vec::with_capacity(1 + 4 + asset_ids.len() * 32);
    out.push(0x01);
    out.extend_from_slice(&count.to_be_bytes());
    for id in asset_ids {
        out.extend_from_slice(id);
    }
    Ok(out)
}

/// `request_hash = H("zkCoins/v1/IssueGrant" ‖ subject ‖ grantee_pk ‖
/// asset_ids ‖ not_before ‖ not_after ‖ expiry)` (§7.5 L2896).
pub fn issue_grant_request_hash(
    subject: &[u8; 32],
    grantee_pk: &[u8; 32],
    asset_enc: &[u8],
    not_before: u64,
    not_after: u64,
    grant_expiry: u64,
) -> [u8; 32] {
    let mut pre =
        Vec::with_capacity(ISSUE_GRANT_REQUEST_TAG.len() + 32 + 32 + asset_enc.len() + 8 + 8 + 8);
    pre.extend_from_slice(ISSUE_GRANT_REQUEST_TAG.as_bytes());
    pre.extend_from_slice(subject);
    pre.extend_from_slice(grantee_pk);
    pre.extend_from_slice(asset_enc);
    pre.extend_from_slice(&not_before.to_be_bytes());
    pre.extend_from_slice(&not_after.to_be_bytes());
    pre.extend_from_slice(&grant_expiry.to_be_bytes());
    sha256(&pre)
}

// ---------------------------------------------------------------------------
// Wire parsers
// ---------------------------------------------------------------------------

/// Parse a §7.1 canonical decimal-string u64 (`0|[1-9][0-9]*`).
pub fn parse_u64_decimal(s: &str) -> Result<u64, ApiError> {
    if s.is_empty() {
        return Err(ApiError::malformed("empty decimal string"));
    }
    if s == "0" {
        return Ok(0);
    }
    if s.as_bytes()[0] == b'0' {
        return Err(ApiError::malformed(
            "leading zeros are not allowed in canonical u64 decimal strings",
        ));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::malformed(
            "decimal string must contain only ASCII digits",
        ));
    }
    s.parse::<u64>()
        .map_err(|_| ApiError::malformed(format!("decimal string out of u64 range: {s}")))
}

/// Decode a Bech32m `zk` address to its 32-byte payload.
pub fn decode_zk_address(s: &str) -> Result<[u8; 32], ApiError> {
    let checked = CheckedHrpstring::new::<Bech32m>(s)
        .map_err(|e| ApiError::malformed(format!("subject: invalid Bech32m address: {e}")))?;
    if checked.hrp().as_str() != ADDRESS_HRP {
        return Err(ApiError::malformed(format!(
            "subject: expected HRP {ADDRESS_HRP:?}, got {:?}",
            checked.hrp().as_str()
        )));
    }
    let data: Vec<u8> = checked.byte_iter().collect();
    if data.len() != 32 {
        return Err(ApiError::malformed(format!(
            "subject: address payload must be 32 bytes, got {}",
            data.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

/// Encode 32 raw address bytes as Bech32m `zk` (tests / helpers).
#[cfg(test)]
pub fn encode_zk_address(raw: &[u8; 32]) -> String {
    let hrp = bech32::Hrp::parse(ADDRESS_HRP).expect("constant HRP");
    bech32::encode::<Bech32m>(hrp, raw).expect("32-byte payload encodes")
}

/// Parse a fixed-width hex field that is **not** a proof credential (e.g.
/// `challenge.nonce`). Bad hex → `400 malformed_request`.
fn parse_hex32_field(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let v = decode_hex_exact(s, 32).map_err(|e| ApiError::malformed(format!("{field}: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Parse an OwnershipProof / GrantProof hex field. Bad hex (wrong width,
/// non-hex, odd length) → `401 unauthorized` (§7.5 proof-field rule).
fn parse_proof_hex32(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let v = decode_hex_exact(s, 32).map_err(|e| ApiError::unauthorized(format!("{field}: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn parse_proof_hex64(s: &str, field: &str) -> Result<[u8; 64], ApiError> {
    let v = decode_hex_exact(s, 64).map_err(|e| ApiError::unauthorized(format!("{field}: {e}")))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Reject non-canonical Goldilocks limbs in an `nk_commit` wire value.
fn validate_nk_commit_limbs(bytes: &[u8; 32]) -> Result<(), ApiError> {
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let limb = u64::from_be_bytes(buf);
        if limb >= GOLDILOCKS_ORDER {
            return Err(ApiError::malformed(format!(
                "ownership_proof.nk_commit: non-canonical Goldilocks limb {i}"
            )));
        }
    }
    Ok(())
}

/// `address = SHA-256(Pk₀ ‖ nk_commit_bytes)` (§1.4) where `nk_commit_bytes`
/// is the canonical 32-byte digest encoding on the wire.
fn address_from_pk0_nk_commit(pk0: &[u8; 32], nk_commit: &[u8; 32]) -> [u8; 32] {
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(pk0);
    pre[32..].copy_from_slice(nk_commit);
    sha256(&pre)
}

// ---------------------------------------------------------------------------
// BIP-340
// ---------------------------------------------------------------------------

/// Verify BIP-340 Schnorr over a 32-byte message digest under an x-only key.
///
/// Uses `bitcoin::secp256k1` — the same stack as zk-coins/node.
/// `fail_message` is returned on cryptographic mismatch (wrong key, bad sig,
/// wrong preimage) so callers can name OwnershipProof vs GrantProof context.
pub fn verify_bip340(
    pk: &[u8; 32],
    signature: &[u8; 64],
    message_digest: &[u8; 32],
) -> Result<(), ApiError> {
    verify_bip340_with_message(
        pk,
        signature,
        message_digest,
        "public key is not a valid x-only pubkey",
        "signature is not a valid BIP-340 signature",
        "BIP-340 signature invalid (key, preimage, or chan_bind/domain mismatch)",
    )
}

/// BIP-340 verify with caller-chosen unauthorized messages (grant vs ownership).
pub fn verify_bip340_with_message(
    pk: &[u8; 32],
    signature: &[u8; 64],
    message_digest: &[u8; 32],
    bad_pk_message: &str,
    bad_sig_encoding_message: &str,
    verify_fail_message: &str,
) -> Result<(), ApiError> {
    let xonly = XOnlyPublicKey::from_slice(pk)
        .map_err(|_| ApiError::unauthorized(bad_pk_message.to_string()))?;
    let sig = SchnorrSignature::from_slice(signature)
        .map_err(|_| ApiError::unauthorized(bad_sig_encoding_message.to_string()))?;
    let msg = Message::from_digest_slice(message_digest)
        .map_err(|_| ApiError::internal("BIP-340 message digest must be 32 bytes"))?;
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| ApiError::unauthorized(verify_fail_message.to_string()))
}

// ---------------------------------------------------------------------------
// Capability gate (order-independent GrantProof rejection)
// ---------------------------------------------------------------------------

/// Closed capability kind for owner-only actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerOnlyCapability {
    Ownership,
    Grant,
}

fn capability_from_wire(proof_type: &str) -> Result<OwnerOnlyCapability, ApiError> {
    match proof_type {
        "ownership" => Ok(OwnerOnlyCapability::Ownership),
        "grant" => Ok(OwnerOnlyCapability::Grant),
        other => Err(ApiError::unauthorized(format!(
            "unknown capability type {other:?}; only OwnershipProof authorises this action"
        ))),
    }
}

fn require_ownership(kind: OwnerOnlyCapability) -> Result<(), ApiError> {
    match kind {
        OwnerOnlyCapability::Ownership => Ok(()),
        OwnerOnlyCapability::Grant => Err(ApiError::unauthorized(
            "GrantProof does not authorise this owner-only action \
             (AttestBalance / IssueViewGrant / Entrust / Revoke require OwnershipProof; \
             no-escalation)",
        )),
    }
}

// ---------------------------------------------------------------------------
// Main gate
// ---------------------------------------------------------------------------

/// Verify an action-bound OwnershipProof **without** calling the kernel.
///
/// # Arguments
///
/// * `domain` — from the **endpoint**, via [`ChallengeDomain`] (not the body)
/// * `request_subject` — Bech32m subject on the outer request
/// * `challenge` — client echo of issued `{ nonce, expiry }`
/// * `proof` — `OwnershipProofJson`
/// * `request_hash` — server-computed digest of the request body fields
/// * `public_hosts` — authoritative hosts from server config
///
/// On success returns the `chan_bind` that accepted the signature and the
/// decoded subject/nonce for the subsequent kernel RPC.
pub fn verify_ownership_proof(
    domain: ChallengeDomain,
    request_subject: &str,
    challenge: &ChallengeEcho,
    proof: &OwnershipProofJson,
    request_hash: &[u8; 32],
    public_hosts: &[String],
) -> Result<VerifiedOwnership, ApiError> {
    // 1. Closed capability match — GrantProof rejected by typed arm.
    let capability = capability_from_wire(&proof.proof_type)?;
    require_ownership(capability)?;

    // 2. Subject identity (Bech32m + proof subject equality).
    let subject_raw = decode_zk_address(request_subject)?;
    let proof_subject_raw = decode_zk_address(&proof.subject)?;
    if proof_subject_raw != subject_raw {
        return Err(ApiError::unauthorized(
            "ownership_proof.subject does not match request subject",
        ));
    }

    // 3. Parse fixed-width proof fields (401) and challenge.nonce (400).
    let pk0 = parse_proof_hex32(&proof.public_key, "ownership_proof.public_key")?;
    let nk_commit = parse_proof_hex32(&proof.nk_commit, "ownership_proof.nk_commit")?;
    validate_nk_commit_limbs(&nk_commit)?;
    let signature = parse_proof_hex64(&proof.signature, "ownership_proof.signature")?;
    let nonce = parse_hex32_field(&challenge.nonce, "challenge.nonce")?;
    let challenge_expiry = parse_u64_decimal(&challenge.expiry)
        .map_err(|e| ApiError::malformed(format!("challenge.expiry: {}", e.body.message)))?;

    // 4. Address binding: H(Pk₀ ‖ nk_commit) == subject (§5.1(a)).
    let expected = address_from_pk0_nk_commit(&pk0, &nk_commit);
    if expected != subject_raw {
        return Err(ApiError::unauthorized(
            "H(Pk0 ‖ nk_commit) does not equal subject address",
        ));
    }

    // 5. Authoritative chan_bind set (config only — never Host header).
    if public_hosts.is_empty() {
        return Err(ApiError::internal(
            "no authoritative public hosts configured for chan_bind (ZKCOINS_PUBLIC_HOST)",
        ));
    }
    let allowed: Vec<[u8; 32]> = public_hosts.iter().map(|h| chan_bind_for_host(h)).collect();

    // 6. BIP-340 over chal under the **endpoint** domain. Try each host's
    //    chan_bind; accept the first that verifies. Domain is NOT taken from
    //    the body — a proof signed under the other action domain fails here.
    let domain_str = domain.as_str();
    let mut accepted_bind: Option<[u8; 32]> = None;
    for cb in &allowed {
        let chal = ownership_challenge_message(
            domain_str,
            &nonce,
            cb,
            &subject_raw,
            challenge_expiry,
            request_hash,
        );
        if verify_bip340(&pk0, &signature, &chal).is_ok() {
            accepted_bind = Some(*cb);
            break;
        }
    }
    let chan_bind = match accepted_bind {
        Some(b) => b,
        None => {
            return Err(ApiError::unauthorized(
                "OwnershipProof signature invalid or chan_bind/domain mismatch",
            ));
        }
    };

    Ok(VerifiedOwnership {
        subject_bech32: request_subject.to_string(),
        subject_raw,
        nonce,
        challenge_expiry,
        chan_bind,
    })
}

/// §7.5 `GrantProofJson` on the wire (pull path only).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantProofJson {
    #[serde(rename = "type")]
    pub proof_type: String,
    /// Bech32m `zkgrant` string (§5.2).
    pub grant: String,
    pub grantee_pk: String,
    pub signature: String,
}

/// Session authority that follows from the verified proof kind.
///
/// Wire tokens match the interim kernel metadata
/// `x-zkcoins-session-authority` (`ownership` | `grant`) in
/// `node/src/kernel_rpc.rs` / `parse_session_authority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthority {
    Ownership,
    Grant,
}

impl SessionAuthority {
    /// Metadata / wire token. Never empty; never a defaulted ownership.
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionAuthority::Ownership => "ownership",
            SessionAuthority::Grant => "grant",
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved scope (§5.1) — intersection of request and capability
// ---------------------------------------------------------------------------

/// Normalised pull/grant scope after unbounded-sentinel normalisation.
///
/// Shape matches `ViewGrant.scope` minus grant-only `expiry`: assets × time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedScope {
    pub all_assets: bool,
    /// Empty iff `all_assets`. Strictly ascending when non-empty.
    pub asset_ids: Vec<[u8; 32]>,
    pub not_before: u64,
    pub not_after: u64,
}

impl ResolvedScope {
    /// Unbounded sentinel pair: `asset_ids = "*"`, `not_before = 0`,
    /// `not_after = 2⁶³−1` (§5.1).
    pub fn unbounded() -> Self {
        Self {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        }
    }

    /// True only when every dimension uses its unbounded sentinel.
    pub fn is_fully_unbounded(&self) -> bool {
        self.all_assets && self.not_before == 0 && self.not_after == SCOPE_NOT_AFTER_UNBOUNDED
    }
}

/// Decoded §5.2 `ViewGrant` (payload fields; signature checked separately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedViewGrant {
    pub version: u8,
    pub subject: [u8; 32],
    pub grantee: [u8; 32],
    pub scope: ResolvedScope,
    /// Grant usability deadline (unix seconds) — not part of pull scope.
    pub expiry: u64,
    pub nonce: [u8; 16],
    pub op_signature: [u8; 64],
    /// `grant_id = H(grant_message)` (§5.2).
    pub grant_id: [u8; 32],
    /// Preimage of `grant_message` after the domain tag (version…nonce).
    pub message_prefix: Vec<u8>,
}

/// Outcome of a successful GrantProof verification (§5.1(b)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub subject_bech32: String,
    pub subject_raw: [u8; 32],
    pub grantee_pk: [u8; 32],
    pub nonce: [u8; 32],
    pub challenge_expiry: u64,
    pub chan_bind: [u8; 32],
    /// Capability-only scope from the grant (before request intersection).
    pub grant_scope: ResolvedScope,
    /// `requested ∩ grant.scope` — what the pull session must record.
    pub resolved_scope: ResolvedScope,
    pub grant_id: [u8; 32],
}

/// Process-local map of subject address → published `op_pubkey`.
///
/// §5.1(b) step 1 requires the subject's **published** op. Population
/// happens at `POST /v1/bootstrap/entrust`: when the kernel accepts a
/// subject's entrust, the api derives the x-only public key from the
/// `op` field (byte offset 65..97 of the §7.7 Operational Bundle) of the
/// bundle the subject itself submitted under an authenticated
/// OwnershipProof, and installs it under that subject's address. That is
/// the legitimate binding — the subject authenticates as itself and hands
/// over exactly the key material GrantProof needs for step-1 verification.
/// No new trust assumption; no foreign claim about another subject.
///
/// The directory is **process-local, not durable**: it starts empty on
/// every boot (like the kernel-side `BundleStore`), so GrantProof for a
/// subject fails closed at §5.1(b) step 1 until that subject re-entrusts
/// in this process. Tests may still install fixtures directly. Nostr
/// kind-30420 profile resolution (with the §4.3 address binding) may
/// become an additional population source later; it is not required for
/// the entrust path above.
///
/// Not a config default and not an operator free-form setting for foreign
/// subjects — a forged entry would make grants verify under an attacker's
/// key (see the §4.3 binding threat). The entrust path upholds this: only
/// the subject that authenticated itself gets its own op installed.
#[derive(Debug, Default)]
pub struct SubjectOpDirectory {
    inner: RwLock<HashMap<[u8; 32], [u8; 32]>>,
}

impl SubjectOpDirectory {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Install a published op for `subject`. Overwrites any prior entry.
    pub fn insert(&self, subject: [u8; 32], op_pubkey: [u8; 32]) {
        let mut guard = self.inner.write().expect("subject_ops lock poisoned");
        guard.insert(subject, op_pubkey);
    }

    /// Look up the published op. `None` is fail-closed (never a zero key).
    pub fn get(&self, subject: &[u8; 32]) -> Option<[u8; 32]> {
        let guard = self.inner.read().expect("subject_ops lock poisoned");
        guard.get(subject).copied()
    }

    /// Remove the published op for `subject` (§7.7 revoke cease-use). No-op
    /// (not an error) if the subject has no cached entry.
    pub fn remove(&self, subject: &[u8; 32]) {
        let mut guard = self.inner.write().expect("subject_ops lock poisoned");
        guard.remove(subject);
    }
}

/// Process-local map: subject → async mutex.
///
/// Serializes kernel dial + `SubjectOpDirectory` write per subject for
/// entrust/revoke (lost-update guard). Not a multi-process CAS; unused
/// entries may be retained for the process lifetime (v1, like other maps).
#[derive(Debug, Default)]
pub struct SubjectOpLocks {
    inner: std::sync::Mutex<HashMap<[u8; 32], std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

impl SubjectOpLocks {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Return a cloned Arc mutex for `subject`, creating it if absent.
    pub fn mutex_for(&self, subject: [u8; 32]) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.inner.lock().expect("subject_op_locks lock poisoned");
        guard
            .entry(subject)
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

/// Process-local revocation set for `grant_id` (§5.2 — forward-only).
///
/// The set is **process-local, not durable**: it starts empty on every boot
/// (like [`SubjectOpDirectory`]). Forward-only inserts; no persistence.
#[derive(Debug, Default)]
pub struct RevokedGrantSet {
    inner: RwLock<HashSet<[u8; 32]>>,
}

impl RevokedGrantSet {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashSet::new()),
        }
    }

    pub fn revoke(&self, grant_id: [u8; 32]) {
        let mut guard = self.inner.write().expect("revoked_grants lock poisoned");
        guard.insert(grant_id);
    }

    pub fn contains(&self, grant_id: &[u8; 32]) -> bool {
        let guard = self.inner.read().expect("revoked_grants lock poisoned");
        guard.contains(grant_id)
    }
}

/// A single issued-but-not-yet-consumed grant-revoke challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeEntry {
    pub subject: [u8; 32],
    pub expiry: u64,
}

/// Cap on outstanding (not-yet-consumed, not-yet-expired) grant-revoke
/// challenges held in [`GrantRevokeChallengeStore`].
pub const MAX_OUTSTANDING_GRANT_REVOKE_CHALLENGES: usize = 4096;

/// Single-use, api-local challenge store for `POST /v1/grants/revoke` (§5.2).
///
/// Grant revocation is enforced entirely inside this process — the kernel has
/// no concept of grants and therefore no Redeem RPC that could consume this
/// nonce for us. This store IS the single-use and expiry enforcement for the
/// grant-revoke action, analogous to `SubjectOpDirectory` / `RevokedGrantSet`:
/// process-local, starts empty on every boot, no durability.
#[derive(Debug, Default)]
pub struct GrantRevokeChallengeStore {
    inner: RwLock<HashMap<[u8; 32], ChallengeEntry>>,
}

impl GrantRevokeChallengeStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Issue a fresh single-use nonce bound to `subject` and `expiry`.
    ///
    /// Evicts expired entries first (`now > expiry`, matching the handler).
    /// Refuses with [`ApiError::bounds_exceeded`] when the store is already at
    /// [`MAX_OUTSTANDING_GRANT_REVOKE_CHALLENGES`] non-expired entries.
    ///
    /// Nonce is 32 CSPRNG bytes (`getrandom::fill`) — no fixed-nonce fallback,
    /// no weak RNG. A broken system CSPRNG is an unrecoverable process
    /// invariant violation (same class as a poisoned lock elsewhere in this
    /// file) and panics loudly rather than silently degrading the nonce.
    pub fn issue(&self, subject: [u8; 32], expiry: u64, now: u64) -> Result<[u8; 32], ApiError> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce)
            .expect("system CSPRNG must be available to issue a grant-revoke challenge nonce");
        let mut guard = self
            .inner
            .write()
            .expect("grant_revoke_challenges lock poisoned");
        guard.retain(|_, entry| now <= entry.expiry);
        if guard.len() >= MAX_OUTSTANDING_GRANT_REVOKE_CHALLENGES {
            return Err(ApiError::bounds_exceeded(
                "too many outstanding grant-revoke challenges",
            ));
        }
        guard.insert(nonce, ChallengeEntry { subject, expiry });
        Ok(nonce)
    }

    /// Peek at the entry for `nonce` without consuming it.
    ///
    /// Evicts *other* expired entries (`now > expiry`). The looked-up nonce is
    /// still returned when present even if it is itself expired, so the
    /// revoke handler can verify the proof and then return 410
    /// `challenge_expired`.
    ///
    /// `None` covers both "never issued" and "already consumed"; callers must
    /// not distinguish the two on the wire. Use [`Self::take`] only after the
    /// proof (and grant→subject binding) has been validated.
    pub fn get(&self, nonce: &[u8; 32], now: u64) -> Option<ChallengeEntry> {
        let mut guard = self
            .inner
            .write()
            .expect("grant_revoke_challenges lock poisoned");
        // Keep the looked-up key even when expired (410 path); drop others.
        guard.retain(|k, entry| k == nonce || now <= entry.expiry);
        guard.get(nonce).copied()
    }

    /// Atomically remove and return the entry for `nonce` — this IS the
    /// single-use check. `None` covers both "never issued" and "already
    /// consumed"; callers must not distinguish the two in the response.
    pub fn take(&self, nonce: &[u8; 32]) -> Option<ChallengeEntry> {
        let mut guard = self
            .inner
            .write()
            .expect("grant_revoke_challenges lock poisoned");
        guard.remove(nonce)
    }
}

/// Verify an OwnershipProof for domains **without** `request_hash`
/// (Pull / Entrust / Revoke — §5.1 L1916 / §7.7).
///
/// Pure: does not dial the kernel. Body `expiry` is part of the signed
/// preimage (Redeem-body `expiry` normative); a wrong value fails BIP-340.
/// `domain` is endpoint-selected — never taken from the request body.
pub fn verify_simple_ownership_proof(
    domain: ChallengeDomain,
    request_subject: &str,
    challenge: &ChallengeEcho,
    proof: &OwnershipProofJson,
    public_hosts: &[String],
) -> Result<VerifiedOwnership, ApiError> {
    if !domain.is_simple() {
        return Err(ApiError::internal(format!(
            "verify_simple_ownership_proof refuses request_hash domain {:?}",
            domain.as_str()
        )));
    }

    // Closed capability match — GrantProof is a different type on the wire;
    // if the ownership shape carries type=grant, reject here.
    let capability = capability_from_wire(&proof.proof_type)?;
    require_ownership(capability)?;

    let subject_raw = decode_zk_address(request_subject)?;
    let proof_subject_raw = decode_zk_address(&proof.subject)?;
    if proof_subject_raw != subject_raw {
        return Err(ApiError::unauthorized(
            "ownership_proof.subject does not match request subject",
        ));
    }

    let pk0 = parse_proof_hex32(&proof.public_key, "ownership_proof.public_key")?;
    let nk_commit = parse_proof_hex32(&proof.nk_commit, "ownership_proof.nk_commit")?;
    validate_nk_commit_limbs(&nk_commit)?;
    let signature = parse_proof_hex64(&proof.signature, "ownership_proof.signature")?;
    let nonce = parse_hex32_field(&challenge.nonce, "challenge.nonce")?;
    let challenge_expiry = parse_u64_decimal(&challenge.expiry)
        .map_err(|e| ApiError::malformed(format!("challenge.expiry: {}", e.body.message)))?;

    let expected = address_from_pk0_nk_commit(&pk0, &nk_commit);
    if expected != subject_raw {
        return Err(ApiError::unauthorized(
            "H(Pk0 ‖ nk_commit) does not equal subject address",
        ));
    }

    if public_hosts.is_empty() {
        return Err(ApiError::internal(
            "no authoritative public hosts configured for chan_bind (ZKCOINS_PUBLIC_HOST)",
        ));
    }
    let allowed: Vec<[u8; 32]> = public_hosts.iter().map(|h| chan_bind_for_host(h)).collect();

    let domain_str = domain.as_str();
    let mut accepted_bind: Option<[u8; 32]> = None;
    for cb in &allowed {
        let chal = pull_challenge_message(domain_str, &nonce, cb, &subject_raw, challenge_expiry);
        if verify_bip340(&pk0, &signature, &chal).is_ok() {
            accepted_bind = Some(*cb);
            break;
        }
    }
    let chan_bind = match accepted_bind {
        Some(b) => b,
        None => {
            return Err(ApiError::unauthorized(
                "OwnershipProof signature invalid or chan_bind/domain mismatch",
            ));
        }
    };

    Ok(VerifiedOwnership {
        subject_bech32: request_subject.to_string(),
        subject_raw,
        nonce,
        challenge_expiry,
        chan_bind,
    })
}

/// Verify a pull-domain OwnershipProof (`chal` without `request_hash`).
///
/// Thin adapter over [`verify_simple_ownership_proof`] for the pull wire shape
/// (top-level `nonce` / `expiry` rather than nested `challenge`).
pub fn verify_pull_ownership_proof(
    request_subject: &str,
    nonce_hex: &str,
    expiry_decimal: &str,
    proof: &OwnershipProofJson,
    public_hosts: &[String],
) -> Result<VerifiedOwnership, ApiError> {
    verify_simple_ownership_proof(
        ChallengeDomain::Pull,
        request_subject,
        &ChallengeEcho {
            nonce: nonce_hex.to_string(),
            expiry: expiry_decimal.to_string(),
        },
        proof,
        public_hosts,
    )
}

// ---------------------------------------------------------------------------
// View grant decode + grant_message (§5.2)
// ---------------------------------------------------------------------------

/// `grant_message = H("zkCoins/v1/Grant" ‖ version ‖ subject ‖ grantee
/// ‖ asset_ids ‖ not_before ‖ not_after ‖ expiry ‖ nonce)`.
///
/// Field order is the **formula**, not a struct layout. `asset_enc` is the
/// discriminator encoding from [`encode_grant_asset_ids`].
///
/// The eight parameters mirror the normative field concatenation of
/// `grant_message` (§5.2). Bundling them into a struct would invite treating
/// that struct's field order as authoritative — the same confusion the spec
/// warns against for `invoice_message` (§4.3). The formula is normative; keep
/// the parameters flat so the call site cannot drift from the byte order.
#[allow(clippy::too_many_arguments)]
pub fn grant_message_digest(
    version: u8,
    subject: &[u8; 32],
    grantee: &[u8; 32],
    asset_enc: &[u8],
    not_before: u64,
    not_after: u64,
    expiry: u64,
    grant_nonce: &[u8; 16],
) -> ([u8; 32], Vec<u8>) {
    let mut prefix = Vec::with_capacity(1 + 32 + 32 + asset_enc.len() + 8 + 8 + 8 + 16);
    prefix.push(version);
    prefix.extend_from_slice(subject);
    prefix.extend_from_slice(grantee);
    prefix.extend_from_slice(asset_enc);
    prefix.extend_from_slice(&not_before.to_be_bytes());
    prefix.extend_from_slice(&not_after.to_be_bytes());
    prefix.extend_from_slice(&expiry.to_be_bytes());
    prefix.extend_from_slice(grant_nonce);

    let mut pre = Vec::with_capacity(GRANT_MESSAGE_TAG.len() + prefix.len());
    pre.extend_from_slice(GRANT_MESSAGE_TAG.as_bytes());
    pre.extend_from_slice(&prefix);
    (sha256(&pre), prefix)
}

/// Decode Bech32m `zkgrant` payload per §5.2.
///
/// Rejects wrong HRP, unknown version, non-ascending asset lists, truncated
/// or trailing bytes. Does **not** verify the op signature.
pub fn decode_view_grant(bech32m: &str) -> Result<DecodedViewGrant, ApiError> {
    let checked = CheckedHrpstring::new::<Bech32m>(bech32m)
        .map_err(|e| ApiError::malformed(format!("grant: invalid Bech32m zkgrant: {e}")))?;
    if checked.hrp().as_str() != GRANT_HRP {
        return Err(ApiError::malformed(format!(
            "grant: expected HRP {GRANT_HRP:?}, got {:?}",
            checked.hrp().as_str()
        )));
    }
    let data: Vec<u8> = checked.byte_iter().collect();
    // Minimum: version(1)+subject(32)+grantee(32)+asset disc(1)+times(24)+nonce(16)+sig(64)
    // = 170 for wildcard assets.
    if data.len() < 170 {
        return Err(ApiError::malformed(format!(
            "grant: payload too short ({} bytes)",
            data.len()
        )));
    }

    let mut cur = 0usize;
    let version = data[cur];
    cur += 1;
    if version != GRANT_VERSION {
        return Err(ApiError::malformed(format!(
            "grant: unknown version byte 0x{version:02x}; expected 0x{GRANT_VERSION:02x}"
        )));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&data[cur..cur + 32]);
    cur += 32;
    let mut grantee = [0u8; 32];
    grantee.copy_from_slice(&data[cur..cur + 32]);
    cur += 32;

    if cur >= data.len() {
        // 170-byte floor already guarantees the discriminator byte is present
        #[cfg_attr(coverage_nightly, coverage(off))]
        return Err(ApiError::malformed("grant: truncated at asset_ids"));
    }
    let asset_disc = data[cur];
    cur += 1;
    let (all_assets, asset_ids) = match asset_disc {
        0x00 => (true, Vec::new()),
        0x01 => {
            if cur + 4 > data.len() {
                // 170-byte floor already guarantees the 4-byte count is present
                #[cfg_attr(coverage_nightly, coverage(off))]
                return Err(ApiError::malformed("grant: truncated asset_ids count"));
            }
            let mut count_buf = [0u8; 4];
            count_buf.copy_from_slice(&data[cur..cur + 4]);
            cur += 4;
            let count = u32::from_be_bytes(count_buf) as usize;
            if count == 0 {
                return Err(ApiError::malformed(
                    "grant: asset_ids list must be non-empty when not \"*\"",
                ));
            }
            let need = count.checked_mul(32).ok_or_else(|| {
                // u32 count * 32 cannot overflow usize on this target
                #[cfg_attr(coverage_nightly, coverage(off))]
                {
                    ApiError::malformed("grant: asset_ids count overflows size calculation")
                }
            })?;
            if cur + need > data.len() {
                return Err(ApiError::malformed("grant: truncated asset_ids list"));
            }
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                let mut id = [0u8; 32];
                id.copy_from_slice(&data[cur..cur + 32]);
                cur += 32;
                ids.push(id);
            }
            for w in ids.windows(2) {
                if w[0] >= w[1] {
                    return Err(ApiError::malformed(
                        "grant: asset_ids must be strictly ascending",
                    ));
                }
            }
            (false, ids)
        }
        other => {
            return Err(ApiError::malformed(format!(
                "grant: unknown asset_ids discriminator 0x{other:02x}"
            )));
        }
    };

    // Fixed tail after assets: not_before + not_after + expiry + nonce + sig.
    const TAIL_LEN: usize = 8 + 8 + 8 + 16 + 64;
    let remaining = data.len().saturating_sub(cur);
    if remaining < TAIL_LEN {
        return Err(ApiError::malformed("grant: truncated time/nonce/signature"));
    }
    if remaining > TAIL_LEN {
        return Err(ApiError::malformed("grant: trailing bytes after signature"));
    }

    let mut not_before_buf = [0u8; 8];
    not_before_buf.copy_from_slice(&data[cur..cur + 8]);
    cur += 8;
    let not_before = u64::from_be_bytes(not_before_buf);
    let mut not_after_buf = [0u8; 8];
    not_after_buf.copy_from_slice(&data[cur..cur + 8]);
    cur += 8;
    let not_after = u64::from_be_bytes(not_after_buf);
    let mut expiry_buf = [0u8; 8];
    expiry_buf.copy_from_slice(&data[cur..cur + 8]);
    cur += 8;
    let expiry = u64::from_be_bytes(expiry_buf);

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&data[cur..cur + 16]);
    cur += 16;
    let mut op_signature = [0u8; 64];
    op_signature.copy_from_slice(&data[cur..cur + 64]);

    let asset_enc = encode_grant_asset_ids(all_assets, &asset_ids)
        .map_err(|e| ApiError::malformed(format!("grant asset_ids: {}", e.body.message)))?;
    let (grant_message, message_prefix) = grant_message_digest(
        version, &subject, &grantee, &asset_enc, not_before, not_after, expiry, &nonce,
    );
    let grant_id = sha256(&grant_message);

    // message_prefix must be byte-identical to the version…nonce payload slice.
    let expected_prefix_len = data.len() - 64;
    if message_prefix.as_slice() != &data[..expected_prefix_len] {
        // recompute is an inverse-encoding invariant of encode_grant_asset_ids
        #[cfg_attr(coverage_nightly, coverage(off))]
        return Err(ApiError::internal(
            "grant message_prefix recompute diverged from decoded payload",
        ));
    }

    Ok(DecodedViewGrant {
        version,
        subject,
        grantee,
        scope: ResolvedScope {
            all_assets,
            asset_ids,
            not_before,
            not_after,
        },
        expiry,
        nonce,
        op_signature,
        grant_id,
        message_prefix,
    })
}

/// Encode a view grant as Bech32m `zkgrant` (tests / helpers).
#[cfg(test)]
pub fn encode_view_grant(
    subject: &[u8; 32],
    grantee: &[u8; 32],
    scope: &ResolvedScope,
    expiry: u64,
    grant_nonce: &[u8; 16],
    op_signature: &[u8; 64],
) -> Result<String, ApiError> {
    let asset_enc = encode_grant_asset_ids(scope.all_assets, &scope.asset_ids)?;
    let (_msg, prefix) = grant_message_digest(
        GRANT_VERSION,
        subject,
        grantee,
        &asset_enc,
        scope.not_before,
        scope.not_after,
        expiry,
        grant_nonce,
    );
    let mut payload = prefix;
    payload.extend_from_slice(op_signature);
    let hrp = bech32::Hrp::parse(GRANT_HRP).expect("constant HRP");
    bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|e| ApiError::internal(format!("zkgrant encode failed: {e}")))
}

// ---------------------------------------------------------------------------
// Scope intersection (§5.1)
// ---------------------------------------------------------------------------

/// Resolve `requested_scope ∩ grant.scope` per §5.1.
///
/// - Time windows always intersect (`max` lower / `min` upper, inclusive).
/// - `asset_ids = "*"` against a narrower grant is **clamped** (silent).
/// - An **explicit** requested `asset_id` not in the grant → `403 scope_exceeded`
///   (not silent removal of the foreign id).
/// - Empty intersection (empty assets after clamp, or `not_before > not_after`)
///   → `403 scope_exceeded`.
pub fn intersect_scopes(
    requested: &ResolvedScope,
    grant: &ResolvedScope,
) -> Result<ResolvedScope, ApiError> {
    let not_before = requested.not_before.max(grant.not_before);
    let not_after = requested.not_after.min(grant.not_after);
    if not_before > not_after {
        return Err(ApiError::scope_exceeded(
            "resolved scope time window is empty (requested ∩ grant)",
        ));
    }

    let (all_assets, asset_ids) = match (requested.all_assets, grant.all_assets) {
        (true, true) => (true, Vec::new()),
        (true, false) => {
            // Clamp * to the grant's explicit set.
            if grant.asset_ids.is_empty() {
                return Err(ApiError::scope_exceeded(
                    "resolved scope asset intersection is empty",
                ));
            }
            (false, grant.asset_ids.clone())
        }
        (false, true) => {
            if requested.asset_ids.is_empty() {
                return Err(ApiError::scope_exceeded(
                    "resolved scope asset intersection is empty",
                ));
            }
            (false, requested.asset_ids.clone())
        }
        (false, false) => {
            // Every explicitly named requested id must be in the grant.
            for id in &requested.asset_ids {
                if !grant.asset_ids.iter().any(|g| g == id) {
                    return Err(ApiError::scope_exceeded(
                        "request names an asset_id outside grant.scope.asset_ids",
                    ));
                }
            }
            if requested.asset_ids.is_empty() {
                return Err(ApiError::scope_exceeded(
                    "resolved scope asset intersection is empty",
                ));
            }
            (false, requested.asset_ids.clone())
        }
    };

    Ok(ResolvedScope {
        all_assets,
        asset_ids,
        not_before,
        not_after,
    })
}

// ---------------------------------------------------------------------------
// GrantProof verification (§5.1(b) + §5.2)
// ---------------------------------------------------------------------------

/// Environment / policy inputs for GrantProof verification.
///
/// These are **not** part of the proof under examination: they are the node's
/// authoritative host list, wall-clock for grant expiry, and local revocation
/// set. Proof-carrying fields stay as distinct parameters on
/// [`verify_grant_proof`].
#[derive(Debug, Clone, Copy)]
pub struct GrantVerificationContext<'a> {
    /// Authoritative public hosts for §5.1 `chan_bind` (config only).
    pub public_hosts: &'a [String],
    /// Unix seconds used for grant `expiry` (inclusive upper bound).
    pub now: u64,
    /// Process-local revocation set (`grant_id` → refuse). Empty on every boot; not durable.
    pub revoked: &'a RevokedGrantSet,
}

/// Verify a pull-domain GrantProof **without** calling the kernel.
///
/// Normative order (§5.1(b)):
/// 1. Decode `zkgrant`; recompute `grant_message` (fixed field concatenation);
///    verify BIP-340 under the subject's **published** `op_pubkey`.
/// 2. `grantee_pk == grant.grantee` and BIP-340 over `chal` under grantee `D`.
/// 3. Grant not expired (`now ≤ grant.expiry`) and not revoked.
/// 4. Resolve `requested ∩ grant.scope` (empty / explicit foreign asset → 403).
///
/// Pure: a failed check never dials the kernel and cannot burn the nonce.
pub fn verify_grant_proof(
    nonce_hex: &str,
    expiry_decimal: &str,
    proof: &GrantProofJson,
    op_pubkey: &[u8; 32],
    requested_scope: &ResolvedScope,
    ctx: &GrantVerificationContext<'_>,
) -> Result<VerifiedGrant, ApiError> {
    if proof.proof_type != "grant" {
        return Err(ApiError::unauthorized(format!(
            "GrantProof type must be \"grant\", got {:?}",
            proof.proof_type
        )));
    }

    // ---- decode grant (structural) ----
    let grant = decode_view_grant(&proof.grant)?;

    // ---- (1) op signature over grant_message ----
    let asset_enc = encode_grant_asset_ids(grant.scope.all_assets, &grant.scope.asset_ids)?;
    let (grant_message, _) = grant_message_digest(
        grant.version,
        &grant.subject,
        &grant.grantee,
        &asset_enc,
        grant.scope.not_before,
        grant.scope.not_after,
        grant.expiry,
        &grant.nonce,
    );
    verify_bip340_with_message(
        op_pubkey,
        &grant.op_signature,
        &grant_message,
        "grant op_pubkey is not a valid x-only pubkey",
        "grant op_signature is not a valid BIP-340 signature",
        "grant op signature invalid (wrong signer, manipulated signature, or grant_message field order)",
    )?;

    // ---- (2) grantee identity + chal signature ----
    let grantee_pk = parse_proof_hex32(&proof.grantee_pk, "grant_proof.grantee_pk")?;
    if grantee_pk != grant.grantee {
        return Err(ApiError::unauthorized(
            "grant_proof.grantee_pk does not equal grant.grantee",
        ));
    }

    let challenge_nonce = parse_hex32_field(nonce_hex, "challenge.nonce")?;
    let challenge_expiry = parse_u64_decimal(expiry_decimal)
        .map_err(|e| ApiError::malformed(format!("challenge.expiry: {}", e.body.message)))?;

    if ctx.public_hosts.is_empty() {
        return Err(ApiError::internal(
            "no authoritative public hosts configured for chan_bind (ZKCOINS_PUBLIC_HOST)",
        ));
    }
    let allowed: Vec<[u8; 32]> = ctx
        .public_hosts
        .iter()
        .map(|h| chan_bind_for_host(h))
        .collect();
    let grantee_sig = parse_proof_hex64(&proof.signature, "grant_proof.signature")?;

    let domain_str = ChallengeDomain::Pull.as_str();
    let mut accepted_bind: Option<[u8; 32]> = None;
    for cb in &allowed {
        let chal = pull_challenge_message(
            domain_str,
            &challenge_nonce,
            cb,
            &grant.subject,
            challenge_expiry,
        );
        if verify_bip340_with_message(
            &grantee_pk,
            &grantee_sig,
            &chal,
            "grant_proof.grantee_pk is not a valid x-only pubkey",
            "grant_proof.signature is not a valid BIP-340 signature",
            "GrantProof grantee signature invalid or chan_bind/domain mismatch",
        )
        .is_ok()
        {
            accepted_bind = Some(*cb);
            break;
        }
    }
    let chan_bind = match accepted_bind {
        Some(b) => b,
        None => {
            return Err(ApiError::unauthorized(
                "GrantProof grantee signature invalid or chan_bind/domain mismatch",
            ));
        }
    };

    // ---- (3) expiry + revocation ----
    // `now > expiry` is unusable. Equality at the exact second remains valid
    // (inclusive upper bound on usability).
    if ctx.now > grant.expiry {
        return Err(ApiError::unauthorized(
            "view grant has expired (scope.expiry is in the past)",
        ));
    }
    if ctx.revoked.contains(&grant.grant_id) {
        return Err(ApiError::unauthorized(
            "view grant has been revoked (grant_id is in the node revocation set)",
        ));
    }

    // ---- (4) scope intersection ----
    let resolved_scope = intersect_scopes(requested_scope, &grant.scope)?;

    let subject_bech32 = encode_zk_address_public(&grant.subject)?;

    Ok(VerifiedGrant {
        subject_bech32,
        subject_raw: grant.subject,
        grantee_pk,
        nonce: challenge_nonce,
        challenge_expiry,
        chan_bind,
        grant_scope: grant.scope,
        resolved_scope,
        grant_id: grant.grant_id,
    })
}

/// Encode 32 raw address bytes as Bech32m `zk` (public helper for grant path).
pub fn encode_zk_address_public(raw: &[u8; 32]) -> Result<String, ApiError> {
    let hrp = bech32::Hrp::parse(ADDRESS_HRP)
        .map_err(|e| ApiError::internal(format!("address HRP parse: {e}")))?;
    bech32::encode::<Bech32m>(hrp, raw)
        .map_err(|e| ApiError::internal(format!("address encode failed: {e}")))
}

/// Hex-encode a 32-byte digest (re-export convenience for handlers).
pub fn hex32(bytes: &[u8; 32]) -> String {
    encode_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    fn sample_sk_pk() -> (SecretKey, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("32-byte secret");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        (sk, xonly.serialize())
    }

    fn sign_chal(sk: &SecretKey, chal: &[u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, sk);
        let msg = Message::from_digest_slice(chal).expect("32-byte digest");
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let bytes = sig.as_ref();
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes);
        out
    }

    fn fixture_identity() -> (SecretKey, [u8; 32], [u8; 32], [u8; 32], String) {
        let (sk, pk0) = sample_sk_pk();
        // Canonical Goldilocks limbs (all zeros) — valid nk_commit encoding.
        let nk_commit = [0u8; 32];
        let subject_raw = address_from_pk0_nk_commit(&pk0, &nk_commit);
        let subject_bech = encode_zk_address(&subject_raw);
        (sk, pk0, nk_commit, subject_raw, subject_bech)
    }

    #[test]
    fn domain_strings_match_node_challenge_action() {
        assert_eq!(ChallengeDomain::Pull.as_str(), "zkCoins/v1/PullChallenge");
        assert_eq!(
            ChallengeDomain::AttestBalance.as_str(),
            "zkCoins/v1/AttestBalanceChallenge"
        );
        assert_eq!(
            ChallengeDomain::IssueGrant.as_str(),
            "zkCoins/v1/IssueGrantChallenge"
        );
        assert_eq!(
            ChallengeDomain::Entrust.as_str(),
            "zkCoins/v1/EntrustChallenge"
        );
        assert_eq!(
            ChallengeDomain::Revoke.as_str(),
            "zkCoins/v1/RevokeChallenge"
        );
        assert_ne!(
            ChallengeDomain::AttestBalance.as_str(),
            ChallengeDomain::IssueGrant.as_str()
        );
        assert_ne!(
            ChallengeDomain::Pull.as_str(),
            ChallengeDomain::AttestBalance.as_str()
        );
        // Bootstrap domains are pairwise distinct from each other and from Pull
        // so a proof cannot be retargeted across actions (§7.7).
        assert_ne!(
            ChallengeDomain::Entrust.as_str(),
            ChallengeDomain::Revoke.as_str()
        );
        assert_ne!(
            ChallengeDomain::Entrust.as_str(),
            ChallengeDomain::Pull.as_str()
        );
        assert_ne!(
            ChallengeDomain::Revoke.as_str(),
            ChallengeDomain::Pull.as_str()
        );
        assert!(ChallengeDomain::Entrust.is_simple());
        assert!(ChallengeDomain::Revoke.is_simple());
        assert!(ChallengeDomain::RevokeGrant.is_simple());
        assert!(ChallengeDomain::Pull.is_simple());
        assert!(!ChallengeDomain::AttestBalance.is_simple());
        assert!(!ChallengeDomain::IssueGrant.is_simple());
        assert_eq!(
            ChallengeDomain::RevokeGrant.as_str(),
            REVOKE_GRANT_CHALLENGE_DOMAIN
        );
    }

    #[test]
    fn grant_revoke_challenge_store_issue_distinct_and_take_is_single_use() {
        let store = GrantRevokeChallengeStore::new();
        let subject = [0xABu8; 32];
        let now = 1_700_000_000u64;
        let expiry = 1_700_000_060u64;
        let n1 = store.issue(subject, expiry, now).expect("issue n1");
        let n2 = store.issue(subject, expiry, now).expect("issue n2");
        assert_ne!(n1, n2, "CSPRNG nonces must be distinct across issues");

        let entry = store
            .take(&n1)
            .expect("first take must return issued entry");
        assert_eq!(entry.subject, subject);
        assert_eq!(entry.expiry, expiry);
        assert!(
            store.take(&n1).is_none(),
            "second take must be None (single-use)"
        );
        assert!(
            store.take(&[0u8; 32]).is_none(),
            "never-issued nonce must be None"
        );
    }

    #[test]
    fn grant_revoke_challenge_store_get_peeks_without_consuming() {
        let store = GrantRevokeChallengeStore::new();
        let subject = [0xABu8; 32];
        let now = 1_700_000_000u64;
        let expiry = 1_700_000_060u64;
        let nonce = store.issue(subject, expiry, now).expect("issue");

        let first = store
            .get(&nonce, now)
            .expect("first get must return issued entry");
        assert_eq!(first.subject, subject);
        assert_eq!(first.expiry, expiry);

        let second = store
            .get(&nonce, now)
            .expect("second get must still return entry");
        assert_eq!(second.subject, subject);
        assert_eq!(second.expiry, expiry);

        let taken = store.take(&nonce).expect("take must return issued entry");
        assert_eq!(taken.subject, subject);
        assert_eq!(taken.expiry, expiry);

        assert!(store.get(&nonce, now).is_none());
        assert!(store.take(&nonce).is_none());
        assert!(store.get(&[0u8; 32], now).is_none());
    }

    #[test]
    fn grant_revoke_challenge_store_issue_evicts_expired() {
        let store = GrantRevokeChallengeStore::new();
        let subject = [0xABu8; 32];
        let n1 = store.issue(subject, 100, 50).expect("issue non-expired");
        assert!(store.get(&n1, 50).is_some());
        // now > n1.expiry → issue evicts n1 before insert.
        let n2 = store
            .issue(subject, 200, 101)
            .expect("issue after n1 expired");
        assert!(
            store.get(&n1, 101).is_none(),
            "expired entry must be evicted on issue"
        );
        assert!(store.get(&n2, 101).is_some());
    }

    #[test]
    fn grant_revoke_challenge_store_get_keeps_expired_looked_up_evicts_others() {
        let store = GrantRevokeChallengeStore::new();
        let s1 = [0x01u8; 32];
        let s2 = [0x02u8; 32];
        let expired = store.issue(s1, 100, 50).expect("issue expired-to-be");
        let other_expired = store.issue(s2, 100, 50).expect("issue other");
        // Looked-up expired entry must remain so the handler can return 410.
        let entry = store
            .get(&expired, 101)
            .expect("expired looked-up entry kept for 410 path");
        assert_eq!(entry.subject, s1);
        assert_eq!(entry.expiry, 100);
        // Other expired entries are hygiene-evicted on get.
        assert!(
            store.get(&other_expired, 101).is_none(),
            "other expired entries must be evicted on get"
        );
    }

    #[test]
    fn grant_revoke_challenge_store_cap_rejects_over_limit() {
        let store = GrantRevokeChallengeStore::new();
        let now = 1_700_000_000u64;
        let expiry = now + 60;
        for _ in 0..MAX_OUTSTANDING_GRANT_REVOKE_CHALLENGES {
            store
                .issue([0u8; 32], expiry, now)
                .expect("issue under cap");
        }
        let err = store
            .issue([0u8; 32], expiry, now)
            .expect_err("at cap must refuse");
        assert_eq!(err.body.error, "bounds_exceeded");
        // Cap still holds: a subsequent issue also fails without insert growth.
        let err2 = store
            .issue([0u8; 32], expiry, now)
            .expect_err("still at cap");
        assert_eq!(err2.body.error, "bounds_exceeded");
    }

    #[test]
    fn entrust_domain_rejects_revoke_signed_proof() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xCCu8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        // Sign under Revoke; redeem under Entrust.
        let chal = pull_challenge_message(
            ChallengeDomain::Revoke.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_simple_ownership_proof(
            ChallengeDomain::Entrust,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &[host.to_string()],
        )
        .expect_err("revoke-signed proof must not authorise entrust");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn revoke_domain_rejects_entrust_signed_proof() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xDDu8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Entrust.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_simple_ownership_proof(
            ChallengeDomain::Revoke,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &[host.to_string()],
        )
        .expect_err("entrust-signed proof must not authorise revoke");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn pull_ownership_proof_verifies_without_request_hash() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xAAu8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = sign_chal(&sk, &chal);
        let verified = verify_pull_ownership_proof(
            &subject_bech,
            &encode_hex(&nonce),
            &expiry.to_string(),
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &[host.to_string()],
        )
        .expect("valid pull proof");
        assert_eq!(verified.chan_bind, cb);
        assert_eq!(verified.nonce, nonce);
    }

    #[test]
    fn pull_ownership_wrong_expiry_is_unauthorized() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xBBu8; 32];
        let signed_expiry = 100u64;
        let presented_expiry = 999u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            signed_expiry,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_pull_ownership_proof(
            &subject_bech,
            &encode_hex(&nonce),
            &presented_expiry.to_string(),
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &[host.to_string()],
        )
        .expect_err("altered expiry");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn simple_verify_refuses_attest_balance_domain() {
        let subject = encode_zk_address(&[0u8; 32]);
        let err = verify_simple_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject.clone(),
                public_key: encode_hex(&[0u8; 32]),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &["h.example".into()],
        )
        .expect_err("attest-balance domain is not simple");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn simple_verify_rejects_subject_mismatch() {
        let (_sk, _pk0, _nkc, _subject_raw, subject_bech) = fixture_identity();
        let other_subject = encode_zk_address(&[0x11u8; 32]);
        let err = verify_simple_ownership_proof(
            ChallengeDomain::Pull,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: other_subject,
                public_key: encode_hex(&[0u8; 32]),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &["h.example".into()],
        )
        .expect_err("subject mismatch");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("does not match request subject"),
            "message must name subject mismatch: {}",
            err.body.message
        );
    }

    #[test]
    fn simple_verify_rejects_pk0_nk_not_equal_address() {
        let (_sk, pk0, _nkc, _subject_raw, subject_bech) = fixture_identity();
        // Canonical limbs (each 0x02… < GOLDILOCKS_ORDER), not the fixture nk_commit.
        let wrong_nk = [0x02u8; 32];
        let err = verify_simple_ownership_proof(
            ChallengeDomain::Pull,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&wrong_nk),
                signature: encode_hex(&[0u8; 64]),
            },
            &["h.example".into()],
        )
        .expect_err("pk0||nk_commit must equal subject");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("does not equal subject address"),
            "message must name address equality: {}",
            err.body.message
        );
    }

    #[test]
    fn simple_verify_rejects_empty_public_hosts() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xAAu8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_simple_ownership_proof(
            ChallengeDomain::Pull,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &[],
        )
        .expect_err("empty public_hosts must be internal_error");
        assert_eq!(err.body.error, "internal_error");
    }

    #[test]
    fn nk_commit_non_canonical_goldilocks_limb_is_malformed() {
        let mut non_canonical = [0u8; 32];
        non_canonical[..8].copy_from_slice(&GOLDILOCKS_ORDER.to_be_bytes());

        let err = validate_nk_commit_limbs(&non_canonical)
            .expect_err("limb 0 == GOLDILOCKS_ORDER is non-canonical");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("non-canonical Goldilocks"),
            "message must name non-canonical Goldilocks: {}",
            err.body.message
        );

        let (_sk, pk0, _nkc, _subject_raw, subject_bech) = fixture_identity();
        let err = verify_simple_ownership_proof(
            ChallengeDomain::Pull,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&non_canonical),
                signature: encode_hex(&[0u8; 64]),
            },
            &["h.example".into()],
        )
        .expect_err("non-canonical nk_commit must fail before signature check");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("non-canonical Goldilocks"),
            "message must name non-canonical Goldilocks: {}",
            err.body.message
        );
    }

    #[test]
    fn session_authority_wire_tokens_match_node_metadata() {
        // node `parse_session_authority`: "ownership" | "grant" only.
        assert_eq!(SessionAuthority::Ownership.as_str(), "ownership");
        assert_eq!(SessionAuthority::Grant.as_str(), "grant");
        assert_ne!(
            SessionAuthority::Ownership.as_str(),
            SessionAuthority::Grant.as_str()
        );
    }

    #[test]
    fn subject_op_directory_remove_clears_entry() {
        let dir = SubjectOpDirectory::new();
        let subject = [0x11u8; 32];
        let op_pk = [0x22u8; 32];
        dir.insert(subject, op_pk);
        assert_eq!(dir.get(&subject), Some(op_pk));
        dir.remove(&subject);
        assert_eq!(dir.get(&subject), None);
    }

    #[test]
    fn subject_op_directory_remove_absent_subject_is_noop() {
        let dir = SubjectOpDirectory::new();
        let subject = [0x33u8; 32];
        dir.remove(&subject);
        assert_eq!(dir.get(&subject), None);
    }

    #[test]
    fn valid_ownership_proof_verifies_under_endpoint_domain() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xAAu8; 32];
        let expiry = 1_700_000_060u64;
        let request_hash = [0x11u8; 32];
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = sign_chal(&sk, &chal);

        let verified = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &request_hash,
            &[host.to_string()],
        )
        .expect("valid proof");
        assert_eq!(verified.chan_bind, cb);
        assert_eq!(verified.subject_raw, subject_raw);
        assert_eq!(verified.nonce, nonce);
    }

    #[test]
    fn wrong_domain_is_unauthorized() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xBBu8; 32];
        let expiry = 99u64;
        let request_hash = [0x22u8; 32];
        let cb = chan_bind_for_host(host);
        // Sign under AttestBalance…
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = sign_chal(&sk, &chal);
        // …verify under IssueGrant → must fail.
        let err = verify_ownership_proof(
            ChallengeDomain::IssueGrant,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &request_hash,
            &[host.to_string()],
        )
        .expect_err("cross-domain");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn validate_resolved_scope_rejects_non_ascending_and_empty_interval() {
        let a = [0x01u8; 32];
        let mut b = [0x02u8; 32];
        b[0] = 0x02;
        // Descending
        let s = ResolvedScope {
            all_assets: false,
            asset_ids: vec![b, a],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = validate_resolved_scope(&s).expect_err("descending");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("ascending"));

        // Duplicate
        let s = ResolvedScope {
            all_assets: false,
            asset_ids: vec![a, a],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        assert!(validate_resolved_scope(&s).is_err());

        // Empty interval
        let s = ResolvedScope {
            all_assets: true,
            asset_ids: vec![],
            not_before: 100,
            not_after: 50,
        };
        let err = validate_resolved_scope(&s).expect_err("empty interval");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("empty") || err.body.message.contains("not_before"));

        // Valid ascending
        let s = ResolvedScope {
            all_assets: false,
            asset_ids: vec![a, b],
            not_before: 10,
            not_after: 20,
        };
        assert!(validate_resolved_scope(&s).is_ok());
    }

    #[test]
    fn grant_proof_type_is_unauthorized() {
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &encode_zk_address(&[0u8; 32]),
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "grant".into(),
                subject: encode_zk_address(&[0u8; 32]),
                public_key: encode_hex(&[0u8; 32]),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &[0u8; 32],
            &["h.example".into()],
        )
        .expect_err("grant");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("GrantProof"),
            "message must name GrantProof: {}",
            err.body.message
        );
    }

    #[test]
    fn ownership_proof_garbage_public_key_is_unauthorized() {
        let subject = encode_zk_address(&[0u8; 32]);
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject.clone(),
                public_key: "zz".into(),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &[0u8; 32],
            &["h.example".into()],
        )
        .expect_err("garbage public_key");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("ownership_proof.public_key"),
            "message must name the field: {}",
            err.body.message
        );
    }

    #[test]
    fn challenge_nonce_garbage_hex_is_malformed() {
        let subject = encode_zk_address(&[0u8; 32]);
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject,
            &ChallengeEcho {
                nonce: "zz".into(),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject.clone(),
                // Valid width so parse reaches challenge.nonce after proof fields.
                public_key: encode_hex(&[0u8; 32]),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &[0u8; 32],
            &["h.example".into()],
        )
        .expect_err("garbage challenge.nonce");
        assert_eq!(err.body.error, "malformed_request");
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn ownership_proof_json_rejects_unknown_field() {
        let v = serde_json::json!({
            "type": "ownership",
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqun6mw",
            "public_key": "00".repeat(32),
            "nk_commit": "00".repeat(32),
            "signature": "00".repeat(64),
            "ghost": true,
        });
        let err = serde_json::from_value::<OwnershipProofJson>(v).expect_err("deny");
        assert!(
            err.to_string().contains("ghost") || err.to_string().contains("unknown field"),
            "serde must reject unknown field, got {err}"
        );
    }

    #[test]
    fn wrong_chan_bind_is_unauthorized() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let signed_host = "signed.example.com";
        let serve_host = "other.example.com";
        let nonce = [0xCCu8; 32];
        let expiry = 50u64;
        let request_hash = [0x33u8; 32];
        let cb = chan_bind_for_host(signed_host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &request_hash,
            &[serve_host.to_string()],
        )
        .expect_err("wrong host");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn wrong_request_hash_is_unauthorized() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xDDu8; 32];
        let expiry = 60u64;
        let signed_hash = [0x44u8; 32];
        let presented_hash = [0x55u8; 32];
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &signed_hash,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &presented_hash,
            &[host.to_string()],
        )
        .expect_err("body changed after sign");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn ceiling_encoding_both_or_neither() {
        assert_eq!(ceiling_encoding(None, None).unwrap(), vec![0x00]);
        let nav = [0xABu8; 32];
        let enc = ceiling_encoding(Some(&nav), Some(7)).unwrap();
        assert_eq!(enc[0], 0x01);
        assert_eq!(&enc[1..33], &nav);
        assert_eq!(&enc[33..], &7u64.to_be_bytes());
        assert!(ceiling_encoding(Some(&nav), None).is_err());
        assert!(ceiling_encoding(None, Some(1)).is_err());
    }

    #[test]
    fn scope_not_after_unbounded_is_i64_max_bit_pattern() {
        assert_eq!(SCOPE_NOT_AFTER_UNBOUNDED, i64::MAX as u64);
    }

    // -----------------------------------------------------------------------
    // GrantProof verification (§5.1(b) / §5.2) — pure, real BIP-340
    // -----------------------------------------------------------------------

    fn sample_op_sk_pk() -> (SecretKey, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x55u8; 32]).expect("op secret");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        (sk, xonly.serialize())
    }

    fn sample_grantee_sk_pk() -> (SecretKey, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x66u8; 32]).expect("grantee secret");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        (sk, xonly.serialize())
    }

    /// Build a valid signed zkgrant for tests.
    fn signed_grant(
        op_sk: &SecretKey,
        subject: &[u8; 32],
        grantee: &[u8; 32],
        scope: &ResolvedScope,
        expiry: u64,
        grant_nonce: &[u8; 16],
    ) -> (String, [u8; 32], [u8; 32]) {
        let asset_enc = encode_grant_asset_ids(scope.all_assets, &scope.asset_ids).unwrap();
        let (grant_message, _prefix) = grant_message_digest(
            GRANT_VERSION,
            subject,
            grantee,
            &asset_enc,
            scope.not_before,
            scope.not_after,
            expiry,
            grant_nonce,
        );
        let grant_id = sha256(&grant_message);
        let op_sig = sign_chal(op_sk, &grant_message);
        let bech =
            encode_view_grant(subject, grantee, scope, expiry, grant_nonce, &op_sig).unwrap();
        (bech, grant_message, grant_id)
    }

    fn grant_fixture() -> GrantFixture {
        let (op_sk, op_pk) = sample_op_sk_pk();
        let (grantee_sk, grantee_pk) = sample_grantee_sk_pk();
        // Subject is an independent address digest (not derived from op).
        let subject = [0x10u8; 32];
        let scope = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01u8; 32], [0x02u8; 32]],
            not_before: 1_000,
            not_after: 2_000_000_000,
        };
        let grant_expiry = 1_800_000_000u64;
        let grant_nonce = [0x77u8; 16];
        let (bech, grant_message, grant_id) = signed_grant(
            &op_sk,
            &subject,
            &grantee_pk,
            &scope,
            grant_expiry,
            &grant_nonce,
        );
        GrantFixture {
            op_sk,
            op_pk,
            grantee_sk,
            grantee_pk,
            subject,
            scope,
            grant_expiry,
            grant_nonce,
            bech,
            grant_message,
            grant_id,
        }
    }

    struct GrantFixture {
        op_sk: SecretKey,
        op_pk: [u8; 32],
        grantee_sk: SecretKey,
        grantee_pk: [u8; 32],
        subject: [u8; 32],
        scope: ResolvedScope,
        grant_expiry: u64,
        grant_nonce: [u8; 16],
        bech: String,
        grant_message: [u8; 32],
        grant_id: [u8; 32],
    }

    fn sign_grantee_chal(
        f: &GrantFixture,
        host: &str,
        nonce: &[u8; 32],
        chal_expiry: u64,
    ) -> [u8; 64] {
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            nonce,
            &cb,
            &f.subject,
            chal_expiry,
        );
        sign_chal(&f.grantee_sk, &chal)
    }

    fn grant_ctx<'a>(
        hosts: &'a [String],
        now: u64,
        revoked: &'a RevokedGrantSet,
    ) -> GrantVerificationContext<'a> {
        GrantVerificationContext {
            public_hosts: hosts,
            now,
            revoked,
        }
    }

    #[test]
    fn grant_proof_valid_verifies_and_intersects_scope() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xAAu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let now = 1_700_000_000u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);

        // Request asks for more assets + wider time than the grant.
        let requested = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let verified = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &requested,
            &grant_ctx(&hosts, now, &revoked),
        )
        .expect("valid grant proof");
        assert_eq!(verified.subject_raw, f.subject);
        assert_eq!(verified.grant_id, f.grant_id);
        assert_eq!(verified.resolved_scope, f.scope);
        assert!(
            !verified.resolved_scope.is_fully_unbounded(),
            "grant session must not receive unbounded scope when grant is scoped"
        );
    }

    #[test]
    fn grant_proof_manipulated_op_signature_is_unauthorized() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xBBu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        // Flip one byte of the trailing op signature inside the bech payload.
        let mut bad_sig = {
            let decoded = decode_view_grant(&f.bech).unwrap();
            decoded.op_signature
        };
        bad_sig[0] ^= 0x01;
        let bad_bech = encode_view_grant(
            &f.subject,
            &f.grantee_pk,
            &f.scope,
            f.grant_expiry,
            &f.grant_nonce,
            &bad_sig,
        )
        .unwrap();
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: bad_bech,
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("manipulated op signature");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn grant_proof_wrong_op_signer_is_unauthorized() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xCCu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        // Present a different published op_pubkey than the one that signed.
        let (_other_sk, other_op_pk) = {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[0x99u8; 32]).unwrap();
            let kp = Keypair::from_secret_key(&secp, &sk);
            let (xonly, _) = kp.x_only_public_key();
            (sk, xonly.serialize())
        };
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &other_op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("wrong op signer");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn grant_message_swapped_field_order_fails_op_verify() {
        // Normative formula is version‖subject‖grantee‖assets‖… — not struct order.
        // Sign under swapped subject/grantee in the preimage; verify with correct order.
        let f = grant_fixture();
        let asset_enc = encode_grant_asset_ids(f.scope.all_assets, &f.scope.asset_ids).unwrap();
        // Swapped: grantee before subject in the tagged preimage.
        let mut wrong_pre = Vec::new();
        wrong_pre.extend_from_slice(GRANT_MESSAGE_TAG.as_bytes());
        wrong_pre.push(GRANT_VERSION);
        wrong_pre.extend_from_slice(&f.grantee_pk); // swapped
        wrong_pre.extend_from_slice(&f.subject); // swapped
        wrong_pre.extend_from_slice(&asset_enc);
        wrong_pre.extend_from_slice(&f.scope.not_before.to_be_bytes());
        wrong_pre.extend_from_slice(&f.scope.not_after.to_be_bytes());
        wrong_pre.extend_from_slice(&f.grant_expiry.to_be_bytes());
        wrong_pre.extend_from_slice(&f.grant_nonce);
        let wrong_msg: [u8; 32] = sha256(&wrong_pre);
        let wrong_sig = sign_chal(&f.op_sk, &wrong_msg);
        // Encode a payload whose prefix is the **correct** order (as a real grant
        // wire would carry) but signature was over the swapped preimage.
        let bad_bech = encode_view_grant(
            &f.subject,
            &f.grantee_pk,
            &f.scope,
            f.grant_expiry,
            &f.grant_nonce,
            &wrong_sig,
        )
        .unwrap();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xDDu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: bad_bech,
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("swapped grant_message field order");
        assert_eq!(err.body.error, "unauthorized");
        // Correct-order signature still verifies against the normative digest.
        assert_ne!(wrong_msg, f.grant_message);
    }

    #[test]
    fn grant_proof_expired_is_unauthorized() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xEEu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        // now strictly after grant.expiry
        let now = f.grant_expiry + 1;
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, now, &revoked),
        )
        .expect_err("expired grant");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("expired"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn grant_proof_explicit_asset_outside_grant_is_scope_exceeded() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xF1u8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        let foreign_asset = [0xFFu8; 32];
        let requested = ResolvedScope {
            all_assets: false,
            asset_ids: vec![foreign_asset],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &requested,
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("asset outside grant");
        assert_eq!(err.body.error, "scope_exceeded");
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn scope_request_wider_than_grant_is_clamped_to_intersection() {
        let grant = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01u8; 32]],
            not_before: 100,
            not_after: 200,
        };
        let requested = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let resolved = intersect_scopes(&requested, &grant).unwrap();
        assert_eq!(resolved, grant);
        assert!(!resolved.is_fully_unbounded());
    }

    #[test]
    fn scope_request_narrower_than_grant_keeps_request() {
        let grant = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let requested = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0xAAu8; 32]],
            not_before: 50,
            not_after: 60,
        };
        let resolved = intersect_scopes(&requested, &grant).unwrap();
        assert_eq!(resolved, requested);
    }

    #[test]
    fn scope_partial_time_overlap_intersects() {
        let grant = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 100,
            not_after: 200,
        };
        let requested = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 150,
            not_after: 250,
        };
        let resolved = intersect_scopes(&requested, &grant).unwrap();
        assert_eq!(resolved.not_before, 150);
        assert_eq!(resolved.not_after, 200);
    }

    #[test]
    fn scope_disjoint_time_is_scope_exceeded() {
        let grant = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 100,
            not_after: 200,
        };
        let requested = ResolvedScope {
            all_assets: true,
            asset_ids: Vec::new(),
            not_before: 201,
            not_after: 300,
        };
        let err = intersect_scopes(&requested, &grant).expect_err("disjoint");
        assert_eq!(err.body.error, "scope_exceeded");
    }

    #[test]
    fn grant_based_resolved_scope_never_unbounded_when_grant_is_scoped() {
        let grant = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01u8; 32]],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let requested = ResolvedScope::unbounded();
        let resolved = intersect_scopes(&requested, &grant).unwrap();
        assert!(
            !resolved.is_fully_unbounded(),
            "intersection with a scoped grant must not be fully unbounded"
        );
        assert!(!resolved.all_assets);
    }

    #[test]
    fn grant_proof_revoked_is_unauthorized() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xF2u8; 32];
        let chal_expiry = 1_700_000_060u64;
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        let revoked = RevokedGrantSet::new();
        revoked.revoke(f.grant_id);
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("revoked");
        assert_eq!(err.body.error, "unauthorized");
        assert!(err.body.message.contains("revoked"));
    }

    #[test]
    fn grant_proof_grantee_mismatch_is_unauthorized() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xF3u8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        let other_pk = [0x88u8; 32];
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&other_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("grantee mismatch");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn grant_proof_manipulated_grantee_signature_is_unauthorized() {
        let f = grant_fixture();
        let host = "node.example.com";
        let hosts = [host.to_string()];
        let nonce = [0xF4u8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let mut bad_sig = sign_grantee_chal(&f, host, &nonce, chal_expiry);
        bad_sig[0] ^= 0x01;
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&bad_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&hosts, 1_700_000_000, &revoked),
        )
        .expect_err("manipulated grantee signature");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn grant_proof_wrong_chan_bind_is_unauthorized() {
        // Grantee signs under a different host than the authoritative set.
        let f = grant_fixture();
        let signed_host = "other.example.com";
        let served_hosts = ["node.example.com".to_string()];
        let nonce = [0xF5u8; 32];
        let chal_expiry = 1_700_000_060u64;
        let revoked = RevokedGrantSet::new();
        let grantee_sig = sign_grantee_chal(&f, signed_host, &nonce, chal_expiry);
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&grantee_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&served_hosts, 1_700_000_000, &revoked),
        )
        .expect_err("wrong chan_bind");
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn validate_resolved_scope_rejects_all_assets_with_non_empty_ids() {
        let s = ResolvedScope {
            all_assets: true,
            asset_ids: vec![[0u8; 32]],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = validate_resolved_scope(&s).expect_err("all_assets with non-empty asset_ids");
        assert_eq!(err.body.error, "internal_error");
    }

    #[test]
    fn validate_resolved_scope_rejects_explicit_empty_asset_ids() {
        let s = ResolvedScope {
            all_assets: false,
            asset_ids: vec![],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = validate_resolved_scope(&s).expect_err("empty asset_ids when not all_assets");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("non-empty"));
    }

    #[test]
    fn encode_grant_asset_ids_rejects_all_assets_with_ids() {
        let err = encode_grant_asset_ids(true, &[[0u8; 32]]).expect_err("all_assets with ids");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("empty"));
    }

    #[test]
    fn encode_grant_asset_ids_rejects_explicit_empty_list() {
        let err = encode_grant_asset_ids(false, &[]).expect_err("empty explicit list");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("non-empty"));
    }

    #[test]
    fn encode_grant_asset_ids_rejects_non_ascending() {
        let err = encode_grant_asset_ids(false, &[[0x02u8; 32], [0x01u8; 32]])
            .expect_err("non-ascending");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("ascending"));
    }

    #[test]
    fn parse_u64_decimal_rejects_empty_leading_non_digit_and_overflow() {
        let err = parse_u64_decimal("").expect_err("empty");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("empty"));

        let err = parse_u64_decimal("01").expect_err("leading zero");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("leading"));

        let err = parse_u64_decimal("1a").expect_err("non-digit");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("digit"));

        let err = parse_u64_decimal("18446744073709551616").expect_err("overflow");
        assert_eq!(err.body.error, "malformed_request");
        assert!(err.body.message.contains("u64"));
    }

    #[test]
    fn parse_u64_decimal_accepts_zero_and_positive() {
        assert_eq!(parse_u64_decimal("0").expect("zero"), 0);
        assert_eq!(parse_u64_decimal("42").expect("forty-two"), 42);
    }

    #[test]
    fn decode_zk_address_rejects_invalid_bech32() {
        let err = decode_zk_address("not-a-bech32").expect_err("invalid bech32");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("Bech32m") || err.body.message.contains("invalid"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_zk_address_rejects_wrong_hrp() {
        let hrp = bech32::Hrp::parse("bc").expect("test HRP");
        let encoded =
            bech32::encode::<bech32::Bech32m>(hrp, &[0u8; 32]).expect("32-byte payload encodes");
        let err = decode_zk_address(&encoded).expect_err("wrong HRP");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("HRP") || err.body.message.contains("zk"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_zk_address_rejects_wrong_payload_length() {
        let hrp = bech32::Hrp::parse(ADDRESS_HRP).expect("constant HRP");
        let encoded =
            bech32::encode::<bech32::Bech32m>(hrp, &[0u8; 20]).expect("20-byte payload encodes");
        let err = decode_zk_address(&encoded).expect_err("wrong payload length");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("32"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_wrong_hrp_is_malformed() {
        let scope = ResolvedScope {
            all_assets: true,
            asset_ids: vec![],
            not_before: 0,
            not_after: u64::MAX,
        };
        let subject = [0u8; 32];
        let grantee = [0u8; 32];
        let nonce = [0u8; 16];
        let sig = [0u8; 64];
        let good = encode_view_grant(&subject, &grantee, &scope, 0, &nonce, &sig)
            .expect("encode dummy grant");
        let checked = CheckedHrpstring::new::<Bech32m>(&good).expect("valid Bech32m grant");
        let data: Vec<u8> = checked.byte_iter().collect();
        let bad_hrp = bech32::Hrp::parse("zkxxxx").expect("test HRP");
        let bad = bech32::encode::<Bech32m>(bad_hrp, &data).expect("re-encode with wrong HRP");
        let err = decode_view_grant(&bad).expect_err("wrong HRP");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("HRP") || err.body.message.contains("zkgrant"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_truncated_payload_is_malformed() {
        let hrp = bech32::Hrp::parse(GRANT_HRP).expect("constant HRP");
        let encoded =
            bech32::encode::<Bech32m>(hrp, &[GRANT_VERSION]).expect("1-byte payload encodes");
        let err = decode_view_grant(&encoded).expect_err("truncated payload");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("too short") || err.body.message.contains("invalid"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_unknown_version_is_malformed() {
        let mut payload = vec![0u8; 170];
        payload[0] = 0xFF;
        let hrp = bech32::Hrp::parse(GRANT_HRP).expect("constant HRP");
        let encoded = bech32::encode::<Bech32m>(hrp, &payload).expect("170-byte payload encodes");
        let err = decode_view_grant(&encoded).expect_err("unknown version");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("version"),
            "message: {}",
            err.body.message
        );
    }

    fn encode_grant_payload(payload: &[u8]) -> String {
        let hrp = bech32::Hrp::parse(GRANT_HRP).expect("hrp");
        bech32::encode::<Bech32m>(hrp, payload).expect("encode")
    }

    #[test]
    fn decode_view_grant_explicit_zero_asset_count_is_malformed() {
        // version(1)+subject(32)+grantee(32)+disc(1)+count(4)+tail(104) = 174
        let mut payload = Vec::with_capacity(174);
        payload.push(GRANT_VERSION);
        payload.extend_from_slice(&[0u8; 32]); // subject
        payload.extend_from_slice(&[0u8; 32]); // grantee
        payload.push(0x01); // explicit asset list
        payload.extend_from_slice(&0u32.to_be_bytes()); // count = 0
        payload.extend_from_slice(&[0u8; 104]); // tail
        let encoded = encode_grant_payload(&payload);
        let err = decode_view_grant(&encoded).expect_err("zero asset count");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("non-empty") || err.body.message.contains("asset_ids"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_truncated_asset_ids_list_is_malformed() {
        // count must exceed remaining/32 so list truncates despite the 170-byte floor.
        // count=4 → need=128; after header (70) remaining at len=170 is 100 < 128.
        let mut payload = Vec::with_capacity(170);
        payload.push(GRANT_VERSION);
        payload.extend_from_slice(&[0u8; 32]); // subject
        payload.extend_from_slice(&[0u8; 32]); // grantee
        payload.push(0x01); // explicit asset list
        payload.extend_from_slice(&4u32.to_be_bytes()); // count = 4
        payload.extend_from_slice(&[0u8; 8]); // only 8 of 128 required id bytes
        payload.resize(170, 0);
        let encoded = encode_grant_payload(&payload);
        let err = decode_view_grant(&encoded).expect_err("truncated asset_ids list");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("truncated asset_ids list"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_asset_ids_not_strictly_ascending_is_malformed() {
        // version(1)+subject(32)+grantee(32)+disc(1)+count(4)+2*32 ids+tail(104) = 238
        let mut payload = Vec::with_capacity(238);
        payload.push(GRANT_VERSION);
        payload.extend_from_slice(&[0u8; 32]); // subject
        payload.extend_from_slice(&[0u8; 32]); // grantee
        payload.push(0x01); // explicit asset list
        payload.extend_from_slice(&2u32.to_be_bytes()); // count = 2
        payload.extend_from_slice(&[0x02u8; 32]); // id0
        payload.extend_from_slice(&[0x01u8; 32]); // id1 (descending)
        payload.extend_from_slice(&[0u8; 104]); // tail
        let encoded = encode_grant_payload(&payload);
        let err = decode_view_grant(&encoded).expect_err("non-ascending asset_ids");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("ascending"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_unknown_asset_discriminator_is_malformed() {
        let mut payload = vec![0u8; 170];
        payload[0] = GRANT_VERSION;
        payload[65] = 0x02; // unknown discriminator at offset 1+32+32
        let encoded = encode_grant_payload(&payload);
        let err = decode_view_grant(&encoded).expect_err("unknown asset discriminator");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("discriminator") || err.body.message.contains("0x02"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_truncated_tail_is_malformed() {
        // disc 0x01, count=1, full 32-byte id → cur=102; at len=170 remaining=68 < 104.
        let mut payload = Vec::with_capacity(170);
        payload.push(GRANT_VERSION);
        payload.extend_from_slice(&[0u8; 32]); // subject
        payload.extend_from_slice(&[0u8; 32]); // grantee
        payload.push(0x01); // explicit asset list
        payload.extend_from_slice(&1u32.to_be_bytes()); // count = 1
        payload.extend_from_slice(&[0u8; 32]); // full asset id
        payload.resize(170, 0); // short tail (68 bytes)
        let encoded = encode_grant_payload(&payload);
        let err = decode_view_grant(&encoded).expect_err("truncated tail");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("truncated time")
                || err.body.message.contains("nonce")
                || err.body.message.contains("signature"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn decode_view_grant_trailing_bytes_is_malformed() {
        // Valid 170-byte wildcard (disc 0x00 + full 104-byte tail) plus one extra byte.
        let mut payload = vec![0u8; 171];
        payload[0] = GRANT_VERSION;
        // disc at offset 65 remains 0x00 (wildcard); bytes 66..170 are the tail; 170 is trailing.
        let encoded = encode_grant_payload(&payload);
        let err = decode_view_grant(&encoded).expect_err("trailing bytes");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("trailing"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn intersect_scopes_empty_time_window_is_403() {
        let requested = ResolvedScope {
            all_assets: true,
            asset_ids: vec![],
            not_before: 10,
            not_after: 20,
        };
        let grant = ResolvedScope {
            all_assets: true,
            asset_ids: vec![],
            not_before: 30,
            not_after: 40,
        };
        let err = intersect_scopes(&requested, &grant).expect_err("empty time window");
        assert_eq!(err.body.error, "scope_exceeded");
    }

    #[test]
    fn intersect_scopes_star_against_empty_grant_assets_is_403() {
        let requested = ResolvedScope {
            all_assets: true,
            asset_ids: vec![],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let grant = ResolvedScope {
            all_assets: false,
            asset_ids: vec![],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = intersect_scopes(&requested, &grant).expect_err("star vs empty grant assets");
        assert_eq!(err.body.error, "scope_exceeded");
    }

    #[test]
    fn intersect_scopes_explicit_id_outside_grant_is_403() {
        let requested = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01; 32]],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let grant = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x02; 32]],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = intersect_scopes(&requested, &grant).expect_err("explicit id outside grant");
        assert_eq!(err.body.error, "scope_exceeded");
        assert!(
            err.body.message.contains("outside") || err.body.message.contains("asset"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn verify_grant_proof_empty_public_hosts_is_internal() {
        let f = grant_fixture();
        let nonce = [0xAAu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let now = 1_700_000_000u64;
        let revoked = RevokedGrantSet::new();
        let dummy_sig = [0u8; 64];
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "grant".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&dummy_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&[], now, &revoked),
        )
        .expect_err("empty public hosts");
        assert_eq!(err.body.error, "internal_error");
    }

    #[test]
    fn unknown_proof_type_session_is_unauthorized() {
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &encode_zk_address(&[0u8; 32]),
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "session".into(),
                subject: encode_zk_address(&[0u8; 32]),
                public_key: encode_hex(&[0u8; 32]),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &[0u8; 32],
            &["h.example".into()],
        )
        .expect_err("unknown proof type");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("session") || err.body.message.contains("unknown"),
            "message must name the unknown type: {}",
            err.body.message
        );
    }

    #[test]
    fn verify_ownership_proof_rejects_subject_mismatch() {
        let (_sk, _pk0, _nkc, _subject_raw, subject_bech) = fixture_identity();
        let other_subject = encode_zk_address(&[0x11u8; 32]);
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: other_subject,
                public_key: encode_hex(&[0u8; 32]),
                nk_commit: encode_hex(&[0u8; 32]),
                signature: encode_hex(&[0u8; 64]),
            },
            &[0u8; 32],
            &["h.example".into()],
        )
        .expect_err("subject mismatch");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("does not match request subject"),
            "message must name subject mismatch: {}",
            err.body.message
        );
    }

    #[test]
    fn verify_ownership_proof_rejects_pk0_nk_not_equal_address() {
        let (_sk, pk0, _nkc, _subject_raw, subject_bech) = fixture_identity();
        let wrong_nk = [0x02u8; 32];
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&[1u8; 32]),
                expiry: "1".into(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&wrong_nk),
                signature: encode_hex(&[0u8; 64]),
            },
            &[0u8; 32],
            &["h.example".into()],
        )
        .expect_err("pk0||nk_commit must equal subject");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("does not equal subject address"),
            "message must name address equality: {}",
            err.body.message
        );
    }

    #[test]
    fn verify_ownership_proof_rejects_empty_public_hosts() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = fixture_identity();
        let host = "node.example.com";
        let nonce = [0xAAu8; 32];
        let expiry = 1_700_000_060u64;
        let request_hash = [0x11u8; 32];
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = sign_chal(&sk, &chal);
        let err = verify_ownership_proof(
            ChallengeDomain::AttestBalance,
            &subject_bech,
            &ChallengeEcho {
                nonce: encode_hex(&nonce),
                expiry: expiry.to_string(),
            },
            &OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: encode_hex(&pk0),
                nk_commit: encode_hex(&nkc),
                signature: encode_hex(&sig),
            },
            &request_hash,
            &[],
        )
        .expect_err("empty public_hosts must be internal_error");
        assert_eq!(err.body.error, "internal_error");
    }

    #[test]
    fn intersect_scopes_empty_request_assets_against_all_assets_grant_is_403() {
        let requested = ResolvedScope {
            all_assets: false,
            asset_ids: vec![],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let grant = ResolvedScope {
            all_assets: true,
            asset_ids: vec![],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err = intersect_scopes(&requested, &grant).expect_err("empty request assets");
        assert_eq!(err.body.error, "scope_exceeded");
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        assert!(
            err.body
                .message
                .contains("resolved scope asset intersection is empty"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn intersect_scopes_empty_request_assets_against_explicit_grant_is_403() {
        let requested = ResolvedScope {
            all_assets: false,
            asset_ids: vec![],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let grant = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01u8; 32]],
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let err =
            intersect_scopes(&requested, &grant).expect_err("empty request vs explicit grant");
        assert_eq!(err.body.error, "scope_exceeded");
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        assert!(
            err.body
                .message
                .contains("resolved scope asset intersection is empty"),
            "message: {}",
            err.body.message
        );
    }

    #[test]
    fn verify_grant_proof_ownership_type_is_unauthorized() {
        let f = grant_fixture();
        let nonce = [0xAAu8; 32];
        let chal_expiry = 1_700_000_060u64;
        let now = 1_700_000_000u64;
        let revoked = RevokedGrantSet::new();
        let dummy_sig = [0u8; 64];
        let err = verify_grant_proof(
            &encode_hex(&nonce),
            &chal_expiry.to_string(),
            &GrantProofJson {
                proof_type: "ownership".into(),
                grant: f.bech.clone(),
                grantee_pk: encode_hex(&f.grantee_pk),
                signature: encode_hex(&dummy_sig),
            },
            &f.op_pk,
            &ResolvedScope::unbounded(),
            &grant_ctx(&["node.example.com".into()], now, &revoked),
        )
        .expect_err("ownership type on grant proof");
        assert_eq!(err.body.error, "unauthorized");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.body.message.contains("grant"),
            "message must mention grant: {}",
            err.body.message
        );
    }
}

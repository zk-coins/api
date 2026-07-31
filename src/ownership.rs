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

/// §7.5 `request_hash` tag for `POST /v1/attest/balance`.
pub const ATTEST_BALANCE_REQUEST_TAG: &str = "zkCoins/v1/AttestBalance";

/// §7.5 `request_hash` tag for `POST /v1/grants`.
pub const ISSUE_GRANT_REQUEST_TAG: &str = "zkCoins/v1/IssueGrant";

/// §5.1 clearnet `chan_bind` host domain.
pub const PULL_HOST_DOMAIN: &str = "zkCoins/v1/PullHost";

/// Bech32m HRP for a zkCoins address (§1.7.7).
pub const ADDRESS_HRP: &str = "zk";

/// Unbounded `not_after` sentinel: `2⁶³−1` (§5.1).
pub const SCOPE_NOT_AFTER_UNBOUNDED: u64 = 9_223_372_036_854_775_807;

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
        }
    }

    /// Whether `chal` omits `request_hash` (pull / bootstrap).
    pub const fn is_simple(self) -> bool {
        matches!(
            self,
            ChallengeDomain::Pull | ChallengeDomain::Entrust | ChallengeDomain::Revoke
        )
    }
}

/// §7.5 / §5.1(a) `OwnershipProofJson` on the wire.
#[derive(Debug, Clone, Deserialize)]
pub struct OwnershipProofJson {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub subject: String,
    pub public_key: String,
    pub nk_commit: String,
    pub signature: String,
}

/// Challenge fields echoed by the client so the API can recompute `chal`
/// without holding challenge state.
///
/// Spec §7.5 abbreviated bodies list only `nonce` (the monlithic node looked
/// up `expiry` from its local store). On a **stateless** API edge the client
/// MUST resubmit the issued `expiry` so BIP-340 verification can run
/// **before** any kernel call that would consume the nonce.
#[derive(Debug, Clone, Deserialize)]
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

fn parse_hex32_field(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let v = decode_hex_exact(s, 32).map_err(|e| ApiError::malformed(format!("{field}: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn parse_hex64_field(s: &str, field: &str) -> Result<[u8; 64], ApiError> {
    let v = decode_hex_exact(s, 64).map_err(|e| ApiError::malformed(format!("{field}: {e}")))?;
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
pub fn verify_bip340(
    pk0: &[u8; 32],
    signature: &[u8; 64],
    message_digest: &[u8; 32],
) -> Result<(), ApiError> {
    let xonly = XOnlyPublicKey::from_slice(pk0).map_err(|_| {
        ApiError::unauthorized("ownership_proof.public_key is not a valid x-only pubkey")
    })?;
    let sig = SchnorrSignature::from_slice(signature).map_err(|_| {
        ApiError::unauthorized("ownership_proof.signature is not a valid BIP-340 signature")
    })?;
    let msg = Message::from_digest_slice(message_digest)
        .map_err(|_| ApiError::internal("BIP-340 message digest must be 32 bytes"))?;
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &msg, &xonly).map_err(|_| {
        ApiError::unauthorized("OwnershipProof signature invalid or chan_bind/domain mismatch")
    })
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

    // 3. Parse fixed-width proof fields.
    let pk0 = parse_hex32_field(&proof.public_key, "ownership_proof.public_key")?;
    let nk_commit = parse_hex32_field(&proof.nk_commit, "ownership_proof.nk_commit")?;
    validate_nk_commit_limbs(&nk_commit)?;
    let signature = parse_hex64_field(&proof.signature, "ownership_proof.signature")?;
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
///
/// Present so the pull handler can discriminate proof kinds without treating
/// an unknown shape as ownership. Full §5.1(b) verification is **not**
/// implemented here — see [`reject_grant_proof`].
#[derive(Debug, Clone, Deserialize)]
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

    let pk0 = parse_hex32_field(&proof.public_key, "ownership_proof.public_key")?;
    let nk_commit = parse_hex32_field(&proof.nk_commit, "ownership_proof.nk_commit")?;
    validate_nk_commit_limbs(&nk_commit)?;
    let signature = parse_hex64_field(&proof.signature, "ownership_proof.signature")?;
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

/// Reject a GrantProof on the pull path (fail-closed, not half-checked).
///
/// §5.1(b) requires verifying the grant's `op` signature against the subject's
/// **published** `op` pubkey. A half-checked grant (structural + grantee chal
/// only) would authorise disclosure under a forged `op` signature — worse than
/// a loud reject. All grant pull attempts therefore fail with `401 unauthorized`.
///
/// # The missing prerequisite is Nostr, not a config field
///
/// `op` is **node-held** (§1.2 key-custody table) and is published as the author
/// of the subject's kind-0 profile (§7.3, §4.3). A node the subject does not
/// control therefore cannot be handed `op_pubkey` as an operator setting, and no
/// kernel RPC can supply it either — the kernel knows its **own** `op`, not a
/// foreign subject's. Obtaining it means resolving that profile and running the
/// §4.3 address binding on the result: `H(pk0 ‖ nk_commit) == subject`, `addr_sig`
/// under `pk0`, and the event signature under the author `op_pubkey`. Without all
/// three, an attacker who knows the subject's public `pk0` / `nk_commit` publishes
/// a profile naming their own `op_pubkey` and the grant check verifies against the
/// forger's key.
///
/// So the prerequisite is a **Nostr profile-resolution path** — the same one the
/// bundle delivery (§4.2) and recovery (§4.5) wait on — not a lookup that could be
/// bolted onto this process.
///
/// Takes the proof so the call site cannot "forget" to name the grant shape
/// (and so tests can assert the reject path against a concrete body).
pub fn reject_grant_proof(_proof: &GrantProofJson) -> ApiError {
    ApiError::unauthorized(
        "GrantProof is not accepted: verifying the grant's op signature needs the subject's \
         published op_pubkey, which is the author of its kind-0 Nostr profile (§7.3) and is \
         reachable only through profile resolution plus the §4.3 address binding — not built; \
         half-checked grants are forbidden (§5.1(b))",
    )
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
        assert!(ChallengeDomain::Pull.is_simple());
        assert!(!ChallengeDomain::AttestBalance.is_simple());
        assert!(!ChallengeDomain::IssueGrant.is_simple());
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
    fn grant_proof_is_rejected_not_half_checked() {
        let err = reject_grant_proof(&GrantProofJson {
            proof_type: "grant".into(),
            grant: "zkgrant1qq".into(),
            grantee_pk: encode_hex(&[0u8; 32]),
            signature: encode_hex(&[0u8; 64]),
        });
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("op_pubkey") || err.body.message.contains("op signature"),
            "message must name the missing op check: {}",
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
}

//! Kind-`24242` Blossom authorization events (§7.4).
//!
//! Pure verification: every check takes an injected `now_unix` so the time
//! window is unit-testable (same discipline as challenge-echo expiry — the
//! verifier never reads the system clock itself).
//!
//! Wire form: `Authorization: Nostr <base64(event JSON)>`.
//!
//! Data permanence (Requirement 12): only **upload** authorization is
//! defined. There is no `t=delete` action and no DELETE route.

use crate::blossom::base64;
use crate::error::ApiError;
use crate::hexutil::decode_hex_exact;
use crate::ownership::verify_bip340;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Recommended replay window from §7.4 (seconds). Fixed server-side bound.
pub const REPLAY_WINDOW_SECS: u64 = 300;

/// Clock-skew allowance: `created_at ≤ now + CLOCK_SKEW_SECS`.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// Nostr event kind for Blossom upload authorization.
pub const BLOSSOM_AUTH_KIND: u64 = 24242;

/// Action tag value for PUT/POST upload.
pub const TAG_T_UPLOAD: &str = "upload";

/// Decoded and cryptographically verified kind-24242 event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthEvent {
    /// `op` x-only public key (32 bytes) that signed the event.
    pub op_pubkey: [u8; 32],
    /// `t` tag: always `"upload"` for v1 (data permanence — no delete).
    pub action: AuthAction,
    /// `x` tag: body hash of the upload.
    pub x_tag: [u8; 32],
    /// Parsed `expiration` tag (unix seconds).
    pub expiration: u64,
    /// Event `created_at`.
    pub created_at: u64,
    /// Nostr event id (SHA-256 of the canonical serialization).
    pub event_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAction {
    Upload,
}

impl AuthAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthAction::Upload => TAG_T_UPLOAD,
        }
    }
}

/// Expected action for the HTTP method under check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredAction {
    Upload,
}

impl RequiredAction {
    pub const fn as_action(self) -> AuthAction {
        match self {
            RequiredAction::Upload => AuthAction::Upload,
        }
    }
}

#[derive(Debug, Deserialize)]
struct WireEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    #[serde(default)]
    content: String,
    sig: String,
}

/// Parse `Authorization: Nostr <base64>` and fully verify a kind-24242 event.
///
/// # Arguments
///
/// * `authorization_header` — full `Authorization` header value
/// * `required` — method-selected action (upload only under data permanence)
/// * `x_expected` — `H(actual body)`. The `x` tag is checked **against this
///   value**, not against any header claim — that is the whole authorization hinge.
/// * `now_unix` — injected clock (seconds since epoch)
///
/// # Status codes (§7.4)
///
/// Signature / kind / `t` / `x` / time-window failures → `401 unauthorized`.
/// Malformed header framing (not `Nostr …`) → `401` as well (capability
/// missing/invalid). The caller maps `op`-key ACL failures to `403`.
pub fn verify_blossom_auth(
    authorization_header: &str,
    required: RequiredAction,
    x_expected: &[u8; 32],
    now_unix: u64,
) -> Result<VerifiedAuthEvent, ApiError> {
    let b64 = parse_nostr_authorization(authorization_header)?;
    let raw = base64::decode(b64).map_err(|e| {
        ApiError::unauthorized(format!(
            "Authorization Nostr payload is not valid base64: {e}"
        ))
    })?;
    let event: WireEvent = serde_json::from_slice(&raw).map_err(|e| {
        ApiError::unauthorized(format!(
            "Authorization Nostr payload is not a JSON event: {e}"
        ))
    })?;

    // kind
    if event.kind != BLOSSOM_AUTH_KIND {
        return Err(ApiError::unauthorized(format!(
            "auth event kind must be {BLOSSOM_AUTH_KIND}, got {}",
            event.kind
        )));
    }

    // content must be empty (§7.4)
    if !event.content.is_empty() {
        return Err(ApiError::unauthorized("auth event content must be empty"));
    }

    let op_pubkey = parse_hex32_lower_or_upper(&event.pubkey, "auth event pubkey")?;
    let sig = parse_hex64_field(&event.sig, "auth event sig")?;
    let claimed_id = parse_hex32_lower_or_upper(&event.id, "auth event id")?;

    // Recompute event id from the canonical serialization and require match.
    let computed_id = compute_event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )?;
    if computed_id != claimed_id {
        return Err(ApiError::unauthorized(
            "auth event id does not match canonical serialization",
        ));
    }

    // BIP-340 over the event id under the op pubkey.
    verify_bip340(&op_pubkey, &sig, &computed_id)
        .map_err(|_| ApiError::unauthorized("auth event signature invalid"))?;

    // Tags: t, x, expiration — each required exactly once for v1.
    let action = require_t_tag(&event.tags)?;
    if action != required.as_action() {
        return Err(ApiError::unauthorized(format!(
            "auth event t tag is {:?}, expected {:?} for this method",
            action.as_str(),
            required.as_action().as_str()
        )));
    }

    let x_tag = require_x_tag(&event.tags)?;
    if x_tag != *x_expected {
        return Err(ApiError::unauthorized(
            "auth event x tag does not match the actual body hash / target blob",
        ));
    }

    let expiration = require_expiration_tag(&event.tags)?;

    // Time window — pure over injected now.
    check_time_window(event.created_at, expiration, now_unix)?;

    Ok(VerifiedAuthEvent {
        op_pubkey,
        action,
        x_tag,
        expiration,
        created_at: event.created_at,
        event_id: computed_id,
    })
}

/// `created_at ≤ now + 60` and `created_at ≥ now − replay_window` and
/// `expiration ≥ now`. Pure: takes `now_unix` as an argument.
pub fn check_time_window(created_at: u64, expiration: u64, now_unix: u64) -> Result<(), ApiError> {
    if expiration < now_unix {
        return Err(ApiError::unauthorized(format!(
            "auth event expiration {expiration} is in the past (now {now_unix})"
        )));
    }
    // created_at ≤ now + 60 (clock skew)
    let max_future = now_unix.saturating_add(CLOCK_SKEW_SECS);
    if created_at > max_future {
        return Err(ApiError::unauthorized(format!(
            "auth event created_at {created_at} is more than {CLOCK_SKEW_SECS}s ahead of now {now_unix}"
        )));
    }
    // created_at ≥ now − replay_window
    let min_created = now_unix.saturating_sub(REPLAY_WINDOW_SECS);
    if created_at < min_created {
        return Err(ApiError::unauthorized(format!(
            "auth event created_at {created_at} is older than replay window \
             ({REPLAY_WINDOW_SECS}s) relative to now {now_unix}"
        )));
    }
    Ok(())
}

fn parse_nostr_authorization(header: &str) -> Result<&str, ApiError> {
    let header = header.trim();
    if header == "Nostr" {
        return Err(ApiError::unauthorized(
            "Authorization Nostr payload is empty",
        ));
    }
    if let Some(rest) = header.strip_prefix("Nostr ") {
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(ApiError::unauthorized(
                "Authorization Nostr payload is empty",
            ));
        }
        return Ok(rest);
    }
    Err(ApiError::unauthorized(
        "Authorization must be \"Nostr <base64(event JSON)>\"",
    ))
}

fn require_t_tag(tags: &[Vec<String>]) -> Result<AuthAction, ApiError> {
    let mut found: Option<AuthAction> = None;
    for tag in tags {
        if tag.first().map(String::as_str) != Some("t") {
            continue;
        }
        // Named tag must be exactly `["t", value]` — len 1 is missing value;
        // len > 2 is a structural rejection (both 401).
        if tag.len() < 2 {
            return Err(ApiError::unauthorized(
                "auth event t tag is missing its value",
            ));
        }
        if tag.len() != 2 {
            return Err(ApiError::unauthorized(
                "auth event t tag must have exactly two elements",
            ));
        }
        let value = tag[1].as_str();
        let action = match value {
            TAG_T_UPLOAD => AuthAction::Upload,
            other => {
                return Err(ApiError::unauthorized(format!(
                    "auth event t tag must be \"upload\", got {other:?}"
                )));
            }
        };
        if found.is_some() {
            return Err(ApiError::unauthorized(
                "auth event must not carry multiple t tags",
            ));
        }
        found = Some(action);
    }
    found.ok_or_else(|| ApiError::unauthorized("auth event is missing the t tag"))
}

fn require_x_tag(tags: &[Vec<String>]) -> Result<[u8; 32], ApiError> {
    let mut found: Option<[u8; 32]> = None;
    for tag in tags {
        if tag.first().map(String::as_str) != Some("x") {
            continue;
        }
        if tag.len() < 2 {
            return Err(ApiError::unauthorized(
                "auth event x tag is missing its value",
            ));
        }
        if tag.len() != 2 {
            return Err(ApiError::unauthorized(
                "auth event x tag must have exactly two elements",
            ));
        }
        let value = tag[1].as_str();
        // x is lowercase-hex SHA-256 of body / blob_id.
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ApiError::unauthorized(
                "auth event x tag must be 64 lowercase hex characters",
            ));
        }
        let bytes = decode_hex_exact(value, 32)
            .map_err(|e| ApiError::unauthorized(format!("auth event x tag: {e}")))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        if found.is_some() {
            return Err(ApiError::unauthorized(
                "auth event must not carry multiple x tags",
            ));
        }
        found = Some(out);
    }
    found.ok_or_else(|| ApiError::unauthorized("auth event is missing the x tag"))
}

fn require_expiration_tag(tags: &[Vec<String>]) -> Result<u64, ApiError> {
    let mut found: Option<u64> = None;
    for tag in tags {
        if tag.first().map(String::as_str) != Some("expiration") {
            continue;
        }
        if tag.len() < 2 {
            return Err(ApiError::unauthorized(
                "auth event expiration tag is missing its value",
            ));
        }
        if tag.len() != 2 {
            return Err(ApiError::unauthorized(
                "auth event expiration tag must have exactly two elements",
            ));
        }
        let value = tag[1].as_str();
        let exp = parse_decimal_u64(value)
            .map_err(|m| ApiError::unauthorized(format!("auth event expiration: {m}")))?;
        if found.is_some() {
            return Err(ApiError::unauthorized(
                "auth event must not carry multiple expiration tags",
            ));
        }
        found = Some(exp);
    }
    found.ok_or_else(|| ApiError::unauthorized("auth event is missing the expiration tag"))
}

fn parse_decimal_u64(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("empty".into());
    }
    if s == "0" {
        return Ok(0);
    }
    if s.as_bytes()[0] == b'0' {
        return Err("leading zeros are not allowed".into());
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("must be decimal digits only".into());
    }
    s.parse::<u64>().map_err(|_| "out of u64 range".to_string())
}

/// Accept lowercase or uppercase hex for Nostr `pubkey`/`id` fields (NIP-01
/// commonly uses lowercase; reject wrong width still).
fn parse_hex32_lower_or_upper(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let v = decode_hex_exact(s, 32).map_err(|e| ApiError::unauthorized(format!("{field}: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn parse_hex64_field(s: &str, field: &str) -> Result<[u8; 64], ApiError> {
    let v = decode_hex_exact(s, 64).map_err(|e| ApiError::unauthorized(format!("{field}: {e}")))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    Ok(out)
}

/// NIP-01 event id: `SHA-256(JSON-array [0, pubkey, created_at, kind, tags, content])`.
///
/// Uses the **wire** `pubkey` string (as presented) and a compact JSON array
/// with no insignificant whitespace. Tags are serialised as JSON arrays of
/// strings in order.
fn compute_event_id(
    pubkey_hex: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32], ApiError> {
    // Build the canonical array via serde_json so string escaping matches
    // the JSON the client signed.
    let tags_value: Vec<Value> = tags
        .iter()
        .map(|t| Value::Array(t.iter().cloned().map(Value::String).collect()))
        .collect();
    let arr = Value::Array(vec![
        Value::Number(0.into()),
        Value::String(pubkey_hex.to_string()),
        Value::Number(created_at.into()),
        Value::Number(kind.into()),
        Value::Array(tags_value),
        Value::String(content.to_string()),
    ]);
    let serialized = serde_json::to_vec(&arr)
        .map_err(|e| ApiError::internal(format!("auth event id serialization failed: {e}")))?;
    Ok(Sha256::digest(&serialized).into())
}

/// Build a signed kind-24242 event (tests / helpers). Returns the base64
/// payload for the `Authorization: Nostr …` header.
#[cfg(test)]
pub fn sign_auth_event_base64(
    sk: &bitcoin::secp256k1::SecretKey,
    pubkey: &[u8; 32],
    action: AuthAction,
    x_tag: &[u8; 32],
    created_at: u64,
    expiration: u64,
) -> String {
    use crate::hexutil::encode_hex;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

    let pubkey_hex = encode_hex(pubkey);
    let tags = vec![
        vec!["t".to_string(), action.as_str().to_string()],
        vec!["x".to_string(), encode_hex(x_tag)],
        vec!["expiration".to_string(), expiration.to_string()],
    ];
    let content = String::new();
    let id = compute_event_id(&pubkey_hex, created_at, BLOSSOM_AUTH_KIND, &tags, &content)
        .expect("event id");
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, sk);
    let msg = Message::from_digest_slice(&id).expect("32-byte digest");
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig.as_ref());

    let event = serde_json::json!({
        "id": encode_hex(&id),
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": BLOSSOM_AUTH_KIND,
        "tags": tags,
        "content": content,
        "sig": encode_hex(&sig_bytes),
    });
    base64::encode(event.to_string().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn sample_sk_pk() -> (SecretKey, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x7au8; 32]).expect("secret");
        let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        (sk, xonly.serialize())
    }

    #[test]
    fn valid_upload_event_verifies() {
        let (sk, pk) = sample_sk_pk();
        let x = [0xabu8; 32];
        let now = 1_700_000_000u64;
        let b64 = sign_auth_event_base64(&sk, &pk, AuthAction::Upload, &x, now, now + 60);
        let header = format!("Nostr {b64}");
        let v = verify_blossom_auth(&header, RequiredAction::Upload, &x, now).expect("ok");
        assert_eq!(v.op_pubkey, pk);
        assert_eq!(v.action, AuthAction::Upload);
        assert_eq!(v.x_tag, x);
    }

    #[test]
    fn delete_t_tag_is_401() {
        // Data permanence: t=delete is not a valid auth action.
        let (sk, pk) = sample_sk_pk();
        let x = [0x11u8; 32];
        let now = 1_700_000_000u64;
        // Build a valid-looking event with t=delete by signing a custom tag set.
        use crate::hexutil::encode_hex;
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
        let pubkey_hex = encode_hex(&pk);
        let tags = vec![
            vec!["t".to_string(), "delete".to_string()],
            vec!["x".to_string(), encode_hex(&x)],
            vec!["expiration".to_string(), (now + 60).to_string()],
        ];
        let content = String::new();
        let id = compute_event_id(&pubkey_hex, now, BLOSSOM_AUTH_KIND, &tags, &content).unwrap();
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest_slice(&id).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig.as_ref());
        let event = serde_json::json!({
            "id": encode_hex(&id),
            "pubkey": pubkey_hex,
            "created_at": now,
            "kind": BLOSSOM_AUTH_KIND,
            "tags": tags,
            "content": content,
            "sig": encode_hex(&sig_bytes),
        });
        let b64 = base64::encode(event.to_string().as_bytes());
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, now)
            .expect_err("delete t must fail");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("t tag") || err.body.message.contains("upload"),
            "cause must name t tag: {}",
            err.body.message
        );
    }

    #[test]
    fn x_tag_must_match_actual_body_hash() {
        let (sk, pk) = sample_sk_pk();
        let signed_x = [0x22u8; 32];
        let actual_x = [0x33u8; 32];
        let now = 1_700_000_000u64;
        let b64 = sign_auth_event_base64(&sk, &pk, AuthAction::Upload, &signed_x, now, now + 60);
        let err = verify_blossom_auth(
            &format!("Nostr {b64}"),
            RequiredAction::Upload,
            &actual_x,
            now,
        )
        .expect_err("x mismatch");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("x tag"),
            "cause must name x tag: {}",
            err.body.message
        );
    }

    #[test]
    fn expired_event_is_401() {
        let (sk, pk) = sample_sk_pk();
        let x = [0x44u8; 32];
        let now = 1_700_000_100u64;
        let b64 = sign_auth_event_base64(
            &sk,
            &pk,
            AuthAction::Upload,
            &x,
            now - 10,
            now - 1, // expiration in the past
        );
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, now)
            .expect_err("expired");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("expiration"),
            "cause must name expiration: {}",
            err.body.message
        );
    }

    #[test]
    fn created_at_too_far_future_is_401() {
        let (sk, pk) = sample_sk_pk();
        let x = [0x55u8; 32];
        let now = 1_700_000_000u64;
        let created = now + CLOCK_SKEW_SECS + 1;
        let b64 = sign_auth_event_base64(&sk, &pk, AuthAction::Upload, &x, created, created + 60);
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, now)
            .expect_err("future");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("created_at"),
            "cause must name created_at: {}",
            err.body.message
        );
    }

    #[test]
    fn created_at_older_than_replay_window_is_401() {
        let (sk, pk) = sample_sk_pk();
        let x = [0x66u8; 32];
        let now = 1_700_000_000u64;
        let created = now - REPLAY_WINDOW_SECS - 1;
        let b64 = sign_auth_event_base64(
            &sk,
            &pk,
            AuthAction::Upload,
            &x,
            created,
            now + 60, // expiration still valid
        );
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, now)
            .expect_err("replay window");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("replay window"),
            "cause must name replay window: {}",
            err.body.message
        );
    }

    #[test]
    fn bad_signature_is_401() {
        let (sk, pk) = sample_sk_pk();
        let x = [0x77u8; 32];
        let now = 1_700_000_000u64;
        let b64 = sign_auth_event_base64(&sk, &pk, AuthAction::Upload, &x, now, now + 60);
        // Flip one base64 character in the payload if possible; simpler: decode,
        // tweak sig, re-encode.
        let raw = base64::decode(&b64).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        // Corrupt the last hex nibble of sig.
        let sig = v["sig"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = sig.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        v["sig"] = serde_json::Value::String(chars.into_iter().collect());
        let bad = base64::encode(v.to_string().as_bytes());
        let err = verify_blossom_auth(&format!("Nostr {bad}"), RequiredAction::Upload, &x, now)
            .expect_err("bad sig");
        // Either id mismatch (if we broke something else) or signature invalid.
        assert_eq!(err.body.error, "unauthorized");
    }

    #[test]
    fn event_id_mismatch_is_401() {
        let (sk, pk) = sample_sk_pk();
        let x = [0x88u8; 32];
        let now = 1_700_000_000u64;
        let b64 = sign_auth_event_base64(&sk, &pk, AuthAction::Upload, &x, now, now + 60);
        let raw = base64::decode(&b64).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        // Flip one hex nibble of the claimed id so it no longer matches canonical.
        let id = v["id"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = id.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        v["id"] = serde_json::Value::String(chars.into_iter().collect());
        let bad = base64::encode(v.to_string().as_bytes());
        let err = verify_blossom_auth(&format!("Nostr {bad}"), RequiredAction::Upload, &x, now)
            .expect_err("id mismatch");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("does not match canonical"),
            "cause must name canonical id mismatch: {}",
            err.body.message
        );
    }

    #[test]
    fn time_window_is_pure_over_injected_now() {
        // Direct unit of the pure helper — no system clock.
        // `now` must be large enough that `now − REPLAY_WINDOW_SECS − 1` is a
        // real u64 value (small toy clocks like 150 under-flow the "too old"
        // case and never exercise the named branch).
        let now = 1_700_000_000u64;

        check_time_window(now - 10, now + 60, now).expect("in window");

        let err = check_time_window(now - 10, now - 1, now).expect_err("expired");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("expiration"),
            "cause must name expiration: {}",
            err.body.message
        );

        let err = check_time_window(now + CLOCK_SKEW_SECS + 1, now + 999, now)
            .expect_err("created_at too far future");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("created_at"),
            "cause must name created_at: {}",
            err.body.message
        );

        let err = check_time_window(now - REPLAY_WINDOW_SECS - 1, now + 999, now)
            .expect_err("created_at older than replay window");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("replay window"),
            "cause must name replay window: {}",
            err.body.message
        );
    }

    #[test]
    fn time_window_saturates_when_now_smaller_than_replay_window() {
        // Production uses saturating_sub: with now < REPLAY_WINDOW_SECS the
        // lower bound is 0, not a panic. created_at = 0 is therefore in-window
        // when expiration is still in the future.
        let now = 10u64;
        assert!(
            now < REPLAY_WINDOW_SECS,
            "precondition: now under the window"
        );
        check_time_window(0, now + 60, now).expect("saturates to min_created = 0");
        // Even created_at = 0 is accepted; there is no "too old" case when
        // now < REPLAY_WINDOW_SECS (the window reaches the epoch).
        let err = check_time_window(now + CLOCK_SKEW_SECS + 1, now + 999, now)
            .expect_err("future still rejected under small now");
        assert!(
            err.body.message.contains("created_at"),
            "cause must name created_at: {}",
            err.body.message
        );
    }

    // --- Header framing -------------------------------------------------------

    #[test]
    fn header_nostr_prefix_only_is_rejected() {
        let x = [0u8; 32];
        let err =
            verify_blossom_auth("Nostr ", RequiredAction::Upload, &x, 0).expect_err("prefix only");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("Nostr"),
            "cause must name Nostr: {}",
            err.body.message
        );
    }

    #[test]
    fn header_nostr_without_payload_is_empty() {
        let x = [0u8; 32];
        for header in ["Nostr", "Nostr   "] {
            let err = verify_blossom_auth(header, RequiredAction::Upload, &x, 0).expect_err(header);
            assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
            assert_eq!(err.body.error, "unauthorized");
            assert!(
                err.body.message.contains("payload is empty"),
                "header {header:?} must name empty payload: {}",
                err.body.message
            );
        }
    }

    #[test]
    fn header_bearer_scheme_is_rejected() {
        let x = [0u8; 32];
        let err = verify_blossom_auth("Bearer abc", RequiredAction::Upload, &x, 0)
            .expect_err("Bearer scheme");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("Nostr"),
            "cause must name Nostr: {}",
            err.body.message
        );
    }

    #[test]
    fn header_invalid_base64_is_rejected() {
        let x = [0u8; 32];
        let err = verify_blossom_auth("Nostr !!!", RequiredAction::Upload, &x, 0)
            .expect_err("invalid base64");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("base64"),
            "cause must name base64: {}",
            err.body.message
        );
    }

    #[test]
    fn header_non_json_payload_is_rejected() {
        let x = [0u8; 32];
        let b64 = crate::blossom::base64::encode(b"not-json");
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, 0)
            .expect_err("non-JSON payload");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("JSON"),
            "cause must name JSON: {}",
            err.body.message
        );
    }

    // --- Event field checks before signature ----------------------------------

    fn dummy_event_json(kind: u64, content: &str) -> String {
        // Dummy hex only: kind/content are checked before sig verification.
        format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":1,"kind":{},"tags":[],"content":"{}","sig":"{}"}}"#,
            "11".repeat(32),
            "22".repeat(32),
            kind,
            content,
            "33".repeat(64),
        )
    }

    #[test]
    fn wrong_kind_is_401_before_signature() {
        let x = [0u8; 32];
        let b64 = crate::blossom::base64::encode(dummy_event_json(1, "").as_bytes());
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, 0)
            .expect_err("wrong kind");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("kind"),
            "cause must name kind: {}",
            err.body.message
        );
    }

    #[test]
    fn non_empty_content_is_401_before_signature() {
        let x = [0u8; 32];
        let b64 = crate::blossom::base64::encode(dummy_event_json(24242, "nope").as_bytes());
        let err = verify_blossom_auth(&format!("Nostr {b64}"), RequiredAction::Upload, &x, 0)
            .expect_err("non-empty content");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("content"),
            "cause must name content: {}",
            err.body.message
        );
    }

    // --- Tag helpers ----------------------------------------------------------

    #[test]
    fn require_t_tag_missing() {
        let err = require_t_tag(&[]).expect_err("missing t");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("missing the t tag"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_t_tag_missing_value() {
        let err = require_t_tag(&[vec!["t".into()]]).expect_err("missing t value");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("missing its value"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_t_tag_extra_element_is_unauthorized() {
        let err = require_t_tag(&[vec!["t".into(), "upload".into(), "junk".into()]])
            .expect_err("extra t element");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("exactly two elements"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_t_tag_download_rejected() {
        let err = require_t_tag(&[vec!["t".into(), "download".into()]]).expect_err("download");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("upload"),
            "cause must name upload: {}",
            err.body.message
        );
    }

    #[test]
    fn require_t_tag_multiple() {
        let err = require_t_tag(&[
            vec!["t".into(), "upload".into()],
            vec!["t".into(), "upload".into()],
        ])
        .expect_err("multiple t");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("multiple t"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_x_tag_missing_value() {
        let err = require_x_tag(&[vec!["x".into()]]).expect_err("missing x value");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("missing its value"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_x_tag_extra_element_is_unauthorized() {
        let err = require_x_tag(&[vec!["x".into(), "aa".repeat(32), "junk".into()]])
            .expect_err("extra x element");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("exactly two elements"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_x_tag_uppercase_hex_rejected() {
        let err = require_x_tag(&[vec!["x".into(), "AA".repeat(32)]]).expect_err("uppercase");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("lowercase"),
            "cause must name lowercase: {}",
            err.body.message
        );
    }

    #[test]
    fn require_x_tag_multiple() {
        let err = require_x_tag(&[
            vec!["x".into(), "aa".repeat(32)],
            vec!["x".into(), "bb".repeat(32)],
        ])
        .expect_err("multiple x");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("multiple x"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_expiration_tag_missing_value() {
        let err = require_expiration_tag(&[vec!["expiration".into()]])
            .expect_err("missing expiration value");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("missing its value"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_expiration_tag_extra_element_is_unauthorized() {
        let err = require_expiration_tag(&[vec!["expiration".into(), "123".into(), "junk".into()]])
            .expect_err("extra expiration element");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("exactly two elements"),
            "cause: {}",
            err.body.message
        );
    }

    #[test]
    fn require_expiration_tag_multiple() {
        let err = require_expiration_tag(&[
            vec!["expiration".into(), "1".into()],
            vec!["expiration".into(), "2".into()],
        ])
        .expect_err("multiple expiration");
        assert_eq!(err.body.error, "unauthorized");
        assert!(
            err.body.message.contains("multiple expiration"),
            "cause: {}",
            err.body.message
        );
    }

    // --- parse_decimal_u64 ----------------------------------------------------

    #[test]
    fn parse_decimal_u64_empty() {
        let err = parse_decimal_u64("").expect_err("empty");
        assert!(err.contains("empty"), "cause: {err}");
    }

    #[test]
    fn parse_decimal_u64_zero_is_ok() {
        assert_eq!(parse_decimal_u64("0"), Ok(0));
    }

    #[test]
    fn parse_decimal_u64_leading_zero() {
        let err = parse_decimal_u64("01").expect_err("leading zero");
        assert!(err.contains("leading"), "cause: {err}");
    }

    #[test]
    fn parse_decimal_u64_non_digit() {
        let err = parse_decimal_u64("1a").expect_err("non-digit");
        assert!(err.contains("digit"), "cause: {err}");
    }

    #[test]
    fn parse_decimal_u64_overflow() {
        let err = parse_decimal_u64("18446744073709551616").expect_err("overflow");
        assert!(err.contains("u64"), "cause: {err}");
    }
}

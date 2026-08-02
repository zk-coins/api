//! `GET /v1/info` and `GET /health/ready` (§7.5 L2876–L2877) over `GetInfo` (§7.8).
//!
//! `/health/ready` takes its readiness statement **only** from kernel
//! `Info.ready` / `Info.ready_reason` — one source, no second readiness
//! table. Diagnostic tip fields that appear on a successful `GetInfo` are
//! forwarded when well-formed; the api never invents tip height, lag, or
//! a NAV root of its own.
//!
//! `GET /v1/info` `features` is API configuration (`AppState.features`),
//! not `Info.kernel_parts`. The array order is **API-fixed** (lexicographic
//! by wire string); §7.5 does not prescribe it — see `info_to_json`.

use crate::error::ApiError;
use crate::hexutil::encode_hex;
use crate::kernel::kernel_v1::{BootstrapManifest, Info};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

/// Closed §7.5 `/health/ready` `reason` set (L2876).
const READY_REASONS: &[&str] = &[
    "syncing",
    "scanner_lag",
    "circuit_mismatch",
    "deep_reorg",
    "dependency_unavailable",
];

/// `GET /v1/info` → `GetInfo` + API-owned `features`.
pub async fn get_info(State(state): State<AppState>) -> Result<Response, ApiError> {
    let info = state.kernel.get_info().await?;
    // When Blossom is configured, advertise the API-enforced upload limit
    // (`ZKCOINS_BLOSSOM_MAX_BLOB_BYTES`), not the kernel's independent
    // `Info.max_blob_bytes`. Clients must see the bound that PUT/POST
    // `/blossom/upload` actually applies; publishing a higher kernel figure
    // while the API rejects larger bodies would be inconsistent. Equality
    // with the kernel is **not** required at boot — the REST surface is
    // authoritative for the public limit when this process stores blobs.
    let max_blob_override = state.blossom.as_ref().map(|b| b.max_blob_bytes);
    let body = info_to_json(&info, &state.features, max_blob_override)?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `GET /health/ready` → readiness projection of `GetInfo`.
///
/// Shape is **always** `{ ready, reason? , …diags? }` — never the generic
/// `{ "error", "message" }` body (L2876). When the kernel call fails, the
/// probe answers **not ready** with `dependency_unavailable` (HTTP 503).
/// Inventing `ready: true` on a failed `GetInfo` would be the worst outcome:
/// a process that cannot ask the kernel is not ready to serve consensus-
/// dependent reads. Today's production kernel fails `GetInfo` closed when
/// `ChainIdentity` is unset; this endpoint therefore returns 503 not-ready
/// rather than a green probe.
pub async fn health_ready(State(state): State<AppState>) -> Response {
    match state.kernel.get_info().await {
        Ok(info) => readiness_from_info(&info),
        Err(err) => not_ready_dependency(err),
    }
}

fn readiness_from_info(info: &Info) -> Response {
    if info.ready {
        // ready == true: reason must be absent (proto optional empty / None).
        if let Some(reason) = info.ready_reason.as_deref() {
            if !reason.is_empty() {
                // Kernel violated the structural invariant. Do not claim ready.
                return not_ready_body("dependency_unavailable");
            }
        }
        let mut body = Map::new();
        body.insert("ready".to_string(), Value::Bool(true));
        attach_diagnostics(&mut body, info);
        (StatusCode::OK, Json(Value::Object(body))).into_response()
    } else {
        let reason = match info.ready_reason.as_deref() {
            Some(r) if is_closed_ready_reason(r) => r,
            Some(_) | None => {
                // Missing, empty, or non-closed reason: do not invent ready:true
                // and do not pass an out-of-set token. Closed fallback reason.
                return not_ready_body("dependency_unavailable");
            }
        };
        let mut body = Map::new();
        body.insert("ready".to_string(), Value::Bool(false));
        body.insert("reason".to_string(), Value::String(reason.to_string()));
        attach_diagnostics(&mut body, info);
        (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Object(body))).into_response()
    }
}

/// When `GetInfo` itself fails: not-ready, closed reason, readiness shape.
///
/// The underlying `ApiError` message is **not** put on the wire as a
/// generic error body (that shape is excluded for this path). It is also
/// not rewritten into a different closed reason — the only honest probe
/// answer when the dependency cannot answer is `dependency_unavailable`.
fn not_ready_dependency(_err: ApiError) -> Response {
    // `_err` is deliberately not projected onto the wire: /health/ready is
    // excluded from the generic error body, and the closed reason set has no
    // "internal_error" token. The honest readiness answer when GetInfo cannot
    // complete is dependency_unavailable.
    not_ready_body("dependency_unavailable")
}

fn not_ready_body(reason: &'static str) -> Response {
    debug_assert!(is_closed_ready_reason(reason));
    let mut body = Map::new();
    body.insert("ready".to_string(), Value::Bool(false));
    body.insert("reason".to_string(), Value::String(reason.to_string()));
    (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Object(body))).into_response()
}

/// Diagnostic fields from a successful `GetInfo` (§7.5 L2876 MAY).
///
/// `root` is **not** emitted here: the accumulator `root` must be paired
/// with its `size` (L2882), and `Info` carries `accumulator_root` without
/// `size`. Emitting an unpaired root would invent a half-fact. Tip height
/// and scanner lag are complete on their own and come straight from Info.
fn attach_diagnostics(body: &mut Map<String, Value>, info: &Info) {
    body.insert(
        "bitcoin_tip_height".to_string(),
        json!(info.bitcoin_tip_height),
    );
    body.insert("scanner_lag".to_string(), json!(info.scanner_lag));
}

fn is_closed_ready_reason(reason: &str) -> bool {
    // Same truth value as `iter().any(|&r| r == reason)` for every input,
    // including empty / non-closed strings (both false). Prefer `contains`.
    READY_REASONS.contains(&reason)
}

/// Project kernel `Info` into the §7.5 `/v1/info` JSON object (L2877).
///
/// Pass-through fields are taken from the kernel; `features` is built
/// solely from API config. `kernel_parts`, `ready`, `ready_reason`, tip
/// diagnostics, and `accumulator_root` are **not** part of this surface.
///
/// **`features` array order (API-fixed, intentional):** §7.5 / §6.1 close the
/// *set* of feature strings but do **not** prescribe array order. This layer
/// emits them in **lexicographic order of the wire string**
/// (`explorer` before `wallet`, …). That order is independent of env-var
/// token order and of `Feature` enum discriminant/`Ord` order — do not
/// "clean up" to input order or to enum declaration order; a public
/// response field must be bit-stable for the same enabled set.
fn info_to_json(
    info: &Info,
    features: &std::collections::BTreeSet<crate::config::Feature>,
    max_blob_bytes_override: Option<u64>,
) -> Result<Value, ApiError> {
    let network = info.network.as_str();
    match network {
        "mainnet" | "testnet" | "regtest" => {}
        other => {
            return Err(ApiError::internal(format!(
                "kernel Info.network is not a closed tag: {other:?}"
            )));
        }
    }
    if info.protocol_version != "v1" {
        return Err(ApiError::internal(format!(
            "kernel Info.protocol_version must be \"v1\", got {:?}",
            info.protocol_version
        )));
    }

    let circuit_digests = circuit_digests_json(&info.circuit_digests)?;
    let bootstrap_pubkey = require_hex32(&info.bootstrap_pubkey, "bootstrap_pubkey")?;
    let bootstrap = match &info.bootstrap {
        Some(m) => bootstrap_to_json(m)?,
        None => {
            return Err(ApiError::internal(
                "kernel Info.bootstrap is absent — BootstrapManifest is required on /v1/info",
            ));
        }
    };

    // BTreeSet<Feature> already deduplicates; sort by wire string so the
    // public array is not bound to enum Ord (Wallet < Explorer would emit
    // ["wallet","explorer"] — wrong for the fixed lexicographic order).
    let mut feature_names: Vec<&'static str> = features.iter().map(|f| f.as_str()).collect();
    feature_names.sort_unstable();
    let feature_list: Vec<Value> = feature_names
        .into_iter()
        .map(|s| Value::String(s.to_string()))
        .collect();

    // Prefer the API Blossom limit when configured; otherwise the kernel value
    // (informational — no local upload path without a store).
    let max_blob_bytes = match max_blob_bytes_override {
        Some(api_limit) => api_limit,
        None => info.max_blob_bytes,
    };

    Ok(json!({
        "network": network,
        "protocol_version": "v1",
        "circuit_digests": circuit_digests,
        "bootstrap_pubkey": bootstrap_pubkey,
        "relay_url": info.relay_url,
        "blossom_url": info.blossom_url,
        "max_blob_bytes": max_blob_bytes,
        "finality_confirmations": info.finality_confirmations,
        "activation_height": info.activation_height,
        "max_tx_inputs": info.max_tx_inputs,
        "max_tx_outputs": info.max_tx_outputs,
        "max_rx_coins": info.max_rx_coins,
        "max_account_assets": info.max_account_assets,
        "features": feature_list,
        "bootstrap": bootstrap,
    }))
}

fn circuit_digests_json(
    digests: &std::collections::HashMap<String, Vec<u8>>,
) -> Result<Value, ApiError> {
    let c = match digests.get("C") {
        Some(bytes) => require_hex32(bytes, "circuit_digests.C")?,
        None => {
            return Err(ApiError::internal(
                "kernel Info.circuit_digests is missing key \"C\"",
            ));
        }
    };
    let c_balance = match digests.get("C_balance") {
        Some(bytes) => require_hex32(bytes, "circuit_digests.C_balance")?,
        None => {
            return Err(ApiError::internal(
                "kernel Info.circuit_digests is missing key \"C_balance\"",
            ));
        }
    };
    // Only the two closed keys — extra map entries from a future kernel
    // are not part of §7.5 /v1/info and must not be silently advertised.
    if digests.len() != 2 {
        return Err(ApiError::internal(format!(
            "kernel Info.circuit_digests must contain exactly C and C_balance, got {} keys",
            digests.len()
        )));
    }
    Ok(json!({
        "C": c,
        "C_balance": c_balance,
    }))
}

fn bootstrap_to_json(m: &BootstrapManifest) -> Result<Value, ApiError> {
    match m.network.as_str() {
        "mainnet" | "testnet" | "regtest" => {}
        other => {
            return Err(ApiError::internal(format!(
                "kernel BootstrapManifest.network is not a closed tag: {other:?}"
            )));
        }
    }
    if m.protocol_version != "v1" {
        return Err(ApiError::internal(format!(
            "kernel BootstrapManifest.protocol_version must be \"v1\", got {:?}",
            m.protocol_version
        )));
    }
    let mut operator_ids = Vec::with_capacity(m.operator_ids.len());
    for (i, id) in m.operator_ids.iter().enumerate() {
        operator_ids.push(Value::String(require_hex32(
            id,
            &format!("bootstrap.operator_ids[{i}]"),
        )?));
    }
    let manifest_sig = require_hex_exact(&m.manifest_sig, 64, "bootstrap.manifest_sig")?;
    Ok(json!({
        "network": m.network,
        "protocol_version": m.protocol_version,
        "seed_relays": m.seed_relays,
        "blob_stores": m.blob_stores,
        "operator_ids": operator_ids,
        "issued_at": m.issued_at,
        "expires_at": m.expires_at,
        "manifest_sig": manifest_sig,
    }))
}

fn require_hex32(bytes: &[u8], field: &str) -> Result<String, ApiError> {
    require_hex_exact(bytes, 32, field)
}

fn require_hex_exact(bytes: &[u8], expected: usize, field: &str) -> Result<String, ApiError> {
    if bytes.len() != expected {
        return Err(ApiError::internal(format!(
            "kernel field {field} must be {expected} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(encode_hex(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Feature;
    use std::collections::{BTreeSet, HashMap};

    fn sample_info(ready: bool, reason: Option<&str>) -> Info {
        let mut circuit_digests = HashMap::new();
        circuit_digests.insert("C".to_string(), vec![0x11; 32]);
        circuit_digests.insert("C_balance".to_string(), vec![0x22; 32]);
        Info {
            network: "regtest".into(),
            protocol_version: "v1".into(),
            circuit_digests,
            relay_url: "wss://relay.example".into(),
            blossom_url: "https://blossom.example".into(),
            finality_confirmations: 6,
            max_tx_inputs: 8,
            max_tx_outputs: 8,
            max_rx_coins: 4,
            max_account_assets: 32,
            ready,
            bitcoin_tip_height: 100,
            accumulator_root: vec![0xAA; 32],
            scanner_lag: 0,
            max_blob_bytes: 1_048_576,
            activation_height: 0,
            bootstrap: Some(BootstrapManifest {
                network: "regtest".into(),
                protocol_version: "v1".into(),
                seed_relays: vec!["wss://seed.example".into()],
                blob_stores: vec!["https://blob.example".into()],
                operator_ids: vec![vec![0x33; 32]],
                issued_at: 1,
                expires_at: 9_999_999_999,
                manifest_sig: vec![0x44; 64],
            }),
            kernel_parts: vec!["scanner".into()],
            ready_reason: reason.map(|s| s.to_string()),
            bootstrap_pubkey: vec![0x55; 32],
        }
    }

    #[test]
    fn info_json_features_from_api_not_kernel_parts() {
        let info = sample_info(true, None);
        let features = BTreeSet::from([Feature::Wallet, Feature::Explorer]);
        let json = info_to_json(&info, &features, None).expect("info");
        assert_eq!(json["network"], "regtest");
        assert_eq!(json["protocol_version"], "v1");
        assert_eq!(json["features"], json!(["explorer", "wallet"]));
        assert_eq!(json["max_blob_bytes"], 1_048_576);
        // kernel_parts must not leak onto the public surface.
        assert!(json.get("kernel_parts").is_none());
        assert!(json.get("ready").is_none());
        assert_eq!(json["bootstrap_pubkey"].as_str().unwrap().len(), 64);
        assert_eq!(json["circuit_digests"]["C"].as_str().unwrap().len(), 64);
        assert_eq!(
            json["bootstrap"]["manifest_sig"].as_str().unwrap().len(),
            128
        );
    }

    /// Without the override, a lower API Blossom limit would leave clients
    /// seeing the higher kernel figure while uploads reject at the API bound.
    #[test]
    fn info_json_prefers_api_max_blob_bytes_when_override_set() {
        let info = sample_info(true, None);
        assert_eq!(info.max_blob_bytes, 1_048_576);
        let features = BTreeSet::new();
        let json = info_to_json(&info, &features, Some(4096)).expect("info");
        assert_eq!(
            json["max_blob_bytes"], 4096,
            "API-enforced limit must be advertised when Blossom is configured"
        );
    }

    #[test]
    fn readiness_ready_is_200_without_reason() {
        let info = sample_info(true, None);
        let res = readiness_from_info(&info);
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn readiness_not_ready_is_503_with_closed_reason() {
        let info = sample_info(false, Some("syncing"));
        let res = readiness_from_info(&info);
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_rejects_unknown_reason_as_dependency_unavailable() {
        let info = sample_info(false, Some("something_else"));
        let res = readiness_from_info(&info);
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

//! Public chain read surface (§7.5 L2878, L2880) over kernel procedures.
//!
//! | REST | Kernel |
//! |---|---|
//! | `GET /v1/chain/accumulator` | `GetAccumulator` |
//! | `GET /v1/chain/nullifier/<pubkey>` | `GetNullifierPath` |
//!
//! **Not served:** `chain_inscriptions` / `ListInscriptions`. The node answers
//! that procedure `Unimplemented` until a scanner-written inscription catalog
//! (reveal txid + §3.5 format) exists; wrapping it in REST that always 501s
//! would only create a second place to learn the same absence. The key stays
//! in the closed inventory and is omitted from `GET /` until the catalog lands.
//!
//! The api **does not recompute** `nav_root = Hc("NfLog/Root", size ‖ mth)`.
//! Every `root` byte is what the kernel returned. Width checks reject a
//! malformed kernel payload; they never invent a substitute digest.

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{AccumulatorTip, NullifierPath, NullifierPathRequest};
use crate::kernel::KernelHandle;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

/// `GET /v1/chain/accumulator` → `GetAccumulator`.
///
/// Response form §7.5 L2878: `{ size, root, tip_block_hash, tip_height }`.
/// `root` is the kernel's `nav_root` — pass-through, not recomputed.
pub async fn get_accumulator(State(kernel): State<KernelHandle>) -> Result<Response, ApiError> {
    let tip = kernel.get_accumulator().await?;
    let body = accumulator_to_json(&tip)?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `GET /v1/chain/nullifier/<pubkey>` → `GetNullifierPath`.
///
/// Response form §7.5 L2880. **present** and **absent** are distinct domain
/// answers from the kernel's `present` flag:
/// - `present: true` → inclusion proof fields (`position`, `leaf`, `audit_path`)
/// - `present: false` → unauthenticated local-index absence (no position/leaf)
///
/// A kernel `internal_error` (e.g. corrupt index) is returned as that error
/// via `ErrorInfo` — **never** rewritten as `present: false`. Absence is only
/// the successful path with `present == false`.
pub async fn get_nullifier(
    State(kernel): State<KernelHandle>,
    Path(pubkey_hex): Path<String>,
) -> Result<Response, ApiError> {
    let pubkey = decode_hex_exact(&pubkey_hex, 32).map_err(|e| {
        ApiError::malformed(format!("pubkey path segment must be 32-byte hex: {e}"))
    })?;
    let path = kernel
        .get_nullifier_path(NullifierPathRequest { pubkey })
        .await?;
    let body = nullifier_path_to_json(&path)?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

fn accumulator_to_json(tip: &AccumulatorTip) -> Result<Value, ApiError> {
    Ok(json!({
        "size": tip.size,
        "root": require_hex32(&tip.root, "root")?,
        "tip_block_hash": require_hex32(&tip.tip_block_hash, "tip_block_hash")?,
        "tip_height": tip.tip_height,
    }))
}

fn nullifier_path_to_json(path: &NullifierPath) -> Result<Value, ApiError> {
    let mut obj = Map::new();
    obj.insert("present".to_string(), Value::Bool(path.present));
    obj.insert(
        "root".to_string(),
        Value::String(require_hex32(&path.root, "root")?),
    );
    obj.insert(
        "tip_block_hash".to_string(),
        Value::String(require_hex32(&path.tip_block_hash, "tip_block_hash")?),
    );
    obj.insert("tip_height".to_string(), json!(path.tip_height));
    obj.insert("tree_size".to_string(), json!(path.tree_size));

    if path.present {
        // Inclusion proof fields — required when present (L2880).
        if path.leaf.is_empty() {
            return Err(ApiError::internal(
                "kernel NullifierPath.present is true but leaf is empty",
            ));
        }
        obj.insert("position".to_string(), json!(path.position));
        obj.insert(
            "leaf".to_string(),
            Value::String(require_hex32(&path.leaf, "leaf")?),
        );
        let mut audit = Vec::with_capacity(path.audit_path.len());
        if path.audit_path.len() > 64 {
            return Err(ApiError::internal(format!(
                "kernel NullifierPath.audit_path exceeds 64 entries (got {})",
                path.audit_path.len()
            )));
        }
        for (i, node) in path.audit_path.iter().enumerate() {
            audit.push(Value::String(require_hex32(
                node,
                &format!("audit_path[{i}]"),
            )?));
        }
        obj.insert("audit_path".to_string(), Value::Array(audit));
    } else {
        // Unauthenticated absence (L2880 / §3.7 Path B). position and leaf
        // are omitted — not null, not zero. audit_path is the empty list.
        // Proto may carry position=0 / leaf empty as scalar defaults; those
        // must not appear on the REST wire as if they were proof material.
        if !path.leaf.is_empty() {
            return Err(ApiError::internal(
                "kernel NullifierPath.present is false but leaf is non-empty",
            ));
        }
        if !path.audit_path.is_empty() {
            return Err(ApiError::internal(
                "kernel NullifierPath.present is false but audit_path is non-empty",
            ));
        }
        obj.insert("audit_path".to_string(), Value::Array(Vec::new()));
    }

    Ok(Value::Object(obj))
}

fn require_hex32(bytes: &[u8], field: &str) -> Result<String, ApiError> {
    if bytes.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel field {field} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(encode_hex(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_pass_through_does_not_recompute_root() {
        let tip = AccumulatorTip {
            root: vec![0xAB; 32],
            tip_block_hash: vec![0xCD; 32],
            tip_height: 42,
            size: 7,
        };
        let json = accumulator_to_json(&tip).expect("json");
        assert_eq!(json["size"], 7);
        assert_eq!(json["tip_height"], 42);
        assert_eq!(json["root"].as_str().unwrap(), encode_hex(&[0xAB; 32]));
        assert_eq!(
            json["tip_block_hash"].as_str().unwrap(),
            encode_hex(&[0xCD; 32])
        );
    }

    #[test]
    fn present_path_includes_position_and_leaf() {
        let path = NullifierPath {
            root: vec![0x01; 32],
            tip_height: 10,
            present: true,
            leaf: vec![0x02; 32],
            position: 3,
            audit_path: vec![vec![0x03; 32]],
            tree_size: 4,
            tip_block_hash: vec![0x04; 32],
        };
        let json = nullifier_path_to_json(&path).expect("json");
        assert_eq!(json["present"], true);
        assert_eq!(json["position"], 3);
        assert_eq!(json["leaf"].as_str().unwrap().len(), 64);
        assert_eq!(json["audit_path"].as_array().unwrap().len(), 1);
        assert_eq!(json["tree_size"], 4);
    }

    #[test]
    fn absent_path_omits_position_and_leaf() {
        let path = NullifierPath {
            root: vec![0x01; 32],
            tip_height: 10,
            present: false,
            leaf: Vec::new(),
            position: 0,
            audit_path: Vec::new(),
            tree_size: 4,
            tip_block_hash: vec![0x04; 32],
        };
        let json = nullifier_path_to_json(&path).expect("json");
        assert_eq!(json["present"], false);
        assert!(json.get("position").is_none());
        assert!(json.get("leaf").is_none());
        assert_eq!(json["audit_path"], json!([]));
        assert_eq!(json["tree_size"], 4);
        assert_eq!(json["root"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn wrong_width_root_is_internal_not_silent_pad() {
        let tip = AccumulatorTip {
            root: vec![0xAB; 16],
            tip_block_hash: vec![0xCD; 32],
            tip_height: 1,
            size: 0,
        };
        let err = accumulator_to_json(&tip).expect_err("bad root");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("root"),
            "message must name the field, got {}",
            err.body.message
        );
    }
}

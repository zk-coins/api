//! Public chain read surface (§7.5 L2878–L2880) over kernel procedures.
//!
//! | REST | Kernel |
//! |---|---|
//! | `GET /v1/chain/accumulator` | `GetAccumulator` |
//! | `GET /v1/chain/inscriptions` | `ListInscriptions` (server-stream → one page) |
//! | `GET /v1/chain/nullifier/<pubkey>` | `GetNullifierPath` |
//!
//! The api **does not recompute** `nav_root = Hc("NfLog/Root", size ‖ mth)`.
//! Every `root` byte is what the kernel returned. Width checks reject a
//! malformed kernel payload; they never invent a substitute digest.

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{
    AccumulatorTip, Inscription, ListInscriptionsRequest, Nullifier, NullifierPath,
    NullifierPathRequest,
};
use crate::kernel::KernelHandle;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use serde_json::{json, Map, Value};

/// Inclusive lower bound + page size after REST query normalisation (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListInscriptionsQuery {
    from_height: u64,
    from_tx_index: u64,
    from_vin_index: u64,
    /// Client page size; valid range `1..=1000` (enforced at parse).
    limit: u32,
}

/// Exclusive triple-cursor after the last returned inscription (§7.5).
///
/// Structural all-or-nothing: the REST body either carries all three `next_*`
/// fields (this value is `Some`) or none of them (`None`). A proper subset is
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TripleCursor {
    height: u64,
    tx_index: u64,
    vin_index: u64,
}

impl TripleCursor {
    fn from_inscription(ins: &Inscription) -> Self {
        Self {
            height: ins.height,
            tx_index: ins.tx_index,
            vin_index: ins.vin_index,
        }
    }

    /// Lexicographic successor of this triple — the inclusive `from_*` that
    /// starts strictly after `self`. Used only for the limit=1000 peek path.
    fn exclusive_successor(self) -> Result<Self, ApiError> {
        if self.vin_index < u64::MAX {
            return Ok(Self {
                height: self.height,
                tx_index: self.tx_index,
                vin_index: self.vin_index + 1,
            });
        }
        if self.tx_index < u64::MAX {
            return Ok(Self {
                height: self.height,
                tx_index: self.tx_index + 1,
                vin_index: 0,
            });
        }
        if self.height < u64::MAX {
            return Ok(Self {
                height: self.height + 1,
                tx_index: 0,
                vin_index: 0,
            });
        }
        Err(ApiError::internal(
            "inscription triple cursor cannot advance past (u64::MAX, u64::MAX, u64::MAX)",
        ))
    }
}

/// One REST page: inscriptions plus an optional all-or-nothing next cursor.
///
/// `PartialEq` only — prost `Inscription` is not `Eq`, and this type is never
/// used as a map/set key. Ordering of `inscriptions` is the kernel's contract
/// (§7.8), checked rather than re-derived.
#[derive(Debug, Clone, PartialEq)]
struct InscriptionsPage {
    inscriptions: Vec<Inscription>,
    next: Option<TripleCursor>,
}

/// Named kernel-limit translation for pagination (`PAGE_LOOKAHEAD`).
///
/// REST `limit` is the number of inscriptions on the page. To learn whether a
/// further page exists, the API must see one item beyond that page. When
/// `rest_limit < MAX_LIMIT` (strictly below the kernel's closed max), the kernel
/// receives `rest_limit + 1` in a single `ListInscriptions` call — that is the
/// **page-lookahead** translation: deliberate, named, and never a silent
/// clamp of the client value. At `rest_limit == MAX_LIMIT` the kernel cannot
/// accept `MAX_LIMIT + 1`, so the handler requests exactly `MAX_LIMIT` and, only
/// if the stream is full, issues a second **peek** RPC with `limit = 1` from
/// the exclusive successor of the last returned triple.
///
// §7.5 `GET /v1/chain/inscriptions` query defaults (normative; API-normalised
// before RPC when the REST query omits them). Named constants — not
// `unwrap_or_default()` — so the literal value and its protocol origin stay
// visible at every use site.
/// §7.5 `GET /v1/chain/inscriptions`: `from_height` optional, default 0.
const DEFAULT_FROM_HEIGHT: u64 = 0;
/// §7.5: `from_tx_index` optional, default 0.
const DEFAULT_FROM_TX_INDEX: u64 = 0;
/// §7.5: `from_vin_index` optional, default 0.
const DEFAULT_FROM_VIN_INDEX: u64 = 0;
/// §7.5: `limit` optional, default 100; valid range `1..=1000`.
const DEFAULT_LIMIT: u32 = 100;
/// §7.5: lower bound of valid `limit` (inclusive).
const MIN_LIMIT: u32 = 1;
/// §7.5: upper bound of valid `limit` (inclusive).
const MAX_LIMIT: u32 = 1000;

/// `GET /v1/chain/accumulator` → `GetAccumulator`.
///
/// Response form §7.5 L2878: `{ size, root, tip_block_hash, tip_height }`.
/// `root` is the kernel's `nav_root` — pass-through, not recomputed.
pub async fn get_accumulator(State(kernel): State<KernelHandle>) -> Result<Response, ApiError> {
    let tip = kernel.get_accumulator().await?;
    let body = accumulator_to_json(&tip)?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `GET /v1/chain/inscriptions` → `ListInscriptions` (stream collected into one page).
///
/// Query/response form §7.5 L2879. Empty catalogue → `{ "inscriptions": [] }`
/// with no `next_*` fields (200, never 404).
pub async fn list_inscriptions(
    State(kernel): State<KernelHandle>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let query = parse_list_inscriptions_query(raw.as_deref())?;
    let page = fetch_inscriptions_page(&kernel, query).await?;
    let body = inscriptions_page_to_json(&page)?;
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

// ---------------------------------------------------------------------------
// Query parse (malformed vs bounds_exceeded)
// ---------------------------------------------------------------------------

fn parse_list_inscriptions_query(raw: Option<&str>) -> Result<ListInscriptionsQuery, ApiError> {
    let mut from_height: Option<u64> = None;
    let mut from_tx_index: Option<u64> = None;
    let mut from_vin_index: Option<u64> = None;
    let mut limit: Option<u32> = None;

    if let Some(q) = raw {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            match key {
                "from_height" => {
                    if from_height.is_some() {
                        return Err(ApiError::malformed("duplicate query parameter from_height"));
                    }
                    from_height = Some(parse_decimal_u64("from_height", value)?);
                }
                "from_tx_index" => {
                    if from_tx_index.is_some() {
                        return Err(ApiError::malformed(
                            "duplicate query parameter from_tx_index",
                        ));
                    }
                    from_tx_index = Some(parse_decimal_u64("from_tx_index", value)?);
                }
                "from_vin_index" => {
                    if from_vin_index.is_some() {
                        return Err(ApiError::malformed(
                            "duplicate query parameter from_vin_index",
                        ));
                    }
                    from_vin_index = Some(parse_decimal_u64("from_vin_index", value)?);
                }
                "limit" => {
                    if limit.is_some() {
                        return Err(ApiError::malformed("duplicate query parameter limit"));
                    }
                    limit = Some(parse_decimal_u32("limit", value)?);
                }
                _ => {
                    // Unknown query keys are ignored — only the closed set is
                    // interpreted; extra keys must not soft-fail the request.
                }
            }
        }
    }

    // §7.5 defaults for omitted parameters (API-normalised before RPC).
    let from_height = from_height.unwrap_or(DEFAULT_FROM_HEIGHT);
    let from_tx_index = from_tx_index.unwrap_or(DEFAULT_FROM_TX_INDEX);
    let from_vin_index = from_vin_index.unwrap_or(DEFAULT_FROM_VIN_INDEX);
    let limit = match limit {
        None => DEFAULT_LIMIT,
        Some(n) if n < MIN_LIMIT => {
            return Err(ApiError::bounds_exceeded(format!(
                "limit must be in {MIN_LIMIT}..={MAX_LIMIT}; got {n}"
            )));
        }
        Some(n) if n > MAX_LIMIT => {
            return Err(ApiError::bounds_exceeded(format!(
                "limit must be in {MIN_LIMIT}..={MAX_LIMIT}; got {n}"
            )));
        }
        Some(n) => n,
    };

    Ok(ListInscriptionsQuery {
        from_height,
        from_tx_index,
        from_vin_index,
        limit,
    })
}

fn parse_decimal_u64(name: &str, raw: &str) -> Result<u64, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::malformed(format!(
            "{name} must be a non-empty decimal integer"
        )));
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::malformed(format!(
            "{name} must be a decimal integer, got {raw:?}"
        )));
    }
    // Leading zeros are fine for "0"; multi-digit with leading zeros still
    // parse as the same integer (no alternate encoding).
    raw.parse::<u64>()
        .map_err(|_| ApiError::malformed(format!("{name} overflows u64: {raw:?}")))
}

fn parse_decimal_u32(name: &str, raw: &str) -> Result<u32, ApiError> {
    let v = parse_decimal_u64(name, raw)?;
    u32::try_from(v).map_err(|_| ApiError::malformed(format!("{name} overflows u32: {raw:?}")))
}

// ---------------------------------------------------------------------------
// Page fetch (PAGE_LOOKAHEAD + optional peek at limit=1000)
// ---------------------------------------------------------------------------

async fn fetch_inscriptions_page(
    kernel: &KernelHandle,
    query: ListInscriptionsQuery,
) -> Result<InscriptionsPage, ApiError> {
    let rest_limit = query.limit;
    // PAGE_LOOKAHEAD: ask for one extra when the kernel can still accept it.
    let kernel_limit = if rest_limit < MAX_LIMIT {
        rest_limit + 1
    } else {
        rest_limit
    };

    let collected = collect_stream(
        kernel,
        ListInscriptionsRequest {
            from_height: Some(query.from_height),
            from_tx_index: Some(query.from_tx_index),
            from_vin_index: Some(query.from_vin_index),
            limit: Some(kernel_limit),
        },
    )
    .await?;

    let rest_limit_usize = rest_limit as usize;

    if collected.len() > rest_limit_usize {
        // Lookahead item proves a further page; its triple is the exclusive next.
        let next_ins = &collected[rest_limit_usize];
        let next = TripleCursor::from_inscription(next_ins);
        let inscriptions = collected.into_iter().take(rest_limit_usize).collect();
        return Ok(InscriptionsPage {
            inscriptions,
            next: Some(next),
        });
    }

    // At rest_limit == MAX_LIMIT the kernel cannot take MAX_LIMIT+1; if the
    // stream filled the page exactly, peek one item from the exclusive successor.
    if rest_limit == MAX_LIMIT && collected.len() == rest_limit_usize {
        let last = match collected.last() {
            Some(ins) => ins,
            None => {
                // limit is 1000 and len is 1000, so last is always present;
                // this arm is unreachable by construction.
                return Err(ApiError::internal(
                    "page-full inscription stream has no last element",
                ));
            }
        };
        // End of the u64 triple space: no exclusive successor exists; do not
        // call exclusive_successor (that is 500 for the max triple) and do not
        // issue a peek RPC — the page is final.
        if last.height == u64::MAX && last.tx_index == u64::MAX && last.vin_index == u64::MAX {
            return Ok(InscriptionsPage {
                inscriptions: collected,
                next: None,
            });
        }
        let peek_from = TripleCursor::from_inscription(last).exclusive_successor()?;
        let peek = collect_stream(
            kernel,
            ListInscriptionsRequest {
                from_height: Some(peek_from.height),
                from_tx_index: Some(peek_from.tx_index),
                from_vin_index: Some(peek_from.vin_index),
                limit: Some(1),
            },
        )
        .await?;
        if let Some(first) = peek.first() {
            return Ok(InscriptionsPage {
                inscriptions: collected,
                next: Some(TripleCursor::from_inscription(first)),
            });
        }
    }

    Ok(InscriptionsPage {
        inscriptions: collected,
        next: None,
    })
}

async fn collect_stream(
    kernel: &KernelHandle,
    req: ListInscriptionsRequest,
) -> Result<Vec<Inscription>, ApiError> {
    let mut stream = kernel.list_inscriptions(req).await?;
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        out.push(item?);
    }
    // §7.8: the kernel stream is already in stable triple order. Do not
    // re-sort — a violation is a kernel bug and must surface as internal_error.
    require_strict_triple_order(&out)?;
    Ok(out)
}

/// Inscription triple used as the §7.5 / §7.8 sort and cursor key.
fn inscription_triple(ins: &Inscription) -> (u64, u64, u64) {
    (ins.height, ins.tx_index, ins.vin_index)
}

/// Reject a kernel stream that is not strictly increasing in
/// `(height, tx_index, vin_index)`. Equal or reversed neighbours mean the
/// kernel broke its §7.8 ordering contract; silent repair would hide that.
fn require_strict_triple_order(items: &[Inscription]) -> Result<(), ApiError> {
    for pair in items.windows(2) {
        let prev = inscription_triple(&pair[0]);
        let next = inscription_triple(&pair[1]);
        if prev >= next {
            return Err(ApiError::internal(format!(
                "kernel ListInscriptions stream is not strictly increasing in \
                 (height, tx_index, vin_index): {prev:?} is not before {next:?}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON encoding
// ---------------------------------------------------------------------------

fn accumulator_to_json(tip: &AccumulatorTip) -> Result<Value, ApiError> {
    Ok(json!({
        "size": tip.size,
        "root": require_hex32(&tip.root, "root")?,
        "tip_block_hash": require_hex32(&tip.tip_block_hash, "tip_block_hash")?,
        "tip_height": tip.tip_height,
    }))
}

fn inscriptions_page_to_json(page: &InscriptionsPage) -> Result<Value, ApiError> {
    let mut inscriptions = Vec::with_capacity(page.inscriptions.len());
    for ins in &page.inscriptions {
        inscriptions.push(inscription_to_json(ins)?);
    }

    let mut obj = Map::new();
    obj.insert("inscriptions".to_string(), Value::Array(inscriptions));
    // Structural all-or-nothing: emit every next_* or none.
    if let Some(next) = page.next {
        obj.insert("next_height".to_string(), json!(next.height));
        obj.insert("next_tx_index".to_string(), json!(next.tx_index));
        obj.insert("next_vin_index".to_string(), json!(next.vin_index));
    }
    Ok(Value::Object(obj))
}

fn inscription_to_json(ins: &Inscription) -> Result<Value, ApiError> {
    let mut nullifiers = Vec::with_capacity(ins.nullifiers.len());
    for (i, n) in ins.nullifiers.iter().enumerate() {
        nullifiers.push(nullifier_member_to_json(n, i)?);
    }

    // confirmation_state is reveal-tx depth only — never an aggregate of
    // member states, never "failed" (§7.5 / §3.9).
    match ins.confirmation_state.as_str() {
        "pending" | "completed" => {}
        other => {
            return Err(ApiError::internal(format!(
                "kernel Inscription.confirmation_state must be \"pending\" or \"completed\", got {other:?}"
            )));
        }
    }

    // format: 0x00 raw | 0x01 half-aggregated (§3.5); other values are not on the closed set.
    if ins.format > 1 {
        return Err(ApiError::internal(format!(
            "kernel Inscription.format must be 0 (raw) or 1 (half-aggregated), got {}",
            ins.format
        )));
    }

    Ok(json!({
        "txid": require_hex32(&ins.txid, "txid")?,
        "height": ins.height,
        "tx_index": ins.tx_index,
        "vin_index": ins.vin_index,
        "count": ins.count,
        "format": ins.format,
        "nullifiers": nullifiers,
        "confirmation_state": ins.confirmation_state,
    }))
}

fn nullifier_member_to_json(n: &Nullifier, index: usize) -> Result<Value, ApiError> {
    // Per-member §3.10 state — members of one aggregate MAY differ.
    match n.state.as_str() {
        "completed" | "pending" | "failed" => {}
        other => {
            return Err(ApiError::internal(format!(
                "kernel Nullifier.state[{index}] must be \"completed\", \"pending\", or \"failed\", got {other:?}"
            )));
        }
    }
    Ok(json!({
        "pubkey": require_hex32(&n.pubkey, &format!("nullifiers[{index}].pubkey"))?,
        "r": require_hex32(&n.r, &format!("nullifiers[{index}].r"))?,
        "state": n.state,
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
    use crate::kernel::kernel_v1::Nullifier as ProtoNullifier;
    use crate::kernel::KernelRpc;
    use async_trait::async_trait;
    use futures_util::stream::{self, BoxStream};
    use std::sync::Arc;

    fn sample_nullifier(state: &str) -> ProtoNullifier {
        ProtoNullifier {
            pubkey: vec![0x11; 32],
            r: vec![0x22; 32],
            state: state.to_string(),
        }
    }

    fn sample_inscription(
        height: u64,
        tx_index: u64,
        vin_index: u64,
        confirmation_state: &str,
        nullifiers: Vec<ProtoNullifier>,
    ) -> Inscription {
        let mut txid = vec![0u8; 32];
        // Asymmetric bytes so a byte-order reverse would fail hex equality.
        for (i, b) in txid.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        Inscription {
            txid,
            height,
            count: nullifiers.len() as u32,
            format: 1,
            nullifiers,
            confirmation_state: confirmation_state.to_string(),
            tx_index,
            vin_index,
        }
    }

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
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("root"),
            "operator cause must name the field, got {:?}",
            err.cause()
        );
    }

    /// Failed member + completed confirmation in one inscription — the two
    /// states are independent (§3.10 vs reveal-tx depth).
    #[test]
    fn failed_member_with_completed_confirmation_state() {
        let ins = sample_inscription(
            100,
            2,
            0,
            "completed",
            vec![sample_nullifier("completed"), sample_nullifier("failed")],
        );
        let json = inscription_to_json(&ins).expect("json");
        assert_eq!(json["confirmation_state"], "completed");
        let nullifiers = json["nullifiers"].as_array().expect("nullifiers");
        assert_eq!(nullifiers.len(), 2);
        assert_eq!(nullifiers[0]["state"], "completed");
        assert_eq!(nullifiers[1]["state"], "failed");
        // txid is internal byte order — encode_hex of kernel bytes, never reversed.
        let expected_txid: Vec<u8> = (1u8..=32).collect();
        assert_eq!(json["txid"].as_str().unwrap(), encode_hex(&expected_txid));
    }

    #[test]
    fn confirmation_state_failed_is_rejected() {
        let ins = sample_inscription(1, 0, 0, "failed", vec![sample_nullifier("pending")]);
        let err = inscription_to_json(&ins).expect_err("failed confirmation");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("confirmation_state"),
            "operator cause must name confirmation_state, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn next_cursor_all_or_nothing_in_json() {
        let page_with = InscriptionsPage {
            inscriptions: vec![sample_inscription(
                1,
                0,
                0,
                "pending",
                vec![sample_nullifier("pending")],
            )],
            next: Some(TripleCursor {
                height: 1,
                tx_index: 0,
                vin_index: 1,
            }),
        };
        let json = inscriptions_page_to_json(&page_with).expect("json");
        assert_eq!(json["next_height"], 1);
        assert_eq!(json["next_tx_index"], 0);
        assert_eq!(json["next_vin_index"], 1);

        let page_without = InscriptionsPage {
            inscriptions: vec![],
            next: None,
        };
        let json = inscriptions_page_to_json(&page_without).expect("json");
        assert!(json.get("next_height").is_none());
        assert!(json.get("next_tx_index").is_none());
        assert!(json.get("next_vin_index").is_none());
        assert_eq!(json["inscriptions"], json!([]));
    }

    #[test]
    fn limit_zero_is_bounds_exceeded_not_malformed() {
        let err = parse_list_inscriptions_query(Some("limit=0")).expect_err("limit=0");
        assert_eq!(err.body.error, "bounds_exceeded");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn limit_over_1000_is_bounds_exceeded() {
        let err = parse_list_inscriptions_query(Some("limit=1001")).expect_err("limit=1001");
        assert_eq!(err.body.error, "bounds_exceeded");
    }

    #[test]
    fn limit_non_numeric_is_malformed() {
        let err = parse_list_inscriptions_query(Some("limit=abc")).expect_err("limit=abc");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("limit"),
            "message must name limit, got {}",
            err.body.message
        );
    }

    #[test]
    fn omitted_query_normalises_to_defaults() {
        let q = parse_list_inscriptions_query(None).expect("defaults");
        assert_eq!(q.from_height, 0);
        assert_eq!(q.from_tx_index, 0);
        assert_eq!(q.from_vin_index, 0);
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn explicit_zero_cursors_are_not_replaced() {
        let q = parse_list_inscriptions_query(Some(
            "from_height=0&from_tx_index=0&from_vin_index=0&limit=1",
        ))
        .expect("zeros");
        assert_eq!(q.from_height, 0);
        assert_eq!(q.from_tx_index, 0);
        assert_eq!(q.from_vin_index, 0);
        assert_eq!(q.limit, 1);
    }

    #[test]
    fn parse_list_inscriptions_query_ignores_unknown_keys() {
        let q = parse_list_inscriptions_query(Some("foo=1&limit=5")).expect("unknown keys ok");
        assert_eq!(q.limit, 5);
        assert_eq!(q.from_height, 0);
        assert_eq!(q.from_tx_index, 0);
        assert_eq!(q.from_vin_index, 0);
    }

    #[test]
    fn parse_list_inscriptions_query_skips_empty_pairs() {
        let q =
            parse_list_inscriptions_query(Some("limit=5&&from_height=3")).expect("empty pairs ok");
        assert_eq!(q.limit, 5);
        assert_eq!(q.from_height, 3);
        assert_eq!(q.from_tx_index, 0);
        assert_eq!(q.from_vin_index, 0);
    }

    #[test]
    fn parse_list_inscriptions_query_key_without_equals_is_malformed() {
        let err = parse_list_inscriptions_query(Some("from_height")).expect_err("key without =");
        assert_eq!(err.body.error, "malformed_request");
    }

    #[test]
    fn parse_list_inscriptions_query_empty_value_is_malformed() {
        let err = parse_list_inscriptions_query(Some("from_height=")).expect_err("empty value");
        assert_eq!(err.body.error, "malformed_request");
    }

    // -----------------------------------------------------------------------
    // Page-boundary pagination against a catalog double
    // -----------------------------------------------------------------------

    struct CatalogKernel {
        catalog: Vec<Inscription>,
    }

    fn filter_catalog(catalog: &[Inscription], req: &ListInscriptionsRequest) -> Vec<Inscription> {
        // Kernel-side double: same §7.5 defaults the API normalises before RPC
        // (proto comment on ListInscriptionsRequest).
        let from_h = req.from_height.unwrap_or(DEFAULT_FROM_HEIGHT);
        let from_t = req.from_tx_index.unwrap_or(DEFAULT_FROM_TX_INDEX);
        let from_v = req.from_vin_index.unwrap_or(DEFAULT_FROM_VIN_INDEX);
        let limit = req.limit.unwrap_or(DEFAULT_LIMIT) as usize;
        catalog
            .iter()
            .filter(|ins| (ins.height, ins.tx_index, ins.vin_index) >= (from_h, from_t, from_v))
            .take(limit)
            .cloned()
            .collect()
    }

    #[async_trait]
    impl KernelRpc for CatalogKernel {
        async fn get_token_provenance(
            &self,
            _req: crate::kernel::kernel_v1::GetTokenProvenanceRequest,
        ) -> Result<crate::kernel::kernel_v1::TokenProvenance, ApiError> {
            Err(ApiError::internal("not used"))
        }

        async fn submit_transition(
            &self,
            _req: crate::kernel::kernel_v1::TransitionRequest,
        ) -> Result<crate::kernel::kernel_v1::JobHandle, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn get_job(
            &self,
            _req: crate::kernel::kernel_v1::JobRequest,
        ) -> Result<crate::kernel::kernel_v1::Job, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn stream_job(
            &self,
            _req: crate::kernel::kernel_v1::JobRequest,
        ) -> Result<
            BoxStream<'static, Result<crate::kernel::kernel_v1::JobEvent, ApiError>>,
            ApiError,
        > {
            Err(ApiError::internal("not used"))
        }
        async fn sign_transition(
            &self,
            _req: crate::kernel::kernel_v1::SignRequest,
        ) -> Result<crate::kernel::kernel_v1::Job, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn cancel_job(
            &self,
            _req: crate::kernel::kernel_v1::JobRequest,
        ) -> Result<crate::kernel::kernel_v1::Job, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn get_info(&self) -> Result<crate::kernel::kernel_v1::Info, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn get_accumulator(&self) -> Result<AccumulatorTip, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn list_inscriptions(
            &self,
            req: ListInscriptionsRequest,
        ) -> Result<BoxStream<'static, Result<Inscription, ApiError>>, ApiError> {
            let items = filter_catalog(&self.catalog, &req);
            Ok(Box::pin(stream::iter(items.into_iter().map(Ok))))
        }
        async fn get_nullifier_path(
            &self,
            _req: NullifierPathRequest,
        ) -> Result<NullifierPath, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn open_pull_challenge(
            &self,
            _req: crate::kernel::kernel_v1::PullChallengeRequest,
        ) -> Result<crate::kernel::kernel_v1::Challenge, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn attest_balance(
            &self,
            _req: crate::kernel::kernel_v1::AttestRequest,
        ) -> Result<crate::kernel::kernel_v1::JobHandle, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn issue_view_grant(
            &self,
            _req: crate::kernel::kernel_v1::GrantRequest,
        ) -> Result<crate::kernel::kernel_v1::GrantResult, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn pull(
            &self,
            _req: crate::kernel::kernel_v1::PullRequest,
            _authority: crate::ownership::SessionAuthority,
        ) -> Result<crate::kernel::kernel_v1::PullResult, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn get_record(
            &self,
            _req: crate::kernel::kernel_v1::RecordRequest,
        ) -> Result<crate::kernel::kernel_v1::RecordBlob, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn get_coin_proof(
            &self,
            _req: crate::kernel::kernel_v1::CoinProofRequest,
        ) -> Result<crate::kernel::kernel_v1::CoinProofBlob, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn get_account_state(
            &self,
            _req: crate::kernel::kernel_v1::AccountStateRequest,
        ) -> Result<crate::kernel::kernel_v1::AccountStateResult, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn subscribe_receipts(
            &self,
            _req: crate::kernel::kernel_v1::SubscribeReceiptsRequest,
        ) -> Result<BoxStream<'static, Result<crate::kernel::kernel_v1::Receipt, ApiError>>, ApiError>
        {
            Err(ApiError::internal("not used"))
        }
        async fn entrust_operational_bundle(
            &self,
            _req: crate::kernel::kernel_v1::EntrustRequest,
        ) -> Result<crate::kernel::kernel_v1::EntrustResult, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn revoke_operational_bundle(
            &self,
            _req: crate::kernel::kernel_v1::RevokeRequest,
        ) -> Result<crate::kernel::kernel_v1::RevokeResult, ApiError> {
            Err(ApiError::internal("not used"))
        }
        async fn publish(
            &self,
            _req: crate::kernel::kernel_v1::PublishRequest,
        ) -> Result<crate::kernel::kernel_v1::PublishResult, ApiError> {
            Err(ApiError::internal("not used"))
        }
    }

    /// Every CatalogKernel KernelRpc stub except list_inscriptions returns
    /// internal_error so llvm-cov does not treat the stubs as misses.
    #[tokio::test]
    async fn catalog_kernel_unused_rpcs_are_internal() {
        use crate::kernel::kernel_v1::{
            AccountStateRequest, AttestRequest, CoinProofRequest, EntrustRequest,
            GetTokenProvenanceRequest, GrantRequest, JobRequest, PublishRequest,
            PullChallengeRequest, PullRequest, RecordRequest, RevokeRequest, SignRequest,
            SubscribeReceiptsRequest, TransitionRequest,
        };

        let k = CatalogKernel { catalog: vec![] };

        let err = k
            .get_token_provenance(GetTokenProvenanceRequest { asset_id: vec![] })
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .submit_transition(TransitionRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .get_job(JobRequest {
                job_id: String::new(),
            })
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let result = k
            .stream_job(JobRequest {
                job_id: String::new(),
            })
            .await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.body.error, "internal_error");
        }

        let err = k
            .sign_transition(SignRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .cancel_job(JobRequest {
                job_id: String::new(),
            })
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k.get_info().await.expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k.get_accumulator().await.expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .get_nullifier_path(NullifierPathRequest { pubkey: vec![] })
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .open_pull_challenge(PullChallengeRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .attest_balance(AttestRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .issue_view_grant(GrantRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .pull(
                PullRequest::default(),
                crate::ownership::SessionAuthority::Ownership,
            )
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .get_record(RecordRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .get_coin_proof(CoinProofRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .get_account_state(AccountStateRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let result = k
            .subscribe_receipts(SubscribeReceiptsRequest::default())
            .await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.body.error, "internal_error");
        }

        let err = k
            .entrust_operational_bundle(EntrustRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .revoke_operational_bundle(RevokeRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");

        let err = k
            .publish(PublishRequest::default())
            .await
            .expect_err("unused stub");
        assert_eq!(err.body.error, "internal_error");
    }

    /// Three pages with limit=1; page boundary sits mid-reveal-tx (vin 0/1/2
    /// of the same (height, tx_index)). Exclusive next of page n is inclusive
    /// from of page n+1 — no duplicates, no gaps.
    #[tokio::test]
    async fn multi_page_cursor_splits_mid_reveal_tx() {
        let catalog = vec![
            sample_inscription(10, 0, 0, "completed", vec![sample_nullifier("completed")]),
            sample_inscription(10, 0, 1, "completed", vec![sample_nullifier("completed")]),
            sample_inscription(10, 0, 2, "completed", vec![sample_nullifier("pending")]),
            sample_inscription(10, 1, 0, "pending", vec![sample_nullifier("pending")]),
        ];
        let kernel: KernelHandle = Arc::new(CatalogKernel { catalog });

        // Page 1
        let page1 = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: 0,
                from_tx_index: 0,
                from_vin_index: 0,
                limit: 1,
            },
        )
        .await
        .expect("page1");
        assert_eq!(page1.inscriptions.len(), 1);
        assert_eq!(page1.inscriptions[0].vin_index, 0);
        let next1 = page1.next.expect("page1 must have next");
        assert_eq!(
            (next1.height, next1.tx_index, next1.vin_index),
            (10, 0, 1),
            "exclusive next after first vin of the multi-vin reveal"
        );

        // Page 2 — exclusive next of page1 is inclusive from here
        let page2 = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: next1.height,
                from_tx_index: next1.tx_index,
                from_vin_index: next1.vin_index,
                limit: 1,
            },
        )
        .await
        .expect("page2");
        assert_eq!(page2.inscriptions.len(), 1);
        assert_eq!(page2.inscriptions[0].vin_index, 1);
        assert_eq!(
            page2.inscriptions[0].height, page1.inscriptions[0].height,
            "same reveal height"
        );
        assert_eq!(
            page2.inscriptions[0].tx_index, page1.inscriptions[0].tx_index,
            "same reveal tx_index — boundary is mid-transaction"
        );
        let next2 = page2.next.expect("page2 must have next");
        assert_eq!((next2.height, next2.tx_index, next2.vin_index), (10, 0, 2));

        // Page 3
        let page3 = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: next2.height,
                from_tx_index: next2.tx_index,
                from_vin_index: next2.vin_index,
                limit: 1,
            },
        )
        .await
        .expect("page3");
        assert_eq!(page3.inscriptions.len(), 1);
        assert_eq!(page3.inscriptions[0].vin_index, 2);
        let next3 = page3
            .next
            .expect("page3 must have next (fourth item remains)");
        assert_eq!((next3.height, next3.tx_index, next3.vin_index), (10, 1, 0));

        // Collect all via the three page starts + final remainder — no dups/gaps.
        let mut seen = vec![
            (
                page1.inscriptions[0].height,
                page1.inscriptions[0].tx_index,
                page1.inscriptions[0].vin_index,
            ),
            (
                page2.inscriptions[0].height,
                page2.inscriptions[0].tx_index,
                page2.inscriptions[0].vin_index,
            ),
            (
                page3.inscriptions[0].height,
                page3.inscriptions[0].tx_index,
                page3.inscriptions[0].vin_index,
            ),
        ];
        let page4 = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: next3.height,
                from_tx_index: next3.tx_index,
                from_vin_index: next3.vin_index,
                limit: 1,
            },
        )
        .await
        .expect("page4");
        assert_eq!(page4.inscriptions.len(), 1);
        assert!(page4.next.is_none(), "final page must omit all next_*");
        seen.push((
            page4.inscriptions[0].height,
            page4.inscriptions[0].tx_index,
            page4.inscriptions[0].vin_index,
        ));
        assert_eq!(
            seen,
            vec![(10, 0, 0), (10, 0, 1), (10, 0, 2), (10, 1, 0)],
            "contiguous coverage across mid-tx page boundary"
        );
    }

    #[tokio::test]
    async fn empty_catalog_is_empty_list_not_404() {
        let kernel: KernelHandle = Arc::new(CatalogKernel {
            catalog: Vec::new(),
        });
        let page = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: 0,
                from_tx_index: 0,
                from_vin_index: 0,
                limit: 100,
            },
        )
        .await
        .expect("empty");
        assert!(page.inscriptions.is_empty());
        assert!(page.next.is_none());
        let json = inscriptions_page_to_json(&page).expect("json");
        assert_eq!(json["inscriptions"], json!([]));
        assert!(json.get("next_height").is_none());
    }

    /// At `limit == MAX_LIMIT` the handler peeks the exclusive successor instead
    /// of requesting `MAX_LIMIT + 1`; a successor sets `next` to that item.
    #[tokio::test]
    async fn max_limit_page_peek_sets_next_when_successor_exists() {
        let catalog: Vec<_> = (0..1001)
            .map(|h| sample_inscription(h, 0, 0, "completed", vec![sample_nullifier("completed")]))
            .collect();
        let kernel: KernelHandle = Arc::new(CatalogKernel { catalog });
        let page = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: 0,
                from_tx_index: 0,
                from_vin_index: 0,
                limit: MAX_LIMIT,
            },
        )
        .await
        .expect("max-limit page with successor");
        assert_eq!(page.inscriptions.len(), 1000);
        let next = page.next.expect("peek must find the 1001st item");
        assert_eq!(
            (next.height, next.tx_index, next.vin_index),
            (1000, 0, 0),
            "next must be the exclusive successor's triple"
        );
    }

    /// Full page of exactly `MAX_LIMIT` with no catalog successor → no `next`.
    #[tokio::test]
    async fn max_limit_page_without_successor_has_no_next() {
        let catalog: Vec<_> = (0..MAX_LIMIT as u64)
            .map(|h| sample_inscription(h, 0, 0, "completed", vec![sample_nullifier("completed")]))
            .collect();
        let kernel: KernelHandle = Arc::new(CatalogKernel { catalog });
        let page = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: 0,
                from_tx_index: 0,
                from_vin_index: 0,
                limit: MAX_LIMIT,
            },
        )
        .await
        .expect("max-limit page without successor");
        assert_eq!(page.inscriptions.len(), 1000);
        assert!(
            page.next.is_none(),
            "peek must find nothing past the last item"
        );
    }

    /// Full page whose last triple is the u64 max — end of cursor space, not 500.
    #[tokio::test]
    async fn max_limit_page_ending_at_max_triple_has_no_next() {
        let mut catalog: Vec<_> = (0..999u64)
            .map(|h| sample_inscription(h, 0, 0, "completed", vec![sample_nullifier("completed")]))
            .collect();
        catalog.push(sample_inscription(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            "completed",
            vec![sample_nullifier("completed")],
        ));
        assert_eq!(catalog.len(), MAX_LIMIT as usize);
        let kernel: KernelHandle = Arc::new(CatalogKernel { catalog });
        let page = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: 0,
                from_tx_index: 0,
                from_vin_index: 0,
                limit: MAX_LIMIT,
            },
        )
        .await
        .expect("max triple end-of-space must not 500");
        assert_eq!(page.inscriptions.len(), 1000);
        assert!(
            page.next.is_none(),
            "no exclusive successor past (u64::MAX, u64::MAX, u64::MAX)"
        );
    }

    /// §7.8 promises stable triple order; an out-of-order stream is
    /// `internal_error`, not a silently re-sorted page.
    #[tokio::test]
    async fn out_of_order_kernel_stream_is_internal_error() {
        let catalog = vec![
            sample_inscription(10, 0, 1, "completed", vec![sample_nullifier("completed")]),
            sample_inscription(10, 0, 0, "completed", vec![sample_nullifier("completed")]),
        ];
        let kernel: KernelHandle = Arc::new(CatalogKernel { catalog });
        let err = fetch_inscriptions_page(
            &kernel,
            ListInscriptionsQuery {
                from_height: 0,
                from_tx_index: 0,
                from_vin_index: 0,
                limit: 10,
            },
        )
        .await
        .expect_err("reversed triples must fail closed");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("strictly increasing")
                && cause.contains("height")
                && cause.contains("tx_index")
                && cause.contains("vin_index"),
            "operator cause must name the triple-order contract, got {cause}"
        );
    }

    #[test]
    fn strict_triple_order_accepts_increasing_and_rejects_equal() {
        require_strict_triple_order(&[]).expect("empty");
        require_strict_triple_order(&[sample_inscription(
            1,
            0,
            0,
            "pending",
            vec![sample_nullifier("pending")],
        )])
        .expect("singleton");
        let ok = vec![
            sample_inscription(1, 0, 0, "pending", vec![sample_nullifier("pending")]),
            sample_inscription(1, 0, 1, "pending", vec![sample_nullifier("pending")]),
        ];
        require_strict_triple_order(&ok).expect("increasing");
        let dup = vec![
            sample_inscription(1, 0, 0, "pending", vec![sample_nullifier("pending")]),
            sample_inscription(1, 0, 0, "pending", vec![sample_nullifier("pending")]),
        ];
        let err = require_strict_triple_order(&dup).expect_err("duplicate triple");
        assert_eq!(err.body.error, "internal_error");
    }

    // -----------------------------------------------------------------------
    // Fail-closed parse / encode / cursor branches (no kernel mock)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_list_inscriptions_query_duplicate_keys_are_malformed() {
        for (query, key) in [
            ("from_height=1&from_height=2", "from_height"),
            ("from_tx_index=1&from_tx_index=2", "from_tx_index"),
            ("from_vin_index=1&from_vin_index=2", "from_vin_index"),
            ("limit=1&limit=2", "limit"),
        ] {
            let err = parse_list_inscriptions_query(Some(query)).expect_err(key);
            assert_eq!(err.body.error, "malformed_request");
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert!(
                err.body.message.contains(key),
                "message must name {key}, got {}",
                err.body.message
            );
        }
    }

    #[test]
    fn inscription_to_json_rejects_format_above_one() {
        let mut ins = sample_inscription(1, 0, 0, "pending", vec![sample_nullifier("pending")]);
        ins.format = 2;
        let err = inscription_to_json(&ins).expect_err("format 2");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.cause().unwrap_or("").contains("format"),
            "operator cause must name format, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn exclusive_successor_increments_and_rejects_max_triple() {
        let next = TripleCursor {
            height: 1,
            tx_index: 2,
            vin_index: 3,
        }
        .exclusive_successor()
        .expect("vin+1");
        assert_eq!((next.height, next.tx_index, next.vin_index), (1, 2, 4));

        let next = TripleCursor {
            height: 1,
            tx_index: 2,
            vin_index: u64::MAX,
        }
        .exclusive_successor()
        .expect("tx+1, vin=0");
        assert_eq!((next.height, next.tx_index, next.vin_index), (1, 3, 0));

        let next = TripleCursor {
            height: 1,
            tx_index: u64::MAX,
            vin_index: u64::MAX,
        }
        .exclusive_successor()
        .expect("height+1");
        assert_eq!((next.height, next.tx_index, next.vin_index), (2, 0, 0));

        let err = TripleCursor {
            height: u64::MAX,
            tx_index: u64::MAX,
            vin_index: u64::MAX,
        }
        .exclusive_successor()
        .expect_err("max triple");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn present_true_empty_leaf_is_internal() {
        let path = NullifierPath {
            root: vec![0x01; 32],
            tip_height: 10,
            present: true,
            leaf: Vec::new(),
            position: 3,
            audit_path: Vec::new(),
            tree_size: 4,
            tip_block_hash: vec![0x04; 32],
        };
        let err = nullifier_path_to_json(&path).expect_err("present without leaf");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn nullifier_state_unknown_is_internal() {
        let ins = sample_inscription(1, 0, 0, "completed", vec![sample_nullifier("bogus")]);
        let err = inscription_to_json(&ins).expect_err("unknown nullifier state");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("Nullifier.state") || cause.contains("completed"),
            "operator cause must name Nullifier.state or completed, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn present_true_audit_path_over_64_is_internal() {
        let path = NullifierPath {
            root: vec![0x01; 32],
            tip_height: 10,
            present: true,
            leaf: vec![0x02; 32],
            position: 3,
            audit_path: vec![vec![0x03; 32]; 65],
            tree_size: 4,
            tip_block_hash: vec![0x04; 32],
        };
        let err = nullifier_path_to_json(&path).expect_err("audit_path over 64");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.cause().unwrap_or("").contains("audit_path"),
            "operator cause must name audit_path, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn present_false_nonempty_leaf_is_internal() {
        let path = NullifierPath {
            root: vec![0x01; 32],
            tip_height: 10,
            present: false,
            leaf: vec![0x02; 32],
            position: 0,
            audit_path: Vec::new(),
            tree_size: 4,
            tip_block_hash: vec![0x04; 32],
        };
        let err = nullifier_path_to_json(&path).expect_err("absent with leaf");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn present_false_nonempty_audit_path_is_internal() {
        let path = NullifierPath {
            root: vec![0x01; 32],
            tip_height: 10,
            present: false,
            leaf: Vec::new(),
            position: 0,
            audit_path: vec![vec![0x03; 32]],
            tree_size: 4,
            tip_block_hash: vec![0x04; 32],
        };
        let err = nullifier_path_to_json(&path).expect_err("absent with audit_path");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

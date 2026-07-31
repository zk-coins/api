//! Job-surface REST handlers (§7.5) over kernel job procedures (§7.8).
//!
//! Endpoints (Spec-Schreibweise): `POST /v1/tx`, `GET /v1/jobs/<job_id>`,
//! `GET /v1/jobs/<job_id>/stream`, `POST /v1/jobs/<job_id>/sign`,
//! `POST /v1/jobs/<job_id>/cancel`. Axum registers the derived `:job_id` matcher.

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex, HexError};
use crate::kernel::kernel_v1::{
    AwaitingSignature, Issuance, Job, JobEvent, JobHandle, JobRequest, JobResult as ProtoJobResult,
    OutputTemplate as ProtoOutputTemplate, SignRequest, TransitionRequest,
};
use crate::kernel::KernelHandle;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::Stream;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;

// ---------------------------------------------------------------------------
// JSON request types (exact §7.5 shapes)
// ---------------------------------------------------------------------------

/// §7.5 `TransitionRequest` JSON body for `POST /v1/tx` (L2898–L2930).
#[derive(Debug, Deserialize)]
pub struct TransitionRequestJson {
    pub kind: String,
    pub subject: String,
    pub next_pubkey: String,
    pub npk_rand: String,
    #[serde(default)]
    pub input_coins: Option<Vec<String>>,
    #[serde(default)]
    pub output_templates: Option<Vec<OutputTemplateJson>>,
    #[serde(default)]
    pub publisher_pubkey: Option<String>,
    #[serde(default)]
    pub fee_address: Option<String>,
    #[serde(default)]
    pub fold_coin_ids: Option<Vec<String>>,
    #[serde(default)]
    pub issuance: Option<IssuanceJson>,
}

#[derive(Debug, Deserialize)]
pub struct OutputTemplateJson {
    pub recipient: String,
    pub asset_id: String,
    pub amount: String,
}

#[derive(Debug, Deserialize)]
pub struct IssuanceJson {
    pub name: String,
    pub decimals: u32,
    pub issuance_version: u32,
    pub amount: String,
    #[serde(default)]
    pub cap_total: Option<String>,
    #[serde(default)]
    pub terms_salt: Option<String>,
}

/// §7.5 sign body (L2891): `{ signature: <hex64>, s2c_nonce: <hex32> }`.
#[derive(Debug, Deserialize)]
pub struct SignBodyJson {
    pub signature: String,
    pub s2c_nonce: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/tx` → `SubmitTransition` → `202 { job_id, status: "accepted" }`.
pub async fn post_tx(
    State(kernel): State<KernelHandle>,
    headers: HeaderMap,
    Json(body): Json<TransitionRequestJson>,
) -> Result<Response, ApiError> {
    let mut req = json_to_transition(body)?;
    if let Some(key) = idempotency_key_from_headers(&headers)? {
        req.idempotency_key = key;
    }
    let handle: JobHandle = kernel.submit_transition(req).await?;
    let body = json!({
        "job_id": handle.job_id,
        "status": "accepted",
    });
    // Spec: 202 is the only success status for POST /v1/tx (L3031).
    // Echo kernel status only when it is the closed success literal.
    if !handle.status.is_empty() && handle.status != "accepted" {
        return Err(ApiError::internal(format!(
            "kernel JobHandle.status must be \"accepted\" on submit success, got {:?}",
            handle.status
        )));
    }
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

/// `GET /v1/jobs/<job_id>` → `GetJob`.
pub async fn get_job(
    State(kernel): State<KernelHandle>,
    Path(job_id): Path<String>,
) -> Result<Response, ApiError> {
    if job_id.is_empty() {
        return Err(ApiError::malformed("job_id must not be empty"));
    }
    let job = kernel
        .get_job(JobRequest {
            job_id: job_id.clone(),
        })
        .await?;
    let (status_header, retry_after) = job_poll_headers(&job);
    let mut response = (status_header, Json(job_to_json(&job)?)).into_response();
    if let Some(secs) = retry_after {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_str(&secs.to_string())
                .map_err(|e| ApiError::internal(format!("invalid Retry-After value: {e}")))?,
        );
    }
    Ok(response)
}

/// `GET /v1/jobs/<job_id>/stream` → `StreamJob` as SSE.
///
/// Start failures of `StreamJob` (unknown job, transport, ErrorInfo domain
/// errors) return **before** the SSE response is opened: HTTP status + §7.5
/// JSON body via [`ApiError`]. Only a successful stream handshake upgrades
/// the response to `text/event-stream`.
pub async fn stream_job(
    State(kernel): State<KernelHandle>,
    Path(job_id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>> + Send + 'static>, ApiError> {
    if job_id.is_empty() {
        return Err(ApiError::malformed("job_id must not be empty"));
    }
    // Await the kernel stream handshake first. On `Err`, axum maps `ApiError`
    // to a normal HTTP response (status + JSON body) and never enters SSE.
    let stream = kernel.stream_job(JobRequest { job_id }).await?;

    let sse_stream = job_event_sse_stream(stream);
    Ok(Sse::new(sse_stream).keep_alive(KeepAlive::default()))
}

/// `POST /v1/jobs/<job_id>/sign` → `SignTransition`.
pub async fn post_sign(
    State(kernel): State<KernelHandle>,
    Path(job_id): Path<String>,
    Json(body): Json<SignBodyJson>,
) -> Result<Response, ApiError> {
    if job_id.is_empty() {
        return Err(ApiError::malformed("job_id must not be empty"));
    }
    let signature = decode_hex_exact(&body.signature, 64)
        .map_err(|e| ApiError::malformed(format!("signature: {e}")))?;
    let s2c_nonce = decode_hex_exact(&body.s2c_nonce, 32)
        .map_err(|e| ApiError::malformed(format!("s2c_nonce: {e}")))?;
    let job = kernel
        .sign_transition(SignRequest {
            job_id,
            signature,
            s2c_nonce,
        })
        .await?;
    Ok((StatusCode::OK, Json(job_to_json(&job)?)).into_response())
}

/// `POST /v1/jobs/<job_id>/cancel` → `CancelJob`.
pub async fn post_cancel(
    State(kernel): State<KernelHandle>,
    Path(job_id): Path<String>,
) -> Result<Response, ApiError> {
    if job_id.is_empty() {
        return Err(ApiError::malformed("job_id must not be empty"));
    }
    let job = kernel.cancel_job(JobRequest { job_id }).await?;
    Ok((StatusCode::OK, Json(job_to_json(&job)?)).into_response())
}

// ---------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------

fn job_event_sse_stream<S>(stream: S) -> impl Stream<Item = Result<Event, Infallible>> + Send
where
    S: Stream<Item = Result<JobEvent, ApiError>> + Send + 'static,
{
    // Map each kernel event to one SSE frame. On stream break, emit a single
    // recognizable `error` frame then end — never hang open with silence.
    //
    // `take_while` + stateful scan: after a terminal event (`complete` /
    // `error`) or a stream-break frame we stop polling the kernel stream.
    async_stream_events(stream)
}

fn async_stream_events<S>(stream: S) -> impl Stream<Item = Result<Event, Infallible>> + Send
where
    S: Stream<Item = Result<JobEvent, ApiError>> + Send + 'static,
{
    futures_util::stream::unfold((Box::pin(stream), false), |(mut stream, done)| async move {
        if done {
            return None;
        }
        match stream.next().await {
            None => None,
            Some(Ok(ev)) => {
                let terminal = is_terminal_event_name(&ev.event);
                match job_event_to_sse(&ev) {
                    Ok(frame) => Some((Ok(frame), (stream, terminal))),
                    Err(api_err) => {
                        let frame = stream_break_event(&api_err);
                        Some((Ok(frame), (stream, true)))
                    }
                }
            }
            Some(Err(api_err)) => {
                let frame = stream_break_event(&api_err);
                Some((Ok(frame), (stream, true)))
            }
        }
    })
}

fn is_terminal_event_name(name: &str) -> bool {
    name == "complete" || name == "error"
}

fn stream_break_event(err: &ApiError) -> Event {
    // Recognizable end: an `error` event with the §7.5 error body shape.
    // Clients must not wait forever on a half-open SSE subscription.
    let data = json!({
        "status": "failed",
        "error": {
            "error": err.body.error,
            "message": err.body.message,
        }
    });
    Event::default().event("error").data(data.to_string())
}

fn job_event_to_sse(ev: &JobEvent) -> Result<Event, ApiError> {
    let name = ev.event.as_str();
    if name != "phase" && name != "complete" && name != "error" {
        return Err(ApiError::internal(format!(
            "kernel JobEvent.event is not a §7.5 SSE name: {name:?}"
        )));
    }
    let job = match &ev.job {
        Some(j) => j,
        None => {
            return Err(ApiError::internal(
                "kernel JobEvent is missing the job payload",
            ));
        }
    };
    let data = match name {
        "phase" => phase_event_data(job)?,
        "complete" | "error" => job_to_json(job)?,
        _ => unreachable!("checked above"),
    };
    Ok(Event::default().event(name).data(data.to_string()))
}

/// §7.5 L2947 phase frame: `{ status, phase?, progress }`.
fn phase_event_data(job: &Job) -> Result<Value, ApiError> {
    let mut obj = serde_json::Map::new();
    obj.insert("status".to_string(), Value::String(job.status.clone()));
    if !job.phase.is_empty() {
        obj.insert("phase".to_string(), Value::String(job.phase.clone()));
    }
    obj.insert("progress".to_string(), json!(job.progress));
    // When status is awaiting_signature, embed the surface inline (L3033).
    if job.status == "awaiting_signature" {
        if let Some(a) = &job.awaiting_signature {
            obj.insert(
                "awaiting_signature".to_string(),
                awaiting_signature_json(a)?,
            );
        }
    }
    Ok(Value::Object(obj))
}

// ---------------------------------------------------------------------------
// JSON ↔ proto
// ---------------------------------------------------------------------------

fn json_to_transition(body: TransitionRequestJson) -> Result<TransitionRequest, ApiError> {
    let kind = body.kind;
    match kind.as_str() {
        "mint" | "send" | "receive" => {}
        other => {
            return Err(ApiError::malformed(format!(
                "kind must be mint|send|receive, got {other:?}"
            )));
        }
    }

    // v1: fee_address MUST be absent (L2933–L2939).
    if body.fee_address.is_some() {
        return Err(ApiError::malformed(
            "fee_address must be absent in v1 (publisher presence matrix)",
        ));
    }

    let next_pubkey = decode_hex_field(&body.next_pubkey, 32, "next_pubkey")?;
    let npk_rand = decode_hex_field(&body.npk_rand, 32, "npk_rand")?;

    let publisher_pubkey = match body.publisher_pubkey {
        Some(hex) => decode_hex_field(&hex, 32, "publisher_pubkey")?,
        None => Vec::new(),
    };

    let input_coins = match body.input_coins {
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for (i, h) in list.iter().enumerate() {
                out.push(decode_hex_field(h, 32, &format!("input_coins[{i}]"))?);
            }
            out
        }
        None => Vec::new(),
    };

    let fold_coin_ids = match body.fold_coin_ids {
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for (i, h) in list.iter().enumerate() {
                out.push(decode_hex_field(h, 32, &format!("fold_coin_ids[{i}]"))?);
            }
            out
        }
        None => Vec::new(),
    };

    let output_templates = match body.output_templates {
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for (i, t) in list.into_iter().enumerate() {
                let asset_id =
                    decode_hex_field(&t.asset_id, 32, &format!("output_templates[{i}].asset_id"))?;
                out.push(ProtoOutputTemplate {
                    recipient: t.recipient,
                    asset_id,
                    amount: t.amount,
                });
            }
            out
        }
        None => Vec::new(),
    };

    let issuance = match body.issuance {
        Some(iss) => Some(json_to_issuance(iss)?),
        None => None,
    };

    // Presence rules (§7.5 L2907–L2941) that the API can enforce without kernel:
    // kind-dependent required fields. Remaining bounds stay kernel-side.
    match kind.as_str() {
        "send" => {
            if input_coins.is_empty() {
                return Err(ApiError::malformed(
                    "kind=send requires non-empty input_coins",
                ));
            }
            if output_templates.is_empty() {
                return Err(ApiError::malformed(
                    "kind=send requires non-empty output_templates",
                ));
            }
            if !fold_coin_ids.is_empty() {
                return Err(ApiError::malformed(
                    "kind=send must not carry fold_coin_ids",
                ));
            }
            if issuance.is_some() {
                return Err(ApiError::malformed("kind=send must not carry issuance"));
            }
        }
        "mint" => {
            if !input_coins.is_empty() {
                return Err(ApiError::malformed("kind=mint must not carry input_coins"));
            }
            if !fold_coin_ids.is_empty() {
                return Err(ApiError::malformed(
                    "kind=mint must not carry fold_coin_ids",
                ));
            }
            if output_templates.is_empty() {
                return Err(ApiError::malformed(
                    "kind=mint requires non-empty output_templates",
                ));
            }
            if issuance.is_none() {
                return Err(ApiError::malformed("kind=mint requires issuance"));
            }
        }
        "receive" => {
            if !input_coins.is_empty() {
                return Err(ApiError::malformed(
                    "kind=receive must not carry input_coins",
                ));
            }
            if !output_templates.is_empty() {
                return Err(ApiError::malformed(
                    "kind=receive must not carry output_templates",
                ));
            }
            if fold_coin_ids.is_empty() {
                return Err(ApiError::malformed(
                    "kind=receive requires non-empty fold_coin_ids",
                ));
            }
            if issuance.is_some() {
                return Err(ApiError::malformed("kind=receive must not carry issuance"));
            }
        }
        _ => unreachable!("kind checked above"),
    }

    if body.subject.is_empty() {
        return Err(ApiError::malformed("subject is required"));
    }

    Ok(TransitionRequest {
        kind,
        subject: body.subject,
        next_pubkey,
        npk_rand,
        input_coins,
        output_templates,
        publisher_pubkey,
        fee_address: String::new(),
        fold_coin_ids,
        issuance,
        idempotency_key: String::new(),
    })
}

fn json_to_issuance(iss: IssuanceJson) -> Result<Issuance, ApiError> {
    if iss.issuance_version != 1 && iss.issuance_version != 2 {
        return Err(ApiError::malformed("issuance_version must be 1 or 2"));
    }
    if iss.issuance_version == 2 {
        let cap = match iss.cap_total {
            Some(c) => c,
            None => {
                return Err(ApiError::malformed("issuance_version=2 requires cap_total"));
            }
        };
        let salt = match iss.terms_salt {
            Some(s) => decode_hex_field(&s, 32, "terms_salt")?,
            None => {
                return Err(ApiError::malformed(
                    "issuance_version=2 requires terms_salt",
                ));
            }
        };
        Ok(Issuance {
            name: iss.name,
            decimals: iss.decimals,
            issuance_version: iss.issuance_version,
            amount: iss.amount,
            cap_total: cap,
            terms_salt: salt,
        })
    } else {
        if iss.cap_total.is_some() || iss.terms_salt.is_some() {
            return Err(ApiError::malformed(
                "issuance_version=1 must not carry cap_total or terms_salt",
            ));
        }
        Ok(Issuance {
            name: iss.name,
            decimals: iss.decimals,
            issuance_version: iss.issuance_version,
            amount: iss.amount,
            cap_total: String::new(),
            terms_salt: Vec::new(),
        })
    }
}

fn decode_hex_field(hex: &str, byte_len: usize, field: &str) -> Result<Vec<u8>, ApiError> {
    decode_hex_exact(hex, byte_len)
        .map_err(|e: HexError| ApiError::malformed(format!("{field}: {e}")))
}

fn idempotency_key_from_headers(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(raw) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let s = raw
        .to_str()
        .map_err(|_| ApiError::malformed("Idempotency-Key must be ASCII"))?
        .to_string();
    if s.len() > 64 {
        return Err(ApiError::malformed("Idempotency-Key exceeds 64 bytes"));
    }
    Ok(Some(s))
}

/// §7.5 job poll object (L2889, L2959–L2991).
fn job_to_json(job: &Job) -> Result<Value, ApiError> {
    let mut obj = serde_json::Map::new();
    obj.insert("job_id".to_string(), Value::String(job.job_id.clone()));
    obj.insert("kind".to_string(), Value::String(job.kind.clone()));
    obj.insert("status".to_string(), Value::String(job.status.clone()));
    // phase absent in terminal states (L2889).
    let terminal = matches!(job.status.as_str(), "completed" | "failed" | "cancelled");
    if !terminal && !job.phase.is_empty() {
        obj.insert("phase".to_string(), Value::String(job.phase.clone()));
    }
    obj.insert("progress".to_string(), json!(job.progress));

    if job.status == "awaiting_signature" {
        match &job.awaiting_signature {
            Some(a) => {
                obj.insert(
                    "awaiting_signature".to_string(),
                    awaiting_signature_json(a)?,
                );
            }
            None => {
                return Err(ApiError::internal(
                    "job status is awaiting_signature but payload is absent",
                ));
            }
        }
    }

    if job.status == "completed" {
        match &job.result {
            Some(r) => {
                obj.insert("result".to_string(), job_result_json(r)?);
            }
            None => {
                return Err(ApiError::internal(
                    "job status is completed but result is absent",
                ));
            }
        }
    }

    if job.status == "failed" || job.status == "cancelled" {
        match &job.error {
            Some(e) => {
                obj.insert(
                    "error".to_string(),
                    json!({ "error": e.error, "message": e.message }),
                );
            }
            None => {
                return Err(ApiError::internal(format!(
                    "job status is {} but error is absent",
                    job.status
                )));
            }
        }
    }

    Ok(Value::Object(obj))
}

fn awaiting_signature_json(a: &AwaitingSignature) -> Result<Value, ApiError> {
    // All digests are required 32-byte values on the wire (L2961–L2970).
    Ok(json!({
        "new_account_state_hash": require_hex32(&a.new_account_state_hash, "new_account_state_hash")?,
        "output_coins_root": require_hex32(&a.output_coins_root, "output_coins_root")?,
        "input_nullifiers_root": require_hex32(&a.input_nullifiers_root, "input_nullifiers_root")?,
        "coin_history_root": require_hex32(&a.coin_history_root, "coin_history_root")?,
        "nav_commitment": require_hex32(&a.nav_commitment, "nav_commitment")?,
        "npk_commit": require_hex32(&a.npk_commit, "npk_commit")?,
        "proof_data_hash": require_hex32(&a.proof_data_hash, "proof_data_hash")?,
        "txn_pubkey": require_hex32(&a.txn_pubkey, "txn_pubkey")?,
        "send_counter": a.send_counter,
    }))
}

fn job_result_json(r: &ProtoJobResult) -> Result<Value, ApiError> {
    let mut obj = serde_json::Map::new();
    // Digest fields may be empty for attest_balance jobs; only encode when set.
    if !r.new_account_state_hash.is_empty() {
        obj.insert(
            "new_account_state_hash".to_string(),
            Value::String(require_hex32(
                &r.new_account_state_hash,
                "result.new_account_state_hash",
            )?),
        );
    }
    if !r.output_coins_root.is_empty() {
        obj.insert(
            "output_coins_root".to_string(),
            Value::String(require_hex32(
                &r.output_coins_root,
                "result.output_coins_root",
            )?),
        );
    }
    if !r.input_nullifiers_root.is_empty() {
        obj.insert(
            "input_nullifiers_root".to_string(),
            Value::String(require_hex32(
                &r.input_nullifiers_root,
                "result.input_nullifiers_root",
            )?),
        );
    }
    let mut coin_ids = Vec::with_capacity(r.output_coin_ids.len());
    for (i, id) in r.output_coin_ids.iter().enumerate() {
        coin_ids.push(require_hex32(id, &format!("result.output_coin_ids[{i}]"))?);
    }
    obj.insert("output_coin_ids".to_string(), json!(coin_ids));

    if !r.publisher_pubkey.is_empty() {
        obj.insert(
            "publisher_pubkey".to_string(),
            Value::String(require_hex32(
                &r.publisher_pubkey,
                "result.publisher_pubkey",
            )?),
        );
    }
    if !r.attestation.is_empty() {
        obj.insert(
            "attestation".to_string(),
            Value::String(encode_hex(&r.attestation)),
        );
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

/// Poll headers: 200 always on success; Retry-After on non-terminal (L2944).
fn job_poll_headers(job: &Job) -> (StatusCode, Option<u64>) {
    let terminal = matches!(job.status.as_str(), "completed" | "failed" | "cancelled");
    if terminal {
        return (StatusCode::OK, None);
    }
    let secs = match job.status.as_str() {
        "awaiting_signature" => 0,
        _ => 2, // proving / publishing / accepted — RECOMMENDED 2 (L2944)
    };
    (StatusCode::OK, Some(secs))
}

//! Job-surface REST handlers (§7.5) over kernel job procedures (§7.8).
//!
//! Endpoints (Spec-Schreibweise): `POST /v1/tx`, `GET /v1/jobs/<job_id>`,
//! `GET /v1/jobs/<job_id>/stream`, `POST /v1/jobs/<job_id>/sign`,
//! `POST /v1/jobs/<job_id>/cancel`. Axum registers the derived `:job_id` matcher.

use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::hexutil::{decode_hex_exact, encode_hex, HexError};
use crate::kernel::kernel_v1::{
    delivery_credential, AwaitingSignature, DeliveryCredential as ProtoDeliveryCredential,
    Invoice as ProtoInvoice, Issuance, Job, JobEvent, JobHandle, JobRequest,
    JobResult as ProtoJobResult, Kind0Event as ProtoKind0Event,
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
use std::fmt;

// ---------------------------------------------------------------------------
// Closed job status / error sets (§7.5 jobs family)
// ---------------------------------------------------------------------------

/// Closed `Job.status` vocabulary on the public poll / SSE surface.
const CLOSED_JOB_STATUSES: &[&str] = &[
    "accepted",
    "proving",
    "awaiting_signature",
    "publishing",
    "completed",
    "failed",
    "cancelled",
];

/// Closed terminal `JobError.error` machine codes (§7.5 jobs-family table).
///
/// Includes `dependency_not_final`: the productive node stores a typed
/// `DependencyNotFinal` finalise failure as this terminal machine code
/// (see node `job_dispatcher` / `v1::signature` encode path). Omitting it
/// would turn a normative terminal job failure into API `500 internal_error`.
const CLOSED_JOB_ERROR_CODES: &[&str] = &[
    "invalid_input_coin",
    "insufficient_balance",
    "bounds_exceeded",
    "unknown_publisher",
    "stale_message",
    "invalid_signature",
    "proving_failed",
    "publish_rejected",
    "circuit_digest_mismatch",
    "idempotency_conflict",
    "dependency_not_final",
    "malformed_request",
    "internal_error",
];

fn is_closed_job_status(status: &str) -> bool {
    CLOSED_JOB_STATUSES.contains(&status)
}

fn is_terminal_job_status(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

fn is_closed_job_error_code(code: &str) -> bool {
    CLOSED_JOB_ERROR_CODES.contains(&code)
}

/// Closed `Job.kind` vocabulary on the public poll / SSE surface.
const CLOSED_JOB_KINDS: &[&str] = &["mint", "send", "receive", "attest_balance"];

fn is_closed_job_kind(kind: &str) -> bool {
    CLOSED_JOB_KINDS.contains(&kind)
}

fn is_transition_job_kind(kind: &str) -> bool {
    matches!(kind, "mint" | "send" | "receive")
}

/// Validate a kernel `Job` against the closed status set, status↔payload
/// exclusivity, kind-dependent result shape, and terminal error-code
/// vocabulary. Fail-closed as `500 internal_error` on any contract breach
/// (never forward foreign statuses or error codes onto the public wire).
fn validate_job(job: &Job) -> Result<(), ApiError> {
    if !is_closed_job_status(&job.status) {
        return Err(ApiError::internal(format!(
            "kernel Job.status is not a closed §7.5 job status: {:?}",
            job.status
        )));
    }
    if !is_closed_job_kind(&job.kind) {
        return Err(ApiError::internal(format!(
            "kernel Job.kind is not a closed §7.5 job kind: {:?}",
            job.kind
        )));
    }

    let has_awaiting = job.awaiting_signature.is_some();
    let has_result = job.result.is_some();
    let has_error = job.error.is_some();

    // Terminal states must not carry a phase string (proto comment / §7.5).
    if is_terminal_job_status(&job.status) && !job.phase.is_empty() {
        return Err(ApiError::internal(format!(
            "job status {} must have empty phase, got {:?}",
            job.status, job.phase
        )));
    }

    match job.status.as_str() {
        "awaiting_signature" => {
            if !has_awaiting {
                return Err(ApiError::internal(
                    "job status is awaiting_signature but payload is absent",
                ));
            }
            if has_result || has_error {
                return Err(ApiError::internal(
                    "job status awaiting_signature must not carry result or error",
                ));
            }
            if !is_transition_job_kind(&job.kind) {
                return Err(ApiError::internal(format!(
                    "job kind {:?} must not enter awaiting_signature",
                    job.kind
                )));
            }
        }
        "completed" => {
            if !has_result {
                return Err(ApiError::internal(
                    "job status is completed but result is absent",
                ));
            }
            if has_awaiting || has_error {
                return Err(ApiError::internal(
                    "job status completed must not carry awaiting_signature or error",
                ));
            }
            let result = job.result.as_ref().expect("checked has_result");
            validate_job_result_for_kind(&job.kind, result)?;
        }
        "failed" | "cancelled" => {
            if !has_error {
                return Err(ApiError::internal(format!(
                    "job status is {} but error is absent",
                    job.status
                )));
            }
            if has_awaiting || has_result {
                return Err(ApiError::internal(format!(
                    "job status {} must not carry awaiting_signature or result",
                    job.status
                )));
            }
            let err = job.error.as_ref().expect("checked has_error");
            if !is_closed_job_error_code(&err.error) {
                return Err(ApiError::internal(format!(
                    "kernel JobError.error is not a closed job terminal code: {:?}",
                    err.error
                )));
            }
        }
        // Non-terminal phases: no exclusive payloads.
        "accepted" | "proving" | "publishing" => {
            if has_awaiting || has_result || has_error {
                return Err(ApiError::internal(format!(
                    "job status {} must not carry awaiting_signature, result, or error",
                    job.status
                )));
            }
        }
        _ => unreachable!("closed set checked above"),
    }
    Ok(())
}

/// Kind-dependent completed-result shape.
///
/// - `attest_balance`: non-empty `attestation`; no transition digest fields.
/// - `mint`/`send`/`receive`: required transition digests; no `attestation`.
fn validate_job_result_for_kind(kind: &str, result: &ProtoJobResult) -> Result<(), ApiError> {
    let has_attestation = !result.attestation.is_empty();
    let has_transition_digest = !result.new_account_state_hash.is_empty()
        || !result.output_coins_root.is_empty()
        || !result.input_nullifiers_root.is_empty()
        || !result.publisher_pubkey.is_empty()
        || !result.output_coin_ids.is_empty();

    match kind {
        "attest_balance" => {
            if !has_attestation {
                return Err(ApiError::internal(
                    "attest_balance completed result must carry non-empty attestation",
                ));
            }
            if has_transition_digest {
                return Err(ApiError::internal(
                    "attest_balance completed result must not carry transition digest fields",
                ));
            }
        }
        "mint" | "send" | "receive" => {
            if has_attestation {
                return Err(ApiError::internal(format!(
                    "transition job kind {kind:?} must not carry attestation"
                )));
            }
            // Required digests for transition completion.
            if result.new_account_state_hash.len() != 32 {
                return Err(ApiError::internal(format!(
                    "transition job result.new_account_state_hash must be 32 bytes, got {}",
                    result.new_account_state_hash.len()
                )));
            }
            if result.output_coins_root.len() != 32 {
                return Err(ApiError::internal(format!(
                    "transition job result.output_coins_root must be 32 bytes, got {}",
                    result.output_coins_root.len()
                )));
            }
            if result.input_nullifiers_root.len() != 32 {
                return Err(ApiError::internal(format!(
                    "transition job result.input_nullifiers_root must be 32 bytes, got {}",
                    result.input_nullifiers_root.len()
                )));
            }
        }
        other => {
            return Err(ApiError::internal(format!(
                "kernel Job.kind is not a closed §7.5 job kind: {other:?}"
            )));
        }
    }
    Ok(())
}

/// SSE event name ↔ job status correlation (§7.5 L2947 / L3033).
fn validate_sse_event_status(event_name: &str, job: &Job) -> Result<(), ApiError> {
    validate_job(job)?;
    match event_name {
        "phase" => {
            if is_terminal_job_status(&job.status) {
                return Err(ApiError::internal(format!(
                    "SSE event \"phase\" must not carry terminal status {:?}",
                    job.status
                )));
            }
        }
        "complete" => {
            if job.status != "completed" {
                return Err(ApiError::internal(format!(
                    "SSE event \"complete\" requires status \"completed\", got {:?}",
                    job.status
                )));
            }
        }
        "error" => {
            if job.status != "failed" && job.status != "cancelled" {
                return Err(ApiError::internal(format!(
                    "SSE event \"error\" requires status failed|cancelled, got {:?}",
                    job.status
                )));
            }
        }
        _ => {
            return Err(ApiError::internal(format!(
                "kernel JobEvent.event is not a §7.5 SSE name: {event_name:?}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON request types (exact §7.5 shapes)
// ---------------------------------------------------------------------------

/// §7.5 `TransitionRequest` JSON body for `POST /v1/tx` (L2898–L2930).
///
/// §7.5: "the body is exactly this JSON object" — unknown fields are
/// `400 malformed_request`. `deny_unknown_fields` is set on nested object
/// types below (except NIP-01 `Kind0EventJson`, which accepts extra fields)
/// so a foreign key inside `output_templates[]` or `issuance` is rejected
/// the same way as one at the top level.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Recipient's genesis Pk₀ (32-byte lowercase hex, x-only); required for
    /// a genesis receive (no prior transition), MUST be absent otherwise (§7.5).
    pub genesis_pubkey: Option<String>,
    #[serde(default)]
    pub issuance: Option<IssuanceJson>,
}

/// §7.5 `OutputTemplate`. `delivery` is optional on the wire; presence for
/// non-self outputs is enforced by the **kernel** (§7.5 presence rule), not
/// here. The API only checks form and forwards.
///
/// **Debug** redacts `delivery` entirely — §7.5 retention: the API layer
/// **MUST NOT** log the credential (`pk0` / `memo` / signatures link the
/// recipient to its genesis on-chain nullifier key).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputTemplateJson {
    pub recipient: String,
    pub asset_id: String,
    pub amount: String,
    #[serde(default)]
    pub delivery: Option<DeliveryCredentialJson>,
}

impl fmt::Debug for OutputTemplateJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputTemplateJson")
            .field("recipient", &self.recipient)
            .field("asset_id", &self.asset_id)
            .field("amount", &self.amount)
            .field(
                "delivery",
                &self
                    .delivery
                    .as_ref()
                    .map(|_| "<redacted delivery credential — §7.5 retention>"),
            )
            .finish()
    }
}

/// Closed tagged union matching §7.5 `DeliveryCredential`.
///
/// REST: `{ "type": "invoice", "invoice": … }` | `{ "type": "profile", "event": … }`.
/// Any other `type`, any structural deviation, and unknown nested fields are
/// `400 malformed_request` at the API edge. Content checks (signatures,
/// address preimage, profile kind-0 rules) are **kernel-only**.
///
/// **Debug** never prints credential contents (same §7.5 retention rule).
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum DeliveryCredentialJson {
    #[serde(rename = "invoice")]
    Invoice { invoice: InvoiceJson },
    #[serde(rename = "profile")]
    Profile { event: Kind0EventJson },
}

impl fmt::Debug for DeliveryCredentialJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Spec §7.5 retention: API MUST NOT log delivery. Name only the arm.
        match self {
            Self::Invoice { .. } => {
                f.write_str("DeliveryCredentialJson::Invoice { /* redacted */ }")
            }
            Self::Profile { .. } => {
                f.write_str("DeliveryCredentialJson::Profile { /* redacted */ }")
            }
        }
    }
}

/// Full §1.5 / §4.3 `Invoice` on the REST surface (§7.1 hex + decimal-string).
///
/// Form only at the API: hex widths and required keys. No crypto, no address
/// preimage, no relay-URL policy.
///
/// **`memo` (§1.5 normalisation):** Spec: "memo contributes the empty byte
/// string when absent". `None` and `Some("")` therefore both become the empty
/// proto string via `unwrap_or_default()`. Non-empty memo is copied
/// byte-for-byte (no trim). Forwarding is unchanged **except** for that
/// §1.5 memo normalisation — not a free-form "pass Option through".
///
/// **Debug** redacts `pk0`, `memo`, and both signatures.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceJson {
    pub amount: String,
    pub recipient: String,
    pub asset_id: String,
    #[serde(default)]
    pub memo: Option<String>,
    pub pk0: String,
    pub nk_commit: String,
    pub ivpk: String,
    pub op_pubkey: String,
    pub relays: Vec<String>,
    pub addr_sig: String,
    pub sig: String,
}

impl fmt::Debug for InvoiceJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // §7.5: after a successful check the kernel retains only
        // {ivpk, op_pubkey, relays}; pk0 / memo / signatures MUST NOT be
        // logged. The API never verifies — and still MUST NOT log them.
        f.debug_struct("InvoiceJson")
            .field("amount", &self.amount)
            .field("recipient", &self.recipient)
            .field("asset_id", &self.asset_id)
            .field(
                "memo",
                &self
                    .memo
                    .as_ref()
                    .map(|_| "<redacted memo — §7.5 retention>"),
            )
            .field("pk0", &"<redacted pk0 — §7.5 retention>")
            .field("nk_commit", &"<redacted>")
            .field("ivpk", &"<redacted>")
            .field("op_pubkey", &"<redacted>")
            .field("relays", &self.relays.len())
            .field("addr_sig", &"<redacted>")
            .field("sig", &"<redacted>")
            .finish()
    }
}

/// Canonical NIP-01 kind-0 event shape on the REST surface (`type: "profile"`).
///
/// Binary fields are lowercase-or-uppercase hex of exact width. `tags` is the
/// JSON array of tag arrays; the API serialises it to `Kind0Event.tags_json`
/// without reformatting the `content` string. Extra NIP-01 fields beyond the
/// core set are accepted (no `deny_unknown_fields`).
///
/// **Debug** redacts id / pubkey / content / sig (content holds the `zkcoins`
/// object including `pk0`).
#[derive(Deserialize)]
pub struct Kind0EventJson {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl fmt::Debug for Kind0EventJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kind0EventJson")
            .field("id", &"<redacted>")
            .field("pubkey", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("tags", &self.tags.len())
            .field("content", &"<redacted content — §7.5 retention>")
            .field("sig", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceJson {
    pub name: String,
    pub decimals: u32,
    pub issuance_version: u32,
    pub amount: String,
    /// Genesis spend key `Pk₀` (32-byte lowercase hex); required for both versions.
    pub creator_pubkey: String,
    #[serde(default)]
    pub cap_total: Option<String>,
    #[serde(default)]
    pub terms_salt: Option<String>,
}

/// §7.5 sign body (L2891): `{ signature: <hex64>, s2c_nonce: <hex32> }`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignBodyJson {
    pub signature: String,
    pub s2c_nonce: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/tx` → `SubmitTransition` → `202 { job_id, status: "accepted" }`.
///
/// Body is deserialized via [`JsonBody`] so unknown fields, content-type
/// failures, and other serde rejections become `400 malformed_request` (not
/// axum's default 422 with a non-§7.5 body).
///
/// **Retention (§7.5 `delivery`):** this handler never logs the request body
/// and never interpolates credential fields into success paths. Form-error
/// messages name field *paths* and form classes only — not `pk0` hex or
/// `memo` text. `Debug` on the JSON types redacts `delivery` for the same
/// reason (see `OutputTemplateJson` / `InvoiceJson`).
pub async fn post_tx(
    State(kernel): State<KernelHandle>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<TransitionRequestJson>,
) -> Result<Response, ApiError> {
    let mut req = json_to_transition(body)?;
    // Missing header ⇒ leave proto field empty (kernel treats empty as absent).
    // Present-but-empty is a client error, not silently rewritten to absent.
    if let Some(key) = idempotency_key_from_headers(&headers)? {
        req.idempotency_key = key;
    }
    let handle: JobHandle = kernel.submit_transition(req).await?;
    // Spec §7.5: 202 is the only success for POST /v1/tx, and the body is
    // `{ job_id, status: "accepted" }`. An empty job_id or non-accepted
    // status is a kernel contract violation — never admit as success
    // (same discipline as AttestBalance in `attest.rs`).
    if handle.job_id.is_empty() {
        return Err(ApiError::internal(
            "kernel JobHandle.job_id is empty on SubmitTransition success",
        ));
    }
    if handle.status != "accepted" {
        return Err(ApiError::internal(format!(
            "kernel JobHandle.status must be \"accepted\" on submit success, got {:?}",
            handle.status
        )));
    }
    let body = json!({
        "job_id": handle.job_id,
        "status": "accepted",
    });
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
    let (status_header, retry_after) = job_poll_headers(&job)?;
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
    JsonBody(body): JsonBody<SignBodyJson>,
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
    let job = match &ev.job {
        Some(j) => j,
        None => {
            return Err(ApiError::internal(
                "kernel JobEvent is missing the job payload",
            ));
        }
    };
    // Closed event name + status correlation + payload exclusivity.
    validate_sse_event_status(name, job)?;
    let data = match name {
        "phase" => phase_event_data(job)?,
        "complete" | "error" => job_to_json(job)?,
        _ => unreachable!("validate_sse_event_status checked name"),
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

    let genesis_pubkey = match body.genesis_pubkey {
        Some(hex) => decode_hex_field(&hex, 32, "genesis_pubkey")?,
        None => Vec::new(),
    };

    let output_templates = match body.output_templates {
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for (i, t) in list.into_iter().enumerate() {
                out.push(json_to_output_template(t, i)?);
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
            if !genesis_pubkey.is_empty() {
                return Err(ApiError::malformed(
                    "kind=send must not carry genesis_pubkey",
                ));
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
            if !genesis_pubkey.is_empty() {
                return Err(ApiError::malformed(
                    "kind=mint must not carry genesis_pubkey",
                ));
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
        genesis_pubkey,
        idempotency_key: String::new(),
    })
}

/// REST → proto for one `OutputTemplate`, including optional `delivery`.
///
/// Hex is form-checked (width + charset) and decoded; strings (`recipient`,
/// `amount`, relays, content) pass through unchanged (no trim). Invoice
/// `memo` is normalised per §1.5 (absent → empty byte string); see
/// [`InvoiceJson`]. Credential **content** is never inspected.
fn json_to_output_template(
    t: OutputTemplateJson,
    index: usize,
) -> Result<ProtoOutputTemplate, ApiError> {
    let prefix = format!("output_templates[{index}]");
    let asset_id = decode_hex_field(&t.asset_id, 32, &format!("{prefix}.asset_id"))?;
    let delivery = match t.delivery {
        None => None,
        Some(cred) => Some(json_to_delivery_credential(cred, &prefix)?),
    };
    Ok(ProtoOutputTemplate {
        recipient: t.recipient,
        asset_id,
        amount: t.amount,
        delivery,
    })
}

/// REST closed tagged union → proto `DeliveryCredential` oneof.
///
/// Maps `type: "invoice"` → `body = Invoice`, `type: "profile"` →
/// `body = ProfileEvent`. Unknown `type` is already rejected by serde at the
/// JSON edge. Error messages name only field paths and form classes — never
/// credential bytes or memo text (§7.5 retention).
fn json_to_delivery_credential(
    cred: DeliveryCredentialJson,
    output_prefix: &str,
) -> Result<ProtoDeliveryCredential, ApiError> {
    let prefix = format!("{output_prefix}.delivery");
    let body = match cred {
        DeliveryCredentialJson::Invoice { invoice } => {
            delivery_credential::Body::Invoice(json_to_invoice(invoice, &prefix)?)
        }
        DeliveryCredentialJson::Profile { event } => {
            delivery_credential::Body::ProfileEvent(json_to_kind0_event(event, &prefix)?)
        }
    };
    Ok(ProtoDeliveryCredential { body: Some(body) })
}

fn json_to_invoice(inv: InvoiceJson, delivery_prefix: &str) -> Result<ProtoInvoice, ApiError> {
    let p = format!("{delivery_prefix}.invoice");
    // Form only: exact hex widths. Do not trim strings; do not parse amount as
    // u128; do not require non-empty relays (kernel check-list).
    let asset_id = decode_hex_field(&inv.asset_id, 32, &format!("{p}.asset_id"))?;
    let pk0 = decode_hex_field(&inv.pk0, 32, &format!("{p}.pk0"))?;
    let nk_commit = decode_hex_field(&inv.nk_commit, 32, &format!("{p}.nk_commit"))?;
    let ivpk = decode_hex_field(&inv.ivpk, 32, &format!("{p}.ivpk"))?;
    let op_pubkey = decode_hex_field(&inv.op_pubkey, 32, &format!("{p}.op_pubkey"))?;
    let addr_sig = decode_hex_field(&inv.addr_sig, 64, &format!("{p}.addr_sig"))?;
    let sig = decode_hex_field(&inv.sig, 64, &format!("{p}.sig"))?;
    // §1.5: memo contributes the empty byte string when absent. Present empty
    // and present non-empty (no trim) map unchanged except that normalisation.
    let memo = inv.memo.unwrap_or_default();
    Ok(ProtoInvoice {
        amount: inv.amount,
        recipient: inv.recipient,
        asset_id,
        memo,
        pk0,
        nk_commit,
        ivpk,
        op_pubkey,
        relays: inv.relays,
        addr_sig,
        sig,
    })
}

fn json_to_kind0_event(
    ev: Kind0EventJson,
    delivery_prefix: &str,
) -> Result<ProtoKind0Event, ApiError> {
    let p = format!("{delivery_prefix}.event");
    // Form only: hex widths. kind == 0 and NIP-01 verification are kernel-side.
    let id = decode_hex_field(&ev.id, 32, &format!("{p}.id"))?;
    let pubkey = decode_hex_field(&ev.pubkey, 32, &format!("{p}.pubkey"))?;
    let sig = decode_hex_field(&ev.sig, 64, &format!("{p}.sig"))?;
    // tags → tags_json: canonical JSON array, no pretty-print. Failure here is
    // structural (tags not serialisable) — message names the path only.
    let tags_json = serde_json::to_string(&ev.tags).map_err(|_| {
        ApiError::malformed(format!(
            "{p}.tags must be a JSON-serialisable array of string arrays"
        ))
    })?;
    Ok(ProtoKind0Event {
        id,
        pubkey,
        created_at: ev.created_at,
        kind: ev.kind,
        tags_json,
        content: ev.content,
        sig,
    })
}

fn json_to_issuance(iss: IssuanceJson) -> Result<Issuance, ApiError> {
    if iss.issuance_version != 1 && iss.issuance_version != 2 {
        return Err(ApiError::malformed("issuance_version must be 1 or 2"));
    }
    let creator_pubkey = decode_hex_field(&iss.creator_pubkey, 32, "creator_pubkey")?;
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
            creator_pubkey,
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
            creator_pubkey,
        })
    }
}

fn decode_hex_field(hex: &str, byte_len: usize, field: &str) -> Result<Vec<u8>, ApiError> {
    decode_hex_exact(hex, byte_len)
        .map_err(|e: HexError| ApiError::malformed(format!("{field}: {e}")))
}

/// Parse the §7.5 `Idempotency-Key` request header.
///
/// - **Absent** → `Ok(None)` — caller leaves the proto field empty (missing).
/// - **Present but empty** → `400 malformed_request` (empty ≠ missing).
/// - **Present, non-empty, ≤ 64 bytes, ASCII** → `Ok(Some(key))`.
pub(crate) fn idempotency_key_from_headers(
    headers: &HeaderMap,
) -> Result<Option<String>, ApiError> {
    let Some(raw) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let s = raw
        .to_str()
        .map_err(|_| ApiError::malformed("Idempotency-Key must be ASCII"))?;
    parse_idempotency_key_value(s)
}

/// Validate a present `Idempotency-Key` value (header already observed).
///
/// Separated from header extraction so empty-vs-missing can be unit-tested
/// without depending on `http::HeaderValue` (which rejects empty bytes).
pub(crate) fn parse_idempotency_key_value(s: &str) -> Result<Option<String>, ApiError> {
    if s.is_empty() {
        return Err(ApiError::malformed(
            "Idempotency-Key header is present but empty",
        ));
    }
    if s.len() > 64 {
        return Err(ApiError::malformed("Idempotency-Key exceeds 64 bytes"));
    }
    Ok(Some(s.to_string()))
}

/// §7.5 job poll object (L2889, L2959–L2991).
fn job_to_json(job: &Job) -> Result<Value, ApiError> {
    validate_job(job)?;

    let mut obj = serde_json::Map::new();
    obj.insert("job_id".to_string(), Value::String(job.job_id.clone()));
    obj.insert("kind".to_string(), Value::String(job.kind.clone()));
    obj.insert("status".to_string(), Value::String(job.status.clone()));
    // phase absent in terminal states (L2889).
    if !is_terminal_job_status(&job.status) && !job.phase.is_empty() {
        obj.insert("phase".to_string(), Value::String(job.phase.clone()));
    }
    obj.insert("progress".to_string(), json!(job.progress));

    if job.status == "awaiting_signature" {
        let a = job
            .awaiting_signature
            .as_ref()
            .expect("validate_job checked");
        obj.insert(
            "awaiting_signature".to_string(),
            awaiting_signature_json(a)?,
        );
    }

    if job.status == "completed" {
        let r = job.result.as_ref().expect("validate_job checked");
        obj.insert("result".to_string(), job_result_json(r)?);
    }

    if job.status == "failed" || job.status == "cancelled" {
        let e = job.error.as_ref().expect("validate_job checked");
        // Neutralise internal diagnostics on the public wire (poll + SSE).
        let public_message = if e.error == "internal_error" {
            tracing::error!(
                job_id = %job.job_id,
                message = %e.message,
                "job terminal internal_error (operator diagnostic only)"
            );
            crate::error::PUBLIC_INTERNAL_MESSAGE.to_string()
        } else {
            e.message.clone()
        };
        obj.insert(
            "error".to_string(),
            json!({ "error": e.error, "message": public_message }),
        );
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

/// Project a completed `JobResult` already validated by [`validate_job`].
///
/// Kind-dependent presence is enforced in `validate_job_result_for_kind`;
/// this helper only formats present fields.
fn job_result_json(r: &ProtoJobResult) -> Result<Value, ApiError> {
    let mut obj = serde_json::Map::new();
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
    // Transition jobs always expose the (possibly empty) coin-id list.
    // Attest jobs have no coin ids — omit the field when empty and attestation
    // is present so clients do not see a meaningless empty array.
    if !coin_ids.is_empty() || r.attestation.is_empty() {
        obj.insert("output_coin_ids".to_string(), json!(coin_ids));
    }

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
///
/// Caller must already have [`validate_job`]'d — unknown status is not treated
/// as non-terminal (that would invent a retry schedule for foreign values).
fn job_poll_headers(job: &Job) -> Result<(StatusCode, Option<u64>), ApiError> {
    validate_job(job)?;
    if is_terminal_job_status(&job.status) {
        return Ok((StatusCode::OK, None));
    }
    let secs = match job.status.as_str() {
        "awaiting_signature" => 0,
        _ => 2, // proving / publishing / accepted — RECOMMENDED 2 (L2944)
    };
    Ok((StatusCode::OK, Some(secs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::kernel_v1::delivery_credential::Body as DeliveryBody;
    use axum::http::HeaderMap;

    fn hex32(byte: u8) -> String {
        crate::hexutil::encode_hex(&[byte; 32])
    }

    fn hex64(byte: u8) -> String {
        crate::hexutil::encode_hex(&[byte; 64])
    }

    /// Distinctive 32-byte hex that must never appear in logs / error text.
    fn distinctive_pk0() -> String {
        // Unique nibble pattern so substring false-positives are unlikely.
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()
    }

    fn distinctive_memo() -> String {
        "MEMO_RETENTION_MARKER_DO_NOT_LOG_xyz".to_string()
    }

    fn sample_invoice_json() -> serde_json::Value {
        serde_json::json!({
            "amount": "100",
            "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "asset_id": hex32(0x33),
            "memo": distinctive_memo(),
            "pk0": distinctive_pk0(),
            "nk_commit": hex32(0x44),
            "ivpk": hex32(0x55),
            "op_pubkey": hex32(0x66),
            "relays": ["wss://relay.example"],
            "addr_sig": hex64(0x77),
            "sig": hex64(0x88),
        })
    }

    fn sample_profile_event_json() -> serde_json::Value {
        serde_json::json!({
            "id": hex32(0x91),
            "pubkey": hex32(0x92),
            "created_at": 1_700_000_000_u64,
            "kind": 0,
            "tags": [],
            "content": format!(
                "{{\"zkcoins\":{{\"pk0\":\"{}\",\"memo\":\"should-not-matter\"}}}}",
                distinctive_pk0()
            ),
            "sig": hex64(0x93),
        })
    }

    fn mint_json() -> serde_json::Value {
        serde_json::json!({
            "kind": "mint",
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "next_pubkey": hex32(0x11),
            "npk_rand": hex32(0x22),
            "output_templates": [{
                "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "asset_id": hex32(0x33),
                "amount": "100"
            }],
            "issuance": {
                "name": "TestCoin",
                "decimals": 8,
                "issuance_version": 1,
                "amount": "1000",
                "creator_pubkey": hex32(0x44)
            }
        })
    }

    fn mint_with_invoice_delivery() -> serde_json::Value {
        let mut v = mint_json();
        v["output_templates"][0]["delivery"] = serde_json::json!({
            "type": "invoice",
            "invoice": sample_invoice_json(),
        });
        v
    }

    fn mint_with_profile_delivery() -> serde_json::Value {
        let mut v = mint_json();
        v["output_templates"][0]["delivery"] = serde_json::json!({
            "type": "profile",
            "event": sample_profile_event_json(),
        });
        v
    }

    fn send_two_outputs_with_deliveries() -> serde_json::Value {
        let inv0 = sample_invoice_json();
        let mut inv1 = sample_invoice_json();
        inv1["amount"] = serde_json::json!("200");
        inv1["pk0"] = serde_json::json!(hex32(0xAB));
        inv1["memo"] = serde_json::json!("second-output-memo");
        serde_json::json!({
            "kind": "send",
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "next_pubkey": hex32(0x11),
            "npk_rand": hex32(0x22),
            "input_coins": [hex32(0x01)],
            "output_templates": [
                {
                    "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                    "asset_id": hex32(0x33),
                    "amount": "100",
                    "delivery": { "type": "invoice", "invoice": inv0 }
                },
                {
                    "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                    "asset_id": hex32(0x33),
                    "amount": "200",
                    "delivery": { "type": "invoice", "invoice": inv1 }
                }
            ]
        })
    }

    #[test]
    fn idempotency_missing_header_is_none() {
        let headers = HeaderMap::new();
        let got = idempotency_key_from_headers(&headers).expect("ok");
        assert_eq!(got, None, "absent header must stay None, not empty string");
    }

    /// Present-but-empty is a client error. Distinct from missing (`None`).
    ///
    /// Tested at the value layer: `http::HeaderValue` rejects empty bytes, so
    /// an HTTP request builder cannot construct this case — the wire still
    /// requires the same rule when a stack delivers an empty value.
    #[test]
    fn idempotency_empty_value_is_malformed_not_none() {
        let err = parse_idempotency_key_value("").expect_err("empty");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        // Contrast: missing header is Ok(None), not an error.
        let headers = HeaderMap::new();
        assert!(idempotency_key_from_headers(&headers).unwrap().is_none());
    }

    #[test]
    fn idempotency_nonempty_header_is_some() {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", "abc".parse().unwrap());
        let got = idempotency_key_from_headers(&headers).expect("ok");
        assert_eq!(got.as_deref(), Some("abc"));
    }

    #[test]
    fn transition_request_rejects_unknown_top_level_field() {
        let mut v = mint_json();
        v["not_in_spec"] = serde_json::json!(true);
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("deny");
        assert!(
            err.to_string().contains("not_in_spec") || err.to_string().contains("unknown field"),
            "serde must reject unknown field, got {err}"
        );
    }

    #[test]
    fn transition_request_rejects_unknown_nested_issuance_field() {
        let mut v = mint_json();
        v["issuance"]["ghost"] = serde_json::json!("x");
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("deny nested");
        assert!(
            err.to_string().contains("ghost") || err.to_string().contains("unknown field"),
            "nested deny_unknown_fields must fire, got {err}"
        );
    }

    #[test]
    fn transition_request_rejects_unknown_nested_output_template_field() {
        let mut v = mint_json();
        v["output_templates"][0]["extra"] = serde_json::json!(1);
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("deny nested ot");
        assert!(
            err.to_string().contains("extra") || err.to_string().contains("unknown field"),
            "output_templates deny_unknown_fields must fire, got {err}"
        );
    }

    #[test]
    fn transition_request_accepts_exact_mint_shape() {
        let v = mint_json();
        let parsed: TransitionRequestJson =
            serde_json::from_value(v).expect("exact shape must parse");
        assert_eq!(parsed.kind, "mint");
    }

    // -----------------------------------------------------------------------
    // Delivery credential: form edge + field-for-field forward
    // -----------------------------------------------------------------------

    #[test]
    fn invoice_delivery_forwards_field_for_field() {
        let parsed: TransitionRequestJson =
            serde_json::from_value(mint_with_invoice_delivery()).expect("parse");
        let req = json_to_transition(parsed).expect("convert");
        assert_eq!(req.output_templates.len(), 1);
        let ot = &req.output_templates[0];
        let cred = ot.delivery.as_ref().expect("delivery present");
        assert!(matches!(cred.body.as_ref(), Some(DeliveryBody::Invoice(_))));
        let Some(DeliveryBody::Invoice(inv)) = cred.body.as_ref() else {
            panic!("expected Invoice arm");
        };
        assert_eq!(inv.amount, "100");
        assert_eq!(
            inv.recipient,
            "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        );
        assert_eq!(inv.asset_id, vec![0x33; 32]);
        assert_eq!(inv.memo, distinctive_memo());
        assert_eq!(inv.pk0, decode_hex_exact(&distinctive_pk0(), 32).unwrap());
        assert_eq!(inv.nk_commit, vec![0x44; 32]);
        assert_eq!(inv.ivpk, vec![0x55; 32]);
        assert_eq!(inv.op_pubkey, vec![0x66; 32]);
        assert_eq!(inv.relays, vec!["wss://relay.example".to_string()]);
        assert_eq!(inv.addr_sig, vec![0x77; 64]);
        assert_eq!(inv.sig, vec![0x88; 64]);
        // Output template fields unchanged alongside delivery.
        assert_eq!(ot.amount, "100");
        assert_eq!(ot.asset_id, vec![0x33; 32]);
    }

    #[test]
    fn profile_delivery_forwards_field_for_field() {
        let parsed: TransitionRequestJson =
            serde_json::from_value(mint_with_profile_delivery()).expect("parse");
        let req = json_to_transition(parsed).expect("convert");
        let cred = req.output_templates[0]
            .delivery
            .as_ref()
            .expect("delivery present");
        assert!(matches!(
            cred.body.as_ref(),
            Some(DeliveryBody::ProfileEvent(_))
        ));
        let Some(DeliveryBody::ProfileEvent(ev)) = cred.body.as_ref() else {
            panic!("expected ProfileEvent arm");
        };
        assert_eq!(ev.id, vec![0x91; 32]);
        assert_eq!(ev.pubkey, vec![0x92; 32]);
        assert_eq!(ev.created_at, 1_700_000_000);
        assert_eq!(ev.kind, 0);
        assert_eq!(ev.tags_json, "[]");
        assert!(
            ev.content.contains(&distinctive_pk0()),
            "content must be forwarded byte-for-byte (no redact on the wire)"
        );
        assert_eq!(ev.sig, vec![0x93; 64]);
    }

    #[test]
    fn delivery_position_binding_two_outputs() {
        // Each delivery stays bound to output_templates[i] — never re-keyed.
        let parsed: TransitionRequestJson =
            serde_json::from_value(send_two_outputs_with_deliveries()).expect("parse");
        let req = json_to_transition(parsed).expect("convert");
        assert_eq!(req.output_templates.len(), 2);

        let inv0 = match req.output_templates[0]
            .delivery
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            DeliveryBody::Invoice(i) => i,
            _ => panic!("[0] invoice"),
        };
        let inv1 = match req.output_templates[1]
            .delivery
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            DeliveryBody::Invoice(i) => i,
            _ => panic!("[1] invoice"),
        };
        assert_eq!(inv0.amount, "100");
        assert_eq!(inv0.memo, distinctive_memo());
        assert_eq!(inv0.pk0, decode_hex_exact(&distinctive_pk0(), 32).unwrap());
        assert_eq!(inv1.amount, "200");
        assert_eq!(inv1.memo, "second-output-memo");
        assert_eq!(inv1.pk0, vec![0xAB; 32]);
        // Positions must not swap.
        assert_ne!(inv0.pk0, inv1.pk0);
        assert_eq!(req.output_templates[0].amount, "100");
        assert_eq!(req.output_templates[1].amount, "200");
    }

    #[test]
    fn invoice_memo_absent_vs_empty_both_map_without_trim() {
        // §1.5: absent memo → empty proto string (normalisation, not free pass-through).
        let mut v = mint_with_invoice_delivery();
        v["output_templates"][0]["delivery"]["invoice"]
            .as_object_mut()
            .unwrap()
            .remove("memo");
        let req = json_to_transition(serde_json::from_value(v).unwrap()).unwrap();
        let inv = match req.output_templates[0]
            .delivery
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            DeliveryBody::Invoice(i) => i,
            _ => panic!("invoice"),
        };
        assert_eq!(inv.memo, "");

        // Present empty string also → empty (same §1.5 contribution).
        let mut v_empty = mint_with_invoice_delivery();
        v_empty["output_templates"][0]["delivery"]["invoice"]["memo"] = serde_json::json!("");
        let req_empty = json_to_transition(serde_json::from_value(v_empty).unwrap()).unwrap();
        let inv_empty = match req_empty.output_templates[0]
            .delivery
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            DeliveryBody::Invoice(i) => i,
            _ => panic!("invoice"),
        };
        assert_eq!(inv_empty.memo, "");

        // Present memo with leading/trailing spaces is NOT trimmed.
        let mut v2 = mint_with_invoice_delivery();
        v2["output_templates"][0]["delivery"]["invoice"]["memo"] =
            serde_json::json!("  spaced memo  ");
        let req2 = json_to_transition(serde_json::from_value(v2).unwrap()).unwrap();
        let inv2 = match req2.output_templates[0]
            .delivery
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            DeliveryBody::Invoice(i) => i,
            _ => panic!("invoice"),
        };
        assert_eq!(inv2.memo, "  spaced memo  ");
    }

    fn sample_job(status: &str) -> Job {
        Job {
            job_id: "j1".into(),
            kind: "mint".into(),
            status: status.into(),
            phase: String::new(),
            progress: 0.0,
            awaiting_signature: None,
            result: None,
            error: None,
        }
    }

    #[test]
    fn validate_job_rejects_unknown_status() {
        let job = sample_job("totally_unknown_phase");
        let err = validate_job(&job).expect_err("unknown status");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("totally_unknown_phase")
                || err.cause().unwrap_or("").contains("closed"),
            "cause must name the foreign status, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_rejects_unknown_terminal_error_code() {
        let mut job = sample_job("failed");
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "not_a_real_job_error".into(),
            message: "x".into(),
        });
        let err = validate_job(&job).expect_err("foreign error code");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("not_a_real_job_error")
                || err.cause().unwrap_or("").contains("closed"),
            "cause must name the foreign code, got {:?}",
            err.cause()
        );
    }

    /// Node finalise path stores typed `DependencyNotFinal` as terminal
    /// `JobError.error = "dependency_not_final"`. Poll and SSE must project
    /// that code, not fail-closed as `500 internal_error`.
    #[test]
    fn validate_job_and_poll_accept_dependency_not_final() {
        let mut job = sample_job("failed");
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "dependency_not_final".into(),
            message: "predecessor nullifier not covered by size_final".into(),
        });
        validate_job(&job).expect("dependency_not_final is a closed terminal code");
        assert!(
            validate_sse_event_status("error", &job).is_ok(),
            "SSE error event must accept dependency_not_final terminal job"
        );
        let json = job_to_json(&job).expect("poll projection");
        assert_eq!(json["status"], "failed");
        assert_eq!(json["error"]["error"], "dependency_not_final");
        assert_eq!(
            json["error"]["message"],
            "predecessor nullifier not covered by size_final"
        );
    }

    #[test]
    fn validate_job_enforces_status_payload_exclusivity() {
        // completed without result
        let job = sample_job("completed");
        assert!(validate_job(&job).is_err());

        // accepted with error payload
        let mut job = sample_job("accepted");
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "x".into(),
        });
        assert!(validate_job(&job).is_err());

        // failed without error
        let job = sample_job("failed");
        assert!(validate_job(&job).is_err());
    }

    #[test]
    fn validate_job_rejects_terminal_nonempty_phase() {
        let mut job = sample_job("completed");
        job.phase = "publishing".into();
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        let err = validate_job(&job).expect_err("terminal phase must fail");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("phase"),
            "cause must name phase, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_attest_requires_attestation_rejects_transition_fields() {
        let mut job = sample_job("completed");
        job.kind = "attest_balance".into();
        // Empty result → fail.
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        assert!(validate_job(&job).is_err());

        // Attestation + transition digest → fail.
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![0xaa, 0xbb],
        });
        assert!(validate_job(&job).is_err());

        // Pure attestation → ok.
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![0xaa, 0xbb, 0xcc],
        });
        assert!(validate_job(&job).is_ok());
    }

    #[test]
    fn validate_job_transition_rejects_attestation() {
        let mut job = sample_job("completed");
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![0xaa],
        });
        let err = validate_job(&job).expect_err("attestation on mint");
        assert_eq!(err.body.error, "internal_error");
    }

    #[test]
    fn job_to_json_neutralises_internal_error_message() {
        const SECRET: &str = "enqueue failed: /var/lib/SECRET_PATH_do_not_leak";
        let mut job = sample_job("failed");
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "internal_error".into(),
            message: SECRET.into(),
        });
        let json = job_to_json(&job).expect("project");
        assert_eq!(json["error"]["error"], "internal_error");
        assert_eq!(
            json["error"]["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE
        );
        let wire = json.to_string();
        assert!(
            !wire.contains("SECRET_PATH"),
            "public JSON must not leak secret: {wire}"
        );
        assert!(!wire.contains("enqueue failed"));
    }

    #[test]
    fn validate_sse_event_status_correlation() {
        let mut proving = sample_job("proving");
        proving.phase = "witness".into();
        assert!(validate_sse_event_status("phase", &proving).is_ok());

        // phase + terminal status is a contract breach.
        let mut completed = sample_job("completed");
        completed.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        assert!(validate_sse_event_status("phase", &completed).is_err());
        assert!(validate_sse_event_status("complete", &completed).is_ok());

        // complete with non-completed status
        assert!(validate_sse_event_status("complete", &proving).is_err());

        let mut failed = sample_job("failed");
        failed.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "x".into(),
        });
        assert!(validate_sse_event_status("error", &failed).is_ok());
        assert!(validate_sse_event_status("error", &proving).is_err());
    }

    #[test]
    fn unknown_delivery_type_is_malformed_at_json_edge() {
        let mut v = mint_json();
        v["output_templates"][0]["delivery"] = serde_json::json!({
            "type": "carrier_pigeon",
            "invoice": sample_invoice_json(),
        });
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("unknown type");
        let msg = err.to_string();
        assert!(
            msg.contains("carrier_pigeon")
                || msg.contains("unknown variant")
                || msg.contains("did not match"),
            "unknown type must fail serde, got {msg}"
        );
    }

    #[test]
    fn unknown_field_inside_invoice_is_malformed() {
        let mut v = mint_with_invoice_delivery();
        v["output_templates"][0]["delivery"]["invoice"]["ghost_field"] = serde_json::json!("nope");
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("deny");
        assert!(
            err.to_string().contains("ghost_field") || err.to_string().contains("unknown field"),
            "got {err}"
        );
    }

    #[test]
    fn unknown_field_inside_profile_event_is_accepted() {
        let mut v = mint_with_profile_delivery();
        v["output_templates"][0]["delivery"]["event"]["extra"] = serde_json::json!(1);
        serde_json::from_value::<TransitionRequestJson>(v)
            .expect("NIP-01 kind-0 extra fields must be accepted");
    }

    #[test]
    fn missing_invoice_required_field_is_malformed() {
        let mut v = mint_with_invoice_delivery();
        v["output_templates"][0]["delivery"]["invoice"]
            .as_object_mut()
            .unwrap()
            .remove("pk0");
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("missing pk0");
        assert!(
            err.to_string().contains("pk0") || err.to_string().contains("missing field"),
            "got {err}"
        );
    }

    #[test]
    fn missing_profile_required_field_is_malformed() {
        let mut v = mint_with_profile_delivery();
        v["output_templates"][0]["delivery"]["event"]
            .as_object_mut()
            .unwrap()
            .remove("content");
        let err = serde_json::from_value::<TransitionRequestJson>(v).expect_err("missing content");
        assert!(
            err.to_string().contains("content") || err.to_string().contains("missing field"),
            "got {err}"
        );
    }

    #[test]
    fn invoice_pk0_wrong_hex_width_is_malformed_without_echoing_value() {
        let mut v = mint_with_invoice_delivery();
        // Distinctive wrong-length hex — must not leak into the error message.
        let bad = "deadbeef".repeat(5); // 40 chars, not 64
        v["output_templates"][0]["delivery"]["invoice"]["pk0"] = serde_json::json!(bad.clone());
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("form");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("pk0"),
            "message must name the field path, got {}",
            err.body.message
        );
        assert!(
            !err.body.message.contains(&bad),
            "§7.5 retention: error must not echo pk0 hex, got {}",
            err.body.message
        );
        assert!(
            !err.body.message.contains(&distinctive_memo()),
            "error must not quote memo either, got {}",
            err.body.message
        );
    }

    /// Capture layer for the §7.5 retention rule: Debug of the parsed body
    /// (what a logger that prints the extractor would see) must not contain
    /// `pk0` hex or `memo` text. Same discipline as `BootstrapEntrustBody`.
    #[test]
    fn delivery_debug_and_error_paths_never_log_pk0_or_memo() {
        let parsed: TransitionRequestJson =
            serde_json::from_value(mint_with_invoice_delivery()).expect("parse");
        let dbg = format!("{parsed:?}");
        let pk0 = distinctive_pk0();
        let memo = distinctive_memo();
        assert!(
            !dbg.contains(&pk0),
            "Debug of TransitionRequestJson must redact pk0; got {dbg}"
        );
        assert!(
            !dbg.contains(&memo),
            "Debug of TransitionRequestJson must redact memo; got {dbg}"
        );
        // Arm name is allowed; credential contents are not.
        assert!(
            dbg.contains("redacted") || dbg.contains("Invoice"),
            "Debug should still indicate a redacted delivery arm, got {dbg}"
        );

        // Profile content carries pk0 inside zkcoins JSON — also redacted.
        let parsed_p: TransitionRequestJson =
            serde_json::from_value(mint_with_profile_delivery()).expect("parse profile");
        let dbg_p = format!("{parsed_p:?}");
        assert!(
            !dbg_p.contains(&pk0),
            "profile Debug must redact content-held pk0; got {dbg_p}"
        );

        // Invoice-level Debug alone.
        match &parsed.output_templates.as_ref().unwrap()[0].delivery {
            Some(DeliveryCredentialJson::Invoice { invoice }) => {
                let inv_dbg = format!("{invoice:?}");
                assert!(!inv_dbg.contains(&pk0));
                assert!(!inv_dbg.contains(&memo));
            }
            other => panic!("expected invoice arm, got {other:?}"),
        }
    }

    #[test]
    fn absent_delivery_stays_none_on_proto() {
        // Self-output MAY omit delivery; API does not invent one.
        let parsed: TransitionRequestJson = serde_json::from_value(mint_json()).expect("parse");
        let req = json_to_transition(parsed).expect("convert");
        assert!(req.output_templates[0].delivery.is_none());
    }

    #[test]
    fn mint_must_not_carry_genesis_pubkey() {
        let mut v = mint_json();
        v["genesis_pubkey"] = serde_json::json!(hex32(0xD0));
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("mint + genesis_pubkey");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("must not carry genesis_pubkey"),
            "message must name the forbidden field, got {}",
            err.body.message
        );
    }

    #[test]
    fn send_must_not_carry_genesis_pubkey() {
        let mut v = send_two_outputs_with_deliveries();
        v["genesis_pubkey"] = serde_json::json!(hex32(0xD0));
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("send + genesis_pubkey");
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("must not carry genesis_pubkey"),
            "message must name the forbidden field, got {}",
            err.body.message
        );
    }

    #[test]
    fn receive_with_genesis_pubkey_parses() {
        let v = serde_json::json!({
            "kind": "receive",
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "next_pubkey": hex32(0x11),
            "npk_rand": hex32(0x22),
            "fold_coin_ids": [hex32(0x33)],
            "genesis_pubkey": hex32(0xD0),
        });
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let req = json_to_transition(parsed).expect("receive with genesis_pubkey");
        assert_eq!(req.kind, "receive");
        assert_eq!(req.genesis_pubkey, vec![0xD0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // Helpers for uncovered validate_job / parser / projection paths
    // -----------------------------------------------------------------------

    fn sample_awaiting_signature() -> AwaitingSignature {
        AwaitingSignature {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            coin_history_root: vec![0x44; 32],
            nav_commitment: vec![0x55; 32],
            npk_commit: vec![0x66; 32],
            proof_data_hash: vec![0x77; 32],
            txn_pubkey: vec![0x88; 32],
            send_counter: 7,
        }
    }

    fn sample_transition_result() -> crate::kernel::kernel_v1::JobResult {
        crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        }
    }

    fn send_json() -> serde_json::Value {
        serde_json::json!({
            "kind": "send",
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "next_pubkey": hex32(0x11),
            "npk_rand": hex32(0x22),
            "input_coins": [hex32(0x01)],
            "output_templates": [{
                "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "asset_id": hex32(0x33),
                "amount": "100"
            }]
        })
    }

    fn receive_json() -> serde_json::Value {
        serde_json::json!({
            "kind": "receive",
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "next_pubkey": hex32(0x11),
            "npk_rand": hex32(0x22),
            "fold_coin_ids": [hex32(0x33)]
        })
    }

    // -----------------------------------------------------------------------
    // is_transition_job_kind
    // -----------------------------------------------------------------------

    #[test]
    fn is_transition_job_kind_closed_set() {
        assert!(is_transition_job_kind("mint"));
        assert!(is_transition_job_kind("send"));
        assert!(is_transition_job_kind("receive"));
        assert!(!is_transition_job_kind("attest_balance"));
        assert!(!is_transition_job_kind("foo"));
    }

    // -----------------------------------------------------------------------
    // validate_job — uncovered exclusivity / shape arms
    // -----------------------------------------------------------------------

    #[test]
    fn validate_job_rejects_unknown_kind() {
        let mut job = sample_job("accepted");
        job.kind = "not_a_closed_kind".into();
        let err = validate_job(&job).expect_err("unknown kind");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("not_a_closed_kind")
                || err.cause().unwrap_or("").contains("closed"),
            "cause must name the foreign kind, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_awaiting_signature_requires_payload() {
        let job = sample_job("awaiting_signature");
        let err = validate_job(&job).expect_err("missing awaiting_signature");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("awaiting_signature")
                || err.cause().unwrap_or("").contains("absent"),
            "cause must name absent awaiting_signature, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_awaiting_signature_rejects_result() {
        let mut job = sample_job("awaiting_signature");
        job.awaiting_signature = Some(sample_awaiting_signature());
        job.result = Some(sample_transition_result());
        let err = validate_job(&job).expect_err("result with awaiting_signature");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("result")
                || err.cause().unwrap_or("").contains("error"),
            "cause must name result/error exclusivity, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_awaiting_signature_rejects_error() {
        let mut job = sample_job("awaiting_signature");
        job.awaiting_signature = Some(sample_awaiting_signature());
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "x".into(),
        });
        let err = validate_job(&job).expect_err("error with awaiting_signature");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("result")
                || err.cause().unwrap_or("").contains("error"),
            "cause must name result/error exclusivity, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_attest_balance_must_not_await_signature() {
        let mut job = sample_job("awaiting_signature");
        job.kind = "attest_balance".into();
        job.awaiting_signature = Some(sample_awaiting_signature());
        let err = validate_job(&job).expect_err("attest_balance awaiting_signature");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("attest_balance")
                || err.cause().unwrap_or("").contains("awaiting_signature"),
            "cause must name kind / awaiting_signature, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_completed_rejects_awaiting_signature() {
        let mut job = sample_job("completed");
        job.result = Some(sample_transition_result());
        job.awaiting_signature = Some(sample_awaiting_signature());
        let err = validate_job(&job).expect_err("completed + awaiting_signature");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("awaiting_signature")
                || err.cause().unwrap_or("").contains("error"),
            "cause must name exclusivity, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_completed_rejects_error() {
        let mut job = sample_job("completed");
        job.result = Some(sample_transition_result());
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "x".into(),
        });
        let err = validate_job(&job).expect_err("completed + error");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("awaiting_signature")
                || err.cause().unwrap_or("").contains("error"),
            "cause must name exclusivity, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_failed_rejects_awaiting_signature() {
        let mut job = sample_job("failed");
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "x".into(),
        });
        job.awaiting_signature = Some(sample_awaiting_signature());
        let err = validate_job(&job).expect_err("failed + awaiting_signature");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("awaiting_signature")
                || err.cause().unwrap_or("").contains("result"),
            "cause must name exclusivity, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_cancelled_rejects_result() {
        let mut job = sample_job("cancelled");
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "x".into(),
        });
        job.result = Some(sample_transition_result());
        let err = validate_job(&job).expect_err("cancelled + result");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("awaiting_signature")
                || err.cause().unwrap_or("").contains("result"),
            "cause must name exclusivity, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_accepted_must_not_carry_result() {
        for status in ["accepted", "proving", "publishing"] {
            let mut job = sample_job(status);
            job.result = Some(sample_transition_result());
            let err = validate_job(&job).expect_err("non-terminal must not carry result");
            assert_eq!(err.body.error, "internal_error");
            let cause = err.cause().unwrap_or("");
            assert!(
                cause.contains("must not carry") || cause.contains(status),
                "cause must name exclusivity or status {status}, got {cause:?}"
            );

            let mut job = sample_job(status);
            job.awaiting_signature = Some(sample_awaiting_signature());
            let err =
                validate_job(&job).expect_err("non-terminal must not carry awaiting_signature");
            assert_eq!(err.body.error, "internal_error");
            let cause = err.cause().unwrap_or("");
            assert!(
                cause.contains("must not carry") || cause.contains(status),
                "cause must name exclusivity or status {status}, got {cause:?}"
            );

            let mut job = sample_job(status);
            job.error = Some(crate::kernel::kernel_v1::JobError {
                error: "proving_failed".into(),
                message: "x".into(),
            });
            let err = validate_job(&job).expect_err("non-terminal must not carry error");
            assert_eq!(err.body.error, "internal_error");
            let cause = err.cause().unwrap_or("");
            assert!(
                cause.contains("must not carry") || cause.contains(status),
                "cause must name exclusivity or status {status}, got {cause:?}"
            );
        }
    }

    #[test]
    fn validate_job_transition_rejects_short_new_account_state_hash() {
        let mut job = sample_job("completed");
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 16],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        let err = validate_job(&job).expect_err("short new_account_state_hash");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("new_account_state_hash"),
            "cause must name new_account_state_hash, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_transition_rejects_short_output_coins_root() {
        let mut job = sample_job("completed");
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 16],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        let err = validate_job(&job).expect_err("short output_coins_root");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("output_coins_root"),
            "cause must name output_coins_root, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_transition_rejects_short_input_nullifiers_root() {
        let mut job = sample_job("completed");
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 16],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        let err = validate_job(&job).expect_err("short input_nullifiers_root");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("input_nullifiers_root"),
            "cause must name input_nullifiers_root, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_result_for_kind_rejects_unknown_kind() {
        let result = sample_transition_result();
        let err = validate_job_result_for_kind("not_a_kind", &result).expect_err("unknown kind");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("not_a_kind"),
            "cause must name the kind string, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn validate_job_awaiting_signature_happy_path() {
        let mut job = sample_job("awaiting_signature");
        job.awaiting_signature = Some(sample_awaiting_signature());
        validate_job(&job).expect("valid mint awaiting_signature must pass");
    }

    // -----------------------------------------------------------------------
    // SSE event name
    // -----------------------------------------------------------------------

    #[test]
    fn validate_sse_event_status_rejects_unknown_event_name() {
        let err = validate_sse_event_status("not_an_sse_name", &sample_job("accepted"))
            .expect_err("unknown SSE name");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("not_an_sse_name"),
            "cause must name the event, got {:?}",
            err.cause()
        );
    }

    // -----------------------------------------------------------------------
    // Debug redaction on DeliveryCredentialJson / Kind0EventJson
    // -----------------------------------------------------------------------

    #[test]
    fn delivery_credential_invoice_debug_redacts_contents() {
        let invoice: InvoiceJson =
            serde_json::from_value(sample_invoice_json()).expect("invoice shape");
        let cred = DeliveryCredentialJson::Invoice { invoice };
        let dbg = format!("{cred:?}");
        assert!(
            dbg.contains("Invoice") && dbg.contains("redacted"),
            "Debug must name Invoice arm and redaction, got {dbg}"
        );
        assert!(
            !dbg.contains(&distinctive_pk0()),
            "Debug must not contain pk0, got {dbg}"
        );
        assert!(
            !dbg.contains(&distinctive_memo()),
            "Debug must not contain memo, got {dbg}"
        );
    }

    #[test]
    fn delivery_credential_profile_debug_redacts_contents() {
        let event: Kind0EventJson =
            serde_json::from_value(sample_profile_event_json()).expect("profile shape");
        let cred = DeliveryCredentialJson::Profile { event };
        let dbg = format!("{cred:?}");
        assert!(
            dbg.contains("Profile") && dbg.contains("redacted"),
            "Debug must name Profile arm and redaction, got {dbg}"
        );
        assert!(
            !dbg.contains(&distinctive_pk0()),
            "Debug must not contain pk0, got {dbg}"
        );
    }

    #[test]
    fn kind0_event_json_debug_redacts_sensitive_fields() {
        let event: Kind0EventJson =
            serde_json::from_value(sample_profile_event_json()).expect("profile shape");
        let dbg = format!("{event:?}");
        assert!(
            dbg.contains("created_at") && dbg.contains("1700000000"),
            "created_at must remain visible, got {dbg}"
        );
        assert!(
            dbg.contains("kind") && dbg.contains("0"),
            "kind must remain visible, got {dbg}"
        );
        assert!(
            !dbg.contains(&distinctive_pk0()),
            "Debug must not contain pk0 from content, got {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "id/pubkey/sig must be redacted, got {dbg}"
        );
        assert!(
            dbg.contains("redacted content") || dbg.contains("<redacted content"),
            "content must be redacted, got {dbg}"
        );
    }

    // -----------------------------------------------------------------------
    // json_to_transition — kind presence rules
    // -----------------------------------------------------------------------

    #[test]
    fn json_to_transition_rejects_unknown_kind() {
        let mut v = receive_json();
        v["kind"] = serde_json::json!("swap");
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("unknown kind");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("mint|send|receive"),
            "message must list allowed kinds, got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_forwards_publisher_pubkey() {
        let mut v = receive_json();
        v["publisher_pubkey"] = serde_json::json!(hex32(0xAB));
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let req = json_to_transition(parsed).expect("receive with publisher_pubkey");
        assert_eq!(req.publisher_pubkey, vec![0xAB; 32]);
    }

    #[test]
    fn json_to_transition_send_requires_input_coins() {
        let mut v = send_json();
        v["input_coins"] = serde_json::json!([]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("empty input_coins");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=send requires non-empty input_coins"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_send_requires_output_templates() {
        let mut v = send_json();
        v["output_templates"] = serde_json::json!([]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("empty output_templates");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=send requires non-empty output_templates"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_send_must_not_carry_fold_coin_ids() {
        let mut v = send_json();
        v["fold_coin_ids"] = serde_json::json!([hex32(0x99)]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("send + fold_coin_ids");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=send must not carry fold_coin_ids"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_send_must_not_carry_issuance() {
        let mut v = send_json();
        v["issuance"] = serde_json::json!({
            "name": "TestCoin",
            "decimals": 8,
            "issuance_version": 1,
            "amount": "1000",
            "creator_pubkey": hex32(0x44)
        });
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("send + issuance");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=send must not carry issuance"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_mint_must_not_carry_input_coins() {
        let mut v = mint_json();
        v["input_coins"] = serde_json::json!([hex32(0x01)]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("mint + input_coins");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=mint must not carry input_coins"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_mint_must_not_carry_fold_coin_ids() {
        let mut v = mint_json();
        v["fold_coin_ids"] = serde_json::json!([hex32(0x99)]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("mint + fold_coin_ids");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=mint must not carry fold_coin_ids"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_mint_requires_output_templates() {
        let mut v = mint_json();
        v["output_templates"] = serde_json::json!([]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("mint empty outputs");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=mint requires non-empty output_templates"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_mint_requires_issuance() {
        let mut v = mint_json();
        v.as_object_mut().unwrap().remove("issuance");
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("mint without issuance");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("kind=mint requires issuance"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_receive_must_not_carry_input_coins() {
        let mut v = receive_json();
        v["input_coins"] = serde_json::json!([hex32(0x01)]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("receive + input_coins");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=receive must not carry input_coins"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_receive_must_not_carry_output_templates() {
        let mut v = receive_json();
        v["output_templates"] = serde_json::json!([{
            "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "asset_id": hex32(0x33),
            "amount": "100"
        }]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("receive + output_templates");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=receive must not carry output_templates"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_receive_requires_fold_coin_ids() {
        let mut v = receive_json();
        v["fold_coin_ids"] = serde_json::json!([]);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("empty fold_coin_ids");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=receive requires non-empty fold_coin_ids"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_transition_receive_must_not_carry_issuance() {
        let mut v = receive_json();
        v["issuance"] = serde_json::json!({
            "name": "TestCoin",
            "decimals": 8,
            "issuance_version": 1,
            "amount": "1000",
            "creator_pubkey": hex32(0x44)
        });
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("receive + issuance");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("kind=receive must not carry issuance"),
            "got {}",
            err.body.message
        );
    }

    // -----------------------------------------------------------------------
    // json_to_issuance (via mint body)
    // -----------------------------------------------------------------------

    #[test]
    fn json_to_issuance_rejects_unknown_version() {
        let mut v = mint_json();
        v["issuance"]["issuance_version"] = serde_json::json!(3);
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("issuance_version 3");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("issuance_version must be 1 or 2"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_issuance_v2_requires_cap_total() {
        let mut v = mint_json();
        v["issuance"]["issuance_version"] = serde_json::json!(2);
        v["issuance"]["terms_salt"] = serde_json::json!(hex32(0x55));
        // cap_total intentionally absent
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("v2 without cap_total");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("issuance_version=2 requires cap_total"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_issuance_v2_requires_terms_salt() {
        let mut v = mint_json();
        v["issuance"]["issuance_version"] = serde_json::json!(2);
        v["issuance"]["cap_total"] = serde_json::json!("5000");
        // terms_salt intentionally absent
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("v2 without terms_salt");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("issuance_version=2 requires terms_salt"),
            "got {}",
            err.body.message
        );
    }

    #[test]
    fn json_to_issuance_v2_happy_path() {
        let mut v = mint_json();
        v["issuance"]["issuance_version"] = serde_json::json!(2);
        v["issuance"]["cap_total"] = serde_json::json!("5000");
        v["issuance"]["terms_salt"] = serde_json::json!(hex32(0x55));
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let req = json_to_transition(parsed).expect("issuance v2");
        let iss = req.issuance.as_ref().expect("issuance present");
        assert_eq!(iss.issuance_version, 2);
        assert_eq!(iss.cap_total, "5000");
        assert_eq!(iss.terms_salt, vec![0x55; 32]);
    }

    #[test]
    fn json_to_issuance_v1_must_not_carry_cap_or_salt() {
        let mut v = mint_json();
        v["issuance"]["cap_total"] = serde_json::json!("5000");
        let parsed: TransitionRequestJson = serde_json::from_value(v).expect("shape ok");
        let err = json_to_transition(parsed).expect_err("v1 + cap_total");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body
                .message
                .contains("issuance_version=1 must not carry cap_total or terms_salt"),
            "got {}",
            err.body.message
        );
    }

    // -----------------------------------------------------------------------
    // Idempotency key length
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_key_exceeds_64_bytes_is_malformed() {
        let key = "a".repeat(65);
        let err = parse_idempotency_key_value(&key).expect_err("65 bytes");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("64"),
            "message must mention 64-byte limit, got {}",
            err.body.message
        );
    }

    // -----------------------------------------------------------------------
    // job_to_json / awaiting_signature_json / job_result_json / require_hex32
    // -----------------------------------------------------------------------

    #[test]
    fn job_to_json_includes_phase_for_non_terminal() {
        let mut job = sample_job("proving");
        job.phase = "witness".into();
        let json = job_to_json(&job).expect("project");
        assert_eq!(json["phase"], "witness");
    }

    #[test]
    fn job_to_json_projects_awaiting_signature_fields() {
        let mut job = sample_job("awaiting_signature");
        job.awaiting_signature = Some(sample_awaiting_signature());
        let json = job_to_json(&job).expect("project");
        let a = &json["awaiting_signature"];
        assert!(a.is_object(), "awaiting_signature must be an object");
        assert_eq!(a["new_account_state_hash"], hex32(0x11));
        assert_eq!(a["output_coins_root"], hex32(0x22));
        assert_eq!(a["input_nullifiers_root"], hex32(0x33));
        assert_eq!(a["coin_history_root"], hex32(0x44));
        assert_eq!(a["nav_commitment"], hex32(0x55));
        assert_eq!(a["npk_commit"], hex32(0x66));
        assert_eq!(a["proof_data_hash"], hex32(0x77));
        assert_eq!(a["txn_pubkey"], hex32(0x88));
        assert_eq!(a["send_counter"], 7);
    }

    #[test]
    fn job_to_json_projects_completed_transition_result() {
        let mut job = sample_job("completed");
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![vec![0xAA; 32]],
            publisher_pubkey: vec![0xBB; 32],
            attestation: vec![],
        });
        let json = job_to_json(&job).expect("project");
        let r = &json["result"];
        assert_eq!(r["new_account_state_hash"], hex32(0x11));
        assert_eq!(r["output_coins_root"], hex32(0x22));
        assert_eq!(r["input_nullifiers_root"], hex32(0x33));
        assert_eq!(r["output_coin_ids"][0], hex32(0xAA));
        assert_eq!(r["publisher_pubkey"], hex32(0xBB));
    }

    #[test]
    fn job_to_json_attest_balance_includes_attestation_hex() {
        let mut job = sample_job("completed");
        job.kind = "attest_balance".into();
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![0xaa, 0xbb, 0xcc],
        });
        let json = job_to_json(&job).expect("attest projection");
        assert_eq!(json["result"]["attestation"], "aabbcc");
    }

    #[test]
    fn require_hex32_rejects_wrong_length() {
        let err = require_hex32(&[0u8; 16], "nav_commitment").expect_err("16 bytes");
        assert_eq!(err.body.error, "internal_error");
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("nav_commitment") && cause.contains("16"),
            "cause must name field and length, got {cause:?}"
        );
    }

    #[test]
    fn awaiting_signature_json_rejects_short_digest() {
        let mut a = sample_awaiting_signature();
        a.nav_commitment = vec![0x55; 16];
        let err = awaiting_signature_json(&a).expect_err("short nav_commitment");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("nav_commitment"),
            "cause must name nav_commitment, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn job_result_json_rejects_short_publisher_pubkey() {
        let r = crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![0xBB; 16],
            attestation: vec![],
        };
        let err = job_result_json(&r).expect_err("short publisher_pubkey");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause()
                .unwrap_or("")
                .contains("result.publisher_pubkey"),
            "cause must name result.publisher_pubkey, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn job_result_json_rejects_short_new_account_state_hash() {
        let r = crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 16],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        };
        let err = job_result_json(&r).expect_err("short new_account_state_hash");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause()
                .unwrap_or("")
                .contains("result.new_account_state_hash"),
            "cause must name result.new_account_state_hash, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn job_result_json_rejects_short_output_coins_root() {
        let r = crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![0x22; 16],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        };
        let err = job_result_json(&r).expect_err("short output_coins_root");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause()
                .unwrap_or("")
                .contains("result.output_coins_root"),
            "cause must name result.output_coins_root, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn job_result_json_rejects_short_input_nullifiers_root() {
        let r = crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![],
            input_nullifiers_root: vec![0x33; 16],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        };
        let err = job_result_json(&r).expect_err("short input_nullifiers_root");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause()
                .unwrap_or("")
                .contains("result.input_nullifiers_root"),
            "cause must name result.input_nullifiers_root, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn job_result_json_rejects_short_output_coin_ids() {
        let r = crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![],
            output_coins_root: vec![],
            input_nullifiers_root: vec![],
            output_coin_ids: vec![vec![0x44; 16]],
            publisher_pubkey: vec![],
            attestation: vec![],
        };
        let err = job_result_json(&r).expect_err("short output_coin_ids");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause()
                .unwrap_or("")
                .contains("result.output_coin_ids[0]"),
            "cause must name result.output_coin_ids[0], got {:?}",
            err.cause()
        );
    }

    // -----------------------------------------------------------------------
    // job_event_to_sse / phase_event_data
    // -----------------------------------------------------------------------

    #[test]
    fn job_event_to_sse_requires_job_payload() {
        let ev = JobEvent {
            event: "phase".into(),
            job: None,
        };
        let err = job_event_to_sse(&ev).expect_err("missing job");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("missing")
                || err.cause().unwrap_or("").contains("job"),
            "cause must name missing job payload, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn phase_event_data_embeds_awaiting_signature() {
        let mut job = sample_job("awaiting_signature");
        job.phase = "sign".into();
        job.awaiting_signature = Some(sample_awaiting_signature());
        let data = phase_event_data(&job).expect("phase data");
        assert_eq!(data["status"], "awaiting_signature");
        assert!(
            data.get("awaiting_signature").is_some(),
            "phase data must embed awaiting_signature"
        );
        assert_eq!(data["awaiting_signature"]["send_counter"], 7);
    }

    // -----------------------------------------------------------------------
    // Handler empty job_id guards
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_job_empty_job_id_is_malformed_request() {
        let kernel: crate::KernelHandle =
            std::sync::Arc::new(crate::connect_lazy("http://127.0.0.1:1").expect("lazy"));
        let err = get_job(State(kernel), Path(String::new()))
            .await
            .expect_err("empty job_id");
        assert_eq!(err.body.error, "malformed_request");
    }

    #[tokio::test]
    async fn stream_job_empty_job_id_is_malformed_request() {
        let kernel: crate::KernelHandle =
            std::sync::Arc::new(crate::connect_lazy("http://127.0.0.1:1").expect("lazy"));
        let result = stream_job(State(kernel), Path(String::new())).await;
        assert!(result.is_err(), "empty job_id must be Err");
        if let Err(err) = result {
            assert_eq!(err.body.error, "malformed_request");
        }
    }

    #[tokio::test]
    async fn post_sign_empty_job_id_is_malformed_request() {
        let kernel: crate::KernelHandle =
            std::sync::Arc::new(crate::connect_lazy("http://127.0.0.1:1").expect("lazy"));
        let body = SignBodyJson {
            signature: hex64(0x00),
            s2c_nonce: hex32(0x00),
        };
        let err = post_sign(State(kernel), Path(String::new()), JsonBody(body))
            .await
            .expect_err("empty job_id");
        assert_eq!(err.body.error, "malformed_request");
    }

    #[tokio::test]
    async fn post_cancel_empty_job_id_is_malformed_request() {
        let kernel: crate::KernelHandle =
            std::sync::Arc::new(crate::connect_lazy("http://127.0.0.1:1").expect("lazy"));
        let err = post_cancel(State(kernel), Path(String::new()))
            .await
            .expect_err("empty job_id");
        assert_eq!(err.body.error, "malformed_request");
    }
}

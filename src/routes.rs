//! HTTP routes that this process actually serves.
//!
//! Route registration and the `GET /` discovery document share one source:
//! [`ServedSurface`]. The closed §7.5 inventory ([`CLOSED_ENDPOINT_KEYS`]) is
//! the full key catalogue. **Active** surfaces (from `Config::features` and
//! Blossom store configuration) get real handlers and appear on `GET /`.
//! **Known but inactive** feature-gated surfaces still register a stub that
//! answers `404 feature_disabled` with the §7.5 JSON body — they are omitted
//! from discovery (§7.5 / §6.1 fail-closed gating). **Unconfigured** Blossom
//! (no store) is left unregistered (bare axum 404), not a feature stub. Paths
//! outside the inventory remain a bare axum 404.
//!
//! Inventory paths are the **advertised** §7.5 form (`<name>` placeholders).
//! Axum registration uses a derived **matcher** form (`:name`); see
//! [`advertised_path_to_axum_matcher`].

use crate::attest;
use crate::blossom;
use crate::bootstrap;
use crate::chain;
use crate::config::{Config, Feature};
use crate::error::ApiError;
use crate::grants;
use crate::info;
use crate::jobs;
use crate::kernel::KernelHandle;
use crate::publish;
use crate::pull;
use crate::state::AppState;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post, put};
use axum::{Json, Router};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// Boot-time failure opening configured resources (e.g. Blossom store root).
///
/// Distinct from per-request [`ApiError`]: `main` prints this and exits
/// without panicking, same as other start errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupError {
    pub message: String,
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StartupError {}

/// Closed `endpoints` key set from specification §7.5 (`GET /` row).
///
/// Full inventory of the 28 logical names a conforming producer may emit
/// (data permanence: no `blossom_delete`). Order matches the closed §7.5
/// listing. This constant is the reference for surfaces not yet built; it is
/// **not** what `GET /` returns.
///
/// Path parameters use the §7.5 advertised form `<name>` (one path segment).
/// That string is what `GET /` emits. Axum 0.7 / matchit 0.7 do **not** treat
/// `<name>` (or `{name}`) as a parameter — only `:name` is dynamic — so
/// registration rewrites via [`advertised_path_to_axum_matcher`]. Discovery
/// never uses the matcher form; clients see Spec-Schreibweise only.
///
/// A conforming producer emits exactly the closed keys **for the surfaces this
/// deployment exposes** and MUST omit keys for unadvertised optional roles.
/// Advertisement is derived from [`ServedSurface`], intersected with this
/// inventory via [`closed_path`].
pub const CLOSED_ENDPOINT_KEYS: &[(&str, &str)] = &[
    ("health", "/health"),
    ("health_ready", "/health/ready"),
    ("info", "/v1/info"),
    ("chain_accumulator", "/v1/chain/accumulator"),
    ("chain_inscriptions", "/v1/chain/inscriptions"),
    ("chain_nullifier", "/v1/chain/nullifier/<pubkey>"),
    ("tx", "/v1/tx"),
    ("jobs", "/v1/jobs/<job_id>"),
    ("jobs_stream", "/v1/jobs/<job_id>/stream"),
    ("jobs_sign", "/v1/jobs/<job_id>/sign"),
    ("jobs_cancel", "/v1/jobs/<job_id>/cancel"),
    ("attest_balance_challenge", "/v1/attest/balance/challenge"),
    ("attest_balance", "/v1/attest/balance"),
    ("grants_challenge", "/v1/grants/challenge"),
    ("grants", "/v1/grants"),
    ("pull_challenge", "/v1/pull/challenge"),
    ("pull", "/v1/pull"),
    ("record", "/v1/record/<record_id>"),
    ("proof", "/v1/proof/<coin_id>"),
    ("account_state", "/v1/account/state"),
    ("receipts_stream", "/v1/receipts/stream"),
    ("publish_spendrecord", "/v1/publish/spendrecord"),
    ("bootstrap_challenge", "/v1/bootstrap/challenge"),
    ("bootstrap_entrust", "/v1/bootstrap/entrust"),
    ("bootstrap_revoke", "/v1/bootstrap/revoke"),
    ("blossom_get", "/blossom/<sha256>"),
    ("blossom_head", "/blossom/<sha256>"),
    ("blossom_upload", "/blossom/upload"),
];

/// Surfaces this process actually registers (and therefore advertises on `GET /`).
///
/// **Single source of truth** for both the axum router and the discovery
/// document. Adding a surface requires a new enum variant; the compiler then
/// forces every `match` (discovery key, handler registration) to be updated.
/// A key with no handler therefore fails at compile time. A route that is not
/// wired through this enum cannot appear in discovery — registration and
/// advertisement stay in lockstep.
///
/// `GET /` itself is the discovery document and has **no** closed key in
/// §7.5; it is registered beside this set, never as a member of it.
///
/// ## Feature gating (§6.1 / §7.5)
///
/// Which surfaces are active follows `Config::features` and Blossom store
/// configuration — never a hard-coded always-on set of role-bound routes.
/// A request against a disabled feature is answered `404 feature_disabled`
/// (JSON machine code); `GET /` omits the corresponding keys. Mapping (from
/// §6.1 feature table + the §7.5 inventory, mirrored in `docs/rest-surface.md`):
///
/// | Surfaces | Gate |
/// |---|---|
/// | `health`, `health_ready`, `info` | always (API process) |
/// | `chain_*` | `explorer` |
/// | `tx`, `jobs*`, `attest_*`, `grants_*`, `pull*`, `record`, `proof`, `account_state`, `receipts_stream`, `bootstrap_*` | `wallet` |
/// | `publish_spendrecord` | `publisher` |
/// | `blossom_get` / `blossom_head` / `blossom_upload` | `ZKCOINS_BLOSSOM_STORE` **and** (`wallet` **or** `explorer`) |
///
/// `lightning_bridge` / `mail_bridge` open no §7.5 inventory paths (extension
/// docs only) and therefore add no variants here.
///
/// Inventory keys remain in [`CLOSED_ENDPOINT_KEYS`]; advertisement is exactly
/// the active set derived by [`ServedSurface::active`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServedSurface {
    Health,
    HealthReady,
    Info,
    ChainAccumulator,
    ChainInscriptions,
    ChainNullifier,
    Tx,
    Jobs,
    JobsStream,
    JobsSign,
    JobsCancel,
    AttestBalanceChallenge,
    AttestBalance,
    GrantsChallenge,
    Grants,
    PullChallenge,
    Pull,
    Record,
    Proof,
    AccountState,
    ReceiptsStream,
    PublishSpendrecord,
    BootstrapChallenge,
    BootstrapEntrust,
    BootstrapRevoke,
    BlossomGet,
    BlossomHead,
    BlossomUpload,
}

impl ServedSurface {
    /// Full inventory of surfaces this binary knows how to register.
    ///
    /// Activation is decided per entry by [`ServedSurface::is_active`]; this
    /// list is **not** what `GET /` returns.
    const ALL: &[ServedSurface] = &[
        ServedSurface::Health,
        ServedSurface::HealthReady,
        ServedSurface::Info,
        ServedSurface::ChainAccumulator,
        ServedSurface::ChainInscriptions,
        ServedSurface::ChainNullifier,
        ServedSurface::Tx,
        ServedSurface::Jobs,
        ServedSurface::JobsStream,
        ServedSurface::JobsSign,
        ServedSurface::JobsCancel,
        ServedSurface::AttestBalanceChallenge,
        ServedSurface::AttestBalance,
        ServedSurface::GrantsChallenge,
        ServedSurface::Grants,
        ServedSurface::PullChallenge,
        ServedSurface::Pull,
        ServedSurface::Record,
        ServedSurface::Proof,
        ServedSurface::AccountState,
        ServedSurface::ReceiptsStream,
        ServedSurface::PublishSpendrecord,
        ServedSurface::BootstrapChallenge,
        ServedSurface::BootstrapEntrust,
        ServedSurface::BootstrapRevoke,
        ServedSurface::BlossomGet,
        ServedSurface::BlossomHead,
        ServedSurface::BlossomUpload,
    ];

    /// Whether this surface is a Blossom inventory key.
    fn is_blossom(self) -> bool {
        matches!(
            self,
            ServedSurface::BlossomGet | ServedSurface::BlossomHead | ServedSurface::BlossomUpload
        )
    }

    /// Whether this surface is **active** (real handler + discovery key) for
    /// the given feature set and Blossom store configuration. Inactive
    /// feature-gated inventory surfaces still mount a `feature_disabled`
    /// stub; unconfigured Blossom is left unregistered (see
    /// [`build_router`]).
    fn is_active(self, features: &BTreeSet<Feature>, blossom_configured: bool) -> bool {
        match self {
            // Always-on API process surface (§7.5 L2874–L2877; rest-surface #1–#4).
            ServedSurface::Health | ServedSurface::HealthReady | ServedSurface::Info => true,

            // `explorer` — public chain projection (§6.1 L2338; rest-surface #5–#7).
            ServedSurface::ChainAccumulator
            | ServedSurface::ChainInscriptions
            | ServedSurface::ChainNullifier => features.contains(&Feature::Explorer),

            // `wallet` — proving, submission, pull, attest, grants, bootstrap
            // (§6.1 L2337; rest-surface #8–#22, #24–#26).
            ServedSurface::Tx
            | ServedSurface::Jobs
            | ServedSurface::JobsStream
            | ServedSurface::JobsSign
            | ServedSurface::JobsCancel
            | ServedSurface::AttestBalanceChallenge
            | ServedSurface::AttestBalance
            | ServedSurface::GrantsChallenge
            | ServedSurface::Grants
            | ServedSurface::PullChallenge
            | ServedSurface::Pull
            | ServedSurface::Record
            | ServedSurface::Proof
            | ServedSurface::AccountState
            | ServedSurface::ReceiptsStream
            | ServedSurface::BootstrapChallenge
            | ServedSurface::BootstrapEntrust
            | ServedSurface::BootstrapRevoke => features.contains(&Feature::Wallet),

            // `publisher` — hand-off endpoint (§6.1 L2339; rest-surface #23).
            ServedSurface::PublishSpendrecord => features.contains(&Feature::Publisher),

            // §7.4 Blossom: store must be configured, and at least one of
            // `wallet` / `explorer` must be on (blob fetch under explorer,
            // upload under both). No DELETE — data permanence.
            ServedSurface::BlossomGet
            | ServedSurface::BlossomHead
            | ServedSurface::BlossomUpload => {
                blossom_configured
                    && (features.contains(&Feature::Wallet)
                        || features.contains(&Feature::Explorer))
            }
        }
    }

    /// Surfaces active for this process given enabled features and Blossom.
    fn active(features: &BTreeSet<Feature>, blossom_configured: bool) -> Vec<ServedSurface> {
        Self::ALL
            .iter()
            .copied()
            .filter(|s| s.is_active(features, blossom_configured))
            .collect()
    }

    /// Closed §7.5 discovery key for this surface.
    fn discovery_key(self) -> &'static str {
        match self {
            ServedSurface::Health => "health",
            ServedSurface::HealthReady => "health_ready",
            ServedSurface::Info => "info",
            ServedSurface::ChainAccumulator => "chain_accumulator",
            ServedSurface::ChainInscriptions => "chain_inscriptions",
            ServedSurface::ChainNullifier => "chain_nullifier",
            ServedSurface::Tx => "tx",
            ServedSurface::Jobs => "jobs",
            ServedSurface::JobsStream => "jobs_stream",
            ServedSurface::JobsSign => "jobs_sign",
            ServedSurface::JobsCancel => "jobs_cancel",
            ServedSurface::AttestBalanceChallenge => "attest_balance_challenge",
            ServedSurface::AttestBalance => "attest_balance",
            ServedSurface::GrantsChallenge => "grants_challenge",
            ServedSurface::Grants => "grants",
            ServedSurface::PullChallenge => "pull_challenge",
            ServedSurface::Pull => "pull",
            ServedSurface::Record => "record",
            ServedSurface::Proof => "proof",
            ServedSurface::AccountState => "account_state",
            ServedSurface::ReceiptsStream => "receipts_stream",
            ServedSurface::PublishSpendrecord => "publish_spendrecord",
            ServedSurface::BootstrapChallenge => "bootstrap_challenge",
            ServedSurface::BootstrapEntrust => "bootstrap_entrust",
            ServedSurface::BootstrapRevoke => "bootstrap_revoke",
            ServedSurface::BlossomGet => "blossom_get",
            ServedSurface::BlossomHead => "blossom_head",
            ServedSurface::BlossomUpload => "blossom_upload",
        }
    }

    /// Attach this surface's handler to the router at the axum matcher path.
    ///
    /// Discovery still advertises the inventory (Spec) form; only the route
    /// table sees the rewritten matcher.
    fn register(self, router: Router<AppState>, max_blob_bytes: Option<u64>) -> Router<AppState> {
        let path = advertised_path_to_axum_matcher(closed_path(self.discovery_key()));
        match self {
            ServedSurface::Health => router.route(&path, get(health)),
            ServedSurface::HealthReady => router.route(&path, get(info::health_ready)),
            ServedSurface::Info => router.route(&path, get(info::get_info)),
            ServedSurface::ChainAccumulator => router.route(&path, get(chain::get_accumulator)),
            ServedSurface::ChainInscriptions => router.route(&path, get(chain::list_inscriptions)),
            ServedSurface::ChainNullifier => router.route(&path, get(chain::get_nullifier)),
            ServedSurface::Tx => router.route(&path, post(jobs::post_tx)),
            ServedSurface::Jobs => router.route(&path, get(jobs::get_job)),
            ServedSurface::JobsStream => router.route(&path, get(jobs::stream_job)),
            ServedSurface::JobsSign => router.route(&path, post(jobs::post_sign)),
            ServedSurface::JobsCancel => router.route(&path, post(jobs::post_cancel)),
            ServedSurface::AttestBalanceChallenge => {
                router.route(&path, post(attest::post_attest_balance_challenge))
            }
            ServedSurface::AttestBalance => router.route(&path, post(attest::post_attest_balance)),
            ServedSurface::GrantsChallenge => {
                router.route(&path, post(grants::post_grants_challenge))
            }
            ServedSurface::Grants => router.route(&path, post(grants::post_grants)),
            ServedSurface::PullChallenge => router.route(&path, post(pull::post_pull_challenge)),
            ServedSurface::Pull => router.route(&path, post(pull::post_pull)),
            ServedSurface::Record => router.route(&path, get(pull::get_record)),
            ServedSurface::Proof => router.route(&path, get(pull::get_proof)),
            ServedSurface::AccountState => router.route(&path, get(pull::get_account_state)),
            ServedSurface::ReceiptsStream => router.route(&path, get(pull::stream_receipts)),
            ServedSurface::PublishSpendrecord => {
                router.route(&path, post(publish::post_publish_spendrecord))
            }
            ServedSurface::BootstrapChallenge => {
                router.route(&path, post(bootstrap::post_bootstrap_challenge))
            }
            ServedSurface::BootstrapEntrust => {
                router.route(&path, post(bootstrap::post_bootstrap_entrust))
            }
            ServedSurface::BootstrapRevoke => {
                router.route(&path, post(bootstrap::post_bootstrap_revoke))
            }
            // GET / HEAD share `/blossom/:sha256`; axum merges methods.
            // No DELETE — data permanence (append-only store).
            ServedSurface::BlossomGet => router.route(&path, get(blossom::get_blob)),
            ServedSurface::BlossomHead => router.route(&path, head(blossom::head_blob)),
            ServedSurface::BlossomUpload => {
                // Cap buffering at the advertised max. Bodies above that are
                // rejected by LimitedBytes / DefaultBodyLimit as §7.5
                // `payload_too_large` (including sizes far above max, not only
                // max+1). The handler still double-checks length.
                let limit = max_blob_bytes.unwrap_or(0);
                let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                // Use at least 1 so DefaultBodyLimit::max(0) is never installed
                // for a misconfigured path (upload is only active with max>0).
                let limit = limit.max(1);
                router.route(
                    &path,
                    put(blossom::upload_blob)
                        .post(blossom::upload_blob)
                        .layer(DefaultBodyLimit::max(limit)),
                )
            }
        }
    }

    /// Register a known-but-inactive surface as `404 feature_disabled`.
    ///
    /// Same methods and path matchers as [`Self::register`], so a disabled
    /// feature is still *recognised* (not a bare axum 404) while staying
    /// absent from `GET /` discovery.
    fn register_disabled(self, router: Router<AppState>) -> Router<AppState> {
        let path = advertised_path_to_axum_matcher(closed_path(self.discovery_key()));
        match self {
            ServedSurface::Health | ServedSurface::HealthReady | ServedSurface::Info => {
                // Always-on surfaces are never disabled.
                router
            }
            ServedSurface::ChainAccumulator
            | ServedSurface::ChainInscriptions
            | ServedSurface::ChainNullifier
            | ServedSurface::Jobs
            | ServedSurface::JobsStream
            | ServedSurface::Record
            | ServedSurface::Proof
            | ServedSurface::AccountState
            | ServedSurface::ReceiptsStream
            | ServedSurface::BlossomGet => router.route(&path, get(feature_disabled_handler)),
            ServedSurface::BlossomHead => router.route(&path, head(feature_disabled_handler)),
            ServedSurface::Tx
            | ServedSurface::JobsSign
            | ServedSurface::JobsCancel
            | ServedSurface::AttestBalanceChallenge
            | ServedSurface::AttestBalance
            | ServedSurface::GrantsChallenge
            | ServedSurface::Grants
            | ServedSurface::PullChallenge
            | ServedSurface::Pull
            | ServedSurface::PublishSpendrecord
            | ServedSurface::BootstrapChallenge
            | ServedSurface::BootstrapEntrust
            | ServedSurface::BootstrapRevoke => router.route(&path, post(feature_disabled_handler)),
            ServedSurface::BlossomUpload => router.route(
                &path,
                put(feature_disabled_handler).post(feature_disabled_handler),
            ),
        }
    }
}

/// §7.5 / §6.1: known inventory path whose role feature is off for this
/// deployment. Not used for unconfigured Blossom (those paths stay unregistered).
async fn feature_disabled_handler() -> ApiError {
    ApiError::feature_disabled("this endpoint is not enabled on this deployment (feature_disabled)")
}

/// Look up the canonical **advertised** path for a closed §7.5 key.
///
/// Returns Spec-Schreibweise (`<name>` placeholders). Never the axum matcher
/// form — that is derived only at registration time.
///
/// Panics if `key` is absent from [`CLOSED_ENDPOINT_KEYS`]: a served key
/// without an inventory entry is a programming error, not an empty path.
fn closed_path(key: &str) -> &'static str {
    for &(k, path) in CLOSED_ENDPOINT_KEYS {
        if k == key {
            return path;
        }
    }
    panic!(
        "discovery key {key:?} is not in CLOSED_ENDPOINT_KEYS; \
         served surfaces must be a subset of the §7.5 inventory"
    );
}

/// Rewrite a §7.5 advertised path into an axum 0.7 / matchit 0.7 route pattern.
///
/// Spec writes path parameters as `<name>`. Axum 0.7 (via matchit 0.7) treats
/// only `:name` as a dynamic segment — `{name}` and `<name>` are literal bytes
/// in the radix tree. One projection from the inventory string; no second path
/// list.
///
/// Panics on an unclosed `<` or an empty parameter name: inventory corruption
/// is a programming error, not a runtime soft-fail.
fn advertised_path_to_axum_matcher(advertised: &str) -> String {
    let mut out = String::with_capacity(advertised.len());
    let mut rest = advertised;
    while let Some(open) = rest.find('<') {
        let (before, after_open) = rest.split_at(open);
        out.push_str(before);
        let after_open = &after_open[1..];
        let close = match after_open.find('>') {
            Some(i) => i,
            None => panic!("advertised path has unclosed '<' placeholder: {advertised:?}"),
        };
        let name = &after_open[..close];
        if name.is_empty() {
            panic!("advertised path has empty '<>' placeholder: {advertised:?}");
        }
        if name.contains('/') || name.contains('<') {
            panic!(
                "advertised path placeholder must be a single segment name, got {name:?} in {advertised:?}"
            );
        }
        // axum 0.7 / matchit 0.7 named parameter: colon + name (e.g. ":job_id").
        out.push(':');
        out.push_str(name);
        rest = &after_open[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Build the `endpoints` map for `GET /` from the active surface set.
fn discovery_endpoints(
    features: &BTreeSet<Feature>,
    blossom_configured: bool,
) -> BTreeMap<&'static str, &'static str> {
    let mut endpoints = BTreeMap::new();
    for surface in ServedSurface::active(features, blossom_configured) {
        let key = surface.discovery_key();
        let path = closed_path(key);
        endpoints.insert(key, path);
    }
    endpoints
}

#[derive(Debug, Serialize)]
struct RootResponse {
    name: &'static str,
    version: &'static str,
    endpoints: BTreeMap<&'static str, &'static str>,
}

/// Build the axum router for the given configuration and kernel handle.
///
/// Route registration follows the full inventory: active surfaces get real
/// handlers; known-but-inactive surfaces get `404 feature_disabled` stubs.
/// `GET /` discovery lists only the active set. `config.features` is also
/// stored in [`AppState`] for the API-owned `features` array on `GET /v1/info`.
///
/// Returns a fully state-bound router (`Router` / `Router<()>`). Only that
/// form implements `tower::Service` and is ready for `axum::serve` and test
/// `oneshot` calls. Handlers extract `State<AppState>` or
/// `State<KernelHandle>` (via [`axum::extract::FromRef`]); the concrete
/// state is supplied once at the end.
///
/// # Errors
///
/// Returns [`StartupError`] if Blossom is configured but the store root
/// cannot be opened — boot-time misconfiguration, same fail-closed class as
/// other start errors in `main` (no panic).
pub fn build_router(config: Config, kernel: KernelHandle) -> Result<Router, StartupError> {
    let Config {
        bind_addr: _,
        kernel_addr: _,
        features,
        public_hosts,
        blossom,
    } = config;

    let max_blob_bytes = blossom.as_ref().map(|b| b.max_blob_bytes);
    let blossom_state = match blossom {
        None => None,
        Some(cfg) => {
            let state = blossom::BlossomState::from_config(&cfg).map_err(|e| {
                let detail = match e.cause() {
                    Some(c) => c.to_string(),
                    None => e.body.message.clone(),
                };
                StartupError {
                    message: format!("blossom store open failed: {detail}"),
                }
            })?;
            Some(state)
        }
    };
    let blossom_configured = blossom_state.is_some();

    let state = AppState {
        kernel,
        features: features.clone(),
        public_hosts: Arc::new(public_hosts),
        blossom: blossom_state,
        subject_ops: Arc::new(crate::ownership::SubjectOpDirectory::new()),
        revoked_grants: Arc::new(crate::ownership::RevokedGrantSet::new()),
    };

    // Register every inventory surface as `Router<AppState>`, then bind state
    // so the returned tree is `Router<()>` and implements `Service`. Binding
    // earlier while still returning `Router<AppState>` leaves the tree
    // "missing" state and breaks both `axum::serve` and `oneshot`.
    //
    // Blossom without a configured store is **not** a feature-disabled stub:
    // the surface simply does not exist on this deployment (bare 404, no
    // methods registered). When the store *is* configured but wallet/explorer
    // are off, the path is known-but-inactive → `404 feature_disabled`.
    let mut router = Router::new().route("/", get(root));
    for surface in ServedSurface::ALL {
        if surface.is_active(&features, blossom_configured) {
            router = surface.register(router, max_blob_bytes);
        } else if surface.is_blossom() && !blossom_configured {
            // Leave unregistered.
        } else {
            router = surface.register_disabled(router);
        }
    }
    Ok(router.with_state(state))
}

async fn health() -> Response {
    (StatusCode::OK, "ok").into_response()
}

async fn root(State(state): State<AppState>) -> Json<RootResponse> {
    let blossom_configured = state.blossom.is_some();
    Json(RootResponse {
        name: "zkcoins-api",
        version: env!("CARGO_PKG_VERSION"),
        endpoints: discovery_endpoints(&state.features, blossom_configured),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Feature};
    use crate::error::ApiError;
    use crate::kernel::encode_kernel_error_status;
    use crate::kernel::kernel_v1::{
        AccountStateRequest, AccountStateResult, AccumulatorTip, AttestRequest, BootstrapManifest,
        Challenge, CoinProofBlob, CoinProofRequest, EntrustRequest, EntrustResult, GrantRequest,
        GrantResult, Info, Inscription, Job, JobEvent, JobHandle, JobRequest,
        ListInscriptionsRequest, Nullifier as ProtoNullifier, NullifierPath, NullifierPathRequest,
        PublishRequest, PublishResult, PullChallengeRequest, PullRequest,
        PullResult as ProtoPullResult, Receipt, RecordBlob, RecordRequest, RevokeRequest,
        RevokeResult, SignRequest, SubscribeReceiptsRequest, TransitionRequest,
    };
    use crate::kernel::KernelRpc;
    use crate::ownership::SessionAuthority;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures_util::stream::{self, BoxStream};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tonic::Code;
    use tower::ServiceExt;

    /// Default test config enables every §7.5 role feature so handler tests
    /// exercise the full surface. Feature-gating tests build a narrower set.
    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::from([Feature::Wallet, Feature::Explorer, Feature::Publisher]),
            public_hosts: vec!["node.example.com".to_string()],
            blossom: None,
        }
    }

    /// Config with no optional features — only always-on process surfaces.
    fn test_config_no_features() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::new(),
            public_hosts: vec!["node.example.com".to_string()],
            blossom: None,
        }
    }

    /// Kernel double that never succeeds — used by discovery/health tests.
    struct UnreachableKernel;

    #[async_trait]
    impl KernelRpc for UnreachableKernel {
        async fn submit_transition(&self, _req: TransitionRequest) -> Result<JobHandle, ApiError> {
            Err(ApiError::internal("test double: submit not configured"))
        }
        async fn get_job(&self, _req: JobRequest) -> Result<Job, ApiError> {
            Err(ApiError::internal("test double: get_job not configured"))
        }
        async fn stream_job(
            &self,
            _req: JobRequest,
        ) -> Result<BoxStream<'static, Result<JobEvent, ApiError>>, ApiError> {
            Err(ApiError::internal("test double: stream_job not configured"))
        }
        async fn sign_transition(&self, _req: SignRequest) -> Result<Job, ApiError> {
            Err(ApiError::internal("test double: sign not configured"))
        }
        async fn cancel_job(&self, _req: JobRequest) -> Result<Job, ApiError> {
            Err(ApiError::internal("test double: cancel not configured"))
        }
        async fn get_info(&self) -> Result<Info, ApiError> {
            Err(ApiError::internal("test double: get_info not configured"))
        }
        async fn get_accumulator(&self) -> Result<AccumulatorTip, ApiError> {
            Err(ApiError::internal(
                "test double: get_accumulator not configured",
            ))
        }
        async fn list_inscriptions(
            &self,
            _req: ListInscriptionsRequest,
        ) -> Result<BoxStream<'static, Result<Inscription, ApiError>>, ApiError> {
            Err(ApiError::internal(
                "test double: list_inscriptions not configured",
            ))
        }
        async fn get_nullifier_path(
            &self,
            _req: NullifierPathRequest,
        ) -> Result<NullifierPath, ApiError> {
            Err(ApiError::internal(
                "test double: get_nullifier_path not configured",
            ))
        }
        async fn open_pull_challenge(
            &self,
            _req: PullChallengeRequest,
        ) -> Result<Challenge, ApiError> {
            Err(ApiError::internal(
                "test double: open_pull_challenge not configured",
            ))
        }
        async fn attest_balance(&self, _req: AttestRequest) -> Result<JobHandle, ApiError> {
            Err(ApiError::internal(
                "test double: attest_balance not configured",
            ))
        }
        async fn issue_view_grant(&self, _req: GrantRequest) -> Result<GrantResult, ApiError> {
            Err(ApiError::internal(
                "test double: issue_view_grant not configured",
            ))
        }
        async fn pull(
            &self,
            _req: PullRequest,
            _authority: SessionAuthority,
        ) -> Result<ProtoPullResult, ApiError> {
            Err(ApiError::internal("test double: pull not configured"))
        }
        async fn get_record(&self, _req: RecordRequest) -> Result<RecordBlob, ApiError> {
            Err(ApiError::internal("test double: get_record not configured"))
        }
        async fn get_coin_proof(&self, _req: CoinProofRequest) -> Result<CoinProofBlob, ApiError> {
            Err(ApiError::internal(
                "test double: get_coin_proof not configured",
            ))
        }
        async fn get_account_state(
            &self,
            _req: AccountStateRequest,
        ) -> Result<AccountStateResult, ApiError> {
            Err(ApiError::internal(
                "test double: get_account_state not configured",
            ))
        }
        async fn subscribe_receipts(
            &self,
            _req: SubscribeReceiptsRequest,
        ) -> Result<BoxStream<'static, Result<Receipt, ApiError>>, ApiError> {
            Err(ApiError::internal(
                "test double: subscribe_receipts not configured",
            ))
        }
        async fn entrust_operational_bundle(
            &self,
            _req: EntrustRequest,
        ) -> Result<EntrustResult, ApiError> {
            Err(ApiError::internal("test double: entrust not configured"))
        }
        async fn revoke_operational_bundle(
            &self,
            _req: RevokeRequest,
        ) -> Result<RevokeResult, ApiError> {
            Err(ApiError::internal("test double: revoke not configured"))
        }
        async fn publish(&self, _req: PublishRequest) -> Result<PublishResult, ApiError> {
            Err(ApiError::internal("test double: publish not configured"))
        }
    }

    fn test_app() -> Router {
        build_router(test_config(), Arc::new(UnreachableKernel)).expect("router")
    }

    async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
        res.into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec()
    }

    /// Spec §7.5 L2874 closed keys in order — inventory check only.
    const SPEC_CLOSED_KEYS: &[&str] = &[
        "health",
        "health_ready",
        "info",
        "chain_accumulator",
        "chain_inscriptions",
        "chain_nullifier",
        "tx",
        "jobs",
        "jobs_stream",
        "jobs_sign",
        "jobs_cancel",
        "attest_balance_challenge",
        "attest_balance",
        "grants_challenge",
        "grants",
        "pull_challenge",
        "pull",
        "record",
        "proof",
        "account_state",
        "receipts_stream",
        "publish_spendrecord",
        "bootstrap_challenge",
        "bootstrap_entrust",
        "bootstrap_revoke",
        "blossom_get",
        "blossom_head",
        "blossom_upload",
    ];

    #[test]
    fn closed_endpoint_keys_inventory_matches_spec() {
        assert_eq!(
            CLOSED_ENDPOINT_KEYS.len(),
            28,
            "CLOSED_ENDPOINT_KEYS must list all 28 §7.5 closed keys (no blossom_delete)"
        );
        assert_eq!(
            SPEC_CLOSED_KEYS.len(),
            28,
            "spec key list fixture must stay in sync with closed inventory"
        );
        for (i, (key, path)) in CLOSED_ENDPOINT_KEYS.iter().enumerate() {
            assert_eq!(
                *key, SPEC_CLOSED_KEYS[i],
                "CLOSED_ENDPOINT_KEYS[{i}] key must match §7.5 L2874 order"
            );
            assert!(
                !path.is_empty(),
                "inventory path for key {key} must be non-empty"
            );
            assert!(
                path.starts_with('/'),
                "inventory path for key {key} must be root-relative, got {path:?}"
            );
            assert!(
                !path.contains('{') && !path.contains('}'),
                "inventory path for key {key} must use Spec <name> form, not braces: {path:?}"
            );
        }
        let keys: BTreeSet<&str> = CLOSED_ENDPOINT_KEYS.iter().map(|(k, _)| *k).collect();
        assert!(!keys.contains(""), "empty discovery key is invalid");
        assert_eq!(keys.len(), 28, "closed keys must be unique");
        assert!(
            !keys.contains("blossom_delete"),
            "data permanence: blossom_delete must not be in the inventory"
        );
    }

    #[test]
    fn every_served_surface_is_in_closed_inventory() {
        // Full feature set + Blossom store: every inventory surface must map.
        let features = BTreeSet::from([Feature::Wallet, Feature::Explorer, Feature::Publisher]);
        for surface in ServedSurface::active(&features, true) {
            let key = surface.discovery_key();
            let path = closed_path(key);
            assert!(
                !path.is_empty(),
                "served key {key} must resolve to a non-empty inventory path"
            );
        }
        assert_eq!(
            ServedSurface::active(&features, true).len(),
            ServedSurface::ALL.len(),
            "wallet+explorer+publisher+blossom must activate the full inventory"
        );
    }

    #[tokio::test]
    async fn health_returns_200_ok_plaintext() {
        let app = test_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_bytes(res).await;
        assert_eq!(
            body,
            b"ok",
            "health body must be exactly the bytes of \"ok\", got {:?}",
            String::from_utf8_lossy(&body)
        );
    }

    #[tokio::test]
    async fn root_advertises_exactly_the_served_surfaces() {
        let app = test_app();
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON root body");

        assert_eq!(json["name"], "zkcoins-api");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));

        let endpoints = json["endpoints"].as_object().expect("endpoints object");

        let cfg = test_config();
        let expected_keys: BTreeSet<&str> = ServedSurface::active(&cfg.features, false)
            .iter()
            .map(|s| s.discovery_key())
            .collect();
        let actual_keys: BTreeSet<&str> = endpoints.keys().map(|s| s.as_str()).collect();
        assert_eq!(
            actual_keys, expected_keys,
            "GET / must list exactly the served surfaces, not the full inventory"
        );
        assert_eq!(
            actual_keys,
            BTreeSet::from([
                "health",
                "health_ready",
                "info",
                "chain_accumulator",
                "chain_inscriptions",
                "chain_nullifier",
                "tx",
                "jobs",
                "jobs_stream",
                "jobs_sign",
                "jobs_cancel",
                "attest_balance_challenge",
                "attest_balance",
                "grants_challenge",
                "grants",
                "pull_challenge",
                "pull",
                "record",
                "proof",
                "account_state",
                "receipts_stream",
                "publish_spendrecord",
                "bootstrap_challenge",
                "bootstrap_entrust",
                "bootstrap_revoke",
            ]),
            "test_config (wallet+explorer+publisher, no blossom) advertises 25 keys"
        );
        assert_eq!(
            endpoints["bootstrap_challenge"].as_str(),
            Some("/v1/bootstrap/challenge")
        );
        assert_eq!(
            endpoints["bootstrap_entrust"].as_str(),
            Some("/v1/bootstrap/entrust")
        );
        assert_eq!(
            endpoints["bootstrap_revoke"].as_str(),
            Some("/v1/bootstrap/revoke")
        );
        assert_eq!(
            endpoints["publish_spendrecord"].as_str(),
            Some("/v1/publish/spendrecord")
        );
        // Blossom stays off discovery without ZKCOINS_BLOSSOM_STORE.
        for absent in ["blossom_get", "blossom_head", "blossom_upload"] {
            assert!(
                !endpoints.contains_key(absent),
                "unconfigured Blossom surface {absent} must stay unadvertised"
            );
        }
        assert!(
            !endpoints.contains_key("blossom_delete"),
            "data permanence: blossom_delete must never be advertised"
        );
        assert_eq!(
            endpoints["receipts_stream"].as_str(),
            Some("/v1/receipts/stream"),
            "receipts_stream must be advertised once SubscribeReceipts is wired"
        );
        assert_eq!(
            endpoints["chain_inscriptions"].as_str(),
            Some("/v1/chain/inscriptions"),
            "chain_inscriptions must be advertised once ListInscriptions is served"
        );
        assert_eq!(
            endpoints["attest_balance_challenge"].as_str(),
            Some("/v1/attest/balance/challenge")
        );
        assert_eq!(
            endpoints["attest_balance"].as_str(),
            Some("/v1/attest/balance")
        );
        assert_eq!(
            endpoints["grants_challenge"].as_str(),
            Some("/v1/grants/challenge")
        );
        assert_eq!(endpoints["grants"].as_str(), Some("/v1/grants"));
        assert_eq!(
            endpoints["pull_challenge"].as_str(),
            Some("/v1/pull/challenge")
        );
        assert_eq!(endpoints["pull"].as_str(), Some("/v1/pull"));
        assert_eq!(endpoints["record"].as_str(), Some("/v1/record/<record_id>"));
        assert_eq!(endpoints["proof"].as_str(), Some("/v1/proof/<coin_id>"));
        assert_eq!(
            endpoints["account_state"].as_str(),
            Some("/v1/account/state")
        );
        assert_eq!(
            endpoints["receipts_stream"].as_str(),
            Some("/v1/receipts/stream")
        );
        // chain_inscriptions is advertised — the node catalog backs ListInscriptions.
        assert!(
            endpoints.contains_key("chain_inscriptions"),
            "chain_inscriptions must be advertised while the node catalog is present"
        );
        assert_eq!(
            endpoints["health"].as_str(),
            Some("/health"),
            "health path must match CLOSED_ENDPOINT_KEYS inventory"
        );
        assert_eq!(endpoints["health_ready"].as_str(), Some("/health/ready"));
        assert_eq!(endpoints["info"].as_str(), Some("/v1/info"));
        assert_eq!(
            endpoints["chain_accumulator"].as_str(),
            Some("/v1/chain/accumulator")
        );
        // Spec-Schreibweise on the wire — never the axum matcher form.
        assert_eq!(
            endpoints["chain_nullifier"].as_str(),
            Some("/v1/chain/nullifier/<pubkey>")
        );
        assert_eq!(endpoints["tx"].as_str(), Some("/v1/tx"));
        assert_eq!(endpoints["jobs"].as_str(), Some("/v1/jobs/<job_id>"));
        assert_eq!(
            endpoints["jobs_stream"].as_str(),
            Some("/v1/jobs/<job_id>/stream")
        );
        assert_eq!(
            endpoints["jobs_sign"].as_str(),
            Some("/v1/jobs/<job_id>/sign")
        );
        assert_eq!(
            endpoints["jobs_cancel"].as_str(),
            Some("/v1/jobs/<job_id>/cancel")
        );
    }

    #[test]
    fn advertised_path_to_axum_matcher_rewrites_angle_brackets() {
        assert_eq!(
            advertised_path_to_axum_matcher("/v1/jobs/<job_id>"),
            "/v1/jobs/:job_id"
        );
        assert_eq!(
            advertised_path_to_axum_matcher("/v1/jobs/<job_id>/stream"),
            "/v1/jobs/:job_id/stream"
        );
        assert_eq!(
            advertised_path_to_axum_matcher("/v1/chain/nullifier/<pubkey>"),
            "/v1/chain/nullifier/:pubkey"
        );
        assert_eq!(advertised_path_to_axum_matcher("/health"), "/health");
        assert_eq!(advertised_path_to_axum_matcher("/v1/tx"), "/v1/tx");
        // Every inventory path must round-trip into a matcher without leftover
        // Spec placeholders (guards against a second hand-written list).
        for &(key, path) in CLOSED_ENDPOINT_KEYS {
            let matcher = advertised_path_to_axum_matcher(path);
            assert!(
                !matcher.contains('<') && !matcher.contains('>'),
                "key {key}: matcher still has Spec brackets: {matcher}"
            );
            assert!(
                !matcher.contains('{') && !matcher.contains('}'),
                "key {key}: matcher must not use brace params (axum 0.8); got {matcher}"
            );
        }
    }

    /// Concrete segment for an advertised `<name>` placeholder.
    ///
    /// Values are plausible for the handlers that extract the segment (job_id
    /// is opaque text; pubkey / hashes are 32-byte hex). Unknown names fail
    /// loud — the inventory must not invent slots without a probe value.
    fn concrete_path_param(name: &str) -> &'static str {
        match name {
            "job_id" => "00000000-0000-4000-8000-000000000001",
            "pubkey" | "sha256" | "coin_id" | "record_id" => {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
            other => panic!(
                "no concrete probe value for path parameter {other:?}; \
                 extend concrete_path_param when the inventory gains this slot"
            ),
        }
    }

    /// Replace every `<name>` in an advertised path with a concrete segment.
    fn concrete_probe_uri(advertised: &str) -> String {
        let mut out = String::with_capacity(advertised.len() + 32);
        let mut rest = advertised;
        while let Some(open) = rest.find('<') {
            let (before, after_open) = rest.split_at(open);
            out.push_str(before);
            let after_open = &after_open[1..];
            let close = match after_open.find('>') {
                Some(i) => i,
                None => panic!("unclosed '<' in advertised path {advertised:?}"),
            };
            let name = &after_open[..close];
            out.push_str(concrete_path_param(name));
            rest = &after_open[close + 1..];
        }
        out.push_str(rest);
        out
    }

    /// `true` when the body is a §7.5 domain error (`{ "error", "message" }`)
    /// with a non-empty machine code. Axum's routing fallback is status-only
    /// (empty body) — that is **not** a domain answer.
    fn is_section_75_error_body(body: &[u8]) -> bool {
        let Ok(json) = serde_json::from_slice::<Value>(body) else {
            return false;
        };
        matches!(
            json.get("error").and_then(|v| v.as_str()),
            Some(code) if !code.is_empty()
        )
    }

    /// Would have been **red** when registration used the advertised string as
    /// a literal axum path: the probe hits a *concrete* URI, so a route table
    /// that only matches the Spec placeholder text answers with the empty
    /// axum fallback 404 — distinguishable from a domain 404 that carries the
    /// §7.5 `{ "error", "message" }` body.
    #[tokio::test]
    async fn every_advertised_endpoint_is_reachable() {
        let discovery = {
            let app = test_app();
            let res = app
                .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = body_bytes(res).await;
            let json: Value = serde_json::from_slice(&body).expect("JSON root body");
            let endpoints = json["endpoints"].as_object().expect("endpoints object");
            endpoints
                .iter()
                .map(|(k, v)| {
                    let path = v.as_str().expect("endpoint value must be a string path");
                    assert!(
                        !path.is_empty(),
                        "advertised path for key {k} must not be empty"
                    );
                    (k.clone(), path.to_string())
                })
                .collect::<Vec<_>>()
        };

        assert!(
            !discovery.is_empty(),
            "GET / must advertise at least one served surface"
        );

        for (key, advertised) in &discovery {
            let probe = concrete_probe_uri(advertised);
            assert!(
                !probe.contains('<') && !probe.contains('>'),
                "probe URI for {key} still has a template placeholder: {probe}"
            );

            let app = test_app();
            let res = app
                .oneshot(
                    Request::builder()
                        .uri(probe.as_str())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = res.status();
            if status == StatusCode::NOT_FOUND {
                let body = body_bytes(res).await;
                assert!(
                    is_section_75_error_body(&body),
                    "GET / advertised key {key:?} at {advertised:?}; probe {probe:?} \
                     returned a routing 404 (no §7.5 error body, got {:?}) — the \
                     matcher was never registered for a concrete segment",
                    String::from_utf8_lossy(&body)
                );
                // Domain 404 (handler ran, returned job_not_found etc.) is fine.
            }
            // Any non-404 (200, 405 method, 500 from the unreachable kernel double,
            // 400, …) means the route matched. That is the reachability claim.
        }
    }

    #[tokio::test]
    async fn chain_inscriptions_is_404_and_absent_from_discovery() {
        // Renamed historically: the route is registered, returns a page, and
        // the discovery key is present. The node catalog backs ListInscriptions.
        let kernel = ScriptedKernel {
            list_inscriptions: Some(Ok(Vec::new())),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "GET /v1/chain/inscriptions must be registered and return a page"
        );
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON page body");
        assert_eq!(
            json["inscriptions"],
            serde_json::json!([]),
            "empty catalog is an empty list, not 404"
        );
        assert!(
            json.get("next_height").is_none()
                && json.get("next_tx_index").is_none()
                && json.get("next_vin_index").is_none(),
            "empty page must omit all three next_* fields, got {json}"
        );

        let app = test_app();
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON root body");
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            endpoints.contains_key("chain_inscriptions"),
            "served surface 'chain_inscriptions' must appear in GET / endpoints"
        );
        assert_eq!(
            endpoints["chain_inscriptions"].as_str(),
            Some("/v1/chain/inscriptions")
        );
        assert!(
            endpoints.contains_key("info"),
            "stage B must advertise info"
        );
        assert!(
            endpoints.contains_key("health_ready"),
            "stage B must advertise health_ready"
        );
        assert!(
            endpoints.contains_key("chain_nullifier"),
            "stage B must advertise chain_nullifier"
        );
    }

    #[tokio::test]
    async fn router_accepts_config_with_features() {
        let mut features = BTreeSet::new();
        features.insert(Feature::Wallet);
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://kernel:1".to_string(),
            features,
            public_hosts: vec!["node.example.com".to_string()],
            blossom: None,
        };
        let app = build_router(cfg, Arc::new(UnreachableKernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Wallet alone opens the job/pull surfaces and omits explorer/publisher.
        let app = build_router(
            Config {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                kernel_addr: "http://kernel:1".to_string(),
                features: BTreeSet::from([Feature::Wallet]),
                public_hosts: vec!["node.example.com".to_string()],
                blossom: None,
            },
            Arc::new(UnreachableKernel),
        )
        .expect("router");
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON root body");
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            endpoints.contains_key("tx"),
            "wallet feature must advertise the job surface key 'tx'"
        );
        assert!(
            endpoints.contains_key("pull"),
            "wallet feature must advertise /v1/pull"
        );
        assert!(
            endpoints.contains_key("receipts_stream"),
            "wallet feature must advertise receipts_stream"
        );
        assert!(
            !endpoints.contains_key("chain_accumulator"),
            "explorer surface must stay unadvertised without explorer feature"
        );
        assert!(
            !endpoints.contains_key("publish_spendrecord"),
            "publisher surface must stay unadvertised without publisher feature"
        );
    }

    /// Without the change: wallet/explorer/publisher routes were always-on,
    /// so a disabled feature still returned a non-404 (kernel error / 405 / …)
    /// and `GET /` still advertised the key. With the stub, disabled known
    /// routes answer `404 feature_disabled` (machine code + JSON body), not a
    /// bare axum 404.
    #[tokio::test]
    async fn disabled_wallet_surface_is_404_feature_disabled_and_absent_from_discovery() {
        let app =
            build_router(test_config_no_features(), Arc::new(UnreachableKernel)).expect("router");

        // Probe a concrete wallet path — known inventory, feature off.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "disabled wallet surface must not be served"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(
            json["error"], "feature_disabled",
            "disabled known route must carry machine code feature_disabled, got {json}"
        );
        assert!(
            json.get("message").and_then(|m| m.as_str()).is_some(),
            "§7.5 body must include message, got {json}"
        );

        // Unknown path (not in inventory) stays a bare framework 404 without
        // the feature_disabled machine code.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/not-an-inventory-path")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let unknown_body = body_bytes(res).await;
        if let Ok(j) = serde_json::from_slice::<Value>(&unknown_body) {
            assert_ne!(
                j.get("error").and_then(|e| e.as_str()),
                Some("feature_disabled"),
                "unknown paths must not claim feature_disabled"
            );
        }

        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            !endpoints.contains_key("tx"),
            "GET / must not advertise disabled wallet key 'tx'"
        );
        assert!(
            !endpoints.contains_key("jobs"),
            "GET / must not advertise disabled wallet key 'jobs'"
        );
        // Always-on process surfaces remain.
        assert!(endpoints.contains_key("health"));
        assert!(endpoints.contains_key("info"));
        assert_eq!(
            endpoints.len(),
            3,
            "no-features config must advertise only health, health_ready, info; got {:?}",
            endpoints.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn disabled_explorer_surface_is_404_and_absent_from_discovery() {
        // Wallet on, explorer off: chain routes must vanish.
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::from([Feature::Wallet]),
            public_hosts: vec!["node.example.com".to_string()],
            blossom: None,
        };
        let app = build_router(cfg, Arc::new(UnreachableKernel)).expect("router");
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/accumulator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "disabled explorer surface must not be served"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(
            json["error"], "feature_disabled",
            "disabled explorer must carry feature_disabled machine code"
        );

        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            !endpoints.contains_key("chain_accumulator"),
            "GET / must not advertise disabled explorer key"
        );
        assert!(
            endpoints.contains_key("tx"),
            "wallet surface must remain advertised when only explorer is off"
        );
    }

    #[tokio::test]
    async fn disabled_publisher_surface_is_404_and_absent_from_discovery() {
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::from([Feature::Wallet, Feature::Explorer]),
            public_hosts: vec!["node.example.com".to_string()],
            blossom: None,
        };
        let app = build_router(cfg, Arc::new(UnreachableKernel)).expect("router");
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/publish/spendrecord")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "disabled publisher surface must not be served"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(
            json["error"], "feature_disabled",
            "disabled publisher must carry feature_disabled machine code"
        );

        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            !endpoints.contains_key("publish_spendrecord"),
            "GET / must not advertise disabled publisher key"
        );
    }

    // -----------------------------------------------------------------------
    // Job-surface handler tests against an honest in-trait kernel double
    // -----------------------------------------------------------------------

    /// Yields scripted receipt items, then parks until dropped.
    ///
    /// Drop sets `dropped` so tests can prove client disconnect tears down the
    /// kernel subscription (same pattern as job-stream body drop).
    struct HangAfterReceipts {
        items: std::vec::IntoIter<Result<Receipt, ApiError>>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for HangAfterReceipts {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl futures_util::Stream for HangAfterReceipts {
        type Item = Result<Receipt, ApiError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.items.next() {
                Some(item) => std::task::Poll::Ready(Some(item)),
                // Park until the consumer drops this stream (client disconnect).
                None => std::task::Poll::Pending,
            }
        }
    }

    #[derive(Default)]
    struct ScriptedKernel {
        submit: Option<Result<JobHandle, ApiError>>,
        get: Option<Result<Job, ApiError>>,
        stream: Option<Result<Vec<Result<JobEvent, ApiError>>, ApiError>>,
        sign: Option<Result<Job, ApiError>>,
        cancel: Option<Result<Job, ApiError>>,
        info: Option<Result<Info, ApiError>>,
        accumulator: Option<Result<AccumulatorTip, ApiError>>,
        /// Full catalog; the double filters by inclusive triple + limit.
        list_inscriptions: Option<Result<Vec<Inscription>, ApiError>>,
        nullifier_path: Option<Result<NullifierPath, ApiError>>,
        open_challenge: Option<Result<Challenge, ApiError>>,
        attest: Option<Result<JobHandle, ApiError>>,
        issue_grant: Option<Result<GrantResult, ApiError>>,
        pull: Option<Result<ProtoPullResult, ApiError>>,
        get_record: Option<Result<RecordBlob, ApiError>>,
        get_coin_proof: Option<Result<CoinProofBlob, ApiError>>,
        get_account_state: Option<Result<AccountStateResult, ApiError>>,
        /// Receipts stream: handshake `Err` or a finite list of items (Ok/Err).
        /// When `subscribe_receipts_hang` is true, the double yields the list
        /// then parks until the stream is dropped (disconnect cleanup).
        subscribe_receipts: Option<Result<Vec<Result<Receipt, ApiError>>, ApiError>>,
        /// After scripted items, hang until drop (for cleanup tests).
        subscribe_receipts_hang: bool,
        /// Set true when a hanging receipts stream is dropped.
        subscribe_receipts_dropped: Arc<AtomicBool>,
        entrust: Option<Result<EntrustResult, ApiError>>,
        revoke: Option<Result<RevokeResult, ApiError>>,
        publish: Option<Result<PublishResult, ApiError>>,
        /// Call counters for proving "no kernel call" on auth failure.
        attest_calls: AtomicUsize,
        issue_grant_calls: AtomicUsize,
        open_challenge_calls: AtomicUsize,
        pull_calls: AtomicUsize,
        get_record_calls: AtomicUsize,
        get_coin_proof_calls: AtomicUsize,
        get_account_state_calls: AtomicUsize,
        subscribe_receipts_calls: AtomicUsize,
        entrust_calls: AtomicUsize,
        revoke_calls: AtomicUsize,
        publish_calls: AtomicUsize,
        list_inscriptions_calls: AtomicUsize,
        /// SubmitTransition call counter (delivery form rejections must stay 0).
        submit_calls: AtomicUsize,
        /// Last pull authority observed (for grant/ownership plumbing asserts).
        last_pull_authority: Mutex<Option<SessionAuthority>>,
        /// Last PullRequest observed (resolved_scope / subject plumbing).
        last_pull: Mutex<Option<PullRequest>>,
        /// Last OpenPullChallenge.action observed (bootstrap domain plumbing).
        last_open_challenge_action: Mutex<Option<String>>,
        /// Last entrust request (bundle length / subject checks — never log bundle).
        last_entrust: Mutex<Option<EntrustRequest>>,
        last_revoke: Mutex<Option<RevokeRequest>>,
        last_publish: Mutex<Option<PublishRequest>>,
        /// Last ListInscriptions request (limit / cursor plumbing).
        last_list_inscriptions: Mutex<Option<ListInscriptionsRequest>>,
        /// Last SubscribeReceipts request (session + chan_bind; never subject).
        last_subscribe_receipts: Mutex<Option<SubscribeReceiptsRequest>>,
        /// Last SubmitTransition request (delivery field-for-field asserts).
        last_submit: Mutex<Option<TransitionRequest>>,
    }

    #[async_trait]
    impl KernelRpc for ScriptedKernel {
        async fn submit_transition(&self, req: TransitionRequest) -> Result<JobHandle, ApiError> {
            self.submit_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_submit.lock().unwrap() = Some(req);
            match &self.submit {
                Some(Ok(h)) => Ok(h.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("submit not scripted")),
            }
        }
        async fn get_job(&self, _req: JobRequest) -> Result<Job, ApiError> {
            match &self.get {
                Some(Ok(j)) => Ok(j.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("get not scripted")),
            }
        }
        async fn stream_job(
            &self,
            _req: JobRequest,
        ) -> Result<BoxStream<'static, Result<JobEvent, ApiError>>, ApiError> {
            match &self.stream {
                Some(Ok(events)) => {
                    let events = events.clone();
                    Ok(Box::pin(stream::iter(events)))
                }
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("stream not scripted")),
            }
        }
        async fn sign_transition(&self, _req: SignRequest) -> Result<Job, ApiError> {
            match &self.sign {
                Some(Ok(j)) => Ok(j.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("sign not scripted")),
            }
        }
        async fn cancel_job(&self, _req: JobRequest) -> Result<Job, ApiError> {
            match &self.cancel {
                Some(Ok(j)) => Ok(j.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("cancel not scripted")),
            }
        }
        async fn get_info(&self) -> Result<Info, ApiError> {
            match &self.info {
                Some(Ok(i)) => Ok(i.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("info not scripted")),
            }
        }
        async fn get_accumulator(&self) -> Result<AccumulatorTip, ApiError> {
            match &self.accumulator {
                Some(Ok(t)) => Ok(t.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("accumulator not scripted")),
            }
        }
        async fn list_inscriptions(
            &self,
            req: ListInscriptionsRequest,
        ) -> Result<BoxStream<'static, Result<Inscription, ApiError>>, ApiError> {
            self.list_inscriptions_calls.fetch_add(1, Ordering::SeqCst);
            // ListInscriptionsRequest is Copy (scalar Option fields only).
            *self
                .last_list_inscriptions
                .lock()
                .expect("list_inscriptions mutex") = Some(req);
            match &self.list_inscriptions {
                Some(Ok(catalog)) => {
                    // §7.5 defaults (same as API normalisation before RPC /
                    // ListInscriptionsRequest proto comment). Named so the
                    // protocol values stay visible — not unwrap_or_default().
                    const DEFAULT_FROM_HEIGHT: u64 = 0;
                    const DEFAULT_FROM_TX_INDEX: u64 = 0;
                    const DEFAULT_FROM_VIN_INDEX: u64 = 0;
                    const DEFAULT_LIMIT: u32 = 100;
                    let from_h = req.from_height.unwrap_or(DEFAULT_FROM_HEIGHT);
                    let from_t = req.from_tx_index.unwrap_or(DEFAULT_FROM_TX_INDEX);
                    let from_v = req.from_vin_index.unwrap_or(DEFAULT_FROM_VIN_INDEX);
                    let limit = req.limit.unwrap_or(DEFAULT_LIMIT) as usize;
                    let items: Vec<Result<Inscription, ApiError>> = catalog
                        .iter()
                        .filter(|ins| {
                            (ins.height, ins.tx_index, ins.vin_index) >= (from_h, from_t, from_v)
                        })
                        .take(limit)
                        .cloned()
                        .map(Ok)
                        .collect();
                    Ok(Box::pin(stream::iter(items)))
                }
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("list_inscriptions not scripted")),
            }
        }
        async fn get_nullifier_path(
            &self,
            _req: NullifierPathRequest,
        ) -> Result<NullifierPath, ApiError> {
            match &self.nullifier_path {
                Some(Ok(p)) => Ok(p.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("nullifier_path not scripted")),
            }
        }
        async fn open_pull_challenge(
            &self,
            req: PullChallengeRequest,
        ) -> Result<Challenge, ApiError> {
            self.open_challenge_calls.fetch_add(1, Ordering::SeqCst);
            *self
                .last_open_challenge_action
                .lock()
                .expect("open action mutex") = Some(req.action);
            match &self.open_challenge {
                Some(Ok(c)) => Ok(c.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("open_challenge not scripted")),
            }
        }
        async fn attest_balance(&self, _req: AttestRequest) -> Result<JobHandle, ApiError> {
            self.attest_calls.fetch_add(1, Ordering::SeqCst);
            match &self.attest {
                Some(Ok(h)) => Ok(h.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("attest not scripted")),
            }
        }
        async fn issue_view_grant(&self, _req: GrantRequest) -> Result<GrantResult, ApiError> {
            self.issue_grant_calls.fetch_add(1, Ordering::SeqCst);
            match &self.issue_grant {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("issue_grant not scripted")),
            }
        }
        async fn pull(
            &self,
            req: PullRequest,
            authority: SessionAuthority,
        ) -> Result<ProtoPullResult, ApiError> {
            self.pull_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_pull_authority.lock().expect("authority mutex") = Some(authority);
            *self.last_pull.lock().expect("pull mutex") = Some(req);
            match &self.pull {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("pull not scripted")),
            }
        }
        async fn get_record(&self, _req: RecordRequest) -> Result<RecordBlob, ApiError> {
            self.get_record_calls.fetch_add(1, Ordering::SeqCst);
            match &self.get_record {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("get_record not scripted")),
            }
        }
        async fn get_coin_proof(&self, _req: CoinProofRequest) -> Result<CoinProofBlob, ApiError> {
            self.get_coin_proof_calls.fetch_add(1, Ordering::SeqCst);
            match &self.get_coin_proof {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("get_coin_proof not scripted")),
            }
        }
        async fn get_account_state(
            &self,
            _req: AccountStateRequest,
        ) -> Result<AccountStateResult, ApiError> {
            self.get_account_state_calls.fetch_add(1, Ordering::SeqCst);
            match &self.get_account_state {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("get_account_state not scripted")),
            }
        }
        async fn subscribe_receipts(
            &self,
            req: SubscribeReceiptsRequest,
        ) -> Result<BoxStream<'static, Result<Receipt, ApiError>>, ApiError> {
            self.subscribe_receipts_calls.fetch_add(1, Ordering::SeqCst);
            *self
                .last_subscribe_receipts
                .lock()
                .expect("subscribe_receipts mutex") = Some(req);
            match &self.subscribe_receipts {
                Some(Ok(events)) => {
                    let events = events.clone();
                    if self.subscribe_receipts_hang {
                        let dropped = Arc::clone(&self.subscribe_receipts_dropped);
                        Ok(Box::pin(HangAfterReceipts {
                            items: events.into_iter(),
                            dropped,
                        }))
                    } else {
                        Ok(Box::pin(stream::iter(events)))
                    }
                }
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("subscribe_receipts not scripted")),
            }
        }
        async fn entrust_operational_bundle(
            &self,
            req: EntrustRequest,
        ) -> Result<EntrustResult, ApiError> {
            self.entrust_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_entrust.lock().expect("entrust mutex") = Some(req);
            match &self.entrust {
                Some(Ok(r)) => Ok(*r),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("entrust not scripted")),
            }
        }
        async fn revoke_operational_bundle(
            &self,
            req: RevokeRequest,
        ) -> Result<RevokeResult, ApiError> {
            self.revoke_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_revoke.lock().expect("revoke mutex") = Some(req);
            match &self.revoke {
                Some(Ok(r)) => Ok(*r),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("revoke not scripted")),
            }
        }
        async fn publish(&self, req: PublishRequest) -> Result<PublishResult, ApiError> {
            self.publish_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_publish.lock().expect("publish mutex") = Some(req);
            match &self.publish {
                Some(Ok(r)) => Ok(r.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(ApiError::internal("publish not scripted")),
            }
        }
    }

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

    fn hex32(byte: u8) -> String {
        crate::hexutil::encode_hex(&[byte; 32])
    }

    fn mint_body() -> Value {
        json_mint()
    }

    fn json_mint() -> Value {
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

    fn accepted_job(job_id: &str) -> Job {
        Job {
            job_id: job_id.to_string(),
            kind: "mint".to_string(),
            status: "accepted".to_string(),
            phase: String::new(),
            progress: 0.0,
            awaiting_signature: None,
            result: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn post_tx_happy_path_returns_202() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "job-1".to_string(),
                status: "accepted".to_string(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "k1")
                    .body(Body::from(mint_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["job_id"], "job-1");
        assert_eq!(json["status"], "accepted");
    }

    /// Missing `Idempotency-Key` is optional: request reaches the kernel and
    /// may succeed. Distinct from a present-but-empty header (next test).
    #[tokio::test]
    async fn post_tx_missing_idempotency_key_is_allowed() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "job-no-key".to_string(),
                status: "accepted".to_string(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    // deliberately no Idempotency-Key
                    .body(Body::from(mint_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::ACCEPTED,
            "absent Idempotency-Key must not be rewritten into a client error"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["job_id"], "job-no-key");
    }

    /// Present-but-empty `Idempotency-Key` is `400 malformed_request`.
    ///
    /// Asserts the two outcomes diverge: missing → `Ok(None)`, empty value →
    /// `400 malformed_request`. `http::HeaderValue` cannot encode a zero-byte
    /// value, so the empty branch is exercised through the value parser rather
    /// than a crafted HTTP request; the missing path is also covered by
    /// `post_tx_missing_idempotency_key_is_allowed` at HTTP level.
    #[test]
    fn post_tx_empty_vs_missing_idempotency_key_diverge() {
        // Missing → Ok(None) → not a client error.
        let headers = axum::http::HeaderMap::new();
        assert!(crate::jobs::idempotency_key_from_headers(&headers)
            .expect("missing ok")
            .is_none());
        // Empty value → 400 malformed_request (never Ok(Some(""))).
        let err = crate::jobs::parse_idempotency_key_value("").expect_err("empty must error");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
    }

    /// Unknown top-level field must be `400 malformed_request`, not ignored.
    #[tokio::test]
    async fn post_tx_unknown_top_level_field_is_malformed_400() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let mut body = mint_body();
        body["extra_unknown"] = Value::String("nope".into());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "unknown field must be 400, not 422 or silent drop"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
    }

    /// Unknown field inside a nested object (issuance) is also rejected.
    #[tokio::test]
    async fn post_tx_unknown_nested_field_is_malformed_400() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let mut body = mint_body();
        body["issuance"]["foreign_nested"] = Value::Number(1.into());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "nested unknown field must be 400, not silently dropped"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
    }

    /// Empty job_id from the kernel must not become a client-visible 202.
    #[tokio::test]
    async fn post_tx_empty_job_id_from_kernel_is_not_202() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: String::new(),
                status: "accepted".to_string(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            res.status(),
            StatusCode::ACCEPTED,
            "empty job_id must not be admitted as 202"
        );
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(
            json["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE,
            "public internal_error message must be neutral"
        );
    }

    /// Unknown / non-accepted kernel status must not become a client-visible 202.
    #[tokio::test]
    async fn post_tx_unknown_status_from_kernel_is_not_202() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "job-weird".to_string(),
                status: "totally_unknown_phase".to_string(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            res.status(),
            StatusCode::ACCEPTED,
            "unknown status must not be admitted as 202"
        );
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(
            json["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE,
            "public internal_error message must be neutral"
        );
    }

    /// Empty status string is also not a valid admit terminal.
    #[tokio::test]
    async fn post_tx_empty_status_from_kernel_is_not_202() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "job-empty-status".to_string(),
                status: String::new(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(res.status(), StatusCode::ACCEPTED);
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn post_tx_fee_address_is_malformed_400() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let mut body = mint_body();
        body["fee_address"] = Value::String("zk1fee".into());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        assert!(
            json["message"].as_str().unwrap().contains("fee_address"),
            "message must name fee_address, got {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn post_tx_kernel_bounds_exceeded_is_400() {
        // error_contract: BoundsExceeded → bounds_exceeded / 400.
        let status = encode_kernel_error_status(
            Code::InvalidArgument,
            "too many outputs",
            "bounds_exceeded",
            400,
        );
        let kernel = ScriptedKernel {
            submit: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "bounds_exceeded");
        assert_eq!(json["message"], "too many outputs");
    }

    /// Distinctive pk0 hex used only in delivery HTTP tests — must never
    /// appear in 400 response bodies (form errors name paths, not values).
    fn delivery_test_pk0() -> String {
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()
    }

    fn delivery_test_memo() -> String {
        "MEMO_RETENTION_MARKER_DO_NOT_LOG_xyz".to_string()
    }

    fn mint_body_with_invoice_delivery() -> Value {
        let mut body = mint_body();
        body["output_templates"][0]["delivery"] = serde_json::json!({
            "type": "invoice",
            "invoice": {
                "amount": "100",
                "recipient": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "asset_id": hex32(0x33),
                "memo": delivery_test_memo(),
                "pk0": delivery_test_pk0(),
                "nk_commit": hex32(0x44),
                "ivpk": hex32(0x55),
                "op_pubkey": hex32(0x66),
                "relays": ["wss://relay.example"],
                "addr_sig": crate::hexutil::encode_hex(&[0x77u8; 64]),
                "sig": crate::hexutil::encode_hex(&[0x88u8; 64]),
            }
        });
        body
    }

    /// Well-formed invoice delivery reaches the kernel field-for-field.
    #[tokio::test]
    async fn post_tx_invoice_delivery_forwards_to_kernel() {
        let kernel = Arc::new(ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "job-deliv".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body_with_invoice_delivery().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        assert_eq!(kernel.submit_calls.load(Ordering::SeqCst), 1);
        let last = kernel.last_submit.lock().unwrap();
        let req = last.as_ref().expect("submit captured");
        assert_eq!(req.output_templates.len(), 1);
        let cred = req.output_templates[0]
            .delivery
            .as_ref()
            .expect("delivery present on proto");
        let inv = match cred.body.as_ref().expect("oneof") {
            crate::kernel::kernel_v1::delivery_credential::Body::Invoice(i) => i,
            other => panic!("expected Invoice, got {other:?}"),
        };
        assert_eq!(
            inv.pk0,
            crate::hexutil::decode_hex_exact(&delivery_test_pk0(), 32).unwrap()
        );
        assert_eq!(inv.memo, delivery_test_memo());
        assert_eq!(inv.relays, vec!["wss://relay.example".to_string()]);
        // Position binding: sole template is index 0.
        assert_eq!(req.output_templates[0].amount, "100");
    }

    /// Unknown `delivery.type` is API-edge 400 — kernel is never called.
    #[tokio::test]
    async fn post_tx_unknown_delivery_type_no_kernel_call() {
        let kernel = Arc::new(ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let mut body = mint_body();
        body["output_templates"][0]["delivery"] = serde_json::json!({
            "type": "carrier_pigeon",
            "invoice": { "amount": "1" }
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        assert_eq!(
            kernel.submit_calls.load(Ordering::SeqCst),
            0,
            "form rejection must not call SubmitTransition"
        );
    }

    /// Unknown nested invoice field is API-edge 400 — no kernel call.
    #[tokio::test]
    async fn post_tx_unknown_invoice_field_no_kernel_call() {
        let kernel = Arc::new(ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let mut body = mint_body_with_invoice_delivery();
        body["output_templates"][0]["delivery"]["invoice"]["ghost"] = Value::Bool(true);
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        assert_eq!(kernel.submit_calls.load(Ordering::SeqCst), 0);
    }

    /// Missing required invoice field is API-edge 400 — no kernel call.
    #[tokio::test]
    async fn post_tx_missing_invoice_pk0_no_kernel_call() {
        let kernel = Arc::new(ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let mut body = mint_body_with_invoice_delivery();
        body["output_templates"][0]["delivery"]["invoice"]
            .as_object_mut()
            .unwrap()
            .remove("pk0");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        // Response must not echo a pk0 that was never in the body either —
        // and must not leak the memo that *was* present.
        let msg = json["message"].as_str().unwrap_or("");
        assert!(!msg.contains(&delivery_test_memo()));
        assert!(!msg.contains(&delivery_test_pk0()));
        assert_eq!(kernel.submit_calls.load(Ordering::SeqCst), 0);
    }

    /// Submit with a credential: 400 form-error message (wrong pk0 width)
    /// must contain neither the pk0 hex nor the memo text.
    #[tokio::test]
    async fn post_tx_delivery_form_error_does_not_leak_pk0_or_memo() {
        let kernel = Arc::new(ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let mut body = mint_body_with_invoice_delivery();
        // Wrong width — triggers decode_hex_field form error after parse.
        let bad_pk0 = "ab".repeat(20); // 40 chars
        body["output_templates"][0]["delivery"]["invoice"]["pk0"] = Value::String(bad_pk0.clone());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        let msg = json["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("pk0"),
            "message must name the field path, got {msg}"
        );
        assert!(
            !msg.contains(&bad_pk0),
            "§7.5 retention: must not echo pk0 hex, got {msg}"
        );
        assert!(
            !msg.contains(&delivery_test_memo()),
            "§7.5 retention: must not echo memo, got {msg}"
        );
        assert_eq!(kernel.submit_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn get_job_happy_path() {
        let kernel = ScriptedKernel {
            get: Some(Ok(accepted_job("job-2"))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/job-2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("2"),
            "non-terminal poll must carry Retry-After"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["job_id"], "job-2");
        assert_eq!(json["status"], "accepted");
        assert_eq!(json["kind"], "mint");
    }

    #[tokio::test]
    async fn get_job_not_found_is_404() {
        // error_contract: JobNotFound → job_not_found / 404.
        let status =
            encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        let kernel = ScriptedKernel {
            get: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "job_not_found");
    }

    #[tokio::test]
    async fn post_sign_wrong_phase_is_409() {
        // error_contract: WrongPhase → wrong_phase / 409.
        let status = encode_kernel_error_status(
            Code::FailedPrecondition,
            "not awaiting signature",
            "wrong_phase",
            409,
        );
        let kernel = ScriptedKernel {
            sign: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let body = serde_json::json!({
            "signature": crate::hexutil::encode_hex(&[0u8; 64]),
            "s2c_nonce": hex32(0xab),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/jobs/job-3/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "wrong_phase");
    }

    #[tokio::test]
    async fn post_sign_happy_path() {
        let mut job = accepted_job("job-3");
        job.status = "proving".to_string();
        let kernel = ScriptedKernel {
            sign: Some(Ok(job)),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let body = serde_json::json!({
            "signature": crate::hexutil::encode_hex(&[1u8; 64]),
            "s2c_nonce": hex32(0xcd),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/jobs/job-3/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["job_id"], "job-3");
        assert_eq!(json["status"], "proving");
    }

    #[tokio::test]
    async fn post_cancel_happy_path() {
        let mut job = accepted_job("job-4");
        job.status = "cancelled".to_string();
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "proving_failed".into(),
            message: "cancelled by client".into(),
        });
        let kernel = ScriptedKernel {
            cancel: Some(Ok(job)),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/jobs/job-4/cancel")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["status"], "cancelled");
        assert_eq!(json["error"]["error"], "proving_failed");
    }

    #[tokio::test]
    async fn get_job_internal_error_message_is_neutral() {
        const SECRET: &str = "enqueue failed: /var/lib/SECRET_JOB_PATH_xyz";
        let mut job = accepted_job("job-leak-poll");
        job.status = "failed".to_string();
        job.error = Some(crate::kernel::kernel_v1::JobError {
            error: "internal_error".into(),
            message: SECRET.into(),
        });
        let kernel = ScriptedKernel {
            get: Some(Ok(job)),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/job-leak-poll")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = body_bytes(res).await;
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            !text.contains("SECRET_JOB_PATH"),
            "poll body must not leak operator path: {text}"
        );
        assert!(!text.contains("enqueue failed"));
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["error"], "internal_error");
        assert_eq!(
            json["error"]["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE
        );
    }

    #[tokio::test]
    async fn stream_job_internal_error_message_is_neutral() {
        const SECRET: &str = "enqueue failed: /var/lib/SECRET_SSE_PATH_xyz";
        let err_ev = JobEvent {
            event: "error".into(),
            job: Some(Job {
                job_id: "job-leak-sse".into(),
                kind: "mint".into(),
                status: "failed".into(),
                phase: String::new(),
                progress: 1.0,
                awaiting_signature: None,
                result: None,
                error: Some(crate::kernel::kernel_v1::JobError {
                    error: "internal_error".into(),
                    message: SECRET.into(),
                }),
            }),
        };
        let kernel = ScriptedKernel {
            stream: Some(Ok(vec![Ok(err_ev)])),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/job-leak-sse/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(res).await).expect("utf8");
        assert!(
            body.contains("event: error"),
            "must emit error event, body={body}"
        );
        assert!(
            body.contains(crate::error::PUBLIC_INTERNAL_MESSAGE),
            "SSE must carry neutral internal message, body={body}"
        );
        assert!(
            !body.contains("SECRET_SSE_PATH"),
            "SSE must not leak operator path, body={body}"
        );
        assert!(!body.contains("enqueue failed"));
    }

    #[tokio::test]
    async fn get_job_terminal_nonempty_phase_is_500() {
        let mut job = accepted_job("job-phase");
        job.status = "completed".to_string();
        job.phase = "publishing".to_string();
        job.result = Some(crate::kernel::kernel_v1::JobResult {
            new_account_state_hash: vec![0x11; 32],
            output_coins_root: vec![0x22; 32],
            input_nullifiers_root: vec![0x33; 32],
            output_coin_ids: vec![],
            publisher_pubkey: vec![],
            attestation: vec![],
        });
        let kernel = ScriptedKernel {
            get: Some(Ok(job)),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/job-phase")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(json["message"], crate::error::PUBLIC_INTERNAL_MESSAGE);
    }

    #[tokio::test]
    async fn stream_job_emits_phase_then_complete() {
        let phase = JobEvent {
            event: "phase".into(),
            job: Some(Job {
                job_id: "job-5".into(),
                kind: "mint".into(),
                status: "proving".into(),
                phase: "witness_build".into(),
                progress: 0.25,
                awaiting_signature: None,
                result: None,
                error: None,
            }),
        };
        let complete = JobEvent {
            event: "complete".into(),
            job: Some(Job {
                job_id: "job-5".into(),
                kind: "mint".into(),
                status: "completed".into(),
                phase: String::new(),
                progress: 1.0,
                awaiting_signature: None,
                result: Some(crate::kernel::kernel_v1::JobResult {
                    new_account_state_hash: vec![0x11; 32],
                    output_coins_root: vec![0x22; 32],
                    input_nullifiers_root: vec![0x33; 32],
                    output_coin_ids: vec![vec![0x44; 32]],
                    publisher_pubkey: Vec::new(),
                    attestation: Vec::new(),
                }),
                error: None,
            }),
        };
        let kernel = ScriptedKernel {
            stream: Some(Ok(vec![Ok(phase), Ok(complete)])),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/job-5/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = match res.headers().get("content-type") {
            Some(v) => match v.to_str() {
                Ok(s) => s,
                Err(e) => panic!("content-type is not ASCII: {e}"),
            },
            None => panic!("SSE response missing content-type header"),
        };
        assert!(
            ct.starts_with("text/event-stream"),
            "SSE content-type, got {ct:?}"
        );
        let body = String::from_utf8(body_bytes(res).await).expect("utf8");
        assert!(
            body.contains("event: phase"),
            "must emit phase event, body={body}"
        );
        assert!(
            body.contains("event: complete"),
            "must emit complete event, body={body}"
        );
        assert!(
            body.contains("\"status\":\"proving\""),
            "phase data must carry status, body={body}"
        );
        assert!(
            body.contains("\"status\":\"completed\""),
            "complete data must carry completed status, body={body}"
        );
    }

    #[tokio::test]
    async fn stream_job_break_emits_error_event() {
        let kernel = ScriptedKernel {
            stream: Some(Ok(vec![Err(ApiError::internal("kernel stream dropped"))])),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/job-6/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(res).await).expect("utf8");
        assert!(
            body.contains("event: error"),
            "broken stream must emit error event, body={body}"
        );
        assert!(
            body.contains("internal_error"),
            "error event must carry machine code, body={body}"
        );
        assert!(
            body.contains(crate::error::PUBLIC_INTERNAL_MESSAGE),
            "error event must carry the public internal message, body={body}"
        );
        assert!(
            !body.contains("kernel stream dropped"),
            "error event must not leak the operator cause, body={body}"
        );
    }

    #[tokio::test]
    async fn stream_job_not_found_before_sse() {
        let status =
            encode_kernel_error_status(Code::NotFound, "Job not found", "job_not_found", 404);
        let kernel = ScriptedKernel {
            stream: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/missing/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "job_not_found");
    }

    // -----------------------------------------------------------------------
    // Info / readiness / chain read surface
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_info_happy_path() {
        let kernel = ScriptedKernel {
            info: Some(Ok(sample_info(true, None))),
            ..Default::default()
        };
        let mut features = BTreeSet::new();
        features.insert(Feature::Wallet);
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features,
            public_hosts: vec!["node.example.com".to_string()],
            blossom: None,
        };
        let app = build_router(cfg, Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["network"], "regtest");
        assert_eq!(json["protocol_version"], "v1");
        assert_eq!(json["finality_confirmations"], 6);
        assert_eq!(json["max_tx_inputs"], 8);
        assert_eq!(json["features"], serde_json::json!(["wallet"]));
        assert_eq!(
            json["bootstrap_pubkey"].as_str().unwrap().len(),
            64,
            "bootstrap_pubkey is hex32"
        );
        assert_eq!(json["bootstrap"]["network"], "regtest");
        // Kernel-only fields must not leak onto the public surface.
        assert!(json.get("ready").is_none());
        assert!(json.get("kernel_parts").is_none());
        assert!(json.get("accumulator_root").is_none());
    }

    #[tokio::test]
    async fn get_info_kernel_internal_is_500() {
        let status = encode_kernel_error_status(
            Code::Internal,
            "Chain identity unavailable",
            "internal_error",
            500,
        );
        let kernel = ScriptedKernel {
            info: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(
            json["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE,
            "public message must be neutral, not the kernel diagnostic"
        );
        assert!(
            !json["message"]
                .as_str()
                .unwrap()
                .contains("Chain identity unavailable"),
            "kernel diagnostic must not appear on the wire"
        );
    }

    #[tokio::test]
    async fn health_ready_true_is_200() {
        let kernel = ScriptedKernel {
            info: Some(Ok(sample_info(true, None))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["ready"], true);
        assert!(
            json.get("reason").is_none(),
            "ready:true must not carry reason"
        );
        // Diagnostics from GetInfo (MAY); root/size are not unpaired here.
        assert_eq!(json["bitcoin_tip_height"], 100);
        assert_eq!(json["scanner_lag"], 0);
        assert!(json.get("root").is_none());
        // Must not use the generic error body shape.
        assert!(json.get("error").is_none());
    }

    #[tokio::test]
    async fn health_ready_false_is_503_with_reason() {
        let kernel = ScriptedKernel {
            info: Some(Ok(sample_info(false, Some("syncing")))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["ready"], false);
        assert_eq!(json["reason"], "syncing");
        assert!(json.get("error").is_none());
    }

    /// Fail-closed production posture: node `GetInfo` returns Internal when
    /// `ChainIdentity` is unset. The readiness probe must answer **not ready**
    /// (503 + dependency_unavailable), never invent `ready: true`.
    #[tokio::test]
    async fn health_ready_getinfo_failure_is_not_ready_dependency_unavailable() {
        let status = encode_kernel_error_status(
            Code::Internal,
            "Chain identity unavailable",
            "internal_error",
            500,
        );
        let kernel = ScriptedKernel {
            info: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "failed GetInfo must not green-light readiness"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["ready"], false);
        assert_eq!(json["reason"], "dependency_unavailable");
        // Readiness shape, not the generic §7.5 error body.
        assert!(
            json.get("error").is_none(),
            "must not use generic error body on /health/ready"
        );
    }

    #[tokio::test]
    async fn chain_accumulator_happy_path() {
        let kernel = ScriptedKernel {
            accumulator: Some(Ok(AccumulatorTip {
                root: vec![0xAB; 32],
                tip_block_hash: vec![0xCD; 32],
                tip_height: 42,
                size: 7,
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/accumulator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["size"], 7);
        assert_eq!(json["tip_height"], 42);
        assert_eq!(
            json["root"].as_str().unwrap(),
            crate::hexutil::encode_hex(&[0xAB; 32])
        );
        assert_eq!(
            json["tip_block_hash"].as_str().unwrap(),
            crate::hexutil::encode_hex(&[0xCD; 32])
        );
    }

    #[tokio::test]
    async fn chain_accumulator_kernel_error_uses_error_info() {
        let status = encode_kernel_error_status(
            Code::Internal,
            "Chain view unavailable",
            "internal_error",
            500,
        );
        let kernel = ScriptedKernel {
            accumulator: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/accumulator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(
            json["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE,
            "internal_error must carry the neutral public message, got {}",
            json["message"]
        );
        assert!(
            !json["message"]
                .as_str()
                .unwrap()
                .contains("Chain view unavailable"),
            "kernel cause must stay off the wire"
        );
    }

    #[tokio::test]
    async fn chain_nullifier_present_happy_path() {
        let kernel = ScriptedKernel {
            nullifier_path: Some(Ok(NullifierPath {
                root: vec![0x01; 32],
                tip_height: 10,
                present: true,
                leaf: vec![0x02; 32],
                position: 3,
                audit_path: vec![vec![0x03; 32], vec![0x04; 32]],
                tree_size: 4,
                tip_block_hash: vec![0x05; 32],
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let pk = hex32(0xaa);
        let res = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/chain/nullifier/{pk}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["present"], true);
        assert_eq!(json["position"], 3);
        assert_eq!(
            json["leaf"].as_str().unwrap(),
            crate::hexutil::encode_hex(&[0x02; 32])
        );
        assert_eq!(json["audit_path"].as_array().unwrap().len(), 2);
        assert_eq!(json["tree_size"], 4);
        assert_eq!(json["tip_height"], 10);
    }

    #[tokio::test]
    async fn chain_nullifier_absent_omits_position_and_leaf() {
        let kernel = ScriptedKernel {
            nullifier_path: Some(Ok(NullifierPath {
                root: vec![0x01; 32],
                tip_height: 10,
                present: false,
                leaf: Vec::new(),
                position: 0,
                audit_path: Vec::new(),
                tree_size: 4,
                tip_block_hash: vec![0x05; 32],
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let pk = hex32(0xbb);
        let res = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/chain/nullifier/{pk}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["present"], false);
        assert!(
            json.get("position").is_none(),
            "absent must omit position, got {json}"
        );
        assert!(
            json.get("leaf").is_none(),
            "absent must omit leaf, got {json}"
        );
        assert_eq!(json["audit_path"], serde_json::json!([]));
        assert_eq!(json["tree_size"], 4);
        assert_eq!(
            json["root"].as_str().unwrap(),
            crate::hexutil::encode_hex(&[0x01; 32])
        );
    }

    /// The decisive case: a corrupt index is kernel `internal_error`, not
    /// `present: false`. The api must not flatten that distinction.
    #[tokio::test]
    async fn chain_nullifier_kernel_internal_is_not_absent() {
        let status = encode_kernel_error_status(
            Code::Internal,
            "Failed to build nullifier path",
            "internal_error",
            500,
        );
        let kernel = ScriptedKernel {
            nullifier_path: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let pk = hex32(0xcc);
        let res = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/chain/nullifier/{pk}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(
            json["error"], "internal_error",
            "corrupt index must surface as ErrorInfo, not as present:false"
        );
        assert!(
            json.get("present").is_none(),
            "error body must not look like a Path-B absence answer"
        );
        assert_eq!(
            json["message"],
            crate::error::PUBLIC_INTERNAL_MESSAGE,
            "internal_error must carry the neutral public message, got {}",
            json["message"]
        );
        assert!(
            !json["message"]
                .as_str()
                .unwrap()
                .contains("Failed to build nullifier path"),
            "kernel cause must stay off the wire"
        );
    }

    #[tokio::test]
    async fn chain_nullifier_malformed_pubkey_is_400() {
        let kernel = ScriptedKernel {
            nullifier_path: Some(Ok(NullifierPath {
                root: vec![0x01; 32],
                tip_height: 0,
                present: false,
                leaf: Vec::new(),
                position: 0,
                audit_path: Vec::new(),
                tree_size: 0,
                tip_block_hash: vec![0x05; 32],
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/nullifier/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        assert!(
            json["message"].as_str().unwrap().contains("pubkey"),
            "message must name pubkey, got {}",
            json["message"]
        );
    }

    // -----------------------------------------------------------------------
    // Stage C1 — OwnershipProof gate (attest / grants)
    // -----------------------------------------------------------------------

    use crate::hexutil::encode_hex;
    use crate::ownership::{
        attest_request_hash, ceiling_encoding, chan_bind_for_host, encode_grant_asset_ids,
        encode_zk_address, issue_grant_request_hash, ownership_challenge_message, ChallengeDomain,
        ATTEST_BALANCE_CHALLENGE_DOMAIN, ISSUE_GRANT_CHALLENGE_DOMAIN, SCOPE_NOT_AFTER_UNBOUNDED,
    };
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    /// Expose address helper for tests via a thin re-export path.
    /// (`address_from_pk0_nk_commit` is private; tests use the public
    /// ownership helpers that already cover the same path.)
    mod ownership_fixtures {
        use super::*;

        pub fn sample_sk_pk() -> (SecretKey, [u8; 32]) {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("32-byte secret");
            let kp = Keypair::from_secret_key(&secp, &sk);
            let (xonly, _) = kp.x_only_public_key();
            (sk, xonly.serialize())
        }

        pub fn sign_chal(sk: &SecretKey, chal: &[u8; 32]) -> [u8; 64] {
            let secp = Secp256k1::new();
            let kp = Keypair::from_secret_key(&secp, sk);
            let msg = Message::from_digest_slice(chal).expect("32-byte digest");
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            let mut out = [0u8; 64];
            out.copy_from_slice(sig.as_ref());
            out
        }

        pub fn identity() -> (SecretKey, [u8; 32], [u8; 32], [u8; 32], String) {
            let (sk, pk0) = sample_sk_pk();
            let nk_commit = [0u8; 32];
            // H(Pk0 ‖ nk_commit) with zero digest — same as ownership unit tests.
            let mut pre = [0u8; 64];
            pre[..32].copy_from_slice(&pk0);
            pre[32..].copy_from_slice(&nk_commit);
            let subject_raw: [u8; 32] = {
                use sha2::{Digest, Sha256};
                Sha256::digest(pre).into()
            };
            let subject_bech = encode_zk_address(&subject_raw);
            (sk, pk0, nk_commit, subject_raw, subject_bech)
        }
    }

    fn ownership_proof_json(
        subject: &str,
        pk0: &[u8; 32],
        nkc: &[u8; 32],
        sig: &[u8; 64],
    ) -> Value {
        serde_json::json!({
            "type": "ownership",
            "subject": subject,
            "public_key": encode_hex(pk0),
            "nk_commit": encode_hex(nkc),
            "signature": encode_hex(sig),
        })
    }

    #[tokio::test]
    async fn attest_balance_valid_ownership_calls_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x11u8; 32];
        let expiry = 1_700_000_060u64;
        let asset = [0x22u8; 32];
        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_raw, &asset, &ceiling_enc);
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "attest-job-1".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["job_id"], "attest-job-1");
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 1);
    }

    /// Without the status gate, any non-empty job_id would be admitted as 202
    /// even when JobHandle.status is not `"accepted"`.
    #[tokio::test]
    async fn attest_balance_non_accepted_status_is_500() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x11u8; 32];
        let expiry = 1_700_000_060u64;
        let asset = [0x22u8; 32];
        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_raw, &asset, &ceiling_enc);
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "attest-job-bad".into(),
                status: "proving".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(json["message"], crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn attest_balance_bad_signature_does_not_call_kernel() {
        let host = "node.example.com";
        let (_sk, pk0, nkc, _subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x11u8; 32];
        let expiry = 1_700_000_060u64;
        let asset = [0x22u8; 32];
        let bad_sig = [0xFFu8; 64];

        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "should-not-run".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &bad_sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(
            kernel.attest_calls.load(Ordering::SeqCst),
            0,
            "failed signature must not reach AttestBalance (nonce not consumed)"
        );
        let _ = host; // documents the host used by test_config
    }

    /// Domain separation in both directions — the most important test of C1.
    #[tokio::test]
    async fn domain_separation_attest_signed_proof_does_not_authorise_grants() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x33u8; 32];
        let expiry = 1_700_000_060u64;
        let grantee = [0x44u8; 32];
        let grant_expiry = 2_000_000_000u64;
        let asset_enc = encode_grant_asset_ids(true, &[]).unwrap();
        let request_hash = issue_grant_request_hash(
            &subject_raw,
            &grantee,
            &asset_enc,
            0,
            SCOPE_NOT_AFTER_UNBOUNDED,
            grant_expiry,
        );
        let cb = chan_bind_for_host(host);
        // Sign under **AttestBalance** domain (wrong for /v1/grants).
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            issue_grant: Some(Ok(GrantResult {
                grant: "zkgrant1qqqq".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "grantee_pk": encode_hex(&grantee),
            "scope": { "asset_ids": "*" },
            "expiry": grant_expiry.to_string(),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/grants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(
            kernel.issue_grant_calls.load(Ordering::SeqCst),
            0,
            "attest-domain proof must not call IssueViewGrant"
        );
    }

    #[tokio::test]
    async fn domain_separation_grant_signed_proof_does_not_authorise_attest() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x55u8; 32];
        let expiry = 1_700_000_060u64;
        let asset = [0x66u8; 32];
        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_raw, &asset, &ceiling_enc);
        let cb = chan_bind_for_host(host);
        // Sign under **IssueGrant** domain (wrong for /v1/attest/balance).
        let chal = ownership_challenge_message(
            ChallengeDomain::IssueGrant.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "nope".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wrong_chan_bind_rejects_without_kernel() {
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let signed_host = "other.example.com";
        let nonce = [0x77u8; 32];
        let expiry = 99u64;
        let asset = [0x88u8; 32];
        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_raw, &asset, &ceiling_enc);
        let cb = chan_bind_for_host(signed_host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        // test_config serves node.example.com — signature bound to other host.
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wrong_request_hash_rejects_without_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x99u8; 32];
        let expiry = 100u64;
        let asset_signed = [0xAAu8; 32];
        let asset_presented = [0xBBu8; 32];
        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_raw, &asset_signed, &ceiling_enc);
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset_presented),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn expired_challenge_is_passthrough_from_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0xCCu8; 32];
        let expiry = 1_700_000_060u64;
        let asset = [0xDDu8; 32];
        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_raw, &asset, &ceiling_enc);
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        // Signature is valid; kernel reports challenge_expired via ErrorInfo
        // (gRPC UNAUTHENTICATED + http_status 410 — production triple).
        let expired = encode_kernel_error_status(
            tonic::Code::Unauthenticated,
            "challenge nonce expired",
            "challenge_expired",
            410,
        );
        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Err(crate::kernel::kernel_status_to_api_error(&expired))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&asset),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::GONE);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "challenge_expired");
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn grant_proof_type_is_unauthorized_without_kernel() {
        // Real GrantProof wire shape (no ownership fields). Must deserialise
        // as the grant arm and answer 401 — not 400 from missing subject/pk.
        let (_sk, _pk0, _nkc, _subject_raw, subject_bech) = ownership_fixtures::identity();
        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            issue_grant: Some(Ok(GrantResult {
                grant: "zkgrant1".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&[0u8; 32]),
            "challenge": {
                "nonce": encode_hex(&[1u8; 32]),
                "expiry": "100",
            },
            "ownership_proof": {
                "type": "grant",
                "grant": "zkgrant1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "grantee_pk": encode_hex(&[0xABu8; 32]),
                "signature": encode_hex(&[0u8; 64]),
            },
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "real GrantProof form must be 401, not 400 malformed"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert!(
            json["message"].as_str().unwrap().contains("GrantProof"),
            "message must name GrantProof, got {}",
            json["message"]
        );
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 0);
        assert_eq!(kernel.issue_grant_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn grants_real_grant_proof_form_is_401_without_kernel() {
        let (_sk, _pk0, _nkc, _subject_raw, subject_bech) = ownership_fixtures::identity();
        let kernel = Arc::new(ScriptedKernel {
            issue_grant: Some(Ok(GrantResult {
                grant: "zkgrant1".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "grantee_pk": encode_hex(&[0xFFu8; 32]),
            "scope": { "asset_ids": "*" },
            "expiry": "2000000000",
            "challenge": {
                "nonce": encode_hex(&[2u8; 32]),
                "expiry": "100",
            },
            "ownership_proof": {
                "type": "grant",
                "grant": "zkgrant1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "grantee_pk": encode_hex(&[0xABu8; 32]),
                "signature": encode_hex(&[0u8; 64]),
            },
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/grants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.issue_grant_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn grants_valid_ownership_calls_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0xEEu8; 32];
        let challenge_expiry = 1_700_000_060u64;
        let grantee = [0xFFu8; 32];
        let grant_expiry = 2_000_000_000u64;
        let asset_enc = encode_grant_asset_ids(true, &[]).unwrap();
        let request_hash = issue_grant_request_hash(
            &subject_raw,
            &grantee,
            &asset_enc,
            0,
            SCOPE_NOT_AFTER_UNBOUNDED,
            grant_expiry,
        );
        let cb = chan_bind_for_host(host);
        let chal = ownership_challenge_message(
            ChallengeDomain::IssueGrant.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            challenge_expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            issue_grant: Some(Ok(GrantResult {
                grant: "zkgrant1qpvalid".into(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "subject": subject_bech,
            "grantee_pk": encode_hex(&grantee),
            "scope": { "asset_ids": "*" },
            "expiry": grant_expiry.to_string(),
            "challenge": {
                "nonce": encode_hex(&nonce),
                "expiry": challenge_expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(&subject_bech, &pk0, &nkc, &sig),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/grants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["grant"], "zkgrant1qpvalid");
        assert_eq!(kernel.issue_grant_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn challenge_endpoints_return_endpoint_domain() {
        let (_, _, _, _, subject_bech) = ownership_fixtures::identity();
        let kernel = Arc::new(ScriptedKernel {
            open_challenge: Some(Ok(Challenge {
                nonce: vec![0xABu8; 32],
                expiry: 1_700_000_060,
                domain: ATTEST_BALANCE_CHALLENGE_DOMAIN.to_string(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attest/balance/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "subject": subject_bech }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["domain"], ATTEST_BALANCE_CHALLENGE_DOMAIN);
        assert_eq!(json["expiry"], "1700000060");
        assert_eq!(json["nonce"].as_str().unwrap().len(), 64);
        assert_eq!(kernel.open_challenge_calls.load(Ordering::SeqCst), 1);

        let kernel2 = Arc::new(ScriptedKernel {
            open_challenge: Some(Ok(Challenge {
                nonce: vec![0xCDu8; 32],
                expiry: 1_700_000_120,
                domain: ISSUE_GRANT_CHALLENGE_DOMAIN.to_string(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel2).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/grants/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "subject": subject_bech }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["domain"], ISSUE_GRANT_CHALLENGE_DOMAIN);
    }

    // -----------------------------------------------------------------------
    // Stage C2 — Pull / Record / Proof / AccountState
    // -----------------------------------------------------------------------

    use crate::kernel::kernel_v1::RecordRef;
    use crate::ownership::{pull_challenge_message, PULL_CHALLENGE_DOMAIN};

    fn sample_pull_result() -> ProtoPullResult {
        ProtoPullResult {
            records: vec![RecordRef {
                record_id: vec![0x11u8; 32],
                record_type: "coinproof".into(),
                transition_kind: String::new(),
                blob_id: vec![0x22u8; 32],
                occurred_at: 1_700_000_000,
            }],
            session: "sess-token-1".into(),
            session_expiry: 1_700_000_300,
        }
    }

    fn pull_body_ownership(
        subject: &str,
        pk0: &[u8; 32],
        nkc: &[u8; 32],
        nonce: &[u8; 32],
        expiry: u64,
        sig: &[u8; 64],
    ) -> Value {
        serde_json::json!({
            "nonce": encode_hex(nonce),
            "expiry": expiry.to_string(),
            "proof": {
                "type": "ownership",
                "subject": subject,
                "public_key": encode_hex(pk0),
                "nk_commit": encode_hex(nkc),
                "signature": encode_hex(sig),
            }
        })
    }

    #[tokio::test]
    async fn pull_challenge_returns_pull_domain() {
        let (_, _, _, _, subject_bech) = ownership_fixtures::identity();
        let kernel = Arc::new(ScriptedKernel {
            open_challenge: Some(Ok(Challenge {
                nonce: vec![0xABu8; 32],
                expiry: 1_700_000_060,
                domain: PULL_CHALLENGE_DOMAIN.to_string(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "subject": subject_bech }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["domain"], PULL_CHALLENGE_DOMAIN);
        assert_eq!(json["expiry"], "1700000060");
        assert_eq!(json["nonce"].as_str().unwrap().len(), 64);
        assert_eq!(kernel.open_challenge_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pull_valid_ownership_opens_session_with_ownership_authority() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x11u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &sig)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["session"], "sess-token-1");
        assert_eq!(json["session_expiry"], "1700000300");
        assert_eq!(json["records"][0]["record_type"], "coinproof");
        assert_eq!(json["records"][0]["occurred_at"], "1700000000");
        assert!(
            json["records"][0].get("transition_kind").is_none(),
            "coinproof without transition_kind must omit the field"
        );
        assert_eq!(kernel.pull_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *kernel.last_pull_authority.lock().unwrap(),
            Some(SessionAuthority::Ownership),
            "session authority must follow the OwnershipProof kind"
        );
    }

    #[tokio::test]
    async fn pull_grant_without_published_op_is_rejected_without_kernel_call() {
        // Without a published op_pubkey for the subject (empty subject_ops /
        // no Nostr profile resolution) GrantProof fails at §5.1(b) step 1 —
        // never half-checked, never a kernel call. Uses a structurally valid,
        // op-signed zkgrant whose subject is deliberately absent from
        // subject_ops so the missing-op arm is the one that fires.
        use crate::ownership::{
            encode_grant_asset_ids, encode_view_grant, grant_message_digest, ResolvedScope,
            GRANT_VERSION,
        };
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let op_sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
        let op_kp = Keypair::from_secret_key(&secp, &op_sk);
        let grantee_sk = SecretKey::from_slice(&[0x66u8; 32]).unwrap();
        let grantee_kp = Keypair::from_secret_key(&secp, &grantee_sk);
        let (grantee_xonly, _) = grantee_kp.x_only_public_key();
        let grantee_pk = grantee_xonly.serialize();
        let subject = [0x10u8; 32];
        let grant_scope = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01u8; 32]],
            not_before: 100,
            not_after: 9_000_000_000,
        };
        let grant_expiry = 4_000_000_000u64;
        let grant_nonce = [0x77u8; 16];
        let asset_enc =
            encode_grant_asset_ids(grant_scope.all_assets, &grant_scope.asset_ids).unwrap();
        let (grant_message, _) = grant_message_digest(
            GRANT_VERSION,
            &subject,
            &grantee_pk,
            &asset_enc,
            grant_scope.not_before,
            grant_scope.not_after,
            grant_expiry,
            &grant_nonce,
        );
        let msg = Message::from_digest_slice(&grant_message).unwrap();
        let op_sig = secp.sign_schnorr_no_aux_rand(&msg, &op_kp);
        let mut op_sig_bytes = [0u8; 64];
        op_sig_bytes.copy_from_slice(op_sig.as_ref());
        let grant_bech = encode_view_grant(
            &subject,
            &grantee_pk,
            &grant_scope,
            grant_expiry,
            &grant_nonce,
            &op_sig_bytes,
        )
        .unwrap();

        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        // build_router installs an empty subject_ops — subject has no published op.
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "nonce": encode_hex(&[0x11u8; 32]),
            "expiry": "1700000060",
            "proof": {
                "type": "grant",
                "grant": grant_bech,
                "grantee_pk": encode_hex(&grantee_pk),
                "signature": encode_hex(&[0x44u8; 64]),
            }
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert!(
            json["message"].as_str().unwrap().contains("op_pubkey")
                || json["message"].as_str().unwrap().contains("published"),
            "message must name the missing published op check: {}",
            json["message"]
        );
        assert_eq!(
            kernel.pull_calls.load(Ordering::SeqCst),
            0,
            "rejected grant must not consume the challenge nonce"
        );
    }

    #[tokio::test]
    async fn pull_valid_grant_opens_session_with_grant_authority_and_clamped_scope() {
        use crate::ownership::{
            encode_grant_asset_ids, encode_view_grant, grant_message_digest, ResolvedScope,
            RevokedGrantSet, SubjectOpDirectory, GRANT_VERSION, SCOPE_NOT_AFTER_UNBOUNDED,
        };
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        use sha2::{Digest, Sha256};

        let host = "node.example.com";
        let secp = Secp256k1::new();
        let op_sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
        let op_kp = Keypair::from_secret_key(&secp, &op_sk);
        let (op_xonly, _) = op_kp.x_only_public_key();
        let op_pk = op_xonly.serialize();
        let grantee_sk = SecretKey::from_slice(&[0x66u8; 32]).unwrap();
        let grantee_kp = Keypair::from_secret_key(&secp, &grantee_sk);
        let (grantee_xonly, _) = grantee_kp.x_only_public_key();
        let grantee_pk = grantee_xonly.serialize();
        let subject = [0x10u8; 32];
        let grant_scope = ResolvedScope {
            all_assets: false,
            asset_ids: vec![[0x01u8; 32]],
            not_before: 100,
            not_after: 9_000_000_000,
        };
        // Expiry far in the future so wall-clock `unix_now` in the handler passes.
        let grant_expiry = 4_000_000_000u64;
        let grant_nonce = [0x77u8; 16];
        let asset_enc =
            encode_grant_asset_ids(grant_scope.all_assets, &grant_scope.asset_ids).unwrap();
        let (grant_message, _) = grant_message_digest(
            GRANT_VERSION,
            &subject,
            &grantee_pk,
            &asset_enc,
            grant_scope.not_before,
            grant_scope.not_after,
            grant_expiry,
            &grant_nonce,
        );
        let msg = Message::from_digest_slice(&grant_message).unwrap();
        let op_sig = secp.sign_schnorr_no_aux_rand(&msg, &op_kp);
        let mut op_sig_bytes = [0u8; 64];
        op_sig_bytes.copy_from_slice(op_sig.as_ref());
        let grant_bech = encode_view_grant(
            &subject,
            &grantee_pk,
            &grant_scope,
            grant_expiry,
            &grant_nonce,
            &op_sig_bytes,
        )
        .unwrap();

        let challenge_nonce = [0x11u8; 32];
        let chal_expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let mut chal_pre = Vec::new();
        chal_pre.extend_from_slice(PULL_CHALLENGE_DOMAIN.as_bytes());
        chal_pre.extend_from_slice(&challenge_nonce);
        chal_pre.extend_from_slice(&cb);
        chal_pre.extend_from_slice(&subject);
        chal_pre.extend_from_slice(&chal_expiry.to_be_bytes());
        let chal: [u8; 32] = Sha256::digest(&chal_pre).into();
        let chal_msg = Message::from_digest_slice(&chal).unwrap();
        let grantee_sig = secp.sign_schnorr_no_aux_rand(&chal_msg, &grantee_kp);
        let mut grantee_sig_bytes = [0u8; 64];
        grantee_sig_bytes.copy_from_slice(grantee_sig.as_ref());

        let subject_ops = Arc::new(SubjectOpDirectory::new());
        subject_ops.insert(subject, op_pk);

        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let config = test_config();
        let state = AppState {
            kernel: kernel.clone(),
            features: config.features.clone(),
            public_hosts: Arc::new(config.public_hosts.clone()),
            blossom: None,
            subject_ops,
            revoked_grants: Arc::new(RevokedGrantSet::new()),
        };
        let app = {
            let mut router = Router::new().route("/", get(root));
            for surface in ServedSurface::active(&config.features, false) {
                router = surface.register(router, None);
            }
            router.with_state(state)
        };

        let body = serde_json::json!({
            "nonce": encode_hex(&challenge_nonce),
            "expiry": chal_expiry.to_string(),
            // Request wider than the grant → must clamp to grant scope.
            "scope": {
                "asset_ids": "*",
            },
            "proof": {
                "type": "grant",
                "grant": grant_bech,
                "grantee_pk": encode_hex(&grantee_pk),
                "signature": encode_hex(&grantee_sig_bytes),
            }
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let resp_body = body_bytes(res).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&resp_body)
        );
        assert_eq!(kernel.pull_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *kernel.last_pull_authority.lock().unwrap(),
            Some(SessionAuthority::Grant)
        );
        let last = kernel.last_pull.lock().unwrap().clone().expect("pull req");
        let scope = last.resolved_scope.expect("resolved_scope");
        assert!(!scope.all_assets, "grant session must not be all_assets=*");
        assert_eq!(scope.asset_ids, vec![vec![0x01u8; 32]]);
        assert_eq!(scope.not_before, 100);
        assert_eq!(scope.not_after, 9_000_000_000);
        // Must not be the unbounded sentinel pair.
        assert_ne!(scope.not_after, SCOPE_NOT_AFTER_UNBOUNDED);
    }

    #[tokio::test]
    async fn pull_ownership_passes_requested_scope_not_forced_unbounded() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x19u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let asset = [0xABu8; 32];
        let mut body = pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &sig);
        body["scope"] = serde_json::json!({
            "asset_ids": [encode_hex(&asset)],
            "not_before": "10",
            "not_after": "20",
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let last = kernel.last_pull.lock().unwrap().clone().expect("pull req");
        let scope = last.resolved_scope.expect("resolved_scope");
        assert!(!scope.all_assets);
        assert_eq!(scope.asset_ids, vec![asset.to_vec()]);
        assert_eq!(scope.not_before, 10);
        assert_eq!(scope.not_after, 20);
    }

    #[tokio::test]
    async fn pull_bad_signature_does_not_call_kernel() {
        let (_sk, pk0, nkc, _subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x11u8; 32];
        let expiry = 1_700_000_060u64;
        let bad_sig = [0xFFu8; 64];
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &bad_sig)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.pull_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pull_wrong_domain_signature_does_not_call_kernel() {
        // Sign under AttestBalance domain, redeem under Pull → unauthorized.
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x22u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let request_hash = [0u8; 32];
        let chal = ownership_challenge_message(
            ChallengeDomain::AttestBalance.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
            &request_hash,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &sig)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.pull_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pull_wrong_chan_bind_does_not_call_kernel() {
        let signed_host = "signed.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x33u8; 32];
        let expiry = 50u64;
        let cb = chan_bind_for_host(signed_host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        // test_config serves node.example.com — different chan_bind.
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &sig)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.pull_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pull_altered_expiry_does_not_call_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x44u8; 32];
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
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(sample_pull_result())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            presented_expiry,
                            &sig,
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.pull_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn session_missing_bearer_is_401_not_410() {
        let kernel = Arc::new(ScriptedKernel {
            get_record: Some(Ok(RecordBlob {
                canonical: vec![0xABu8; 8],
                record_type: "coinproof".into(),
                transition_kind: String::new(),
            })),
            get_account_state: Some(Ok(AccountStateResult {
                account_state: vec![0x01],
                state_head: vec![0x02; 32],
                head_record_id: Vec::new(),
                send_counter: 0,
                current_pubkey: vec![0x03; 32],
                last_nullifier_pk: Vec::new(),
                last_nullifier_r: Vec::new(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/record/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.get_record_calls.load(Ordering::SeqCst), 0);

        // Same split on ownership-only account/state.
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/account/state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.get_account_state_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn session_malformed_bearer_is_401_not_410() {
        let kernel = Arc::new(ScriptedKernel {
            get_coin_proof: Some(Ok(CoinProofBlob {
                canonical: vec![0xCDu8; 4],
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/proof/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                    .header("authorization", "NotBearer xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.get_coin_proof_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn session_expired_from_kernel_is_410() {
        // Kernel maps unknown/expired/chan_bind-mismatch → session_expired / 410.
        let status = encode_kernel_error_status(
            Code::Unauthenticated,
            "pull session expired or channel mismatch",
            "session_expired",
            410,
        );
        let kernel = Arc::new(ScriptedKernel {
            get_record: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/record/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .header("authorization", "Bearer expired-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::GONE);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "session_expired");
        assert_eq!(kernel.get_record_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn account_state_grant_session_is_401() {
        // Kernel enforces ownership-only; a grant session is unauthorized / 401.
        let status = encode_kernel_error_status(
            Code::Unauthenticated,
            "grant session does not authorise GetAccountState",
            "unauthorized",
            401,
        );
        let kernel = Arc::new(ScriptedKernel {
            get_account_state: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/account/state")
                    .header("authorization", "Bearer grant-session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.get_account_state_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pull_rejects_unknown_record_type_from_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x55u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let mut result = sample_pull_result();
        result.records[0].record_type = "mystery".into();
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(result)),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &sig)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Kernel closed-set violation → 500 internal_error. Public message is
        // always the neutral PUBLIC_INTERNAL_MESSAGE; the field name lives in
        // the operator cause / logs only (same contract as get_job_unknown_status).
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(json["message"], crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            !json["message"].as_str().unwrap().contains("record_type"),
            "public wire must not leak kernel field diagnostics: {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn pull_rejects_unknown_transition_kind_from_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x66u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Pull.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let mut result = sample_pull_result();
        result.records[0].record_type = "self_delivery".into();
        result.records[0].transition_kind = "explode".into();
        let kernel = Arc::new(ScriptedKernel {
            pull: Some(Ok(result)),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pull")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        pull_body_ownership(&subject_bech, &pk0, &nkc, &nonce, expiry, &sig)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Same contract as unknown record_type: 500 + neutral public message.
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(json["message"], crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            !json["message"]
                .as_str()
                .unwrap()
                .contains("transition_kind"),
            "public wire must not leak kernel field diagnostics: {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn get_record_returns_binary_octet_stream() {
        let kernel = Arc::new(ScriptedKernel {
            get_record: Some(Ok(RecordBlob {
                canonical: b"canonical-record-bytes".to_vec(),
                record_type: "coinproof".into(),
                transition_kind: String::new(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/record/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .header("authorization", "Bearer good-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        let body = body_bytes(res).await;
        assert_eq!(body, b"canonical-record-bytes");
    }

    #[tokio::test]
    async fn get_account_state_json_shape() {
        let kernel = Arc::new(ScriptedKernel {
            get_account_state: Some(Ok(AccountStateResult {
                account_state: vec![0xAAu8; 16],
                state_head: vec![0xBBu8; 32],
                head_record_id: vec![0xCCu8; 32],
                send_counter: 7,
                current_pubkey: vec![0xDDu8; 32],
                last_nullifier_pk: vec![0xEEu8; 32],
                last_nullifier_r: vec![0xFFu8; 32],
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/account/state")
                    .header("authorization", "Bearer own-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["send_counter"], "7");
        assert_eq!(
            json["current_pubkey"].as_str().unwrap().len(),
            64,
            "current_pubkey is hex32"
        );
        assert_eq!(
            json["state_head"].as_str().unwrap().len(),
            64,
            "state_head is hex32"
        );
        assert!(json["account_state"].as_str().unwrap().len() >= 2);
        assert_eq!(json["last_nullifier"]["pubkey"].as_str().unwrap().len(), 64);
        // API does not recompute consistency against serialize(AccountState) —
        // that is a kernel guarantee (report).
    }

    #[tokio::test]
    async fn get_proof_returns_binary_octet_stream() {
        let kernel = Arc::new(ScriptedKernel {
            get_coin_proof: Some(Ok(CoinProofBlob {
                canonical: b"coin-proof-bytes".to_vec(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/proof/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
                    .header("authorization", "Bearer good-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert_eq!(body_bytes(res).await, b"coin-proof-bytes");
    }

    // -----------------------------------------------------------------------
    // Receipts stream — GET /v1/receipts/stream (§7.5 L2953–L2955)
    // -----------------------------------------------------------------------

    fn sample_receipt(coin_byte: u8, amount: &str, credited_at: u64) -> Receipt {
        Receipt {
            coin_id: vec![coin_byte; 32],
            asset_id: vec![0xABu8; 32],
            amount: amount.to_string(),
            state: "completed".into(),
            credited_at,
        }
    }

    #[tokio::test]
    async fn receipts_stream_happy_path_two_frames() {
        let r1 = sample_receipt(0x11, "1000", 1_700_000_100);
        let r2 = sample_receipt(0x22, "250", 1_700_000_200);
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Ok(vec![Ok(r1.clone()), Ok(r2.clone())])),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .header("authorization", "Bearer sess-own-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = match res.headers().get("content-type") {
            Some(v) => match v.to_str() {
                Ok(s) => s,
                Err(e) => panic!("content-type is not ASCII: {e}"),
            },
            None => panic!("SSE response missing content-type header"),
        };
        assert!(
            ct.starts_with("text/event-stream"),
            "SSE content-type, got {ct:?}"
        );
        let body = String::from_utf8(body_bytes(res).await).expect("utf8");

        // Frame form: event: receipt\ndata: <json>\n\n (axum SSE).
        let event_count = body.matches("event: receipt").count();
        assert_eq!(
            event_count, 2,
            "must emit exactly two receipt events, body={body}"
        );
        assert!(
            body.contains("event: receipt\ndata:"),
            "frame must be event then data, body={body}"
        );

        // Field encodings: hex32 digests, decimal strings for amount/credited_at.
        let coin1 = encode_hex(&r1.coin_id);
        let coin2 = encode_hex(&r2.coin_id);
        let asset = encode_hex(&r1.asset_id);
        assert!(
            body.contains(&format!("\"coin_id\":\"{coin1}\"")),
            "first coin_id hex, body={body}"
        );
        assert!(
            body.contains(&format!("\"coin_id\":\"{coin2}\"")),
            "second coin_id hex, body={body}"
        );
        assert!(
            body.contains(&format!("\"asset_id\":\"{asset}\"")),
            "asset_id hex, body={body}"
        );
        assert!(
            body.contains("\"amount\":\"1000\""),
            "amount decimal string, body={body}"
        );
        assert!(
            body.contains("\"amount\":\"250\""),
            "second amount decimal string, body={body}"
        );
        assert!(
            body.contains("\"state\":\"completed\""),
            "state literal, body={body}"
        );
        assert!(
            body.contains("\"credited_at\":\"1700000100\""),
            "credited_at decimal string, body={body}"
        );
        assert!(
            body.contains("\"credited_at\":\"1700000200\""),
            "second credited_at decimal string, body={body}"
        );

        // Kernel saw session + chan_bind only (no subject on the wire type).
        let req = kernel
            .last_subscribe_receipts
            .lock()
            .expect("mutex")
            .clone()
            .expect("subscribe_receipts must have been called");
        assert_eq!(req.session, "sess-own-1");
        let expected_cb = chan_bind_for_host("node.example.com");
        assert_eq!(req.chan_bind, expected_cb.to_vec());
        assert_eq!(kernel.subscribe_receipts_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn receipts_stream_grant_session_is_admitted() {
        // §7.5 L2953: any still-valid ownership OR grant pull session is
        // admissible — contrast with GET /v1/account/state (ownership only).
        let r = sample_receipt(0x33, "42", 1_700_000_300);
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Ok(vec![Ok(r)])),
            // Same grant token on account/state is rejected by the kernel.
            get_account_state: Some(Err(crate::kernel::kernel_status_to_api_error(
                &encode_kernel_error_status(
                    Code::Unauthenticated,
                    "grant session does not authorise GetAccountState",
                    "unauthorized",
                    401,
                ),
            ))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .header("authorization", "Bearer grant-session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "grant session must open the receipts stream"
        );
        let body = String::from_utf8(body_bytes(res).await).expect("utf8");
        assert!(
            body.contains("event: receipt"),
            "grant session must receive receipt frames, body={body}"
        );
        assert_eq!(
            kernel.subscribe_receipts_calls.load(Ordering::SeqCst),
            1,
            "kernel SubscribeReceipts must run for a grant session"
        );

        // Contrast: same grant token on account/state → 401 unauthorized.
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/account/state")
                    .header("authorization", "Bearer grant-session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
    }

    #[tokio::test]
    async fn receipts_stream_missing_bearer_is_401_not_kernel() {
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Ok(vec![Ok(sample_receipt(0x01, "1", 1))])),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(
            kernel.subscribe_receipts_calls.load(Ordering::SeqCst),
            0,
            "missing bearer must fail at the API edge before any kernel call"
        );
    }

    #[tokio::test]
    async fn receipts_stream_malformed_bearer_is_401_not_410() {
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Ok(vec![Ok(sample_receipt(0x01, "1", 1))])),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .header("authorization", "NotBearer xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.subscribe_receipts_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn receipts_stream_unknown_session_is_410() {
        // Unknown / expired / chan_bind-mismatch → session_expired / 410
        // (same split as GET /v1/proof/<coin_id>; never collapse into 401).
        let status = encode_kernel_error_status(
            Code::Unauthenticated,
            "pull session expired or channel mismatch",
            "session_expired",
            410,
        );
        let secret_token = "super-secret-session-token-never-echo";
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .header("authorization", format!("Bearer {secret_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::GONE);
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "session_expired");
        assert_eq!(kernel.subscribe_receipts_calls.load(Ordering::SeqCst), 1);
        // Token must not appear in the error body (no log/message leakage).
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            !body_str.contains(secret_token),
            "session token must never appear in the error body: {body_str}"
        );
        assert!(
            !json["message"]
                .as_str()
                .unwrap_or("")
                .contains(secret_token),
            "session token must never appear in error message"
        );
    }

    #[tokio::test]
    async fn receipts_stream_chan_bind_mismatch_is_410() {
        // Kernel maps chan_bind mismatch to the same 410 as unknown/expired.
        let status = encode_kernel_error_status(
            Code::Unauthenticated,
            "pull session channel binding mismatch",
            "session_expired",
            410,
        );
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Err(crate::kernel::kernel_status_to_api_error(&status))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .header("authorization", "Bearer sess-chan-mismatch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::GONE);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "session_expired");
        // API still forwarded the authoritative config chan_bind (not Host).
        let req = kernel
            .last_subscribe_receipts
            .lock()
            .expect("mutex")
            .clone()
            .expect("subscribe must have been called");
        assert_eq!(
            req.chan_bind,
            chan_bind_for_host("node.example.com").to_vec()
        );
    }

    #[tokio::test]
    async fn receipts_stream_query_subject_is_ignored() {
        // Request carries no subject field to the kernel; a client-supplied
        // query subject must not change the SubscribeReceiptsRequest.
        let r = sample_receipt(0x44, "7", 1_700_000_400);
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Ok(vec![Ok(r)])),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream?subject=zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq&subject=other")
                    .header("authorization", "Bearer sess-ignore-subject")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let req = kernel
            .last_subscribe_receipts
            .lock()
            .expect("mutex")
            .clone()
            .expect("subscribe must have been called");
        assert_eq!(req.session, "sess-ignore-subject");
        assert_eq!(
            req.chan_bind,
            chan_bind_for_host("node.example.com").to_vec()
        );
        // SubscribeReceiptsRequest has only session + chan_bind — no subject
        // field exists to populate; the capture proves that is all that was sent.
        let _ = req;
    }

    #[tokio::test]
    async fn receipts_stream_client_disconnect_drops_subscription() {
        let kernel = Arc::new(ScriptedKernel {
            subscribe_receipts: Some(Ok(vec![])),
            subscribe_receipts_hang: true,
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .header("authorization", "Bearer sess-drop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            !kernel.subscribe_receipts_dropped.load(Ordering::SeqCst),
            "subscription must still be live while the response is held"
        );
        // Dropping the response body tears down the SSE consumer → gRPC stream.
        drop(res);
        // Allow the async drop path to run.
        tokio::task::yield_now().await;
        assert!(
            kernel.subscribe_receipts_dropped.load(Ordering::SeqCst),
            "client disconnect must drop the kernel SubscribeReceipts stream"
        );
        assert_eq!(kernel.subscribe_receipts_calls.load(Ordering::SeqCst), 1);
    }

    // -----------------------------------------------------------------------
    // Stage D — Bootstrap + Publish
    // -----------------------------------------------------------------------

    use crate::bootstrap::{OPERATIONAL_BUNDLE_HEX_CHARS, OPERATIONAL_BUNDLE_LEN};
    use crate::ownership::{ENTRUST_CHALLENGE_DOMAIN, REVOKE_CHALLENGE_DOMAIN};

    /// Canonical 161-byte version-0x01 bundle as hex (322 chars). Secrets are
    /// zeros — only length/form matters at the API edge in these tests.
    fn sample_bundle_hex() -> String {
        format!("01{}", "00".repeat(160))
    }

    fn bootstrap_ownership_body(
        subject: &str,
        pk0: &[u8; 32],
        nkc: &[u8; 32],
        nonce: &[u8; 32],
        expiry: u64,
        sig: &[u8; 64],
        bundle_hex: Option<&str>,
    ) -> Value {
        let mut obj = serde_json::json!({
            "challenge": {
                "nonce": encode_hex(nonce),
                "expiry": expiry.to_string(),
            },
            "ownership_proof": ownership_proof_json(subject, pk0, nkc, sig),
        });
        if let Some(h) = bundle_hex {
            obj.as_object_mut()
                .expect("object")
                .insert("bundle".into(), Value::String(h.to_string()));
        }
        obj
    }

    #[tokio::test]
    async fn bootstrap_challenge_entrust_and_revoke_return_distinct_domains() {
        let (_, _, _, _, subject_bech) = ownership_fixtures::identity();

        // entrust
        let kernel = Arc::new(ScriptedKernel {
            open_challenge: Some(Ok(Challenge {
                nonce: vec![0xABu8; 32],
                expiry: 1_700_000_060,
                domain: ENTRUST_CHALLENGE_DOMAIN.to_string(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "subject": subject_bech,
                            "action": "entrust",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["domain"], ENTRUST_CHALLENGE_DOMAIN);
        assert_eq!(
            kernel.last_open_challenge_action.lock().unwrap().as_deref(),
            Some("entrust")
        );

        // revoke
        let kernel2 = Arc::new(ScriptedKernel {
            open_challenge: Some(Ok(Challenge {
                nonce: vec![0xCDu8; 32],
                expiry: 1_700_000_120,
                domain: REVOKE_CHALLENGE_DOMAIN.to_string(),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel2.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "subject": subject_bech,
                            "action": "revoke",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["domain"], REVOKE_CHALLENGE_DOMAIN);
        assert_eq!(
            kernel2
                .last_open_challenge_action
                .lock()
                .unwrap()
                .as_deref(),
            Some("revoke")
        );
        assert_ne!(ENTRUST_CHALLENGE_DOMAIN, REVOKE_CHALLENGE_DOMAIN);
        assert_ne!(ENTRUST_CHALLENGE_DOMAIN, PULL_CHALLENGE_DOMAIN);
        assert_ne!(REVOKE_CHALLENGE_DOMAIN, PULL_CHALLENGE_DOMAIN);
    }

    #[tokio::test]
    async fn entrust_signed_proof_rejected_on_revoke_endpoint_no_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x11u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        // Sign under Entrust domain — must not authorise /revoke.
        let chal = pull_challenge_message(
            ChallengeDomain::Entrust.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            revoke: Some(Ok(RevokeResult { revoked: true })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            None,
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(kernel.revoke_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn revoke_signed_proof_rejected_on_entrust_endpoint_no_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x22u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Revoke.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            entrust: Some(Ok(EntrustResult { accepted: true })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let bundle = sample_bundle_hex();
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/entrust")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            Some(&bundle),
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(kernel.entrust_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn entrust_bundle_160_and_162_are_400_161_is_forwarded() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x33u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Entrust.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);

        // 160 bytes → 400, no kernel.
        let kernel = Arc::new(ScriptedKernel {
            entrust: Some(Ok(EntrustResult { accepted: true })),
            ..Default::default()
        });
        let short_hex = "01".to_string() + &"00".repeat(159);
        assert_eq!(short_hex.len(), 320);
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/entrust")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            Some(&short_hex),
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "malformed_request");
        assert_eq!(kernel.entrust_calls.load(Ordering::SeqCst), 0);
        // Secret must not appear in the error body.
        assert!(
            !String::from_utf8_lossy(&body).contains(&short_hex),
            "bundle hex must not appear in error response"
        );

        // 162 bytes → 400, no kernel.
        let long_hex = "01".to_string() + &"00".repeat(161);
        assert_eq!(long_hex.len(), 324);
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/entrust")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            Some(&long_hex),
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(kernel.entrust_calls.load(Ordering::SeqCst), 0);

        // 161 bytes → forwarded.
        let ok_hex = sample_bundle_hex();
        assert_eq!(ok_hex.len(), OPERATIONAL_BUNDLE_HEX_CHARS);
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/entrust")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            Some(&ok_hex),
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["accepted"], true);
        assert_eq!(kernel.entrust_calls.load(Ordering::SeqCst), 1);
        let last = kernel.last_entrust.lock().unwrap();
        let req = last.as_ref().expect("entrust request captured");
        assert_eq!(req.bundle.len(), OPERATIONAL_BUNDLE_LEN);
        assert_eq!(req.bundle[0], 0x01);
        assert_eq!(req.subject, subject_bech);
        assert_eq!(req.nonce, nonce.to_vec());
        assert_eq!(req.chan_bind, cb.to_vec());
    }

    #[tokio::test]
    async fn entrust_auth_failure_response_does_not_contain_bundle_hex() {
        // Distinctive non-zero secret hex — if any error path echoes the body,
        // this substring will show up.
        let marker = "f1e2d3c4b5a69788".repeat(20); // 320 chars of pattern
        let bundle = format!("01{}", &marker[..320]);
        assert_eq!(bundle.len(), 322);

        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x44u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        // Sign under Revoke so Entrust verification fails after bundle parse.
        let chal = pull_challenge_message(
            ChallengeDomain::Revoke.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            entrust: Some(Ok(EntrustResult { accepted: true })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/entrust")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            Some(&bundle),
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = String::from_utf8(body_bytes(res).await).expect("utf8");
        assert!(
            !body.contains(&bundle),
            "full bundle hex must not appear in error body"
        );
        assert!(
            !body.contains("f1e2d3c4b5a69788"),
            "distinctive secret substring must not appear in error body: {body}"
        );
        assert_eq!(kernel.entrust_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn revoke_valid_ownership_calls_kernel() {
        let host = "node.example.com";
        let (sk, pk0, nkc, subject_raw, subject_bech) = ownership_fixtures::identity();
        let nonce = [0x55u8; 32];
        let expiry = 1_700_000_060u64;
        let cb = chan_bind_for_host(host);
        let chal = pull_challenge_message(
            ChallengeDomain::Revoke.as_str(),
            &nonce,
            &cb,
            &subject_raw,
            expiry,
        );
        let sig = ownership_fixtures::sign_chal(&sk, &chal);
        let kernel = Arc::new(ScriptedKernel {
            revoke: Some(Ok(RevokeResult { revoked: true })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        bootstrap_ownership_body(
                            &subject_bech,
                            &pk0,
                            &nkc,
                            &nonce,
                            expiry,
                            &sig,
                            None,
                        )
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["revoked"], true);
        assert_eq!(kernel.revoke_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn publish_rejection_is_http_200_with_reason() {
        let kernel = Arc::new(ScriptedKernel {
            publish: Some(Ok(PublishResult {
                accepted: false,
                reason: Some("invalid_signature".into()),
                batch_eta: None,
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "public_key": hex32(0x11),
            "r": hex32(0x22),
            "s": hex32(0x33),
            "r_prime": hex32(0x44),
            "block_anchor": {
                "block_hash": hex32(0x55),
                "height": "100",
            }
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/publish/spendrecord")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "policy/crypto rejection is a successful hand-off result, not 4xx/5xx"
        );
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["accepted"], false);
        assert_eq!(json["reason"], "invalid_signature");
        assert!(json.get("batch_eta").is_none());
        assert!(json.get("error").is_none());
        assert_eq!(kernel.publish_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn publish_accepted_returns_batch_eta() {
        let kernel = Arc::new(ScriptedKernel {
            publish: Some(Ok(PublishResult {
                accepted: true,
                reason: None,
                batch_eta: Some(45),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel).expect("router");
        let body = serde_json::json!({
            "public_key": hex32(0x11),
            "r": hex32(0x22),
            "s": hex32(0x33),
            "r_prime": hex32(0x44),
            "block_anchor": {
                "block_hash": hex32(0x55),
                "height": "42",
            }
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/publish/spendrecord")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["accepted"], true);
        assert_eq!(json["batch_eta"], "45");
        assert!(json.get("reason").is_none());
    }

    #[tokio::test]
    async fn publish_fee_field_is_400_not_silent() {
        let kernel = Arc::new(ScriptedKernel {
            publish: Some(Ok(PublishResult {
                accepted: true,
                reason: None,
                batch_eta: Some(1),
            })),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let body = serde_json::json!({
            "public_key": hex32(0x11),
            "r": hex32(0x22),
            "s": hex32(0x33),
            "r_prime": hex32(0x44),
            "block_anchor": {
                "block_hash": hex32(0x55),
                "height": "100",
            },
            "fee_blob_id": hex32(0x66),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/publish/spendrecord")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        assert_eq!(
            kernel.publish_calls.load(Ordering::SeqCst),
            0,
            "fee field must fail at the edge before any kernel call"
        );
    }

    #[tokio::test]
    async fn unconfigured_blossom_surfaces_remain_404_and_absent_from_discovery() {
        // test_config has blossom: None — Blossom must stay completely off the
        // map: unregistered (bare axum 404, not 404 feature_disabled) and
        // absent from discovery. receipts_stream is always-on (auth fails closed).
        let app = test_app();
        for path in [
            "/blossom/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/blossom/upload",
        ] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "unconfigured Blossom surface {path} must not be registered"
            );
            // Bare axum 404 has no §7.5 JSON body claiming feature_disabled.
            let bytes = body_bytes(res).await;
            if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
                assert_ne!(
                    json.get("error").and_then(|e| e.as_str()),
                    Some("feature_disabled"),
                    "unconfigured Blossom must be bare 404, not feature_disabled: {json}"
                );
            }
        }
        // Always-on receipts stream is registered: missing bearer → 401, not 404.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "receipts_stream must be registered; missing bearer is 401"
        );
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let endpoints = json["endpoints"].as_object().unwrap();
        assert!(
            endpoints.contains_key("receipts_stream"),
            "receipts_stream is always-on and must appear in discovery"
        );
        assert!(!endpoints.contains_key("blossom_get"));
        assert!(!endpoints.contains_key("blossom_upload"));
        assert!(
            endpoints.contains_key("chain_inscriptions"),
            "chain_inscriptions is served and must appear in discovery"
        );
        assert!(endpoints.contains_key("bootstrap_entrust"));
        assert!(endpoints.contains_key("publish_spendrecord"));
    }

    // -----------------------------------------------------------------------
    // chain_inscriptions HTTP surface
    // -----------------------------------------------------------------------

    fn sample_inscription_http(
        height: u64,
        tx_index: u64,
        vin_index: u64,
        confirmation_state: &str,
        member_states: &[&str],
    ) -> Inscription {
        let mut txid = vec![0u8; 32];
        for (i, b) in txid.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x40);
        }
        let nullifiers: Vec<ProtoNullifier> = member_states
            .iter()
            .enumerate()
            .map(|(i, state)| ProtoNullifier {
                pubkey: vec![0xA0 + i as u8; 32],
                r: vec![0xB0 + i as u8; 32],
                state: (*state).to_string(),
            })
            .collect();
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

    #[tokio::test]
    async fn chain_inscriptions_failed_member_completed_confirmation() {
        // The decisive state split: a later Pk collision is failed while the
        // reveal-tx confirmation depth is independently completed.
        let kernel = ScriptedKernel {
            list_inscriptions: Some(Ok(vec![sample_inscription_http(
                50,
                1,
                0,
                "completed",
                &["pending", "failed"],
            )])),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let ins = &json["inscriptions"][0];
        assert_eq!(ins["confirmation_state"], "completed");
        assert_eq!(ins["nullifiers"][0]["state"], "pending");
        assert_eq!(ins["nullifiers"][1]["state"], "failed");
        assert!(
            json.get("next_height").is_none(),
            "single-page result must omit next_*"
        );
    }

    #[tokio::test]
    async fn chain_inscriptions_mid_tx_pagination_three_pages() {
        // Reveal tx (10,0) carries vin 0/1/2; page boundary cuts between them.
        let catalog = vec![
            sample_inscription_http(10, 0, 0, "completed", &["completed"]),
            sample_inscription_http(10, 0, 1, "completed", &["completed"]),
            sample_inscription_http(10, 0, 2, "completed", &["failed"]),
            sample_inscription_http(11, 0, 0, "pending", &["pending"]),
        ];
        let kernel = Arc::new(ScriptedKernel {
            list_inscriptions: Some(Ok(catalog)),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");

        // Page 1
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let p1: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(p1["inscriptions"].as_array().unwrap().len(), 1);
        assert_eq!(p1["inscriptions"][0]["vin_index"], 0);
        assert_eq!(p1["next_height"], 10);
        assert_eq!(p1["next_tx_index"], 0);
        assert_eq!(p1["next_vin_index"], 1);
        // PAGE_LOOKAHEAD: kernel received limit+1
        // Option<ListInscriptionsRequest> is Copy — take by value, no clone.
        let last_req =
            (*kernel.last_list_inscriptions.lock().expect("mutex")).expect("list called");
        assert_eq!(last_req.limit, Some(2), "PAGE_LOOKAHEAD sends limit+1");

        // Page 2 — exclusive next of p1 is inclusive from
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions?from_height=10&from_tx_index=0&from_vin_index=1&limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let p2: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(p2["inscriptions"][0]["vin_index"], 1);
        assert_eq!(p2["inscriptions"][0]["height"], 10);
        assert_eq!(p2["inscriptions"][0]["tx_index"], 0);
        assert_eq!(p2["next_height"], 10);
        assert_eq!(p2["next_tx_index"], 0);
        assert_eq!(p2["next_vin_index"], 2);

        // Page 3
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions?from_height=10&from_tx_index=0&from_vin_index=2&limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let p3: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(p3["inscriptions"][0]["vin_index"], 2);
        assert_eq!(p3["next_height"], 11);
        assert_eq!(p3["next_tx_index"], 0);
        assert_eq!(p3["next_vin_index"], 0);
        // Three distinct triples, mid-tx split, no gap between p1→p2→p3.
        // Typed .get/.as_u64 — Index sugar yields a place of type Value; packing
        // three places into a by-value tuple would move out of the JSON tree.
        let vin_at = |page: &Value, label: &str| -> u64 {
            page.get("inscriptions")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|ins| ins.get("vin_index"))
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| {
                    panic!("{label}: inscriptions[0].vin_index must be present as u64")
                })
        };
        assert_eq!(
            (vin_at(&p1, "p1"), vin_at(&p2, "p2"), vin_at(&p3, "p3")),
            (0, 1, 2),
            "mid-reveal-tx pages must cover vin 0,1,2 without gap or duplicate"
        );
    }

    #[tokio::test]
    async fn chain_inscriptions_limit_zero_is_bounds_exceeded() {
        let kernel = ScriptedKernel {
            list_inscriptions: Some(Ok(Vec::new())),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "bounds_exceeded");
        assert!(
            json["message"].as_str().unwrap().contains("limit"),
            "message must name limit, got {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn chain_inscriptions_limit_non_numeric_is_malformed() {
        let kernel = ScriptedKernel {
            list_inscriptions: Some(Ok(Vec::new())),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions?limit=nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
    }

    #[tokio::test]
    async fn chain_inscriptions_defaults_normalised_before_rpc() {
        let kernel = Arc::new(ScriptedKernel {
            list_inscriptions: Some(Ok(Vec::new())),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone()).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chain/inscriptions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // Option<ListInscriptionsRequest> is Copy — take by value, no clone.
        let req = (*kernel.last_list_inscriptions.lock().expect("mutex")).expect("list called");
        // API normalises defaults before RPC — all fields are Some.
        assert_eq!(req.from_height, Some(0));
        assert_eq!(req.from_tx_index, Some(0));
        assert_eq!(req.from_vin_index, Some(0));
        // PAGE_LOOKAHEAD: default rest limit 100 → kernel limit 101
        assert_eq!(req.limit, Some(101));
    }

    // -----------------------------------------------------------------------
    // §7.4 Blossom surface (configured store only)
    // -----------------------------------------------------------------------

    fn blossom_temp_root(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "zkcoins-blossom-rt-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn blossom_app(root: std::path::PathBuf, max: u64, ops: BTreeSet<[u8; 32]>) -> Router {
        // Blossom mounts only with store **and** wallet|explorer (§6.1 / §7.4).
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::from([Feature::Explorer, Feature::Wallet]),
            public_hosts: vec!["node.example.com".to_string()],
            blossom: Some(crate::config::BlossomConfig {
                store_root: root,
                max_blob_bytes: max,
                allowed_upload_ops: ops,
            }),
        };
        build_router(cfg, Arc::new(UnreachableKernel)).expect("router")
    }

    /// Boot must not panic when the Blossom store root cannot be opened —
    /// same fail-closed class as other start errors.
    #[test]
    fn build_router_blossom_open_failure_is_startup_error_not_panic() {
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::from([Feature::Explorer]),
            public_hosts: vec!["node.example.com".to_string()],
            blossom: Some(crate::config::BlossomConfig {
                // Regular file path cannot be a store root directory.
                store_root: std::env::temp_dir().join(format!(
                    "zkcoins-not-a-dir-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )),
                max_blob_bytes: 1024,
                allowed_upload_ops: BTreeSet::new(),
            }),
        };
        // Create a *file* at store_root so open fails "not a directory".
        let path = cfg.blossom.as_ref().unwrap().store_root.clone();
        std::fs::write(&path, b"not-a-directory").unwrap();
        let err = build_router(cfg, Arc::new(UnreachableKernel)).expect_err("must not panic");
        assert!(
            err.message.contains("blossom store"),
            "startup error must name blossom store: {}",
            err.message
        );
        let _ = std::fs::remove_file(&path);
    }

    fn blossom_sk_pk() -> (bitcoin::secp256k1::SecretKey, [u8; 32]) {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x7au8; 32]).expect("secret");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        (sk, xonly.serialize())
    }

    fn blossom_auth(
        sk: &bitcoin::secp256k1::SecretKey,
        pk: &[u8; 32],
        action: crate::blossom::AuthAction,
        x: &[u8; 32],
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let b64 = crate::blossom::sign_auth_event_base64(sk, pk, action, x, now, now + 120);
        format!("Nostr {b64}")
    }

    #[tokio::test]
    async fn blossom_upload_get_head_roundtrip_bit_equal() {
        let root = blossom_temp_root("roundtrip");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let app = blossom_app(root.clone(), 1_048_576, ops);
        let body = b"ciphertext-bytes-for-roundtrip".to_vec();
        let x = crate::blossom::blob_id_of(&body);
        let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/octet-stream")
                    .header("authorization", &auth)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["blob_id"], crate::hexutil::encode_hex(&x));
        assert!(
            json.get("receipt").is_none(),
            "receipt must be absent without §4.6, got {json}"
        );

        let get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/blossom/{}", crate::hexutil::encode_hex(&x)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(get).await,
            body,
            "GET must return bit-equal body"
        );

        let head = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!("/blossom/{}", crate::hexutil::encode_hex(&x)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        let len = head
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!(len, body.len().to_string());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn blossom_second_upload_same_bytes_is_idempotent() {
        let root = blossom_temp_root("idempotent");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let app = blossom_app(root.clone(), 1024, ops);
        let body = b"same-bytes-twice";
        let x = crate::blossom::blob_id_of(body);
        for _ in 0..2 {
            let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/blossom/upload")
                        .header("content-type", "application/octet-stream")
                        .header("authorization", &auth)
                        .body(Body::from(body.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
            assert_eq!(json["blob_id"], crate::hexutil::encode_hex(&x));
        }
        let store = crate::blossom::BlobStore::open(&root).unwrap();
        let names = store.list_root_names().unwrap();
        let blob_files: Vec<_> = names
            .iter()
            .filter(|n| n.len() == 64 && !n.contains('.'))
            .collect();
        assert_eq!(blob_files.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn blossom_path_traversal_is_400_and_does_not_touch_outside() {
        let root = blossom_temp_root("traversal");
        let outside = root
            .parent()
            .unwrap()
            .join(format!("zkcoins-blossom-outside-{}", std::process::id()));
        std::fs::write(&outside, b"sentinel").unwrap();
        let outside_before = std::fs::read(&outside).unwrap();
        let app = blossom_app(root.clone(), 1024, BTreeSet::new());
        let store_before = crate::blossom::BlobStore::open(&root)
            .unwrap()
            .list_root_names()
            .unwrap();

        for bad in [
            format!("/blossom/{}", "A".repeat(64)),
            format!("/blossom/{}", "a".repeat(63)),
            format!("/blossom/{}", "a".repeat(65)),
            "/blossom/../etc/passwd".to_string(),
        ] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(&bad).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert!(
                res.status() == StatusCode::BAD_REQUEST || res.status() == StatusCode::NOT_FOUND,
                "path {bad} → {}",
                res.status()
            );
            if res.status() == StatusCode::BAD_REQUEST {
                let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
                assert_eq!(json["error"], "malformed_request");
            }
        }

        let store_after = crate::blossom::BlobStore::open(&root)
            .unwrap()
            .list_root_names()
            .unwrap();
        assert_eq!(store_before, store_after);
        assert_eq!(std::fs::read(&outside).unwrap(), outside_before);
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn blossom_upload_rejects_non_peer_op_with_403() {
        let root = blossom_temp_root("nonpeer");
        let (sk, pk) = blossom_sk_pk();
        let app = blossom_app(root.clone(), 1024, BTreeSet::new());
        let body = b"not-a-peer";
        let x = crate::blossom::blob_id_of(body);
        let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
        let res = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/octet-stream")
                    .header("authorization", &auth)
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "scope_exceeded");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn blossom_upload_rejects_oversize_with_413() {
        let root = blossom_temp_root("oversize");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let app = blossom_app(root.clone(), 4, ops);
        let body = b"12345";
        let x = crate::blossom::blob_id_of(body);
        let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
        let res = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/octet-stream")
                    .header("authorization", &auth)
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "payload_too_large");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Bodies far above the limit (not only max+1) must still answer with the
    /// §7.5 JSON `payload_too_large` body — not axum's plain-text 413.
    #[tokio::test]
    async fn blossom_upload_rejects_far_oversize_with_413_json() {
        let root = blossom_temp_root("far-oversize");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let max = 16u64;
        let app = blossom_app(root.clone(), max, ops);
        // Several times the limit so DefaultBodyLimit trips well past max+1.
        let body = vec![0xabu8; (max as usize) * 64];
        let x = crate::blossom::blob_id_of(&body);
        let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
        let res = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/octet-stream")
                    .header("authorization", &auth)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "far-oversize must return §7.5 JSON, not plain text: {e}; body={:?}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(json["error"], "payload_too_large");
        assert!(json.get("message").is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Non-tx JSON handlers must also map bad content-type to §7.5 JSON
    /// (not axum's default 415/422 body).
    #[tokio::test]
    async fn post_sign_missing_json_content_type_is_malformed_request() {
        let kernel = ScriptedKernel {
            sign: Some(Ok(accepted_job("job-ct"))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/jobs/job-ct/sign")
                    .body(Body::from(r#"{"signature":"aa","s2c_nonce":"bb"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
    }

    /// Unknown job status from the kernel is fail-closed 500 (not forwarded
    /// as a non-terminal poll with Retry-After).
    #[tokio::test]
    async fn get_job_unknown_status_is_500_internal() {
        let kernel = ScriptedKernel {
            get: Some(Ok({
                let mut j = accepted_job("j-bad");
                j.status = "not_a_status".into();
                j
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel)).expect("router");
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/jobs/j-bad")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "internal_error");
        assert_eq!(json["message"], crate::error::PUBLIC_INTERNAL_MESSAGE);
    }

    #[tokio::test]
    async fn blossom_upload_rejects_json_content_type_as_malformed_request() {
        let root = blossom_temp_root("jsonct");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let app = blossom_app(root.clone(), 1024, ops);
        let body = b"{}";
        let x = crate::blossom::blob_id_of(body);
        let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
        let res = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/json")
                    .header("authorization", &auth)
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // §7.4 non-conforming form → 400 malformed_request (closed §7.5 set).
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "malformed_request");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Data permanence: DELETE is not registered. Path may match GET/HEAD so
    /// axum answers 405 Method Not Allowed; a bare 404 is also acceptable if
    /// the method is not merged onto the route table. The stored blob must
    /// remain readable after any DELETE attempt.
    #[tokio::test]
    async fn blossom_delete_is_not_registered_and_blob_persists() {
        let root = blossom_temp_root("delgone");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let app = blossom_app(root.clone(), 1024, ops);
        let body = b"must-survive-delete-attempt";
        let x = crate::blossom::blob_id_of(body);
        let auth_up = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/octet-stream")
                    .header("authorization", &auth_up)
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["blob_id"], crate::hexutil::encode_hex(&x));
        assert!(
            json.get("receipt").is_none(),
            "upload must not emit receipt, got {json}"
        );

        let del = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/blossom/{}", crate::hexutil::encode_hex(&x)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            del.status() == StatusCode::METHOD_NOT_ALLOWED || del.status() == StatusCode::NOT_FOUND,
            "DELETE must not succeed; got {}",
            del.status()
        );

        let get = app
            .oneshot(
                Request::builder()
                    .uri(format!("/blossom/{}", crate::hexutil::encode_hex(&x)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(get).await,
            body,
            "blob must remain after DELETE attempt"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn blossom_discovery_keys_bound_to_configuration() {
        // Without store (test_config): absent.
        let app = test_app();
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let endpoints = json["endpoints"].as_object().unwrap();
        for k in [
            "blossom_get",
            "blossom_head",
            "blossom_upload",
            "blossom_delete",
        ] {
            assert!(!endpoints.contains_key(k), "{k} unadvertised without store");
        }

        // With store: get/head/upload present; delete never advertised.
        let root = blossom_temp_root("disc");
        let app = blossom_app(root.clone(), 1024, BTreeSet::new());
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        let endpoints = json["endpoints"].as_object().unwrap();
        assert_eq!(endpoints["blossom_get"], "/blossom/<sha256>");
        assert_eq!(endpoints["blossom_head"], "/blossom/<sha256>");
        assert_eq!(endpoints["blossom_upload"], "/blossom/upload");
        assert!(
            !endpoints.contains_key("blossom_delete"),
            "data permanence: blossom_delete must never be advertised"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Receipt-binding headers are ignored (no §4.6); upload still returns
    /// only `{ blob_id }` with no `receipt` field.
    #[tokio::test]
    async fn blossom_upload_ignores_legacy_binding_headers_and_omits_receipt() {
        let root = blossom_temp_root("bindok");
        let (sk, pk) = blossom_sk_pk();
        let mut ops = BTreeSet::new();
        ops.insert(pk);
        let app = blossom_app(root.clone(), 1024, ops);
        let body = b"with-legacy-binding-headers";
        let x = crate::blossom::blob_id_of(body);
        let auth = blossom_auth(&sk, &pk, crate::blossom::AuthAction::Upload, &x);
        let res = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/blossom/upload")
                    .header("content-type", "application/octet-stream")
                    .header("authorization", &auth)
                    .header(
                        "x-zkcoins-event-id",
                        crate::hexutil::encode_hex(&[0xaa; 32]),
                    )
                    .header(
                        "x-zkcoins-attempt-nonce",
                        crate::hexutil::encode_hex(&[0xbb; 32]),
                    )
                    .header("x-zkcoins-retention", "indefinite")
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["blob_id"], crate::hexutil::encode_hex(&x));
        assert!(
            json.get("receipt").is_none(),
            "receipt must be absent, got {json}"
        );
        // Object keys are exactly blob_id (no optional receipt key).
        let obj = json.as_object().expect("object");
        assert_eq!(
            obj.keys().collect::<Vec<_>>(),
            vec!["blob_id"],
            "upload body must be only {{ blob_id }}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

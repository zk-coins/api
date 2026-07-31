//! HTTP routes that this process actually serves.
//!
//! Route registration and the `GET /` discovery document share one source:
//! [`ServedSurface`]. The closed §7.5 inventory ([`CLOSED_ENDPOINT_KEYS`]) is
//! the full key catalogue for surfaces not yet built; only keys present in
//! `ServedSurface::ALL` are registered and advertised.
//!
//! Inventory paths are the **advertised** §7.5 form (`<name>` placeholders).
//! Axum registration uses a derived **matcher** form (`:name`); see
//! [`advertised_path_to_axum_matcher`].

use crate::attest;
use crate::chain;
use crate::config::Config;
use crate::grants;
use crate::info;
use crate::jobs;
use crate::kernel::KernelHandle;
use crate::state::AppState;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Closed `endpoints` key set from specification §7.5 (`GET /` row).
///
/// Full inventory of the 29 logical names a conforming producer may emit.
/// Order matches the spec listing (line 2874). This constant is the reference
/// for surfaces not yet built; it is **not** what `GET /` returns.
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
    ("blossom_delete", "/blossom/<sha256>"),
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
/// Feature gating (§6.1): further inventory keys belong to `wallet` /
/// `explorer` / `publisher`. This stage's job surface and the info/chain
/// read surface are always-on once the handlers exist — the operator still
/// must set `ZKCOINS_KERNEL_ADDR`. When capability-gated or role-optional
/// handlers land, registration will filter `ServedSurface` by
/// `Config::features`.
///
/// `chain_inscriptions` is intentionally **not** a variant: `ListInscriptions`
/// is Unimplemented in the node until a scanner-written inscription catalog
/// exists; advertising a REST key that can only 501 is not progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServedSurface {
    Health,
    HealthReady,
    Info,
    ChainAccumulator,
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
}

impl ServedSurface {
    /// Every surface this binary currently serves.
    const ALL: &[ServedSurface] = &[
        ServedSurface::Health,
        ServedSurface::HealthReady,
        ServedSurface::Info,
        ServedSurface::ChainAccumulator,
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
    ];

    /// Closed §7.5 discovery key for this surface.
    fn discovery_key(self) -> &'static str {
        match self {
            ServedSurface::Health => "health",
            ServedSurface::HealthReady => "health_ready",
            ServedSurface::Info => "info",
            ServedSurface::ChainAccumulator => "chain_accumulator",
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
        }
    }

    /// Attach this surface's handler to the router at the axum matcher path.
    ///
    /// Discovery still advertises the inventory (Spec) form; only the route
    /// table sees the rewritten matcher.
    fn register(self, router: Router<AppState>) -> Router<AppState> {
        let path = advertised_path_to_axum_matcher(closed_path(self.discovery_key()));
        match self {
            ServedSurface::Health => router.route(&path, get(health)),
            ServedSurface::HealthReady => router.route(&path, get(info::health_ready)),
            ServedSurface::Info => router.route(&path, get(info::get_info)),
            ServedSurface::ChainAccumulator => router.route(&path, get(chain::get_accumulator)),
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
        }
    }
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

/// Build the `endpoints` map for `GET /` from the served set only.
fn discovery_endpoints() -> BTreeMap<&'static str, &'static str> {
    let mut endpoints = BTreeMap::new();
    for surface in ServedSurface::ALL {
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
/// `config.features` is stored in [`AppState`] for `GET /v1/info` (API-owned
/// advertisement). Route registration is still the always-on
/// [`ServedSurface::ALL`] set; §6.1 feature gating of optional roles lands
/// with those handlers.
///
/// Returns a fully state-bound router (`Router` / `Router<()>`). Only that
/// form implements `tower::Service` and is ready for `axum::serve` and test
/// `oneshot` calls. Handlers extract `State<AppState>` or
/// `State<KernelHandle>` (via [`axum::extract::FromRef`]); the concrete
/// state is supplied once at the end.
pub fn build_router(config: Config, kernel: KernelHandle) -> Router {
    let Config {
        bind_addr: _,
        kernel_addr: _,
        features,
        public_hosts,
    } = config;

    let state = AppState {
        kernel,
        features,
        public_hosts: Arc::new(public_hosts),
    };

    // Register every surface as `Router<AppState>`, then bind state so the
    // returned tree is `Router<()>` and implements `Service`. Binding earlier
    // while still returning `Router<AppState>` leaves the tree "missing"
    // state and breaks both `axum::serve` and `oneshot`.
    let mut router = Router::new().route("/", get(root));
    for surface in ServedSurface::ALL {
        router = surface.register(router);
    }
    router.with_state(state)
}

async fn health() -> Response {
    (StatusCode::OK, "ok").into_response()
}

async fn root() -> Json<RootResponse> {
    Json(RootResponse {
        name: "zkcoins-api",
        version: env!("CARGO_PKG_VERSION"),
        endpoints: discovery_endpoints(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Feature};
    use crate::error::ApiError;
    use crate::kernel::encode_kernel_error_status;
    use crate::kernel::kernel_v1::{
        AccumulatorTip, AttestRequest, BootstrapManifest, Challenge, GrantRequest, GrantResult,
        Info, Job, JobEvent, JobHandle, JobRequest, NullifierPath, NullifierPathRequest,
        PullChallengeRequest, SignRequest, TransitionRequest,
    };
    use crate::kernel::KernelRpc;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures_util::stream::{self, BoxStream};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tonic::Code;
    use tower::ServiceExt;

    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::new(),
            public_hosts: vec!["node.example.com".to_string()],
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
    }

    fn test_app() -> Router {
        build_router(test_config(), Arc::new(UnreachableKernel))
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
        "blossom_delete",
    ];

    #[test]
    fn closed_endpoint_keys_inventory_matches_spec() {
        assert_eq!(
            CLOSED_ENDPOINT_KEYS.len(),
            29,
            "CLOSED_ENDPOINT_KEYS must list all 29 §7.5 closed keys"
        );
        assert_eq!(
            SPEC_CLOSED_KEYS.len(),
            29,
            "spec key list fixture must stay in sync with §7.5 L2874"
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
        assert_eq!(keys.len(), 29, "closed keys must be unique");
    }

    #[test]
    fn every_served_surface_is_in_closed_inventory() {
        for surface in ServedSurface::ALL {
            let key = surface.discovery_key();
            let path = closed_path(key);
            assert!(
                !path.is_empty(),
                "served key {key} must resolve to a non-empty inventory path"
            );
        }
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

        let expected_keys: BTreeSet<&str> = ServedSurface::ALL
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
            ]),
            "stage C1 adds the four attest/grants keys to the prior job+info surface"
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
        // chain_inscriptions must not be advertised until ListInscriptions exists.
        assert!(
            !endpoints.contains_key("chain_inscriptions"),
            "chain_inscriptions must stay unadvertised while the node catalog is missing"
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
        // Documented omission: ListInscriptions is Unimplemented in the node
        // (no scanner catalog). REST must not advertise or soft-serve it.
        let app = test_app();
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
            StatusCode::NOT_FOUND,
            "GET /v1/chain/inscriptions must not be registered without a catalog"
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
            !endpoints.contains_key("chain_inscriptions"),
            "unbuilt surface 'chain_inscriptions' must be omitted from GET / endpoints"
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
        };
        let app = build_router(cfg, Arc::new(UnreachableKernel));
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

        // Wallet feature does not yet open extra surfaces beyond the job set
        // (already always-on). Unbuilt wallet keys stay unadvertised.
        let app = build_router(
            Config {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                kernel_addr: "http://kernel:1".to_string(),
                features: BTreeSet::from([Feature::Wallet]),
                public_hosts: vec!["node.example.com".to_string()],
            },
            Arc::new(UnreachableKernel),
        );
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON root body");
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            endpoints.contains_key("tx"),
            "job surface key 'tx' must be advertised once the handler exists"
        );
        assert!(
            !endpoints.contains_key("pull"),
            "wallet feature must not advertise /v1/pull before that handler exists"
        );
    }

    // -----------------------------------------------------------------------
    // Job-surface handler tests against an honest in-trait kernel double
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct ScriptedKernel {
        submit: Option<Result<JobHandle, ApiError>>,
        get: Option<Result<Job, ApiError>>,
        stream: Option<Result<Vec<Result<JobEvent, ApiError>>, ApiError>>,
        sign: Option<Result<Job, ApiError>>,
        cancel: Option<Result<Job, ApiError>>,
        info: Option<Result<Info, ApiError>>,
        accumulator: Option<Result<AccumulatorTip, ApiError>>,
        nullifier_path: Option<Result<NullifierPath, ApiError>>,
        open_challenge: Option<Result<Challenge, ApiError>>,
        attest: Option<Result<JobHandle, ApiError>>,
        issue_grant: Option<Result<GrantResult, ApiError>>,
        /// Call counters for proving "no kernel call" on auth failure.
        attest_calls: AtomicUsize,
        issue_grant_calls: AtomicUsize,
        open_challenge_calls: AtomicUsize,
    }

    #[async_trait]
    impl KernelRpc for ScriptedKernel {
        async fn submit_transition(&self, _req: TransitionRequest) -> Result<JobHandle, ApiError> {
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
            _req: PullChallengeRequest,
        ) -> Result<Challenge, ApiError> {
            self.open_challenge_calls.fetch_add(1, Ordering::SeqCst);
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
                "amount": "1000"
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
        let app = build_router(test_config(), Arc::new(kernel));
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

    #[tokio::test]
    async fn post_tx_fee_address_is_malformed_400() {
        let kernel = ScriptedKernel {
            submit: Some(Ok(JobHandle {
                job_id: "x".into(),
                status: "accepted".into(),
            })),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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

    #[tokio::test]
    async fn get_job_happy_path() {
        let kernel = ScriptedKernel {
            get: Some(Ok(accepted_job("job-2"))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
            body.contains("kernel stream dropped"),
            "error event must carry the cause message, body={body}"
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        };
        let app = build_router(cfg, Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("Chain identity unavailable"),
            "message must carry the kernel cause, got {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn health_ready_true_is_200() {
        let kernel = ScriptedKernel {
            info: Some(Ok(sample_info(true, None))),
            ..Default::default()
        };
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("Chain view unavailable"),
            "message must name the cause, got {}",
            json["message"]
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("Failed to build nullifier path"),
            "message must carry the kernel cause, got {}",
            json["message"]
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
        let app = build_router(test_config(), Arc::new(kernel));
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel.clone());
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

        // Signature is valid; kernel reports challenge_expired via ErrorInfo.
        let expired = encode_kernel_error_status(
            tonic::Code::FailedPrecondition,
            "challenge nonce expired",
            "challenge_expired",
            410,
        );
        let kernel = Arc::new(ScriptedKernel {
            attest: Some(Err(crate::kernel::kernel_status_to_api_error(&expired))),
            ..Default::default()
        });
        let app = build_router(test_config(), kernel.clone());
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
        let (_sk, pk0, nkc, _subject_raw, subject_bech) = ownership_fixtures::identity();
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
        let app = build_router(test_config(), kernel.clone());
        let body = serde_json::json!({
            "subject": subject_bech,
            "asset_id": encode_hex(&[0u8; 32]),
            "challenge": {
                "nonce": encode_hex(&[1u8; 32]),
                "expiry": "100",
            },
            "ownership_proof": {
                "type": "grant",
                "subject": subject_bech,
                "public_key": encode_hex(&pk0),
                "nk_commit": encode_hex(&nkc),
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
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let json: Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert!(json["message"].as_str().unwrap().contains("GrantProof"));
        assert_eq!(kernel.attest_calls.load(Ordering::SeqCst), 0);
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel.clone());
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
        let app = build_router(test_config(), kernel2);
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
}

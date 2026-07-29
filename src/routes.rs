//! HTTP routes that this process actually serves.
//!
//! Route registration and the `GET /` discovery document share one source:
//! [`ServedSurface`]. The closed §7.5 inventory ([`CLOSED_ENDPOINT_KEYS`]) is
//! the full key catalogue for surfaces not yet built; only keys present in
//! `ServedSurface::ALL` are registered and advertised.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::config::Config;

/// Closed `endpoints` key set from specification §7.5 (`GET /` row).
///
/// Full inventory of the 29 logical names a conforming producer may emit.
/// Order matches the spec listing (line 2874). This constant is the reference
/// for surfaces not yet built; it is **not** what `GET /` returns.
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
/// Feature gating (§6.1): several inventory keys belong to `wallet` /
/// `explorer` / `publisher`. Those handlers do not exist yet, so
/// `Config::features` is not consulted here. When they land, registration
/// will filter `ServedSurface` by feature; advertising will follow
/// automatically because discovery reads the same set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServedSurface {
    Health,
}

impl ServedSurface {
    /// Every surface this binary currently serves.
    const ALL: &[ServedSurface] = &[ServedSurface::Health];

    /// Closed §7.5 discovery key for this surface.
    fn discovery_key(self) -> &'static str {
        match self {
            ServedSurface::Health => "health",
        }
    }

    /// Attach this surface's handler to the router at the inventory path.
    fn register(self, router: Router) -> Router {
        match self {
            ServedSurface::Health => {
                let path = closed_path(self.discovery_key());
                router.route(path, get(health))
            }
        }
    }
}

/// Look up the canonical path for a closed §7.5 key.
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

/// Build the axum router for the given configuration.
///
/// `config` is retained so feature-gated surfaces can join the same
/// registration path later. Today only always-on surfaces (`health`) are
/// served; §6.1 features open no extra routes until those handlers exist.
/// Reading `config.features` now would either advertise keys without
/// handlers or filter nothing — both dishonest — so it is intentionally
/// unread.
pub fn build_router(config: Config) -> Router {
    // Intentionally unread: feature-gated registration lands with the handlers.
    let Config {
        bind_addr: _,
        kernel_addr: _,
        features: _,
    } = config;

    let mut router = Router::new().route("/", get(root));
    for surface in ServedSurface::ALL {
        router = surface.register(router);
    }
    router
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://127.0.0.1:50051".to_string(),
            features: BTreeSet::new(),
        }
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
        // Inventory gate: the constant is the full §7.5 catalogue, independent
        // of what this process currently serves or advertises.
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
        }
        // `/` is discovery itself and has no closed key.
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
        let app = build_router(test_config());
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
        let app = build_router(test_config());
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
        // Today: only health. This assertion documents the honest scaffold.
        assert_eq!(
            actual_keys,
            BTreeSet::from(["health"]),
            "scaffold serves only the always-on health surface"
        );
        assert_eq!(
            endpoints["health"].as_str(),
            Some("/health"),
            "health path must match CLOSED_ENDPOINT_KEYS inventory"
        );
    }

    /// Would have been **red** on the old code: the old `root()` advertised all
    /// 29 inventory keys (including `/v1/info`, `/v1/tx`, …) while
    /// `build_router` only registered `/` and `/health`. Hitting each
    /// advertised path therefore produced 404 for every key except `health`.
    #[tokio::test]
    async fn every_advertised_endpoint_is_reachable() {
        // Build once to read discovery, then probe each advertised path on a
        // fresh router (oneshot consumes the service).
        let discovery = {
            let app = build_router(test_config());
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

        for (key, path) in &discovery {
            // Inventory templates may contain `<param>`; served paths today
            // are concrete. Refuse to probe templates — they are not registered.
            assert!(
                !path.contains('<'),
                "advertised path for {key} still has a template placeholder: {path}"
            );

            let app = build_router(test_config());
            let res = app
                .oneshot(
                    Request::builder()
                        .uri(path.as_str())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                res.status(),
                StatusCode::NOT_FOUND,
                "GET / advertised key {key:?} at path {path:?}, but the router \
                 returned 404 — discovery and registration have diverged"
            );
        }
    }

    #[tokio::test]
    async fn unregistered_info_is_404_and_absent_from_discovery() {
        // Honesty: GET /v1/info is a documented inventory gap, not a fake handler,
        // and must not appear in the discovery document either.
        let app = build_router(test_config());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "GET /v1/info must not be a placeholder route"
        );

        let app = build_router(test_config());
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON root body");
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            !endpoints.contains_key("info"),
            "unregistered surface 'info' must be omitted from GET / endpoints"
        );
        assert!(
            !endpoints.contains_key("health_ready"),
            "unregistered surface 'health_ready' must be omitted from GET / endpoints"
        );
    }

    #[tokio::test]
    async fn router_accepts_config_with_features() {
        // Features do not change registration yet; the call must still succeed
        // so the parameter remains part of the public surface.
        let mut features = BTreeSet::new();
        features.insert(Feature::Wallet);
        let cfg = Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://kernel:1".to_string(),
            features,
        };
        let app = build_router(cfg);
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

        // Enabling wallet must not silently advertise wallet-only surfaces.
        let app = build_router(Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            kernel_addr: "http://kernel:1".to_string(),
            features: BTreeSet::from([Feature::Wallet]),
        });
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_bytes(res).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON root body");
        let endpoints = json["endpoints"].as_object().expect("endpoints object");
        assert!(
            !endpoints.contains_key("tx"),
            "wallet feature must not advertise /v1/tx before that handler exists"
        );
    }
}

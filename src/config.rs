//! Fail-closed process configuration from the environment.
//!
//! Required variables (no defaults, no host/port fallbacks):
//! - `ZKCOINS_BIND_ADDR` — HTTP listen address (`host:port`)
//! - `ZKCOINS_KERNEL_ADDR` — kernel gRPC address (opaque non-empty string)
//! - `ZKCOINS_FEATURES` — comma-separated subset of the §6.1 closed feature set
//!   (may be empty string = all features off; unknown token is a start error)
//! - `ZKCOINS_PUBLIC_HOST` — comma-separated authoritative hostnames for
//!   §5.1 `chan_bind` (may be empty string; empty ⇒ OwnershipProof auth fails
//!   loud with no silent localhost). Never taken from a `Host` header.
//!
//! Optional Blossom surface (§7.4) — all-or-nothing:
//! - `ZKCOINS_BLOSSOM_STORE` — filesystem root for the content-addressed store.
//!   **Absent** ⇒ Blossom routes are not mounted and the three discovery keys
//!   are not advertised. **No default path**, no `/tmp` fallback.
//! - When the store is set, these companions are required (fail-closed boot):
//!   - `ZKCOINS_BLOSSOM_MAX_BLOB_BYTES` — advertised upload size limit (`> 0`)
//!   - `ZKCOINS_BLOSSOM_ALLOWED_OPS` — comma-separated lowercase-hex 32-byte
//!     `op` pubkeys allowed to upload (paired accounts + replication peers;
//!     may be empty ⇒ every upload is `403`)

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Closed API feature set from specification §6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    Wallet,
    Explorer,
    Publisher,
    LightningBridge,
    MailBridge,
}

impl Feature {
    pub const ALL: [Feature; 5] = [
        Feature::Wallet,
        Feature::Explorer,
        Feature::Publisher,
        Feature::LightningBridge,
        Feature::MailBridge,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Feature::Wallet => "wallet",
            Feature::Explorer => "explorer",
            Feature::Publisher => "publisher",
            Feature::LightningBridge => "lightning_bridge",
            Feature::MailBridge => "mail_bridge",
        }
    }
}

impl FromStr for Feature {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "wallet" => Ok(Feature::Wallet),
            "explorer" => Ok(Feature::Explorer),
            "publisher" => Ok(Feature::Publisher),
            "lightning_bridge" => Ok(Feature::LightningBridge),
            "mail_bridge" => Ok(Feature::MailBridge),
            other => Err(ConfigError::UnknownFeature(other.to_string())),
        }
    }
}

/// Optional §7.4 Blossom store configuration.
///
/// Present only when `ZKCOINS_BLOSSOM_STORE` is set. Absence means the three
/// Blossom discovery keys stay unadvertised and the routes stay unmounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlossomConfig {
    /// Content-addressed store root on the local filesystem.
    pub store_root: PathBuf,
    /// Advertised maximum upload body size in bytes (`> 0`).
    pub max_blob_bytes: u64,
    /// `op` pubkeys (32 raw bytes) allowed to PUT/POST — paired accounts and
    /// configured replication peers. Empty set ⇒ every upload is `403`.
    pub allowed_upload_ops: BTreeSet<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// HTTP bind address. Parsed as `SocketAddr` so empty/garbage fails loudly.
    pub bind_addr: SocketAddr,
    /// Kernel gRPC target URI; dialled at process start via connect_lazy (no default host/port).
    pub kernel_addr: String,
    /// Enabled API features (§6.1 closed set). Empty = all off.
    pub features: BTreeSet<Feature>,
    /// Authoritative public hostnames for §5.1 `chan_bind` (canonical form).
    /// Derived only from `ZKCOINS_PUBLIC_HOST` — never from request headers.
    pub public_hosts: Vec<String>,
    /// §7.4 Blossom surface. `None` when `ZKCOINS_BLOSSOM_STORE` is unset.
    pub blossom: Option<BlossomConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingEnv(&'static str),
    EmptyEnv(&'static str),
    InvalidBindAddr { value: String, reason: String },
    UnknownFeature(String),
    InvalidBlossomMaxBlobBytes { value: String, reason: String },
    InvalidBlossomAllowedOp { value: String, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingEnv(name) => {
                write!(f, "required environment variable {name} is not set")
            }
            ConfigError::EmptyEnv(name) => {
                write!(f, "required environment variable {name} is set but empty")
            }
            ConfigError::InvalidBindAddr { value, reason } => {
                write!(
                    f,
                    "ZKCOINS_BIND_ADDR value {value:?} is not a valid socket address: {reason}"
                )
            }
            ConfigError::UnknownFeature(name) => {
                write!(
                    f,
                    "unknown feature {name:?}; allowed values are wallet, explorer, publisher, lightning_bridge, mail_bridge"
                )
            }
            ConfigError::InvalidBlossomMaxBlobBytes { value, reason } => {
                write!(
                    f,
                    "ZKCOINS_BLOSSOM_MAX_BLOB_BYTES value {value:?} is invalid: {reason}"
                )
            }
            ConfigError::InvalidBlossomAllowedOp { value, reason } => {
                write!(
                    f,
                    "ZKCOINS_BLOSSOM_ALLOWED_OPS entry {value:?} is invalid: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

const ENV_BIND: &str = "ZKCOINS_BIND_ADDR";
const ENV_KERNEL: &str = "ZKCOINS_KERNEL_ADDR";
const ENV_FEATURES: &str = "ZKCOINS_FEATURES";
const ENV_PUBLIC_HOST: &str = "ZKCOINS_PUBLIC_HOST";
/// Optional gate for the §7.4 Blossom surface. Absent ⇒ not advertised.
const ENV_BLOSSOM_STORE: &str = "ZKCOINS_BLOSSOM_STORE";
/// Required companion when `ZKCOINS_BLOSSOM_STORE` is set.
const ENV_BLOSSOM_MAX_BLOB_BYTES: &str = "ZKCOINS_BLOSSOM_MAX_BLOB_BYTES";
/// Required companion when `ZKCOINS_BLOSSOM_STORE` is set (may be empty).
const ENV_BLOSSOM_ALLOWED_OPS: &str = "ZKCOINS_BLOSSOM_ALLOWED_OPS";

impl Config {
    /// Load configuration from process environment. Fail-closed: every required
    /// variable must be present; bind/kernel must be non-empty; features must
    /// be a (possibly empty) subset of the closed set.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_getter(|key| env::var(key).ok())
    }

    /// Testable entry: same rules as `from_env`, driven by an arbitrary getter.
    /// A missing key is `None`; present-but-empty is `Some("")`.
    pub fn from_getter<F>(mut get: F) -> Result<Self, ConfigError>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let bind_raw = require_present(&mut get, ENV_BIND)?;
        let kernel_raw = require_present(&mut get, ENV_KERNEL)?;
        let features_raw = require_present(&mut get, ENV_FEATURES)?;
        let public_host_raw = require_present(&mut get, ENV_PUBLIC_HOST)?;

        if bind_raw.is_empty() {
            return Err(ConfigError::EmptyEnv(ENV_BIND));
        }
        if kernel_raw.is_empty() {
            return Err(ConfigError::EmptyEnv(ENV_KERNEL));
        }
        // FEATURES and PUBLIC_HOST may be empty. They must still be *set*.
        // Empty PUBLIC_HOST ⇒ no authoritative chan_bind (auth fails loud).

        let bind_addr =
            bind_raw
                .parse::<SocketAddr>()
                .map_err(|e| ConfigError::InvalidBindAddr {
                    value: bind_raw.clone(),
                    reason: e.to_string(),
                })?;

        let features = parse_features(&features_raw)?;
        let public_hosts = parse_public_hosts(&public_host_raw);
        let blossom = parse_blossom_config(&mut get)?;

        Ok(Config {
            bind_addr,
            kernel_addr: kernel_raw,
            features,
            public_hosts,
            blossom,
        })
    }
}

fn require_present<F>(get: &mut F, key: &'static str) -> Result<String, ConfigError>
where
    F: FnMut(&str) -> Option<String>,
{
    match get(key) {
        None => Err(ConfigError::MissingEnv(key)),
        Some(v) => Ok(v),
    }
}

fn parse_features(raw: &str) -> Result<BTreeSet<Feature>, ConfigError> {
    let mut out = BTreeSet::new();
    for part in raw.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        out.insert(Feature::from_str(token)?);
    }
    Ok(out)
}

/// Canonicalise authoritative hosts for `chan_bind` (§5.1): lowercase ASCII,
/// trailing dot stripped. Empty tokens dropped. No localhost default.
fn parse_public_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Optional Blossom surface. `None` only when `ZKCOINS_BLOSSOM_STORE` is
/// **unset**. Present-but-empty store is an error (no silent `/tmp` default).
/// When the store is set, max-blob and allowed-ops companions are required.
fn parse_blossom_config<F>(get: &mut F) -> Result<Option<BlossomConfig>, ConfigError>
where
    F: FnMut(&str) -> Option<String>,
{
    let store_raw = match get(ENV_BLOSSOM_STORE) {
        None => return Ok(None),
        Some(v) => v,
    };
    if store_raw.is_empty() {
        return Err(ConfigError::EmptyEnv(ENV_BLOSSOM_STORE));
    }

    let max_raw = require_present(get, ENV_BLOSSOM_MAX_BLOB_BYTES)?;
    if max_raw.is_empty() {
        return Err(ConfigError::EmptyEnv(ENV_BLOSSOM_MAX_BLOB_BYTES));
    }
    let max_blob_bytes = parse_max_blob_bytes(&max_raw)?;

    let ops_raw = require_present(get, ENV_BLOSSOM_ALLOWED_OPS)?;
    // Empty string is allowed: surface is up, but every upload is 403.
    let allowed_upload_ops = parse_allowed_ops(&ops_raw)?;

    Ok(Some(BlossomConfig {
        store_root: PathBuf::from(store_raw),
        max_blob_bytes,
        allowed_upload_ops,
    }))
}

fn parse_max_blob_bytes(raw: &str) -> Result<u64, ConfigError> {
    // Strict decimal u64, no leading zeros except "0" itself — but 0 is
    // invalid (limit must be > 0). No clamping, no silent default.
    if raw == "0" {
        return Err(ConfigError::InvalidBlossomMaxBlobBytes {
            value: raw.to_string(),
            reason: "must be strictly greater than zero".to_string(),
        });
    }
    if raw.is_empty() || raw.as_bytes()[0] == b'0' {
        return Err(ConfigError::InvalidBlossomMaxBlobBytes {
            value: raw.to_string(),
            reason: "must be a canonical decimal u64 with no leading zeros".to_string(),
        });
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigError::InvalidBlossomMaxBlobBytes {
            value: raw.to_string(),
            reason: "must contain only ASCII digits".to_string(),
        });
    }
    raw.parse::<u64>()
        .map_err(|_| ConfigError::InvalidBlossomMaxBlobBytes {
            value: raw.to_string(),
            reason: "out of u64 range".to_string(),
        })
}

fn parse_allowed_ops(raw: &str) -> Result<BTreeSet<[u8; 32]>, ConfigError> {
    let mut out = BTreeSet::new();
    for part in raw.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        // Lowercase hex only — uppercase is rejected (no silent fold).
        if token.len() != 64 {
            return Err(ConfigError::InvalidBlossomAllowedOp {
                value: token.to_string(),
                reason: format!(
                    "must be exactly 64 lowercase hex characters, got {}",
                    token.len()
                ),
            });
        }
        if !token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ConfigError::InvalidBlossomAllowedOp {
                value: token.to_string(),
                reason: "must be lowercase hex [0-9a-f] only".to_string(),
            });
        }
        let mut key = [0u8; 32];
        for (i, chunk) in token.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]);
            let lo = hex_nibble(chunk[1]);
            key[i] = (hi << 4) | lo;
        }
        out.insert(key);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => unreachable!("caller validated lowercase hex"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::str::FromStr;

    fn getter(map: HashMap<&'static str, &'static str>) -> impl FnMut(&str) -> Option<String> {
        move |k| map.get(k).map(|s| (*s).to_string())
    }

    #[test]
    fn accepts_valid_minimal_config() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let cfg = Config::from_getter(&mut get).expect("valid config");
        assert_eq!(cfg.bind_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.kernel_addr, "http://127.0.0.1:50051");
        assert!(cfg.features.is_empty());
        assert!(cfg.public_hosts.is_empty());
        assert!(
            cfg.blossom.is_none(),
            "unset ZKCOINS_BLOSSOM_STORE must leave blossom unconfigured"
        );
    }

    #[test]
    fn blossom_store_absent_is_not_configured() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let cfg = Config::from_getter(&mut get).expect("valid config");
        assert!(cfg.blossom.is_none());
    }

    #[test]
    fn blossom_store_empty_is_error_not_default() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("empty store");
        assert_eq!(err, ConfigError::EmptyEnv(ENV_BLOSSOM_STORE));
    }

    #[test]
    fn blossom_store_requires_companions() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
        ]));
        let err = Config::from_getter(&mut get).expect_err("missing max");
        assert_eq!(err, ConfigError::MissingEnv(ENV_BLOSSOM_MAX_BLOB_BYTES));
    }

    #[test]
    fn blossom_store_configured_with_companions() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "1048576"),
            (
                ENV_BLOSSOM_ALLOWED_OPS,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ]));
        let cfg = Config::from_getter(&mut get).expect("valid blossom");
        let blossom = cfg.blossom.expect("configured");
        assert_eq!(
            blossom.store_root,
            PathBuf::from("/var/lib/zkcoins/blossom")
        );
        assert_eq!(blossom.max_blob_bytes, 1_048_576);
        assert_eq!(blossom.allowed_upload_ops.len(), 1);
    }

    #[test]
    fn blossom_allowed_ops_skips_empty_tokens() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "1048576"),
            (
                ENV_BLOSSOM_ALLOWED_OPS,
                ",aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,",
            ),
        ]));
        let cfg = Config::from_getter(&mut get).expect("valid blossom");
        let blossom = cfg.blossom.expect("configured");
        assert_eq!(blossom.allowed_upload_ops.len(), 1);
    }

    #[test]
    fn blossom_max_blob_zero_is_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "0"),
            (ENV_BLOSSOM_ALLOWED_OPS, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("zero max");
        assert!(matches!(
            &err,
            ConfigError::InvalidBlossomMaxBlobBytes { value, .. } if value == "0"
        ));
    }

    #[test]
    fn accepts_known_features() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "[::1]:9"),
            (ENV_KERNEL, "http://kernel:50051"),
            (ENV_FEATURES, "wallet, explorer,publisher"),
            (ENV_PUBLIC_HOST, "api.example.com"),
        ]));
        let cfg = Config::from_getter(&mut get).expect("valid config");
        assert_eq!(
            cfg.features,
            BTreeSet::from([Feature::Wallet, Feature::Explorer, Feature::Publisher])
        );
        assert_eq!(cfg.public_hosts, vec!["api.example.com".to_string()]);
    }

    #[test]
    fn public_hosts_are_canonicalised() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, "API.Example.COM., other.EXAMPLE.com"),
        ]));
        let cfg = Config::from_getter(&mut get).expect("valid config");
        assert_eq!(
            cfg.public_hosts,
            vec![
                "api.example.com".to_string(),
                "other.example.com".to_string()
            ]
        );
    }

    #[test]
    fn unknown_feature_is_start_error_with_name() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, "wallet,not_a_feature"),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("unknown feature");
        assert!(matches!(
            &err,
            ConfigError::UnknownFeature(name) if name == "not_a_feature"
        ));
        // Display names the bad token and the closed set.
        let msg = err.to_string();
        assert!(
            msg.contains("not_a_feature"),
            "display must name the unknown feature: {msg}"
        );
        assert!(
            msg.contains("wallet") && msg.contains("mail_bridge"),
            "display must list allowed features: {msg}"
        );
    }

    #[test]
    fn missing_bind_addr_is_named() {
        let mut get = getter(HashMap::from([
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("missing bind");
        assert_eq!(err, ConfigError::MissingEnv(ENV_BIND));
        assert!(
            err.to_string().contains(ENV_BIND),
            "error must name the missing variable: {err}"
        );
    }

    #[test]
    fn missing_kernel_addr_is_named() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("missing kernel");
        assert_eq!(err, ConfigError::MissingEnv(ENV_KERNEL));
        assert!(err.to_string().contains(ENV_KERNEL));
    }

    #[test]
    fn missing_features_var_is_named() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("missing features");
        assert_eq!(err, ConfigError::MissingEnv(ENV_FEATURES));
        assert!(err.to_string().contains(ENV_FEATURES));
    }

    #[test]
    fn missing_public_host_var_is_named() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("missing public host");
        assert_eq!(err, ConfigError::MissingEnv(ENV_PUBLIC_HOST));
        assert!(err.to_string().contains(ENV_PUBLIC_HOST));
    }

    #[test]
    fn empty_bind_addr_is_empty_env_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, ""),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("empty bind");
        assert_eq!(err, ConfigError::EmptyEnv(ENV_BIND));
    }

    #[test]
    fn empty_kernel_addr_is_empty_env_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, ""),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("empty kernel");
        assert_eq!(err, ConfigError::EmptyEnv(ENV_KERNEL));
    }

    #[test]
    fn invalid_bind_addr_reports_value_and_reason() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "not-a-socket"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("bad bind");
        assert!(matches!(
            &err,
            ConfigError::InvalidBindAddr { value, reason }
                if value == "not-a-socket" && !reason.is_empty()
        ));
    }

    #[test]
    fn no_default_localhost_when_bind_missing() {
        // Explicit: absence is an error, never 127.0.0.1 / :0 / etc.
        let mut get = getter(HashMap::from([
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, "wallet"),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("no default bind");
        assert!(matches!(err, ConfigError::MissingEnv(ENV_BIND)));
    }

    #[test]
    fn no_default_localhost_for_public_host() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
        ]));
        let cfg = Config::from_getter(&mut get).expect("empty public host is allowed");
        assert!(
            cfg.public_hosts.is_empty(),
            "empty PUBLIC_HOST must not invent localhost"
        );
    }

    #[test]
    fn feature_all_as_str_and_from_str_roundtrip() {
        let expected = [
            "wallet",
            "explorer",
            "publisher",
            "lightning_bridge",
            "mail_bridge",
        ];
        assert_eq!(Feature::ALL.len(), expected.len());
        for (f, name) in Feature::ALL.iter().zip(expected.iter()) {
            assert_eq!(f.as_str(), *name);
            assert_eq!(Feature::from_str(f.as_str()), Ok(*f));
        }
    }

    #[test]
    fn config_error_display_arms() {
        assert!(ConfigError::EmptyEnv("ZKCOINS_BIND_ADDR")
            .to_string()
            .contains("set but empty"));
        assert!(ConfigError::InvalidBindAddr {
            value: "x".into(),
            reason: "bad".into(),
        }
        .to_string()
        .contains("not a valid socket address"));
        assert!(ConfigError::InvalidBlossomMaxBlobBytes {
            value: "0".into(),
            reason: "must be strictly greater than zero".into(),
        }
        .to_string()
        .contains("ZKCOINS_BLOSSOM_MAX_BLOB_BYTES"));
        assert!(ConfigError::InvalidBlossomAllowedOp {
            value: "zz".into(),
            reason: "must be lowercase hex".into(),
        }
        .to_string()
        .contains("ZKCOINS_BLOSSOM_ALLOWED_OPS"));
    }

    #[test]
    fn blossom_max_blob_leading_zero_is_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "01"),
            (ENV_BLOSSOM_ALLOWED_OPS, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("leading zero max");
        assert!(matches!(
            &err,
            ConfigError::InvalidBlossomMaxBlobBytes { value, .. } if value == "01"
        ));
    }

    #[test]
    fn blossom_max_blob_non_digit_is_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "12a"),
            (ENV_BLOSSOM_ALLOWED_OPS, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("non-digit max");
        assert!(matches!(
            &err,
            ConfigError::InvalidBlossomMaxBlobBytes { value, .. } if value == "12a"
        ));
    }

    #[test]
    fn blossom_max_blob_out_of_u64_is_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "18446744073709551616"),
            (ENV_BLOSSOM_ALLOWED_OPS, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("out of u64 max");
        assert!(matches!(
            &err,
            ConfigError::InvalidBlossomMaxBlobBytes { value, .. }
                if value == "18446744073709551616"
        ));
    }

    #[test]
    fn blossom_max_blob_empty_is_empty_env_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, ""),
            (ENV_BLOSSOM_ALLOWED_OPS, ""),
        ]));
        let err = Config::from_getter(&mut get).expect_err("empty max");
        assert_eq!(err, ConfigError::EmptyEnv(ENV_BLOSSOM_MAX_BLOB_BYTES));
    }

    #[test]
    fn blossom_allowed_ops_uppercase_hex_is_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "1048576"),
            (
                ENV_BLOSSOM_ALLOWED_OPS,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        ]));
        let err = Config::from_getter(&mut get).expect_err("uppercase op");
        assert!(matches!(
            &err,
            ConfigError::InvalidBlossomAllowedOp { value, .. }
                if value
                    == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    #[test]
    fn blossom_allowed_ops_wrong_hex_len_is_error() {
        let mut get = getter(HashMap::from([
            (ENV_BIND, "127.0.0.1:8080"),
            (ENV_KERNEL, "http://127.0.0.1:50051"),
            (ENV_FEATURES, ""),
            (ENV_PUBLIC_HOST, ""),
            (ENV_BLOSSOM_STORE, "/var/lib/zkcoins/blossom"),
            (ENV_BLOSSOM_MAX_BLOB_BYTES, "1048576"),
            (ENV_BLOSSOM_ALLOWED_OPS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]));
        let err = Config::from_getter(&mut get).expect_err("short op hex");
        assert!(matches!(
            &err,
            ConfigError::InvalidBlossomAllowedOp { value, .. }
                if value == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    /// Reads the real process env only (no set_var/remove_var — races other tests).
    #[test]
    fn from_env_without_zkcoins_vars_is_missing_env() {
        let err = Config::from_env().expect_err("missing ZKCOINS_* in typical test process");
        assert!(
            matches!(err, ConfigError::MissingEnv(_)),
            "expected MissingEnv, got {err:?}"
        );
    }

    #[test]
    #[should_panic(expected = "caller validated lowercase hex")]
    fn hex_nibble_non_hex_is_unreachable_contract() {
        let _ = hex_nibble(b'g');
    }
}

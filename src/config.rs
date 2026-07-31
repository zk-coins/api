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

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::net::SocketAddr;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// HTTP bind address. Parsed as `SocketAddr` so empty/garbage fails loudly.
    pub bind_addr: SocketAddr,
    /// Kernel gRPC target. Stored as configured; this scaffold does not dial it.
    pub kernel_addr: String,
    /// Enabled API features (§6.1 closed set). Empty = all off.
    pub features: BTreeSet<Feature>,
    /// Authoritative public hostnames for §5.1 `chan_bind` (canonical form).
    /// Derived only from `ZKCOINS_PUBLIC_HOST` — never from request headers.
    pub public_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingEnv(&'static str),
    EmptyEnv(&'static str),
    InvalidBindAddr { value: String, reason: String },
    UnknownFeature(String),
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
        }
    }
}

impl std::error::Error for ConfigError {}

const ENV_BIND: &str = "ZKCOINS_BIND_ADDR";
const ENV_KERNEL: &str = "ZKCOINS_KERNEL_ADDR";
const ENV_FEATURES: &str = "ZKCOINS_FEATURES";
const ENV_PUBLIC_HOST: &str = "ZKCOINS_PUBLIC_HOST";

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

        Ok(Config {
            bind_addr,
            kernel_addr: kernel_raw,
            features,
            public_hosts,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
        match &err {
            ConfigError::UnknownFeature(name) => assert_eq!(name, "not_a_feature"),
            other => panic!("expected UnknownFeature, got {other:?}"),
        }
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
        match &err {
            ConfigError::InvalidBindAddr { value, reason } => {
                assert_eq!(value, "not-a-socket");
                assert!(!reason.is_empty(), "parse reason must be non-empty");
            }
            other => panic!("expected InvalidBindAddr, got {other:?}"),
        }
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
}

//! Process startup for the zkCoins API.
//!
//! Configuration is fail-closed: missing or invalid environment variables
//! abort startup with a named error. No default bind host, no default kernel
//! address, no silent feature fallthrough.

use crate::{build_router, connect_lazy, Config, KernelHandle};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use tracing::info;

pub async fn run() -> ExitCode {
    init_tracing();
    run_from_config_result(Config::from_env()).await
}

/// Map a config load result to either fail-closed exit 1 or [`run_with_config`].
///
/// Extracted so the `Ok` arm is unit-testable without mutating process env.
async fn run_from_config_result(config: Result<Config, crate::config::ConfigError>) -> ExitCode {
    let config = match config {
        Ok(c) => c,
        Err(e) => {
            eprintln!("api: configuration error: {e}");
            return ExitCode::from(1);
        }
    };

    run_with_config(config).await
}

/// Start the HTTP server from an already-validated [`Config`].
///
/// Shared by [`run`] (env entry) and unit tests that construct `Config`
/// directly. Tracing is **not** initialised here — callers that need it
/// (production `run`) install it before loading config.
pub async fn run_with_config(config: Config) -> ExitCode {
    let kernel: KernelHandle = match connect_lazy(&config.kernel_addr) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("api: kernel client error: {e}");
            return ExitCode::from(1);
        }
    };

    let bind_addr: SocketAddr = config.bind_addr;
    let kernel_addr = config.kernel_addr.clone();
    let feature_count = config.features.len();

    let app = match build_router(config, kernel) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("api: startup error: {e}");
            return ExitCode::from(1);
        }
    };

    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("api: failed to bind {bind_addr}: {e}");
            return ExitCode::from(1);
        }
    };

    info!(
        %bind_addr,
        %kernel_addr,
        feature_count,
        "zkcoins-api listening (health + info/chain + jobs + attest/grants + pull + bootstrap + publish + optional blossom)"
    );

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("api: server error: {e}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

fn init_tracing() {
    // Honour RUST_LOG when set; otherwise info. `try_init` so a second
    // install in tests does not panic.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlossomConfig;
    use std::collections::BTreeSet;
    use std::process::ExitCode;

    fn test_config(bind: &str, kernel: &str, blossom: Option<BlossomConfig>) -> Config {
        Config {
            bind_addr: bind.parse().expect("bind"),
            kernel_addr: kernel.to_string(),
            features: BTreeSet::new(),
            public_hosts: Vec::new(),
            blossom,
        }
    }

    #[tokio::test]
    async fn run_without_env_is_exit_code_1() {
        let code = run().await;
        assert_eq!(code, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_from_config_result_err_is_exit_1() {
        let code = run_from_config_result(Err(crate::config::ConfigError::MissingEnv(
            "ZKCOINS_BIND_ADDR",
        )))
        .await;
        assert_eq!(code, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_with_config_invalid_kernel_uri_is_exit_1() {
        let config = test_config("127.0.0.1:0", "not a uri", None);
        let code = run_with_config(config).await;
        assert_eq!(code, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_with_config_blossom_open_failure_is_exit_1() {
        let path = std::env::temp_dir().join(format!(
            "zkcoins-startup-not-a-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::write(&path, b"not-a-directory").expect("temp file");
        let config = test_config(
            "127.0.0.1:0",
            "http://127.0.0.1:50051",
            Some(BlossomConfig {
                store_root: path.clone(),
                max_blob_bytes: 1024,
                allowed_upload_ops: BTreeSet::new(),
            }),
        );
        let code = run_with_config(config).await;
        assert_eq!(code, ExitCode::from(1));
        let _ = std::fs::remove_file(&path);
    }

    /// Deterministic EADDRINUSE: hold a listener and bind the same address.
    #[tokio::test]
    async fn run_with_config_eaddrinuse_is_exit_1() {
        let holder = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral bind");
        let mut config = test_config("127.0.0.1:0", "http://127.0.0.1:50051", None);
        config.bind_addr = holder.local_addr().expect("local addr");
        let code = run_with_config(config).await;
        assert_eq!(code, ExitCode::from(1));
        // keep holder alive until after run_with_config returns
        drop(holder);
    }

    /// Legacy bind-failure path (privileged :1, with EADDRINUSE fallback).
    #[tokio::test]
    async fn run_with_config_bind_failure_is_exit_1() {
        let mut config = test_config("127.0.0.1:1", "http://127.0.0.1:50051", None);
        // Prefer privileged-port failure; if :1 is unexpectedly free, hold a
        // listener on an ephemeral port so the second bind is EADDRINUSE.
        if let Ok(holder) = tokio::net::TcpListener::bind("127.0.0.1:1").await {
            drop(holder);
            let holder = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("ephemeral bind");
            config.bind_addr = holder.local_addr().expect("local addr");
            let code = run_with_config(config).await;
            assert_eq!(code, ExitCode::from(1));
            // keep holder alive until after run_with_config returns
            drop(holder);
        } else {
            let code = run_with_config(config).await;
            assert_eq!(code, ExitCode::from(1));
        }
    }
}

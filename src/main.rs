//! zkCoins API process entrypoint.
//!
//! Configuration is fail-closed: missing or invalid environment variables
//! abort startup with a named error. No default bind host, no default kernel
//! address, no silent feature fallthrough.

use api::{build_router, connect_lazy, Config};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("api: configuration error: {e}");
            return ExitCode::from(1);
        }
    };

    let kernel: api::KernelHandle = match connect_lazy(&config.kernel_addr) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("api: kernel client error: {e}");
            return ExitCode::from(1);
        }
    };

    let bind_addr: SocketAddr = config.bind_addr;
    let kernel_addr = config.kernel_addr.clone();
    let feature_count = config.features.len();

    let app = build_router(config, kernel);

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
        "zkcoins-api listening (health + job surface)"
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

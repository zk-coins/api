//! zkCoins API process entrypoint.
//!
//! Configuration is fail-closed: missing or invalid environment variables
//! abort startup with a named error. No default bind host, no default kernel
//! address, no silent feature fallthrough.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    api::run().await
}

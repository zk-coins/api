//! zkCoins public REST API layer.
//!
//! Outward surface of specification §7.5. Consumes the kernel RPC (§7.8) via
//! `tonic`. Holds no protocol state, no value-bearing store, and no secrets.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod attest;
pub mod blossom;
pub mod bootstrap;
pub mod chain;
pub mod config;
pub mod error;
pub mod extract;
pub mod grants;
pub mod hexutil;
pub mod info;
pub mod jobs;
pub mod kernel;
pub mod ownership;
pub mod proto_identity;
pub mod provenance;
pub mod publish;
pub mod pull;
pub mod routes;
pub mod startup;
pub mod state;

pub use config::{BlossomConfig, Config, ConfigError, Feature};
pub use kernel::{connect_lazy, KernelClient, KernelHandle};
pub use routes::{build_router, StartupError, CLOSED_ENDPOINT_KEYS};
pub use startup::{run, run_with_config};
pub use state::AppState;

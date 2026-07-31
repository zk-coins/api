//! zkCoins public REST API layer.
//!
//! Outward surface of specification §7.5. Consumes the kernel RPC (§7.8) via
//! `tonic`. Holds no protocol state, no value-bearing store, and no secrets.

pub mod config;
pub mod error;
pub mod hexutil;
pub mod jobs;
pub mod kernel;
pub mod proto_identity;
pub mod routes;

pub use config::{Config, ConfigError, Feature};
pub use kernel::{connect_lazy, KernelClient, KernelHandle};
pub use routes::{build_router, CLOSED_ENDPOINT_KEYS};

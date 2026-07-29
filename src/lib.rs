//! zkCoins public REST API layer.
//!
//! This crate is the **outward** surface of §7.5. It will consume the kernel
//! RPC (§7.8) via `tonic`; the scaffold only implements two API-local
//! endpoints (`GET /`, `GET /health`) so nothing is pretended.

pub mod config;
pub mod routes;

pub use config::{Config, ConfigError, Feature};
pub use routes::{build_router, CLOSED_ENDPOINT_KEYS};

//! Generated `kernel.v1` types and gRPC **client** stubs.
//!
//! This crate contains **only** `tonic`/`prost` output from the workspace
//! `proto/kernel/v1/kernel.proto`. No business logic, no API state, no
//! validation beyond what prost generates.
//!
//! Normative contract: specification §7.8. The carried `.proto` is pinned by
//! content hash in the **api** package (`api::proto_identity`).
//!
//! # Clippy
//!
//! Generated code trips lints such as `result_large_err` (`tonic::Status` is
//! large). Fighting the generator is pointless, and the findings say nothing
//! about hand-written code — this crate must stay generator-only. Clippy is
//! therefore silenced at the crate root (`#![allow(clippy::all)]`), matching
//! the node `kernel-proto` pattern. If hand-written logic is ever added here,
//! the allow no longer applies and must be removed.

// Generated code trips several clippy lints; silence them at the crate
// root rather than fighting the generator.
#![allow(clippy::all)]
#![allow(missing_docs)]

tonic::include_proto!("kernel.v1");

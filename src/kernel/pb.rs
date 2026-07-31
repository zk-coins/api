//! Re-export of generated `kernel.v1` types from the `kernel-proto` crate.
//!
//! Codegen lives in `kernel-proto` (own build.rs / OUT_DIR) so that
//! `cargo clippy -p api` never sees tonic-build output.

/// Generated `kernel.v1` package (types + client stubs).
pub use kernel_proto as kernel_v1;

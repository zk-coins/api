//! Shared axum application state.
//!
//! Handlers that need only the kernel extract `State<KernelHandle>` via
//! [`FromRef`]; handlers that also need API-owned config (e.g. `features`
//! for `GET /v1/info`) extract `State<AppState>`.

use crate::config::Feature;
use crate::kernel::KernelHandle;
use axum::extract::FromRef;
use std::collections::BTreeSet;

/// Process state bound into the router after registration.
#[derive(Clone)]
pub struct AppState {
    pub kernel: KernelHandle,
    /// API-layer §6.1 features (`ZKCOINS_FEATURES`). The kernel never
    /// supplies these — `Info.kernel_parts` is a different closed set.
    pub features: BTreeSet<Feature>,
}

impl FromRef<AppState> for KernelHandle {
    fn from_ref(state: &AppState) -> Self {
        state.kernel.clone()
    }
}

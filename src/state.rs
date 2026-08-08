//! Shared axum application state.
//!
//! Handlers that need only the kernel extract `State<KernelHandle>` via
//! [`FromRef`]; handlers that also need API-owned config (e.g. `features`
//! for `GET /v1/info`, `public_hosts` for OwnershipProof `chan_bind`,
//! optional Blossom store) extract `State<AppState>`.

use crate::blossom::BlossomState;
use crate::config::Feature;
use crate::kernel::KernelHandle;
use crate::ownership::{GrantRevokeChallengeStore, RevokedGrantSet, SubjectOpDirectory};
use axum::extract::FromRef;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Process state bound into the router after registration.
#[derive(Clone)]
pub struct AppState {
    pub kernel: KernelHandle,
    /// API-layer §6.1 features (`ZKCOINS_FEATURES`). The kernel never
    /// supplies these — `Info.kernel_parts` is a different closed set.
    pub features: BTreeSet<Feature>,
    /// Authoritative public hostnames for §5.1 `chan_bind`
    /// (`ZKCOINS_PUBLIC_HOST`). Never derived from request headers.
    pub public_hosts: Arc<Vec<String>>,
    /// §7.4 Blossom surface. `None` when `ZKCOINS_BLOSSOM_STORE` is unset —
    /// routes are not mounted and discovery keys are not advertised.
    pub blossom: Option<BlossomState>,
    /// Published `op_pubkey` by subject for GrantProof step 1 (§5.1(b)).
    /// Starts empty — see [`SubjectOpDirectory`].
    pub subject_ops: Arc<SubjectOpDirectory>,
    /// Forward-only grant revocation set (§5.2).
    pub revoked_grants: Arc<RevokedGrantSet>,
    /// Single-use, api-local challenge nonce store for `POST /v1/grants/revoke`
    /// (§5.2) — no kernel dial; see `GrantRevokeChallengeStore`.
    pub grant_revoke_challenges: Arc<GrantRevokeChallengeStore>,
}

impl FromRef<AppState> for KernelHandle {
    fn from_ref(state: &AppState) -> Self {
        state.kernel.clone()
    }
}

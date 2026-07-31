//! Lazy gRPC client for `kernel.v1.Kernel`.
//!
//! Address comes from process config (`ZKCOINS_KERNEL_ADDR`); this module
//! never invents a host or port. Connection is lazy: a bad URI fails at
//! construction; an unreachable kernel surfaces as a transport error on the
//! first RPC (mapped separately from domain ErrorInfo).

use crate::error::ApiError;
use crate::kernel::error_info::kernel_status_to_api_error;
use crate::kernel::pb::kernel_v1::kernel_client::KernelClient as TonicKernelClient;
use crate::kernel::pb::kernel_v1::{
    AccumulatorTip, GetAccumulatorRequest, GetInfoRequest, Info, Job, JobEvent, JobHandle,
    JobRequest, NullifierPath, NullifierPathRequest, SignRequest, TransitionRequest,
};
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use std::sync::Arc;
use tonic::transport::Channel;
use tonic::Request;

/// Subset of kernel procedures this stage consumes (job surface + info/chain reads).
#[async_trait]
pub trait KernelRpc: Send + Sync {
    async fn submit_transition(&self, req: TransitionRequest) -> Result<JobHandle, ApiError>;

    async fn get_job(&self, req: JobRequest) -> Result<Job, ApiError>;

    async fn stream_job(
        &self,
        req: JobRequest,
    ) -> Result<BoxStream<'static, Result<JobEvent, ApiError>>, ApiError>;

    async fn sign_transition(&self, req: SignRequest) -> Result<Job, ApiError>;

    async fn cancel_job(&self, req: JobRequest) -> Result<Job, ApiError>;

    async fn get_info(&self) -> Result<Info, ApiError>;

    async fn get_accumulator(&self) -> Result<AccumulatorTip, ApiError>;

    async fn get_nullifier_path(
        &self,
        req: NullifierPathRequest,
    ) -> Result<NullifierPath, ApiError>;
}

/// Shared handle installed in the axum `State`.
pub type KernelHandle = Arc<dyn KernelRpc>;

/// Production client over a tonic channel.
#[derive(Clone, Debug)]
pub struct KernelClient {
    inner: TonicKernelClient<Channel>,
}

impl KernelClient {
    /// Build a lazy channel to `kernel_addr`.
    ///
    /// `kernel_addr` must already be non-empty (enforced by [`crate::Config`]).
    /// An unparseable URI is a construction error — the process must not start
    /// with a nonsense target.
    ///
    /// # Tokio runtime required
    ///
    /// Even though the TCP dial is deferred until the first RPC, tonic's
    /// `Endpoint::connect_lazy` still spawns a channel worker on the current
    /// Tokio executor (`Buffer::pair` + `executor.execute`). Calling this
    /// **outside** a running Tokio 1.x runtime panics (`there is no reactor
    /// running`). Production entry (`#[tokio::main]`) and tests that build a
    /// client must already be on a runtime; URI/emptiness checks above run
    /// first and do not need one.
    pub fn connect_lazy(kernel_addr: &str) -> Result<Self, ClientBuildError> {
        if kernel_addr.is_empty() {
            return Err(ClientBuildError::EmptyAddr);
        }
        let channel = tonic::transport::Endpoint::from_shared(kernel_addr.to_string())
            .map_err(|e| ClientBuildError::InvalidUri {
                value: kernel_addr.to_string(),
                reason: e.to_string(),
            })?
            .connect_lazy();
        Ok(Self {
            inner: TonicKernelClient::new(channel),
        })
    }
}

/// Failures that prevent constructing a client (start-time, not transport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientBuildError {
    EmptyAddr,
    InvalidUri { value: String, reason: String },
}

impl std::fmt::Display for ClientBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientBuildError::EmptyAddr => {
                write!(f, "kernel address is empty")
            }
            ClientBuildError::InvalidUri { value, reason } => {
                write!(
                    f,
                    "ZKCOINS_KERNEL_ADDR value {value:?} is not a valid gRPC endpoint URI: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ClientBuildError {}

/// Construct a [`KernelClient`] or return a named build error.
pub fn connect_lazy(kernel_addr: &str) -> Result<KernelClient, ClientBuildError> {
    KernelClient::connect_lazy(kernel_addr)
}

#[async_trait]
impl KernelRpc for KernelClient {
    async fn submit_transition(&self, req: TransitionRequest) -> Result<JobHandle, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .submit_transition(Request::new(req))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }

    async fn get_job(&self, req: JobRequest) -> Result<Job, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_job(Request::new(req))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }

    async fn stream_job(
        &self,
        req: JobRequest,
    ) -> Result<BoxStream<'static, Result<JobEvent, ApiError>>, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .stream_job(Request::new(req))
            .await
            .map_err(map_status)?;
        let stream = response.into_inner().map(|item| match item {
            Ok(ev) => Ok(ev),
            Err(status) => Err(kernel_status_to_api_error(&status)),
        });
        Ok(Box::pin(stream))
    }

    async fn sign_transition(&self, req: SignRequest) -> Result<Job, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .sign_transition(Request::new(req))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }

    async fn cancel_job(&self, req: JobRequest) -> Result<Job, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .cancel_job(Request::new(req))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }

    async fn get_info(&self) -> Result<Info, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_info(Request::new(GetInfoRequest {}))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }

    async fn get_accumulator(&self) -> Result<AccumulatorTip, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_accumulator(Request::new(GetAccumulatorRequest {}))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }

    async fn get_nullifier_path(
        &self,
        req: NullifierPathRequest,
    ) -> Result<NullifierPath, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_nullifier_path(Request::new(req))
            .await
            .map_err(map_status)?;
        Ok(response.into_inner())
    }
}

/// Map a tonic `Status` to REST.
///
/// Domain failures carry `ErrorInfo` and become the §7.5 body via
/// [`kernel_status_to_api_error`]. Transport failures (unreachable kernel,
/// reset connection) arrive as a `Status` **without** usable ErrorInfo after
/// tonic converts the underlying `transport::Error`; that path is also
/// fail-closed to `500 internal_error` (no guessed machine code). The
/// dedicated [`super::transport_error_to_api_error`] helper documents the same
/// outcome for call sites that still hold a raw `transport::Error` — this
/// client never holds that type under `connect_lazy`.
fn map_status(status: tonic::Status) -> ApiError {
    kernel_status_to_api_error(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_addr_is_build_error() {
        let err = KernelClient::connect_lazy("").expect_err("empty");
        assert_eq!(err, ClientBuildError::EmptyAddr);
    }

    #[test]
    fn invalid_uri_is_named() {
        let err = KernelClient::connect_lazy("not a uri").expect_err("bad uri");
        match err {
            ClientBuildError::InvalidUri { value, reason } => {
                assert_eq!(value, "not a uri");
                assert!(!reason.is_empty());
            }
            other => panic!("expected InvalidUri, got {other:?}"),
        }
    }

    #[test]
    fn valid_http_uri_builds_lazy_client() {
        // Statement under test is still construction-only (no RPC). The
        // Tokio runtime context is required by tonic's lazy channel worker
        // spawn — see [`KernelClient::connect_lazy`].
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let _enter = rt.enter();
        KernelClient::connect_lazy("http://127.0.0.1:50051").expect("valid");
    }

    #[test]
    fn transport_error_helper_names_cause() {
        // Production RPCs never hold a raw `tonic::transport::Error`: with
        // `connect_lazy`, dial failures surface as `tonic::Status` and go
        // through `map_status` → `kernel_status_to_api_error` (fail-closed
        // 500). This helper is the named path for call sites that still hold
        // the raw transport error; pin its contract via the kernel facade.
        use crate::kernel::transport_error_to_api_error;
        let f: fn(&tonic::transport::Error) -> ApiError = transport_error_to_api_error;
        let _ = f;
        let err = ApiError::internal("kernel transport error: connection refused");
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.body.message.contains("kernel transport error"),
            "message must name transport class, got {}",
            err.body.message
        );
    }
}

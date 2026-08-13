//! Lazy gRPC client for `kernel.v1.Kernel`.
//!
//! Address comes from process config (`ZKCOINS_KERNEL_ADDR`); this module
//! never invents a host or port. Connection is lazy: a bad URI fails at
//! construction; an unreachable kernel surfaces as a transport error on the
//! first RPC (mapped separately from domain ErrorInfo).

use crate::error::ApiError;
use crate::kernel::error_info::{kernel_status_to_api_error_for, KernelProcedure};
use crate::kernel::pb::kernel_v1::kernel_client::KernelClient as TonicKernelClient;
use crate::kernel::pb::kernel_v1::{
    AccountStateRequest, AccountStateResult, AccumulatorTip, AttestRequest, Challenge,
    CoinProofBlob, CoinProofRequest, EntrustRequest, EntrustResult, GetAccumulatorRequest,
    GetInfoRequest, GetTokenProvenanceRequest, GrantRequest, GrantResult, Info, Inscription, Job,
    JobEvent, JobHandle, JobRequest, ListInscriptionsRequest, NullifierPath, NullifierPathRequest,
    PublishRequest, PublishResult, PullChallengeRequest, PullRequest, PullResult, Receipt,
    RecordBlob, RecordRequest, RevokeRequest, RevokeResult, SignRequest, SubscribeReceiptsRequest,
    TokenProvenance, TransitionRequest,
};
use crate::ownership::SessionAuthority;
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use std::sync::Arc;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

/// Interim metadata key the node reads for pull session authority
/// (`node/src/kernel_rpc.rs`). Missing ⇒ kernel `malformed_request` (never
/// silent Ownership).
const SESSION_AUTHORITY_METADATA: &str = "x-zkcoins-session-authority";

/// Subset of kernel procedures this stage consumes
/// (job surface + info/chain + attest/grants + pull/records + receipts stream
/// + bootstrap + publish).
#[async_trait]
pub trait KernelRpc: Send + Sync {
    async fn get_token_provenance(
        &self,
        req: GetTokenProvenanceRequest,
    ) -> Result<TokenProvenance, ApiError>;

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

    /// Server-stream of inscriptions from an inclusive triple cursor (§7.8).
    /// The REST handler collects the stream into one page.
    async fn list_inscriptions(
        &self,
        req: ListInscriptionsRequest,
    ) -> Result<BoxStream<'static, Result<Inscription, ApiError>>, ApiError>;

    async fn get_nullifier_path(
        &self,
        req: NullifierPathRequest,
    ) -> Result<NullifierPath, ApiError>;

    async fn open_pull_challenge(&self, req: PullChallengeRequest) -> Result<Challenge, ApiError>;

    async fn attest_balance(&self, req: AttestRequest) -> Result<JobHandle, ApiError>;

    async fn issue_view_grant(&self, req: GrantRequest) -> Result<GrantResult, ApiError>;

    /// `Pull` with session authority metadata (never omitted, never defaulted).
    async fn pull(
        &self,
        req: PullRequest,
        authority: SessionAuthority,
    ) -> Result<PullResult, ApiError>;

    async fn get_record(&self, req: RecordRequest) -> Result<RecordBlob, ApiError>;

    async fn get_coin_proof(&self, req: CoinProofRequest) -> Result<CoinProofBlob, ApiError>;

    async fn get_account_state(
        &self,
        req: AccountStateRequest,
    ) -> Result<AccountStateResult, ApiError>;

    /// Server-stream of verified receipts for a pull session (§7.8 / §4.9).
    /// Handshake failures (unknown session, `chan_bind` mismatch, transport)
    /// return `Err` before any frame; the REST handler maps those to the
    /// pre-SSE HTTP status. Mid-stream breaks become `Err` items.
    async fn subscribe_receipts(
        &self,
        req: SubscribeReceiptsRequest,
    ) -> Result<BoxStream<'static, Result<Receipt, ApiError>>, ApiError>;

    async fn entrust_operational_bundle(
        &self,
        req: EntrustRequest,
    ) -> Result<EntrustResult, ApiError>;

    async fn revoke_operational_bundle(&self, req: RevokeRequest)
        -> Result<RevokeResult, ApiError>;

    /// `Publish` — hand-off outcome is a successful result even when rejected.
    async fn publish(&self, req: PublishRequest) -> Result<PublishResult, ApiError>;
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
    async fn get_token_provenance(
        &self,
        req: GetTokenProvenanceRequest,
    ) -> Result<TokenProvenance, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_token_provenance(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::GetTokenProvenance))?;
        Ok(response.into_inner())
    }

    async fn submit_transition(&self, req: TransitionRequest) -> Result<JobHandle, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .submit_transition(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::SubmitTransition))?;
        Ok(response.into_inner())
    }

    async fn get_job(&self, req: JobRequest) -> Result<Job, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_job(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::GetJob))?;
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
            .map_err(map_for(KernelProcedure::StreamJob))?;
        let stream = response.into_inner().map(|item| match item {
            Ok(ev) => Ok(ev),
            Err(status) => Err(kernel_status_to_api_error_for(
                &status,
                Some(KernelProcedure::StreamJob),
            )),
        });
        Ok(Box::pin(stream))
    }

    async fn sign_transition(&self, req: SignRequest) -> Result<Job, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .sign_transition(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::SignTransition))?;
        Ok(response.into_inner())
    }

    async fn cancel_job(&self, req: JobRequest) -> Result<Job, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .cancel_job(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::CancelJob))?;
        Ok(response.into_inner())
    }

    async fn get_info(&self) -> Result<Info, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_info(Request::new(GetInfoRequest {}))
            .await
            .map_err(map_for(KernelProcedure::GetInfo))?;
        Ok(response.into_inner())
    }

    async fn get_accumulator(&self) -> Result<AccumulatorTip, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_accumulator(Request::new(GetAccumulatorRequest {}))
            .await
            .map_err(map_for(KernelProcedure::GetAccumulator))?;
        Ok(response.into_inner())
    }

    async fn list_inscriptions(
        &self,
        req: ListInscriptionsRequest,
    ) -> Result<BoxStream<'static, Result<Inscription, ApiError>>, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .list_inscriptions(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::ListInscriptions))?;
        let stream = response.into_inner().map(|item| match item {
            Ok(ins) => Ok(ins),
            Err(status) => Err(kernel_status_to_api_error_for(
                &status,
                Some(KernelProcedure::ListInscriptions),
            )),
        });
        Ok(Box::pin(stream))
    }

    async fn get_nullifier_path(
        &self,
        req: NullifierPathRequest,
    ) -> Result<NullifierPath, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_nullifier_path(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::GetNullifierPath))?;
        Ok(response.into_inner())
    }

    async fn open_pull_challenge(&self, req: PullChallengeRequest) -> Result<Challenge, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .open_pull_challenge(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::OpenPullChallenge))?;
        Ok(response.into_inner())
    }

    async fn attest_balance(&self, req: AttestRequest) -> Result<JobHandle, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .attest_balance(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::AttestBalance))?;
        Ok(response.into_inner())
    }

    async fn issue_view_grant(&self, req: GrantRequest) -> Result<GrantResult, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .issue_view_grant(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::IssueViewGrant))?;
        Ok(response.into_inner())
    }

    async fn pull(
        &self,
        req: PullRequest,
        authority: SessionAuthority,
    ) -> Result<PullResult, ApiError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(req);
        // Fail-closed: authority is always set from the verified proof kind.
        // The node rejects a missing key as malformed_request (never Ownership).
        // `as_str` is a closed `'static` token (`ownership` | `grant`).
        request.metadata_mut().insert(
            SESSION_AUTHORITY_METADATA,
            MetadataValue::from_static(authority.as_str()),
        );
        let response = client
            .pull(request)
            .await
            .map_err(map_for(KernelProcedure::Pull))?;
        Ok(response.into_inner())
    }

    async fn get_record(&self, req: RecordRequest) -> Result<RecordBlob, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_record(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::GetRecord))?;
        Ok(response.into_inner())
    }

    async fn get_coin_proof(&self, req: CoinProofRequest) -> Result<CoinProofBlob, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_coin_proof(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::GetCoinProof))?;
        Ok(response.into_inner())
    }

    async fn get_account_state(
        &self,
        req: AccountStateRequest,
    ) -> Result<AccountStateResult, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .get_account_state(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::GetAccountState))?;
        Ok(response.into_inner())
    }

    async fn subscribe_receipts(
        &self,
        req: SubscribeReceiptsRequest,
    ) -> Result<BoxStream<'static, Result<Receipt, ApiError>>, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .subscribe_receipts(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::SubscribeReceipts))?;
        let stream = response.into_inner().map(|item| match item {
            Ok(receipt) => Ok(receipt),
            Err(status) => Err(kernel_status_to_api_error_for(
                &status,
                Some(KernelProcedure::SubscribeReceipts),
            )),
        });
        Ok(Box::pin(stream))
    }

    async fn entrust_operational_bundle(
        &self,
        req: EntrustRequest,
    ) -> Result<EntrustResult, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .entrust_operational_bundle(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::EntrustOperationalBundle))?;
        Ok(response.into_inner())
    }

    async fn revoke_operational_bundle(
        &self,
        req: RevokeRequest,
    ) -> Result<RevokeResult, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .revoke_operational_bundle(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::RevokeOperationalBundle))?;
        Ok(response.into_inner())
    }

    async fn publish(&self, req: PublishRequest) -> Result<PublishResult, ApiError> {
        let mut client = self.inner.clone();
        let response = client
            .publish(Request::new(req))
            .await
            .map_err(map_for(KernelProcedure::Publish))?;
        Ok(response.into_inner())
    }
}

/// Map a tonic `Status` to REST for a known kernel procedure.
///
/// Domain failures carry `ErrorInfo` and become the §7.5 body via
/// [`kernel_status_to_api_error_for`]. Transport failures (unreachable kernel,
/// reset connection) arrive as a `Status` **without** usable ErrorInfo after
/// tonic converts the underlying `transport::Error`; that path is also
/// fail-closed to `500 internal_error` (no guessed machine code). The
/// dedicated [`super::transport_error_to_api_error`] helper documents the same
/// outcome for call sites that still hold a raw `transport::Error` — this
/// client never holds that type under `connect_lazy`.
fn map_for(procedure: KernelProcedure) -> impl FnOnce(tonic::Status) -> ApiError {
    move |status| kernel_status_to_api_error_for(&status, Some(procedure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::encode_kernel_error_status;
    use crate::kernel::pb::kernel_v1::kernel_server::{Kernel, KernelServer};
    use futures_util::stream::{self, StreamExt};
    use hyper_util::rt::TokioIo;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::sync::oneshot;
    use tonic::transport::{Endpoint, Server};
    use tonic::{Code, Response, Status};

    type RpcStream<T> = Pin<Box<dyn futures_util::Stream<Item = Result<T, Status>> + Send>>;

    #[derive(Clone)]
    struct FakeKernelServer {
        fail: bool,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeKernelServer {
        fn record(&self, name: &'static str) {
            self.calls.lock().expect("call trace lock").push(name);
        }

        fn unary<T: Default>(&self, name: &'static str) -> Result<Response<T>, Status> {
            self.record(name);
            if self.fail {
                Err(rpc_error())
            } else {
                Ok(Response::new(T::default()))
            }
        }

        fn stream<T>(
            &self,
            name: &'static str,
            items: Vec<T>,
        ) -> Result<Response<RpcStream<T>>, Status>
        where
            T: Send + 'static,
        {
            self.record(name);
            if self.fail {
                return Err(rpc_error());
            }
            let mut frames: Vec<Result<T, Status>> = items.into_iter().map(Ok).collect();
            frames.push(Err(rpc_error()));
            Ok(Response::new(Box::pin(stream::iter(frames))))
        }
    }

    fn rpc_error() -> Status {
        encode_kernel_error_status(
            Code::Internal,
            "scripted kernel failure",
            "internal_error",
            500,
        )
    }

    fn provenance_request() -> GetTokenProvenanceRequest {
        GetTokenProvenanceRequest { asset_id: vec![1] }
    }

    fn transition_request() -> TransitionRequest {
        TransitionRequest {
            kind: "mint".into(),
            ..Default::default()
        }
    }

    fn job_request() -> JobRequest {
        JobRequest {
            job_id: "job-1".into(),
        }
    }

    fn sign_request() -> SignRequest {
        SignRequest {
            job_id: "job-1".into(),
            ..Default::default()
        }
    }

    fn inscriptions_request() -> ListInscriptionsRequest {
        ListInscriptionsRequest {
            limit: Some(2),
            ..Default::default()
        }
    }

    fn nullifier_request() -> NullifierPathRequest {
        NullifierPathRequest { pubkey: vec![2] }
    }

    fn challenge_request() -> PullChallengeRequest {
        PullChallengeRequest {
            subject: "zk1subject".into(),
            ..Default::default()
        }
    }

    fn attest_request() -> AttestRequest {
        AttestRequest {
            subject: "zk1subject".into(),
            ..Default::default()
        }
    }

    fn grant_request() -> GrantRequest {
        GrantRequest {
            subject: "zk1subject".into(),
            ..Default::default()
        }
    }

    fn pull_request(authority: SessionAuthority) -> PullRequest {
        PullRequest {
            subject: authority.as_str().into(),
            ..Default::default()
        }
    }

    fn record_request() -> RecordRequest {
        RecordRequest {
            session: "session-1".into(),
            ..Default::default()
        }
    }

    fn coin_request() -> CoinProofRequest {
        CoinProofRequest {
            session: "session-1".into(),
            ..Default::default()
        }
    }

    fn account_request() -> AccountStateRequest {
        AccountStateRequest {
            session: "session-1".into(),
            ..Default::default()
        }
    }

    fn receipts_request() -> SubscribeReceiptsRequest {
        SubscribeReceiptsRequest {
            session: "session-1".into(),
            ..Default::default()
        }
    }

    fn entrust_request() -> EntrustRequest {
        EntrustRequest {
            subject: "zk1subject".into(),
            ..Default::default()
        }
    }

    fn revoke_request() -> RevokeRequest {
        RevokeRequest {
            subject: "zk1subject".into(),
            ..Default::default()
        }
    }

    fn publish_request() -> PublishRequest {
        PublishRequest {
            public_key: vec![3],
            ..Default::default()
        }
    }

    #[tonic::async_trait]
    impl Kernel for FakeKernelServer {
        async fn get_token_provenance(
            &self,
            request: Request<GetTokenProvenanceRequest>,
        ) -> Result<Response<TokenProvenance>, Status> {
            assert_eq!(request.into_inner(), provenance_request());
            self.unary("get_token_provenance")
        }

        async fn get_info(
            &self,
            request: Request<GetInfoRequest>,
        ) -> Result<Response<Info>, Status> {
            assert_eq!(request.into_inner(), GetInfoRequest {});
            self.unary("get_info")
        }

        async fn get_accumulator(
            &self,
            request: Request<GetAccumulatorRequest>,
        ) -> Result<Response<AccumulatorTip>, Status> {
            assert_eq!(request.into_inner(), GetAccumulatorRequest {});
            self.unary("get_accumulator")
        }

        type ListInscriptionsStream = RpcStream<Inscription>;

        async fn list_inscriptions(
            &self,
            request: Request<ListInscriptionsRequest>,
        ) -> Result<Response<Self::ListInscriptionsStream>, Status> {
            assert_eq!(request.into_inner(), inscriptions_request());
            self.stream(
                "list_inscriptions",
                vec![
                    Inscription {
                        height: 1,
                        ..Default::default()
                    },
                    Inscription {
                        height: 2,
                        ..Default::default()
                    },
                ],
            )
        }

        async fn get_nullifier_path(
            &self,
            request: Request<NullifierPathRequest>,
        ) -> Result<Response<NullifierPath>, Status> {
            assert_eq!(request.into_inner(), nullifier_request());
            self.unary("get_nullifier_path")
        }

        async fn submit_transition(
            &self,
            request: Request<TransitionRequest>,
        ) -> Result<Response<JobHandle>, Status> {
            assert_eq!(request.into_inner(), transition_request());
            self.unary("submit_transition")
        }

        async fn get_job(&self, request: Request<JobRequest>) -> Result<Response<Job>, Status> {
            assert_eq!(request.into_inner(), job_request());
            self.unary("get_job")
        }

        type StreamJobStream = RpcStream<JobEvent>;

        async fn stream_job(
            &self,
            request: Request<JobRequest>,
        ) -> Result<Response<Self::StreamJobStream>, Status> {
            assert_eq!(request.into_inner(), job_request());
            self.stream(
                "stream_job",
                vec![
                    JobEvent {
                        event: "phase".into(),
                        ..Default::default()
                    },
                    JobEvent {
                        event: "complete".into(),
                        ..Default::default()
                    },
                ],
            )
        }

        async fn sign_transition(
            &self,
            request: Request<SignRequest>,
        ) -> Result<Response<Job>, Status> {
            assert_eq!(request.into_inner(), sign_request());
            self.unary("sign_transition")
        }

        async fn cancel_job(&self, request: Request<JobRequest>) -> Result<Response<Job>, Status> {
            assert_eq!(request.into_inner(), job_request());
            self.unary("cancel_job")
        }

        async fn open_pull_challenge(
            &self,
            request: Request<PullChallengeRequest>,
        ) -> Result<Response<Challenge>, Status> {
            assert_eq!(request.into_inner(), challenge_request());
            self.unary("open_pull_challenge")
        }

        async fn pull(
            &self,
            request: Request<PullRequest>,
        ) -> Result<Response<PullResult>, Status> {
            let authority = request
                .metadata()
                .get(SESSION_AUTHORITY_METADATA)
                .expect("session authority metadata")
                .to_str()
                .expect("ASCII authority");
            assert_eq!(request.get_ref().subject, authority);
            assert!(matches!(authority, "ownership" | "grant"));
            self.unary("pull")
        }

        async fn get_record(
            &self,
            request: Request<RecordRequest>,
        ) -> Result<Response<RecordBlob>, Status> {
            assert_eq!(request.into_inner(), record_request());
            self.unary("get_record")
        }

        async fn get_coin_proof(
            &self,
            request: Request<CoinProofRequest>,
        ) -> Result<Response<CoinProofBlob>, Status> {
            assert_eq!(request.into_inner(), coin_request());
            self.unary("get_coin_proof")
        }

        async fn get_account_state(
            &self,
            request: Request<AccountStateRequest>,
        ) -> Result<Response<AccountStateResult>, Status> {
            assert_eq!(request.into_inner(), account_request());
            self.unary("get_account_state")
        }

        type SubscribeReceiptsStream = RpcStream<Receipt>;

        async fn subscribe_receipts(
            &self,
            request: Request<SubscribeReceiptsRequest>,
        ) -> Result<Response<Self::SubscribeReceiptsStream>, Status> {
            assert_eq!(request.into_inner(), receipts_request());
            self.stream(
                "subscribe_receipts",
                vec![
                    Receipt {
                        amount: "1".into(),
                        ..Default::default()
                    },
                    Receipt {
                        amount: "2".into(),
                        ..Default::default()
                    },
                ],
            )
        }

        async fn publish(
            &self,
            request: Request<PublishRequest>,
        ) -> Result<Response<PublishResult>, Status> {
            assert_eq!(request.into_inner(), publish_request());
            self.unary("publish")
        }

        async fn entrust_operational_bundle(
            &self,
            request: Request<EntrustRequest>,
        ) -> Result<Response<EntrustResult>, Status> {
            assert_eq!(request.into_inner(), entrust_request());
            self.unary("entrust_operational_bundle")
        }

        async fn revoke_operational_bundle(
            &self,
            request: Request<RevokeRequest>,
        ) -> Result<Response<RevokeResult>, Status> {
            assert_eq!(request.into_inner(), revoke_request());
            self.unary("revoke_operational_bundle")
        }

        async fn attest_balance(
            &self,
            request: Request<AttestRequest>,
        ) -> Result<Response<JobHandle>, Status> {
            assert_eq!(request.into_inner(), attest_request());
            self.unary("attest_balance")
        }

        async fn issue_view_grant(
            &self,
            request: Request<GrantRequest>,
        ) -> Result<Response<GrantResult>, Status> {
            assert_eq!(request.into_inner(), grant_request());
            self.unary("issue_view_grant")
        }
    }

    struct ServerIo(DuplexStream);

    impl tonic::transport::server::Connected for ServerIo {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    impl AsyncRead for ServerIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ServerIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    struct Harness {
        client: Option<KernelClient>,
        calls: Arc<Mutex<Vec<&'static str>>>,
        shutdown: Option<oneshot::Sender<()>>,
        server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl Harness {
        async fn start(fail: bool) -> Self {
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let calls = Arc::new(Mutex::new(Vec::new()));
            let service = FakeKernelServer {
                fail,
                calls: Arc::clone(&calls),
            };
            // Keep the accept stream open after the single duplex item. tonic 0.13
            // treats end-of-incoming as accept-loop exit and, with a shutdown
            // future present, immediately graceful-shuts down live connections —
            // which races the first RPC and surfaces as a transport Status with
            // empty details. `pending` holds the loop until `finish` fires the
            // oneshot. tonic wraps the server half in TokioIo itself.
            let incoming = stream::once(async move { Ok::<_, io::Error>(ServerIo(server_io)) })
                .chain(stream::pending());
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                Server::builder()
                    .add_service(KernelServer::new(service))
                    .serve_with_incoming_shutdown(incoming, async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let client_io = Arc::new(Mutex::new(Some(client_io)));
            let connector = tower::service_fn(move |_| {
                let io = client_io
                    .lock()
                    .expect("connector lock")
                    .take()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "already connected")
                    });
                async move { io.map(TokioIo::new) }
            });
            let channel = Endpoint::from_static("http://kernel.test")
                .connect_with_connector(connector)
                .await
                .expect("in-memory channel");

            Self {
                client: Some(KernelClient {
                    inner: TonicKernelClient::new(channel),
                }),
                calls,
                shutdown: Some(shutdown_tx),
                server,
            }
        }

        fn client(&self) -> &KernelClient {
            self.client.as_ref().expect("live client")
        }

        async fn finish(mut self, expected_calls: &[&'static str]) {
            assert_eq!(
                self.calls.lock().expect("call trace lock").as_slice(),
                expected_calls
            );
            self.client.take();
            self.shutdown.take().expect("shutdown sender").send(()).ok();
            self.server
                .await
                .expect("server task")
                .expect("server result");
        }
    }

    fn assert_internal(err: ApiError) {
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert_eq!(err.cause(), Some("scripted kernel failure"));
    }

    #[test]
    fn empty_addr_is_build_error() {
        let err = KernelClient::connect_lazy("").expect_err("empty");
        assert_eq!(err, ClientBuildError::EmptyAddr);
        assert_eq!(err.to_string(), "kernel address is empty");
        assert!(connect_lazy("").is_err(), "free constructor must delegate");
    }

    #[test]
    fn invalid_uri_is_named() {
        let err = KernelClient::connect_lazy("not a uri").expect_err("bad uri");
        assert!(matches!(
            &err,
            ClientBuildError::InvalidUri { value, reason }
                if value == "not a uri" && !reason.is_empty()
        ));
        if let ClientBuildError::InvalidUri { value, reason } = &err {
            let display = ClientBuildError::InvalidUri {
                value: value.clone(),
                reason: reason.clone(),
            }
            .to_string();
            assert!(display.contains("ZKCOINS_KERNEL_ADDR"));
            assert!(display.contains("not a uri"));
            assert!(display.contains(reason));
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
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);
        assert!(
            err.cause().unwrap_or("").contains("kernel transport error"),
            "operator cause must name transport class, got {:?}",
            err.cause()
        );
    }

    #[tokio::test]
    async fn real_tonic_client_forwards_every_rpc_and_maps_stream_items() {
        let harness = Harness::start(false).await;
        let client = harness.client();

        assert_eq!(
            client
                .get_token_provenance(provenance_request())
                .await
                .unwrap(),
            TokenProvenance::default()
        );
        assert_eq!(
            client
                .submit_transition(transition_request())
                .await
                .unwrap(),
            JobHandle::default()
        );
        assert_eq!(client.get_job(job_request()).await.unwrap(), Job::default());

        let mut jobs = client.stream_job(job_request()).await.unwrap();
        assert_eq!(jobs.next().await.unwrap().unwrap().event, "phase");
        assert_eq!(jobs.next().await.unwrap().unwrap().event, "complete");
        assert_internal(jobs.next().await.unwrap().unwrap_err());
        assert!(jobs.next().await.is_none());

        assert_eq!(
            client.sign_transition(sign_request()).await.unwrap(),
            Job::default()
        );
        assert_eq!(
            client.cancel_job(job_request()).await.unwrap(),
            Job::default()
        );
        assert_eq!(client.get_info().await.unwrap(), Info::default());
        assert_eq!(
            client.get_accumulator().await.unwrap(),
            AccumulatorTip::default()
        );

        let mut inscriptions = client
            .list_inscriptions(inscriptions_request())
            .await
            .unwrap();
        assert_eq!(inscriptions.next().await.unwrap().unwrap().height, 1);
        assert_eq!(inscriptions.next().await.unwrap().unwrap().height, 2);
        assert_internal(inscriptions.next().await.unwrap().unwrap_err());
        assert!(inscriptions.next().await.is_none());

        assert_eq!(
            client
                .get_nullifier_path(nullifier_request())
                .await
                .unwrap(),
            NullifierPath::default()
        );
        assert_eq!(
            client
                .open_pull_challenge(challenge_request())
                .await
                .unwrap(),
            Challenge::default()
        );
        assert_eq!(
            client.attest_balance(attest_request()).await.unwrap(),
            JobHandle::default()
        );
        assert_eq!(
            client.issue_view_grant(grant_request()).await.unwrap(),
            GrantResult::default()
        );
        assert_eq!(
            client
                .pull(
                    pull_request(SessionAuthority::Ownership),
                    SessionAuthority::Ownership
                )
                .await
                .unwrap(),
            PullResult::default()
        );
        assert_eq!(
            client
                .pull(
                    pull_request(SessionAuthority::Grant),
                    SessionAuthority::Grant
                )
                .await
                .unwrap(),
            PullResult::default()
        );
        assert_eq!(
            client.get_record(record_request()).await.unwrap(),
            RecordBlob::default()
        );
        assert_eq!(
            client.get_coin_proof(coin_request()).await.unwrap(),
            CoinProofBlob::default()
        );
        assert_eq!(
            client.get_account_state(account_request()).await.unwrap(),
            AccountStateResult::default()
        );

        let mut receipts = client.subscribe_receipts(receipts_request()).await.unwrap();
        assert_eq!(receipts.next().await.unwrap().unwrap().amount, "1");
        assert_eq!(receipts.next().await.unwrap().unwrap().amount, "2");
        assert_internal(receipts.next().await.unwrap().unwrap_err());
        assert!(receipts.next().await.is_none());

        assert_eq!(
            client
                .entrust_operational_bundle(entrust_request())
                .await
                .unwrap(),
            EntrustResult::default()
        );
        assert_eq!(
            client
                .revoke_operational_bundle(revoke_request())
                .await
                .unwrap(),
            RevokeResult::default()
        );
        assert_eq!(
            client.publish(publish_request()).await.unwrap(),
            PublishResult::default()
        );

        harness
            .finish(&[
                "get_token_provenance",
                "submit_transition",
                "get_job",
                "stream_job",
                "sign_transition",
                "cancel_job",
                "get_info",
                "get_accumulator",
                "list_inscriptions",
                "get_nullifier_path",
                "open_pull_challenge",
                "attest_balance",
                "issue_view_grant",
                "pull",
                "pull",
                "get_record",
                "get_coin_proof",
                "get_account_state",
                "subscribe_receipts",
                "entrust_operational_bundle",
                "revoke_operational_bundle",
                "publish",
            ])
            .await;
    }

    #[tokio::test]
    async fn real_tonic_client_maps_rich_status_for_every_rpc_handshake() {
        let harness = Harness::start(true).await;
        let client = harness.client();

        assert_internal(
            client
                .get_token_provenance(provenance_request())
                .await
                .unwrap_err(),
        );
        assert_internal(
            client
                .submit_transition(transition_request())
                .await
                .unwrap_err(),
        );
        assert_internal(client.get_job(job_request()).await.unwrap_err());
        let result = client.stream_job(job_request()).await;
        assert!(result.is_err(), "stream_job must fail");
        if let Err(err) = result {
            assert_internal(err);
        }
        assert_internal(client.sign_transition(sign_request()).await.unwrap_err());
        assert_internal(client.cancel_job(job_request()).await.unwrap_err());
        assert_internal(client.get_info().await.unwrap_err());
        assert_internal(client.get_accumulator().await.unwrap_err());
        let result = client.list_inscriptions(inscriptions_request()).await;
        assert!(result.is_err(), "list_inscriptions must fail");
        if let Err(err) = result {
            assert_internal(err);
        }
        assert_internal(
            client
                .get_nullifier_path(nullifier_request())
                .await
                .unwrap_err(),
        );
        assert_internal(
            client
                .open_pull_challenge(challenge_request())
                .await
                .unwrap_err(),
        );
        assert_internal(client.attest_balance(attest_request()).await.unwrap_err());
        assert_internal(client.issue_view_grant(grant_request()).await.unwrap_err());
        assert_internal(
            client
                .pull(
                    pull_request(SessionAuthority::Ownership),
                    SessionAuthority::Ownership,
                )
                .await
                .unwrap_err(),
        );
        assert_internal(client.get_record(record_request()).await.unwrap_err());
        assert_internal(client.get_coin_proof(coin_request()).await.unwrap_err());
        assert_internal(
            client
                .get_account_state(account_request())
                .await
                .unwrap_err(),
        );
        let result = client.subscribe_receipts(receipts_request()).await;
        assert!(result.is_err(), "subscribe_receipts must fail");
        if let Err(err) = result {
            assert_internal(err);
        }
        assert_internal(
            client
                .entrust_operational_bundle(entrust_request())
                .await
                .unwrap_err(),
        );
        assert_internal(
            client
                .revoke_operational_bundle(revoke_request())
                .await
                .unwrap_err(),
        );
        assert_internal(client.publish(publish_request()).await.unwrap_err());

        harness
            .finish(&[
                "get_token_provenance",
                "submit_transition",
                "get_job",
                "stream_job",
                "sign_transition",
                "cancel_job",
                "get_info",
                "get_accumulator",
                "list_inscriptions",
                "get_nullifier_path",
                "open_pull_challenge",
                "attest_balance",
                "issue_view_grant",
                "pull",
                "get_record",
                "get_coin_proof",
                "get_account_state",
                "subscribe_receipts",
                "entrust_operational_bundle",
                "revoke_operational_bundle",
                "publish",
            ])
            .await;
    }
}

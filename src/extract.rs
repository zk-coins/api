//! Shared request extractors that map axum rejections into §7.5 `ApiError`.
//!
//! Axum's default `Json<T>` / `Bytes` rejections answer with framework status
//! codes and non-§7.5 bodies (422 unprocessable, plain-text 413, …). Every
//! public handler that reads a JSON or limited raw body must go through these
//! extractors so clients always see the closed machine-code form.

use crate::error::ApiError;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, JsonRejection};
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::Json;
use serde::de::DeserializeOwned;

/// JSON body extractor that translates every rejection into §7.5 JSON.
///
/// Use in place of `axum::Json<T>` on public handlers.
#[derive(Debug)]
pub struct JsonBody<T>(pub T);

// axum 0.7 / axum-core 0.4: `FromRequest` is an `#[async_trait]` trait — the
// impl must carry the same attribute so the lifetime/Send desugaring matches
// the trait declaration (otherwise E0195 and handlers never see the extractor).
#[async_trait]
impl<S, T> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(rejection) => Err(json_rejection_to_api_error(rejection)),
        }
    }
}

/// Map an axum [`JsonRejection`] onto the closed §7.5 error surface.
///
/// - Missing / wrong Content-Type → `400 malformed_request`
/// - Syntax / data errors → `400 malformed_request`
/// - Body length limit (DefaultBodyLimit) → `413 payload_too_large`
pub fn json_rejection_to_api_error(rejection: JsonRejection) -> ApiError {
    match rejection {
        JsonRejection::MissingJsonContentType(_) => {
            ApiError::malformed("Content-Type must be application/json")
        }
        JsonRejection::JsonDataError(err) => ApiError::malformed(format!("request body: {err}")),
        JsonRejection::JsonSyntaxError(err) => ApiError::malformed(format!("request body: {err}")),
        JsonRejection::BytesRejection(err) => bytes_rejection_to_api_error(err),
        other => ApiError::malformed(format!("request body: {other}")),
    }
}

/// Raw-body extractor with the same §7.5 rejection mapping as [`JsonBody`].
///
/// Used by Blossom upload so oversize bodies (including those far above the
/// configured max, not only `max + 1`) still answer with
/// `413 payload_too_large` and a JSON body — not axum's plain-text 413.
pub struct LimitedBytes(pub Bytes);

#[async_trait]
impl<S> FromRequest<S> for LimitedBytes
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Bytes::from_request(req, state).await {
            Ok(bytes) => Ok(LimitedBytes(bytes)),
            Err(rejection) => Err(bytes_rejection_to_api_error(rejection)),
        }
    }
}

/// Map an axum [`BytesRejection`] (body buffer / length limit) to §7.5.
///
/// axum 0.7 encodes both length-limit and unknown buffer failures under
/// `FailedToBufferBody` with the **same** Display body
/// (`"Failed to buffer the request body"`). The stable discriminator is
/// [`BytesRejection::status`]: `LengthLimitError` is 413, other buffer
/// failures are 400. Matching Display text collapses 413 into 400.
pub fn bytes_rejection_to_api_error(rejection: BytesRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::payload_too_large("request body exceeds the maximum allowed size");
    }
    ApiError::malformed(format!("request body: {}", rejection.body_text()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::http::{Request, StatusCode};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Tiny {
        x: u32,
    }

    fn broken_body() -> Body {
        let stream = futures_util::stream::iter([Err::<Bytes, std::io::Error>(
            std::io::Error::other("broken pipe"),
        )]);
        Body::from_stream(stream)
    }

    #[tokio::test]
    async fn json_body_missing_content_type_is_malformed_request() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(r#"{"x":1}"#))
            .unwrap();
        let err = JsonBody::<Tiny>::from_request(req, &())
            .await
            .expect_err("missing content-type");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("Content-Type")
                || err.body.message.contains("application/json"),
            "message must name content-type rule: {}",
            err.body.message
        );
    }

    #[tokio::test]
    async fn json_body_syntax_error_is_malformed_request() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from("{not-json"))
            .unwrap();
        let err = JsonBody::<Tiny>::from_request(req, &())
            .await
            .expect_err("bad json");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
    }

    #[tokio::test]
    async fn json_body_happy_path() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"x":7}"#))
            .unwrap();
        let JsonBody(v) = JsonBody::<Tiny>::from_request(req, &()).await.expect("ok");
        assert_eq!(v.x, 7);
    }

    #[tokio::test]
    async fn json_body_failed_buffer_is_malformed_request() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(broken_body())
            .unwrap();
        let err = JsonBody::<Tiny>::from_request(req, &())
            .await
            .expect_err("broken body");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
    }

    #[tokio::test]
    async fn limited_bytes_failed_buffer_is_malformed_request() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(broken_body())
            .unwrap();
        let result = LimitedBytes::from_request(req, &()).await;
        assert!(result.is_err(), "broken body must be rejected");
        if let Err(err) = result {
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert_eq!(err.body.error, "malformed_request");
        }
    }

    #[tokio::test]
    async fn json_body_data_error_is_malformed_request() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"x":"not-a-number"}"#))
            .unwrap();
        let err = JsonBody::<Tiny>::from_request(req, &())
            .await
            .expect_err("type mismatch");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
    }
}

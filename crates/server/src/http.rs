//! HTTP/JSON gateway for the gRPC `WalletService`.
//!
//! Routes are generated at build time from `google.api.http` annotations on
//! the proto methods (see `build.rs`). Every RPC handler is reused as-is —
//! the JSON router decodes the request body into the prost message, wraps it
//! in a `tonic::Request`, and serializes the response.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use crate::proto::pb;
use crate::proto::pb::wallet_service_server::WalletService;
use crate::wallet::service::auth::{http_requires_auth, validate_bearer, AuthMode};
use crate::wallet::service::WalletRPC;

include!(concat!(env!("OUT_DIR"), "/http_routes.rs"));

/// Adapter that maps `tonic::Status` to an HTTP response body.
pub struct HttpError(tonic::Status);

impl From<tonic::Status> for HttpError {
    fn from(status: tonic::Status) -> Self {
        Self(status)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = grpc_code_to_http(self.0.code());
        let body = serde_json::json!({
            "code": self.0.code() as i32,
            "message": self.0.message(),
        });
        (status, Json(body)).into_response()
    }
}

/// Bearer-token middleware for the HTTP gateway. Mirrors the gRPC
/// `AuthLayer` semantics — `Disabled` short-circuits, the ping path is
/// always allowed, everything else requires `Authorization: Bearer <t>`.
pub async fn http_auth_middleware(
    State(mode): State<AuthMode>,
    req: axum::http::Request<axum::body::Body>,
    next: Next<axum::body::Body>,
) -> Response {
    if !http_requires_auth(req.uri().path(), &mode) {
        return next.run(req).await;
    }
    let expected = match &mode {
        AuthMode::Required(t) => t.as_str(),
        AuthMode::Disabled => unreachable!("http_requires_auth filters Disabled"),
    };
    if validate_bearer(req.headers(), expected) {
        return next.run(req).await;
    }
    let body = serde_json::json!({
        "code": tonic::Code::Unauthenticated as i32,
        "message": "missing or invalid bearer token",
    });
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

pub(crate) fn grpc_code_to_http(code: tonic::Code) -> StatusCode {
    use tonic::Code::*;
    match code {
        Ok => StatusCode::OK,
        Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        InvalidArgument | OutOfRange | FailedPrecondition => StatusCode::BAD_REQUEST,
        DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        NotFound => StatusCode::NOT_FOUND,
        AlreadyExists | Aborted => StatusCode::CONFLICT,
        PermissionDenied => StatusCode::FORBIDDEN,
        Unauthenticated => StatusCode::UNAUTHORIZED,
        ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        Unimplemented => StatusCode::NOT_IMPLEMENTED,
        Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        Unknown | Internal | DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    fn router() -> Router {
        http_router(Arc::new(WalletRPC::default()))
    }

    fn router_with_auth(mode: AuthMode) -> Router {
        http_router(Arc::new(WalletRPC::default())).layer(
            axum::middleware::from_fn_with_state(mode, http_auth_middleware),
        )
    }

    async fn body_to_string(resp: Response) -> String {
        let bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn json_post(path: &str, body: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[test]
    fn grpc_to_http_covers_each_code() {
        // Spot-check the non-trivial mappings; the catch-all defaults to 500.
        assert_eq!(grpc_code_to_http(tonic::Code::Ok), StatusCode::OK);
        assert_eq!(
            grpc_code_to_http(tonic::Code::InvalidArgument),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::OutOfRange),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::FailedPrecondition),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::NotFound),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::AlreadyExists),
            StatusCode::CONFLICT
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::Aborted),
            StatusCode::CONFLICT
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::PermissionDenied),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unauthenticated),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::ResourceExhausted),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::DeadlineExceeded),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unimplemented),
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::Internal),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::DataLoss),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            grpc_code_to_http(tonic::Code::Unknown),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn http_error_renders_status_and_body() {
        let err: HttpError = tonic::Status::invalid_argument("bad input").into();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["code"], serde_json::json!(tonic::Code::InvalidArgument as i32));
        assert_eq!(v["message"], serde_json::json!("bad input"));
    }

    #[tokio::test]
    async fn ping_route_returns_empty_response() {
        let resp = router().oneshot(json_post("/wallet/ping", "{}")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({}));
    }

    #[tokio::test]
    async fn ping_route_rejects_get_with_405() {
        let req = HttpRequest::builder()
            .method("GET")
            .uri("/wallet/ping")
            .body(Body::empty())
            .unwrap();
        let resp = router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let resp = router()
            .oneshot(json_post("/wallet/does_not_exist", "{}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_json_body_returns_4xx() {
        // axum's Json extractor surfaces decode errors as a 4xx response;
        // we just assert it's a client error rather than reaching the handler.
        let resp = router()
            .oneshot(json_post("/wallet/ping", "not json"))
            .await
            .unwrap();
        assert!(
            resp.status().is_client_error(),
            "expected 4xx, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn auth_disabled_lets_everything_through() {
        let resp = router_with_auth(AuthMode::Disabled)
            .oneshot(json_post("/wallet/ping", "{}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_required_allows_ping_without_token() {
        let resp = router_with_auth(AuthMode::Required("good".into()))
            .oneshot(json_post("/wallet/ping", "{}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_required_rejects_other_routes_without_token() {
        let resp = router_with_auth(AuthMode::Required("good".into()))
            .oneshot(json_post(
                "/wallet/list_managed_keys",
                r#"{"user_id":"","key_type":""}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["code"],
            serde_json::json!(tonic::Code::Unauthenticated as i32)
        );
    }

    #[tokio::test]
    async fn auth_required_rejects_wrong_token() {
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/wallet/list_managed_keys")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong")
            .body(Body::from(r#"{"user_id":"","key_type":""}"#))
            .unwrap();
        let resp = router_with_auth(AuthMode::Required("good".into()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

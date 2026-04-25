//! Bearer-token gRPC auth.
//!
//! Reads `Authorization: Bearer <token>` from request metadata and rejects
//! mismatching or missing tokens with `Status::unauthenticated`. Liveness
//! probes against the `Ping` RPC bypass auth so external monitoring doesn't
//! need to hold the bearer token.

use std::task::{Context, Poll};

use http::header::AUTHORIZATION;
use http::HeaderMap;
use log::warn;
use rand::RngCore;
use subtle::ConstantTimeEq;
use tonic::body::BoxBody;
use tonic::transport::Body;
use tonic::Status;
use tower::{Layer, Service};

/// Authentication mode for the gRPC layer.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// Auth disabled — every request passes through.
    Disabled,
    /// Auth required — requests must carry `Authorization: Bearer <token>`.
    Required(String),
}

impl AuthMode {
    /// Resolve the mode from operator-supplied configuration.
    ///
    /// - If `disabled` is true, returns `Disabled`.
    /// - Else if `configured_token` is `Some`, returns `Required(token)`.
    /// - Else generates a fresh 32-byte token, logs it once with a
    ///   `STORE THIS` prefix so the operator can copy it, and returns
    ///   `Required(generated)`.
    pub fn from_config(disabled: bool, configured_token: Option<String>) -> Self {
        if disabled {
            warn!("WALLETRS_AUTH_DISABLED is set — gRPC requests are not authenticated.");
            return Self::Disabled;
        }

        match configured_token {
            Some(token) if !token.is_empty() => Self::Required(token),
            _ => {
                let generated = generate_token();
                log::info!(
                    "STORE THIS — generated auth token (set WALLETRS_AUTH_TOKEN to override): {}",
                    generated
                );
                Self::Required(generated)
            }
        }
    }
}

/// Generate a hex-encoded 32-byte random token.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Clone)]
pub struct AuthLayer {
    mode: AuthMode,
}

impl AuthLayer {
    pub fn new(mode: AuthMode) -> Self {
        Self { mode }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthMiddleware {
            inner: service,
            mode: self.mode.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    mode: AuthMode,
}

impl<S> Service<hyper::Request<Body>> for AuthMiddleware<S>
where
    S: Service<hyper::Request<Body>, Response = hyper::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: hyper::Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let mode = self.mode.clone();

        Box::pin(async move {
            if !requires_auth(req.uri().path(), &mode) {
                return inner.call(req).await;
            }

            let expected = match &mode {
                AuthMode::Required(t) => t,
                AuthMode::Disabled => unreachable!("requires_auth filters Disabled"),
            };

            if validate_bearer(req.headers(), expected) {
                return inner.call(req).await;
            }

            warn!("rejected unauthenticated request to {}", req.uri().path());
            Ok(Status::unauthenticated("missing or invalid bearer token").to_http())
        })
    }
}

/// Returns true when this request must carry a valid bearer token. Disabled
/// mode and the `Ping` liveness RPC always bypass.
fn requires_auth(path: &str, mode: &AuthMode) -> bool {
    if matches!(mode, AuthMode::Disabled) {
        return false;
    }
    !path.ends_with("/Ping")
}

/// Constant-time bearer-token comparison. Reads `Authorization: Bearer <t>`
/// from the request headers and matches against the expected token.
fn validate_bearer(headers: &HeaderMap, expected: &str) -> bool {
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);

    match presented {
        Some(token) => token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn validate_bearer_accepts_matching_token() {
        let h = headers_with_auth("Bearer good-token");
        assert!(validate_bearer(&h, "good-token"));
    }

    #[test]
    fn validate_bearer_rejects_wrong_token() {
        let h = headers_with_auth("Bearer wrong-token");
        assert!(!validate_bearer(&h, "good-token"));
    }

    #[test]
    fn validate_bearer_rejects_missing_header() {
        let h = HeaderMap::new();
        assert!(!validate_bearer(&h, "good-token"));
    }

    #[test]
    fn validate_bearer_rejects_non_bearer_scheme() {
        let h = headers_with_auth("Basic Zm9vOmJhcg==");
        assert!(!validate_bearer(&h, "good-token"));
    }

    #[test]
    fn validate_bearer_rejects_empty_token() {
        let h = headers_with_auth("Bearer ");
        assert!(!validate_bearer(&h, "good-token"));
    }

    #[test]
    fn validate_bearer_is_constant_time_safe_on_length_mismatch() {
        // Same prefix, different lengths should still reject — not a true CT
        // assertion (we'd need a timing harness for that), but the ct_eq path
        // handles unequal-length inputs without short-circuiting on the prefix.
        let h = headers_with_auth("Bearer good");
        assert!(!validate_bearer(&h, "good-token"));
    }

    #[test]
    fn requires_auth_skips_ping() {
        let mode = AuthMode::Required("t".into());
        assert!(!requires_auth("/walletrpc.WalletService/Ping", &mode));
        assert!(requires_auth(
            "/walletrpc.WalletService/CreateGenericWallet",
            &mode
        ));
    }

    #[test]
    fn requires_auth_skips_everything_when_disabled() {
        let mode = AuthMode::Disabled;
        assert!(!requires_auth("/walletrpc.WalletService/Ping", &mode));
        assert!(!requires_auth(
            "/walletrpc.WalletService/CreateGenericWallet",
            &mode
        ));
    }

    #[test]
    fn from_config_disabled_short_circuits() {
        match AuthMode::from_config(true, Some("ignored".into())) {
            AuthMode::Disabled => (),
            other => panic!("expected Disabled, got {:?}", other),
        }
    }

    #[test]
    fn from_config_uses_configured_token() {
        match AuthMode::from_config(false, Some("supplied".into())) {
            AuthMode::Required(t) => assert_eq!(t, "supplied"),
            other => panic!("expected Required, got {:?}", other),
        }
    }

    #[test]
    fn from_config_generates_when_unset() {
        match AuthMode::from_config(false, None) {
            AuthMode::Required(t) => {
                assert_eq!(t.len(), 64, "32 bytes hex-encoded should be 64 chars");
                assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
            }
            other => panic!("expected Required, got {:?}", other),
        }
    }

    #[test]
    fn from_config_treats_empty_token_as_unset() {
        match AuthMode::from_config(false, Some(String::new())) {
            AuthMode::Required(t) => {
                assert_eq!(t.len(), 64, "should fall back to a generated token");
            }
            other => panic!("expected Required, got {:?}", other),
        }
    }
}

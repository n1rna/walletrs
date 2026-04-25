use log::{debug, info};
use std::task::{Context, Poll};
use std::time::Instant;
use tonic::body::BoxBody;
use tonic::transport::Body;
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub struct LoggingLayer;

impl<S> Layer<S> for LoggingLayer {
    type Service = LoggingMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        LoggingMiddleware { inner: service }
    }
}

#[derive(Debug, Clone)]
pub struct LoggingMiddleware<S> {
    inner: S,
}

impl<S> Service<hyper::Request<Body>> for LoggingMiddleware<S>
where
    S: Service<hyper::Request<Body>, Response = hyper::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: hyper::Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let method = req.uri().path().to_string();
            let start = Instant::now();

            info!("gRPC request: {}", method);

            if log::log_enabled!(log::Level::Debug) {
                debug!(
                    "gRPC request details: method={} headers={:?}",
                    method,
                    req.headers()
                );
            }

            let response = inner.call(req).await;

            let duration = start.elapsed();

            match &response {
                Ok(res) => {
                    info!(
                        "gRPC response: {} - status={:?} duration={:?}",
                        method,
                        res.status(),
                        duration
                    );

                    if log::log_enabled!(log::Level::Debug) {
                        debug!("gRPC response details: method={} status={:?} headers={:?} duration={:?}",
                            method, res.status(), res.headers(), duration);
                    }
                }
                Err(err) => {
                    info!(
                        "gRPC error: {} - error={} duration={:?}",
                        method, err, duration
                    );
                }
            }

            response
        })
    }
}

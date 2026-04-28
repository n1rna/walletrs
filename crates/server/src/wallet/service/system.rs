use crate::proto::pb::{PingRequest, PingResponse};
use tonic::{Request, Response, Status};

pub async fn ping(_request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
    Ok(Response::new(PingResponse {}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_returns_empty_response() {
        let resp = ping(Request::new(PingRequest {})).await.expect("ping ok");
        // PingResponse is an empty message — the test guards against accidental
        // schema drift that adds fields without matching defaults here.
        assert_eq!(resp.into_inner(), PingResponse {});
    }
}

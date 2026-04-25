use tonic::{Request, Response, Status};
use crate::proto::pb::{PingRequest, PingResponse};

pub async fn ping(_request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
    Ok(Response::new(PingResponse {}))
}
use crate::proto::pb::{PingRequest, PingResponse};
use tonic::{Request, Response, Status};

pub async fn ping(_request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
    Ok(Response::new(PingResponse {}))
}

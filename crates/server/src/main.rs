use log::{info, trace};
use std::env;
use tonic::transport::Server;
use tower::ServiceBuilder;
use walletrs_lib::db;

use walletrs_lib::proto::pb::wallet_service_server::WalletServiceServer;
use walletrs_lib::wallet::service::middleware::LoggingLayer;
use walletrs_lib::wallet::service::WalletRPC;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Build marker — bump when you want to confirm a rebuild actually shipped.
    info!("walletrs build marker: R2-SIG-FIX-V1");

    if let Err(e) = db::init_all_storage() {
        return Err(format!("Failed to initialize managed keys storage: {}", e).into());
    }

    // Get port from environment variable or use default
    let port = env::var("WALLETRS_PORT").unwrap_or_else(|_| "50051".to_string());
    let host = env::var("WALLETRS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", host, port).parse()?;
    info!("Starting wallet service on {}", addr);

    let walletrpc = WalletRPC::default();

    trace!("Wallet RPC service initialized");

    info!("Server starting up...");
    info!("Server is running on {}", addr);

    Server::builder()
        .layer(ServiceBuilder::new().layer(LoggingLayer))
        .add_service(WalletServiceServer::new(walletrpc))
        .serve(addr)
        .await?;

    Ok(())
}

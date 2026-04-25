use log::{info, trace};
use tonic::transport::Server;
use tower::ServiceBuilder;
use walletrs_lib::config::CONFIG;
use walletrs_lib::db;
use walletrs_lib::proto::pb::wallet_service_server::WalletServiceServer;
use walletrs_lib::wallet::service::auth::{AuthLayer, AuthMode};
use walletrs_lib::wallet::service::middleware::LoggingLayer;
use walletrs_lib::wallet::service::WalletRPC;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("walletrs starting (network: {})", CONFIG.bitcoin_network());

    if let Err(e) = db::init_all_storage() {
        return Err(format!("Failed to initialize storage: {}", e).into());
    }

    let auth_mode = AuthMode::from_config(
        CONFIG.auth_disabled(),
        CONFIG.auth_token().map(|s| s.to_string()),
    );

    let addr = format!("{}:{}", CONFIG.host(), CONFIG.port()).parse()?;
    let walletrpc = WalletRPC::default();
    trace!("WalletRPC service initialized");
    info!("Listening on {}", addr);

    Server::builder()
        .layer(
            ServiceBuilder::new()
                .layer(AuthLayer::new(auth_mode))
                .layer(LoggingLayer),
        )
        .add_service(WalletServiceServer::new(walletrpc))
        .serve(addr)
        .await?;

    Ok(())
}

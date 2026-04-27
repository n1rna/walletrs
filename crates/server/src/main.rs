use clap::Parser;
use log::{error, info, trace};
use tonic::transport::Server;
use tower::ServiceBuilder;
use walletrs_lib::agent::{self, AgentAction, AgentConfig, AgentKeypair, AgentState};
use walletrs_lib::config::CONFIG;
use walletrs_lib::db;
use walletrs_lib::proto::pb::wallet_service_server::WalletServiceServer;
use walletrs_lib::wallet::service::auth::{AuthLayer, AuthMode};
use walletrs_lib::wallet::service::middleware::LoggingLayer;
use walletrs_lib::wallet::service::WalletRPC;

const DEFAULT_SIGVAULT_ENDPOINT: &str = "https://api.sigvault.org";

#[derive(Parser, Debug)]
#[command(
    name = "walletrs",
    version,
    about = "Standalone gRPC service for advanced Bitcoin wallets."
)]
struct Cli {
    /// One-shot pairing token from the sigvault UI. Triggers first-time
    /// pairing on startup. Required only the first time; subsequent restarts
    /// reconnect using the saved keypair.
    #[arg(long, env = "WALLETRS_SIGVAULT_TOKEN")]
    sigvault_token: Option<String>,

    /// Sigvault API URL. Override only when self-hosting sigvault.
    #[arg(long, env = "WALLETRS_SIGVAULT_ENDPOINT", default_value = DEFAULT_SIGVAULT_ENDPOINT)]
    sigvault_endpoint: String,

    /// Disable the sigvault agent even when paired credentials exist on
    /// disk. Saved credentials are preserved.
    #[arg(long, env = "WALLETRS_SIGVAULT_DISABLED")]
    no_sigvault: bool,

    /// Replace existing pairing credentials with a fresh keypair. Requires
    /// `--sigvault-token`. Without this flag, providing a token while
    /// already paired is a no-op (the daemon reconnects with the saved
    /// keypair — idempotent restart).
    #[arg(long)]
    repair: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    info!("walletrs starting (network: {})", CONFIG.bitcoin_network());

    if let Err(e) = db::init_all_storage() {
        return Err(format!("Failed to initialize storage: {}", e).into());
    }

    // Resolve agent action before starting the gRPC server so first-pair
    // failures exit early.
    let agent_config = AgentConfig {
        token: cli.sigvault_token,
        endpoint: cli.sigvault_endpoint,
        disabled: cli.no_sigvault,
        repair: cli.repair,
    };
    let agent_action = match AgentState::load() {
        Ok(state) => agent_config.resolve(state),
        Err(e) => {
            error!("failed to load agent state: {}", e);
            return Err(e.into());
        }
    };

    let agent_handle = match agent_action {
        AgentAction::None => {
            info!("agent: standalone mode (no sigvault connection)");
            None
        }
        AgentAction::Reconnect(state) => {
            info!("agent: reconnecting as {}", state.agent_id);
            let keypair = AgentKeypair::from_encrypted_b64(&state.private_key_encrypted)?;
            Some(tokio::spawn(agent::connect::run_forever(state, keypair)))
        }
        AgentAction::PairThenConnect { token, endpoint } => {
            info!("agent: first-time pairing with {}", endpoint);
            // Per the spec, first-pairing failure is fatal — propagate.
            let outcome = agent::pair(&token, &endpoint).await?;
            Some(tokio::spawn(agent::connect::run_forever(
                outcome.state,
                outcome.keypair,
            )))
        }
        AgentAction::RepairThenConnect { token, endpoint } => {
            info!("agent: re-pairing (--repair) with {}", endpoint);
            // Re-pair semantically replaces the saved state. Pair first so
            // we don't blow away credentials before we have new ones.
            let outcome = agent::pair(&token, &endpoint).await?;
            Some(tokio::spawn(agent::connect::run_forever(
                outcome.state,
                outcome.keypair,
            )))
        }
    };

    let auth_mode = AuthMode::from_config(
        CONFIG.auth_disabled(),
        CONFIG.auth_token().map(|s| s.to_string()),
    );

    let addr = format!("{}:{}", CONFIG.host(), CONFIG.port()).parse()?;
    let walletrpc = WalletRPC::default();
    trace!("WalletRPC service initialized");
    info!("Listening on {}", addr);

    let server = Server::builder()
        .layer(
            ServiceBuilder::new()
                .layer(AuthLayer::new(auth_mode))
                .layer(LoggingLayer),
        )
        .add_service(WalletServiceServer::new(walletrpc))
        .serve(addr);

    tokio::select! {
        result = server => result?,
        _ = wait_for_agent(agent_handle) => {
            // Agent task should run forever; if it returns, log and exit.
            error!("agent task ended unexpectedly");
        }
    }

    Ok(())
}

async fn wait_for_agent(handle: Option<tokio::task::JoinHandle<()>>) {
    match handle {
        Some(h) => {
            let _ = h.await;
        }
        None => std::future::pending::<()>().await,
    }
}

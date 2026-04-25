use std::time::{SystemTime, UNIX_EPOCH};

use log::info;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use crate::proto::pb::walletrs_agent_client::WalletrsAgentClient;
use crate::proto::pb::PairRequest;

use super::error::AgentError;
use super::keypair::AgentKeypair;
use super::state::AgentState;

/// Outcome of a pairing attempt — both the new state we just persisted and
/// the keypair (so the caller doesn't have to decrypt-then-re-decrypt to
/// open the bidi stream).
pub struct PairOutcome {
    pub state: AgentState,
    pub keypair: AgentKeypair,
}

/// Run the pairing handshake against the given sigvault endpoint. Generates
/// a fresh Ed25519 keypair, exchanges the pairing token for an `agent_id`,
/// persists the encrypted state to disk, and returns both for the connect
/// loop to use.
///
/// On any failure this function returns an error; `main.rs` is responsible
/// for exiting non-zero (the spec says first-pairing failure is fatal).
pub async fn pair(token: &str, endpoint: &str) -> Result<PairOutcome, AgentError> {
    let keypair = AgentKeypair::generate();

    let hostname = hostname_or_default();
    info!(
        "pairing with sigvault at {} (hostname: {})",
        endpoint, hostname
    );

    let channel = build_channel(endpoint).await?;
    let mut client = WalletrsAgentClient::new(channel);

    let request = Request::new(PairRequest {
        pairing_token: token.to_string(),
        public_key: keypair.public_bytes().to_vec(),
        walletrs_version: env!("CARGO_PKG_VERSION").to_string(),
        hostname,
    });

    let response = client
        .pair(request)
        .await
        .map_err(|status| AgentError::Pair(format!("{}: {}", status.code(), status.message())))?
        .into_inner();

    if response.agent_id.is_empty() {
        return Err(AgentError::Pair("sigvault returned empty agent_id".into()));
    }

    let resolved_endpoint = if response.assigned_endpoint.is_empty() {
        endpoint.to_string()
    } else {
        response.assigned_endpoint
    };

    let state = AgentState {
        agent_id: response.agent_id,
        endpoint: resolved_endpoint,
        public_key: keypair.public_b64(),
        private_key_encrypted: keypair.encrypt_to_b64()?,
        paired_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };

    state.save()?;
    info!(
        "paired successfully — agent_id={} endpoint={}",
        state.agent_id, state.endpoint
    );

    Ok(PairOutcome { state, keypair })
}

async fn build_channel(endpoint: &str) -> Result<Channel, AgentError> {
    Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| AgentError::Transport(format!("invalid endpoint {}: {}", endpoint, e)))?
        .connect()
        .await
        .map_err(|e| AgentError::Transport(format!("dial {}: {}", endpoint, e)))
}

fn hostname_or_default() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "walletrs".to_string())
}

use std::time::{SystemTime, UNIX_EPOCH};

use log::info;

use super::error::AgentError;
use super::keypair::AgentKeypair;
use super::state::AgentState;
use super::wire::{PairHttpRequest, PairHttpResponse};

pub struct PairOutcome {
    pub state: AgentState,
    pub keypair: AgentKeypair,
}

/// First-time pair against the sigvault HTTP endpoint. Generates a fresh
/// Ed25519 keypair, exchanges the pairing token for an `agent_id`,
/// persists the encrypted state to disk, and returns both for the connect
/// loop to use.
///
/// `endpoint` is the sigvault base URL (e.g. `https://api.sigvault.org`).
/// On any failure this function returns an error; `main.rs` is responsible
/// for exiting non-zero (the spec says first-pairing failure is fatal).
pub async fn pair(token: &str, endpoint: &str) -> Result<PairOutcome, AgentError> {
    let keypair = AgentKeypair::generate();
    let hostname = hostname_or_default();
    let pair_url = format!(
        "{}/api/v2/walletrs/agent/pair",
        endpoint.trim_end_matches('/')
    );

    info!(
        "pairing with sigvault at {} (hostname: {})",
        endpoint, hostname
    );

    let body = PairHttpRequest {
        pairing_token: token.to_string(),
        public_key: keypair.public_bytes().to_vec(),
        walletrs_version: env!("CARGO_PKG_VERSION").to_string(),
        hostname: hostname.clone(),
    };

    let response = reqwest::Client::new()
        .post(&pair_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentError::Pair(format!("send: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AgentError::Pair(format!("{}: {}", status, body)));
    }

    let parsed: PairHttpResponse = response
        .json()
        .await
        .map_err(|e| AgentError::Pair(format!("decode response: {}", e)))?;

    if parsed.agent_id.is_empty() {
        return Err(AgentError::Pair("sigvault returned empty agent_id".into()));
    }

    let resolved_endpoint = if parsed.assigned_endpoint.is_empty() {
        endpoint.to_string()
    } else {
        parsed.assigned_endpoint
    };

    let state = AgentState {
        agent_id: parsed.agent_id,
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

fn hostname_or_default() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "walletrs".to_string())
}

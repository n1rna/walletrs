//! Persistent bidirectional stream client + reconnect loop.
//!
//! The agent opens a single long-lived `OpenStream` bidi gRPC connection to
//! sigvault. The handshake is:
//!
//! 1. Agent → server : `AgentHello { agent_id, walletrs_version }`
//! 2. Server → agent : `AgentChallenge { nonce }` (32 random bytes)
//! 3. Agent → server : `AgentChallengeResponse { signature }` (Ed25519 sig)
//! 4. Server → agent : `AgentReady`
//! 5. Operation loop : `OperationRequest` ↔ `OperationResponse`, plus
//!    `AgentHeartbeat` in either direction.
//!
//! On disconnect — for any reason other than a clean shutdown — the loop
//! reconnects with exponential backoff. The local gRPC server keeps
//! serving regardless.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use crate::proto::pb::agent_message::Body;
use crate::proto::pb::walletrs_agent_client::WalletrsAgentClient;
use crate::proto::pb::{
    AgentChallengeResponse, AgentHeartbeat, AgentHello, AgentMessage, OperationRequest,
};

use super::dispatcher;
use super::error::AgentError;
use super::keypair::AgentKeypair;
use super::state::AgentState;

const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(120);
const SEND_BUFFER: usize = 64;

/// Run the connect loop forever. Reconnects with exponential backoff on any
/// session failure. Returns only when the future is cancelled (e.g. on
/// process shutdown via `tokio::select!`).
pub async fn run_forever(state: AgentState, keypair: AgentKeypair) {
    let mut backoff = INITIAL_BACKOFF;

    loop {
        match run_session(&state, &keypair).await {
            Ok(()) => {
                info!(
                    "agent session ended cleanly; reconnecting after {:?}",
                    INITIAL_BACKOFF
                );
                backoff = INITIAL_BACKOFF;
                tokio::time::sleep(INITIAL_BACKOFF).await;
            }
            Err(e) => {
                warn!(
                    "agent session ended with error: {e}; reconnecting in {:?}",
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn run_session(state: &AgentState, keypair: &AgentKeypair) -> Result<(), AgentError> {
    let channel = build_channel(&state.endpoint).await?;
    let mut client = WalletrsAgentClient::new(channel);

    let (tx, rx) = mpsc::channel::<AgentMessage>(SEND_BUFFER);
    let outbound = ReceiverStream::new(rx);
    let response = client
        .open_stream(Request::new(outbound))
        .await
        .map_err(|e| AgentError::Transport(format!("open_stream: {}", e)))?;
    let mut inbound = response.into_inner();

    // 1. Hello
    send(
        &tx,
        AgentMessage {
            body: Some(Body::Hello(AgentHello {
                agent_id: state.agent_id.clone(),
                walletrs_version: env!("CARGO_PKG_VERSION").to_string(),
            })),
        },
    )
    .await?;

    // 2. Receive challenge
    let challenge = recv_challenge(&mut inbound).await?;

    // 3. Sign + respond
    send(
        &tx,
        AgentMessage {
            body: Some(Body::ChallengeResponse(AgentChallengeResponse {
                signature: keypair.sign(&challenge),
            })),
        },
    )
    .await?;

    // 4. Wait for ready
    expect_ready(&mut inbound).await?;
    info!("agent connected — awaiting operations");

    // 5. Operation loop
    while let Some(msg) = inbound
        .message()
        .await
        .map_err(|e| AgentError::Loop(format!("recv: {}", e)))?
    {
        let Some(body) = msg.body else {
            continue;
        };
        match body {
            Body::OperationRequest(op) => {
                let tx = tx.clone();
                tokio::spawn(handle_operation(tx, op));
            }
            Body::Heartbeat(_) => {
                // Echo a heartbeat back so sigvault can measure round-trip.
                let _ = send(
                    &tx,
                    AgentMessage {
                        body: Some(Body::Heartbeat(AgentHeartbeat {
                            sent_at_unix_ms: now_unix_ms(),
                        })),
                    },
                )
                .await;
            }
            other => {
                debug!(
                    "ignoring unexpected agent message during op loop: {:?}",
                    other
                );
            }
        }
    }

    Ok(())
}

async fn handle_operation(tx: mpsc::Sender<AgentMessage>, op: OperationRequest) {
    let request_id = op.request_id.clone();
    debug!(
        "dispatch start request_id={} method={}",
        request_id, op.method
    );
    let result = dispatcher::dispatch(&op.method, &op.payload).await;
    let response = dispatcher::build_response(&request_id, result);
    debug!(
        "dispatch end request_id={} status={}",
        request_id,
        response.status.as_ref().map(|s| s.code).unwrap_or(0)
    );

    if let Err(e) = tx
        .send(AgentMessage {
            body: Some(Body::OperationResponse(response)),
        })
        .await
    {
        error!("failed to send operation response: {}", e);
    }
}

async fn recv_challenge(
    inbound: &mut tonic::Streaming<AgentMessage>,
) -> Result<Vec<u8>, AgentError> {
    let msg = inbound
        .message()
        .await
        .map_err(|e| AgentError::Transport(format!("recv challenge: {}", e)))?
        .ok_or_else(|| AgentError::Challenge("stream closed before challenge".into()))?;

    match msg.body {
        Some(Body::Challenge(c)) => Ok(c.nonce),
        other => Err(AgentError::Challenge(format!(
            "expected AgentChallenge, got {:?}",
            other
        ))),
    }
}

async fn expect_ready(inbound: &mut tonic::Streaming<AgentMessage>) -> Result<(), AgentError> {
    let msg = inbound
        .message()
        .await
        .map_err(|e| AgentError::Transport(format!("recv ready: {}", e)))?
        .ok_or_else(|| AgentError::Challenge("stream closed before ready".into()))?;

    match msg.body {
        Some(Body::Ready(_)) => Ok(()),
        other => Err(AgentError::Challenge(format!(
            "expected AgentReady, got {:?}",
            other
        ))),
    }
}

async fn send(tx: &mpsc::Sender<AgentMessage>, msg: AgentMessage) -> Result<(), AgentError> {
    tx.send(msg)
        .await
        .map_err(|e| AgentError::Transport(format!("outbound send: {}", e)))
}

async fn build_channel(endpoint: &str) -> Result<Channel, AgentError> {
    Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| AgentError::Transport(format!("invalid endpoint {}: {}", endpoint, e)))?
        .connect()
        .await
        .map_err(|e| AgentError::Transport(format!("dial {}: {}", endpoint, e)))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

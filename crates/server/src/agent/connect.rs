//! Persistent WebSocket client + reconnect loop.
//!
//! The agent opens one long-lived WebSocket connection to sigvault at
//! `wss://<endpoint>/api/v2/walletrs/agent/connect`. The handshake is:
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

use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::dispatcher;
use super::error::AgentError;
use super::keypair::AgentKeypair;
use super::state::AgentState;
use super::wire::{
    AgentChallengeResponse, AgentHeartbeat, AgentHello, AgentMessage, OperationRequest,
};

const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(120);
const SEND_BUFFER: usize = 64;

/// Run the connect loop forever. Reconnects with exponential backoff on any
/// session failure.
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
    let ws_url = build_ws_url(&state.endpoint)?;
    debug!("connecting agent WebSocket: {}", ws_url);

    let (ws, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| AgentError::Transport(format!("ws connect: {}", e)))?;

    let (mut sink, mut stream) = ws.split();

    // Outbound channel — single-writer to the WS sink.
    let (tx, mut rx) = mpsc::channel::<AgentMessage>(SEND_BUFFER);
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    error!("encode AgentMessage: {}", e);
                    break;
                }
            };
            if let Err(e) = sink.send(Message::Text(json)).await {
                debug!("ws sink send failed (likely peer closed): {}", e);
                break;
            }
        }
        let _ = sink.close().await;
    });

    // 1. Hello
    send(
        &tx,
        AgentMessage::Hello(AgentHello {
            agent_id: state.agent_id.clone(),
            walletrs_version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
    .await?;

    // 2. Receive challenge
    let challenge = match recv(&mut stream).await? {
        AgentMessage::Challenge(c) => c.nonce,
        other => {
            return Err(AgentError::Challenge(format!(
                "expected challenge, got {:?}",
                other
            )));
        }
    };

    // 3. Sign + respond
    send(
        &tx,
        AgentMessage::ChallengeResponse(AgentChallengeResponse {
            signature: keypair.sign(&challenge),
        }),
    )
    .await?;

    // 4. Wait for ready
    match recv(&mut stream).await? {
        AgentMessage::Ready(_) => (),
        other => {
            return Err(AgentError::Challenge(format!(
                "expected ready, got {:?}",
                other
            )));
        }
    }
    info!("agent connected — awaiting operations");

    // 5. Operation loop
    while let Some(frame) = stream.next().await {
        let frame = frame.map_err(|e| AgentError::Loop(format!("ws recv: {}", e)))?;
        let msg = match parse_frame(frame) {
            ParsedFrame::Message(m) => m,
            ParsedFrame::Skip => continue,
            ParsedFrame::Close => break,
        };

        match msg {
            AgentMessage::OperationRequest(op) => {
                let tx = tx.clone();
                tokio::spawn(handle_operation(tx, op));
            }
            AgentMessage::Heartbeat(_) => {
                let _ = send(
                    &tx,
                    AgentMessage::Heartbeat(AgentHeartbeat {
                        sent_at_unix_ms: now_unix_ms(),
                    }),
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

    drop(tx);
    let _ = writer.await;
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
    if let Err(e) = tx.send(AgentMessage::OperationResponse(response)).await {
        error!("failed to send operation response: {}", e);
    }
}

async fn send(tx: &mpsc::Sender<AgentMessage>, msg: AgentMessage) -> Result<(), AgentError> {
    tx.send(msg)
        .await
        .map_err(|e| AgentError::Transport(format!("outbound send: {}", e)))
}

async fn recv<S>(stream: &mut S) -> Result<AgentMessage, AgentError>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let frame = stream
            .next()
            .await
            .ok_or_else(|| AgentError::Transport("ws closed during handshake".into()))?
            .map_err(|e| AgentError::Transport(format!("ws recv: {}", e)))?;

        match parse_frame(frame) {
            ParsedFrame::Message(m) => return Ok(m),
            ParsedFrame::Skip => continue,
            ParsedFrame::Close => {
                return Err(AgentError::Transport("ws closed during handshake".into()))
            }
        }
    }
}

enum ParsedFrame {
    Message(AgentMessage),
    Skip,
    Close,
}

fn parse_frame(frame: Message) -> ParsedFrame {
    match frame {
        Message::Text(text) => match serde_json::from_str::<AgentMessage>(&text) {
            Ok(msg) => ParsedFrame::Message(msg),
            Err(e) => {
                warn!("malformed agent message frame: {}", e);
                ParsedFrame::Skip
            }
        },
        Message::Binary(_) => {
            warn!("ignoring unexpected binary ws frame");
            ParsedFrame::Skip
        }
        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => ParsedFrame::Skip,
        Message::Close(_) => ParsedFrame::Close,
    }
}

fn build_ws_url(endpoint: &str) -> Result<String, AgentError> {
    let url = url::Url::parse(endpoint)
        .map_err(|e| AgentError::Transport(format!("invalid endpoint {}: {}", endpoint, e)))?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => {
            return Err(AgentError::Transport(format!(
                "unsupported endpoint scheme: {}",
                other
            )));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| AgentError::Transport(format!("endpoint has no host: {}", endpoint)))?;
    let port = url.port().map(|p| format!(":{}", p)).unwrap_or_default();
    Ok(format!(
        "{}://{}{}/api/v2/walletrs/agent/connect",
        scheme, host, port
    ))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ws_url_https_to_wss() {
        let result = build_ws_url("https://api.sigvault.org").unwrap();
        assert_eq!(
            result,
            "wss://api.sigvault.org/api/v2/walletrs/agent/connect"
        );
    }

    #[test]
    fn build_ws_url_http_to_ws() {
        let result = build_ws_url("http://localhost:8000").unwrap();
        assert_eq!(result, "ws://localhost:8000/api/v2/walletrs/agent/connect");
    }

    #[test]
    fn build_ws_url_strips_trailing_slash() {
        let result = build_ws_url("https://api.sigvault.org/").unwrap();
        assert_eq!(
            result,
            "wss://api.sigvault.org/api/v2/walletrs/agent/connect"
        );
    }

    #[test]
    fn build_ws_url_rejects_unsupported_scheme() {
        assert!(build_ws_url("ftp://example.com").is_err());
        assert!(build_ws_url("not-a-url").is_err());
    }
}

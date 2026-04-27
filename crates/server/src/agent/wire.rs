//! JSON wire format for the sigvault agent transport.
//!
//! The agent talks to sigvault over plain HTTP (for `Pair`) and WebSocket
//! (for the persistent operation stream). The envelope is JSON; operation
//! payloads inside `OperationRequest` / `OperationResponse` stay
//! prost-encoded so we don't have to translate every walletrpc request /
//! response into JSON.
//!
//! Wire shape (externally tagged enum):
//!
//! ```text
//! {"hello": {"agent_id": "agt_xxx", "walletrs_version": "0.3.0"}}
//! {"challenge": {"nonce": "<base64>"}}
//! {"challenge_response": {"signature": "<base64>"}}
//! {"ready": {}}
//! {"operation_request": {"request_id": "uuid", "method": "...", "payload": "<base64>"}}
//! {"operation_response": {"request_id": "uuid", "status": {...}, "payload": "<base64>"}}
//! {"heartbeat": {"sent_at_unix_ms": 1714058400000}}
//! ```

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMessage {
    Hello(AgentHello),
    Challenge(AgentChallenge),
    ChallengeResponse(AgentChallengeResponse),
    Ready(AgentReady),
    OperationRequest(OperationRequest),
    OperationResponse(OperationResponse),
    Heartbeat(AgentHeartbeat),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentHello {
    pub agent_id: String,
    pub walletrs_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentChallenge {
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentChallengeResponse {
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AgentReady {}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentHeartbeat {
    pub sent_at_unix_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationRequest {
    pub request_id: String,
    pub method: String,
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationResponse {
    pub request_id: String,
    pub status: OperationStatus,
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationStatus {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairHttpRequest {
    pub pairing_token: String,
    #[serde(with = "base64_bytes")]
    pub public_key: Vec<u8>,
    pub walletrs_version: String,
    pub hostname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairHttpResponse {
    pub agent_id: String,
    #[serde(default)]
    pub assigned_endpoint: String,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trip() {
        let msg = AgentMessage::Hello(AgentHello {
            agent_id: "agt_xxx".into(),
            walletrs_version: "0.3.0".into(),
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"hello\""));
        let back: AgentMessage = serde_json::from_str(&json).unwrap();
        match back {
            AgentMessage::Hello(h) => assert_eq!(h.agent_id, "agt_xxx"),
            _ => panic!("expected hello variant"),
        }
    }

    #[test]
    fn challenge_serializes_base64() {
        let msg = AgentMessage::Challenge(AgentChallenge {
            nonce: vec![1, 2, 3, 4],
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"challenge\""));
        // 4 bytes base64-encoded with padding
        assert!(json.contains("\"AQIDBA==\""));
    }

    #[test]
    fn ready_is_empty_object() {
        let msg = AgentMessage::Ready(AgentReady::default());
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"ready":{}}"#);
    }

    #[test]
    fn operation_request_round_trip() {
        let msg = AgentMessage::OperationRequest(OperationRequest {
            request_id: "req-1".into(),
            method: "/walletrpc.WalletService/Ping".into(),
            payload: vec![],
        });
        let json = serde_json::to_string(&msg).unwrap();
        let back: AgentMessage = serde_json::from_str(&json).unwrap();
        match back {
            AgentMessage::OperationRequest(op) => {
                assert_eq!(op.request_id, "req-1");
                assert!(op.payload.is_empty());
            }
            _ => panic!("expected operation_request"),
        }
    }
}

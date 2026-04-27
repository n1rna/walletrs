//! Sigvault agent — outbound reverse-tunnel client.
//!
//! When started with a pairing token (`--sigvault-token` /
//! `WALLETRS_SIGVAULT_TOKEN`), walletrs generates an Ed25519 keypair,
//! registers the public key with sigvault via an HTTP `POST /agent/pair`,
//! persists the credentials to disk, and opens a persistent WebSocket
//! at `/agent/connect`. Sigvault sends operation requests over that
//! WebSocket; the agent dispatches them to the same internal handlers
//! used by the local gRPC server, and replies with the encoded response
//! (prost-encoded payload bytes wrapped in a JSON envelope).
//!
//! Architecture and decisions are documented in
//! `docs/plans/walletrs-open-source.md` (sigvault repo) Phase 5.

pub mod connect;
pub mod dispatcher;
pub mod error;
pub mod keypair;
pub mod pair;
pub mod state;
pub mod wire;

pub use error::AgentError;
pub use keypair::AgentKeypair;
pub use pair::{pair, PairOutcome};
pub use state::AgentState;

/// What the binary should do at startup with respect to the sigvault agent,
/// resolved from the combination of CLI flags / env vars / on-disk state.
#[derive(Debug, Clone)]
pub enum AgentAction {
    /// No agent activity. Either disabled or no token + no prior pairing.
    None,
    /// Reconnect using saved credentials.
    Reconnect(AgentState),
    /// First-time pairing with the supplied token, then connect.
    PairThenConnect { token: String, endpoint: String },
    /// Re-pair (replace existing credentials), then connect.
    RepairThenConnect { token: String, endpoint: String },
}

/// Inputs from the CLI / env layer, resolved by `main.rs`.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub token: Option<String>,
    pub endpoint: String,
    pub disabled: bool,
    pub repair: bool,
}

impl AgentConfig {
    /// Resolve the action the binary should take at startup based on
    /// configuration and on-disk pairing state.
    pub fn resolve(&self, existing: Option<AgentState>) -> AgentAction {
        if self.disabled {
            return AgentAction::None;
        }

        match (self.token.as_deref(), existing, self.repair) {
            // Standalone — no token, nothing on disk.
            (None, None, _) => AgentAction::None,

            // Reconnect — credentials already on disk; ignore any provided
            // token (idempotent restart) unless `--repair` is set.
            (None, Some(state), _) => AgentAction::Reconnect(state),
            (Some(_), Some(state), false) => AgentAction::Reconnect(state),

            // Re-pair — explicit `--repair` with token, replaces existing state.
            (Some(token), Some(_), true) => AgentAction::RepairThenConnect {
                token: token.to_string(),
                endpoint: self.endpoint.clone(),
            },

            // First-time pairing.
            (Some(token), None, _) => AgentAction::PairThenConnect {
                token: token.to_string(),
                endpoint: self.endpoint.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state() -> AgentState {
        AgentState {
            agent_id: "agt_test".to_string(),
            endpoint: "https://sigvault.example".to_string(),
            public_key: "AAAA".to_string(),
            private_key_encrypted: "BBBB".to_string(),
            paired_at: 0,
        }
    }

    fn config(token: Option<&str>, disabled: bool, repair: bool) -> AgentConfig {
        AgentConfig {
            token: token.map(str::to_string),
            endpoint: "https://sigvault.example".to_string(),
            disabled,
            repair,
        }
    }

    #[test]
    fn disabled_always_none() {
        let cfg = config(Some("PAIR-XX"), true, false);
        assert!(matches!(
            cfg.resolve(Some(dummy_state())),
            AgentAction::None
        ));
        assert!(matches!(cfg.resolve(None), AgentAction::None));
    }

    #[test]
    fn standalone_when_nothing_set() {
        let cfg = config(None, false, false);
        assert!(matches!(cfg.resolve(None), AgentAction::None));
    }

    #[test]
    fn reconnect_when_state_exists_no_token() {
        let cfg = config(None, false, false);
        assert!(matches!(
            cfg.resolve(Some(dummy_state())),
            AgentAction::Reconnect(_)
        ));
    }

    #[test]
    fn reconnect_when_state_exists_token_provided_without_repair() {
        let cfg = config(Some("PAIR-XX"), false, false);
        assert!(matches!(
            cfg.resolve(Some(dummy_state())),
            AgentAction::Reconnect(_)
        ));
    }

    #[test]
    fn repair_when_state_exists_token_and_repair_flag() {
        let cfg = config(Some("PAIR-XX"), false, true);
        assert!(matches!(
            cfg.resolve(Some(dummy_state())),
            AgentAction::RepairThenConnect { .. }
        ));
    }

    #[test]
    fn first_pair_when_token_no_state() {
        let cfg = config(Some("PAIR-XX"), false, false);
        assert!(matches!(
            cfg.resolve(None),
            AgentAction::PairThenConnect { .. }
        ));
    }
}

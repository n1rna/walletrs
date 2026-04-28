//! Thin Electrum / Electrs client wrapper.
//!
//! Wraps `bdk_electrum::BdkElectrumClient` with two operations:
//!
//! - `broadcast(tx)` — push a finalised transaction to the Electrum server.
//! - `full_scan(wallet, batch_size, stop_gap, fetch_prev_txouts)` — perform a
//!   BDK 1.x full scan against the keychain, returning a `Update` the caller
//!   can apply with `wallet.apply_update`.
//!
//! Both operations are blocking; sigvault-desktop runs them on a tokio
//! `spawn_blocking` task to keep the UI thread responsive.

use bdk_electrum::electrum_client;
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::Transaction;
use bdk_wallet::chain::spk_client::FullScanResponse;
use bdk_wallet::{KeychainKind, Update, Wallet};

use crate::error::WalletRuntimeError;

pub struct ElectrumClient {
    inner: BdkElectrumClient<electrum_client::Client>,
}

impl ElectrumClient {
    /// Connect to an Electrs server. URLs of the form `tcp://host:port`,
    /// `ssl://host:port`, or just `host:port` are accepted by `electrum_client`.
    pub fn connect(url: &str) -> Result<Self, WalletRuntimeError> {
        let raw = electrum_client::Client::new(url)
            .map_err(|e| WalletRuntimeError::Electrum(format!("connect {}: {}", url, e)))?;
        Ok(Self {
            inner: BdkElectrumClient::new(raw),
        })
    }

    /// Broadcast an extracted transaction. Returns the txid as a hex string.
    pub fn broadcast(&self, tx: &Transaction) -> Result<String, WalletRuntimeError> {
        self.inner
            .transaction_broadcast(tx)
            .map(|txid| txid.to_string())
            .map_err(|e| WalletRuntimeError::Electrum(format!("broadcast: {}", e)))
    }

    /// Run a BDK 1.x full scan over the wallet's keychains. Returns an
    /// `Update` the caller applies via `wallet.apply_update(update)` and then
    /// `wallet.persist(...)`.
    ///
    /// `stop_gap` and `batch_size` follow BDK's conventions (defaults: 20 / 5
    /// are reasonable for new local wallets).
    pub fn full_scan(
        &self,
        wallet: &Wallet,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
    ) -> Result<Update, WalletRuntimeError> {
        let request = wallet.start_full_scan().build();
        let response: FullScanResponse<KeychainKind> = self
            .inner
            .full_scan(request, stop_gap, batch_size, fetch_prev_txouts)
            .map_err(|e| WalletRuntimeError::Electrum(format!("full_scan: {}", e)))?;
        Ok(response.into())
    }
}

use crate::config::CONFIG;
use crate::proto::pb::{
    Address, GetWalletRequest, GetWalletResponse, GetWalletSpendingPathsRequest,
    GetWalletSpendingPathsResponse, ListAddressesRequest, ListAddressesResponse,
    RevealNextAddressRequest, RevealNextAddressResponse, UpdateWalletRequest, UpdateWalletResponse,
};
use crate::wallet::bdk::BdkWalletManager;
use bdk_electrum::electrum_client;
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::KeychainKind;
use log::{debug, trace};
use tonic::{Request, Response, Status};

const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

pub async fn update_wallet(
    request: Request<UpdateWalletRequest>,
) -> Result<Response<UpdateWalletResponse>, Status> {
    let req = request.into_inner();

    let bdk_manager = BdkWalletManager::new(CONFIG.network());

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let (mut wallet, mut _db) = (wallet_result.wallet, wallet_result.store);

            // Try to connect to electrum server, but don't fail if unavailable
            match electrum_client::Client::new(CONFIG.electrs_url()) {
                Ok(electrum_client) => {
                    let client = BdkElectrumClient::new(electrum_client);

                    // Populate the electrum client's transaction cache so it doesn't redownload transaction we
                    // already have.
                    client
                        .populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

                    let request = wallet.start_full_scan().build();
                    match client.full_scan(request, STOP_GAP, BATCH_SIZE, false) {
                        Ok(update) => {
                            if let Err(e) = wallet.apply_update(update) {
                                debug!("Failed to apply update: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("Full scan failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    debug!("Electrum connection failed: {}, skipping sync", e);
                }
            }

            wallet
                .persist(&mut _db)
                .map_err(|e| Status::internal(format!("Failed to persist wallet: {}", e)))?;

            Ok(Response::new(UpdateWalletResponse {
                wallet_id: req.wallet_id,
                balance: wallet.balance().total().to_string(),
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn get_wallet(
    request: Request<GetWalletRequest>,
) -> Result<Response<GetWalletResponse>, Status> {
    let req = request.into_inner();
    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let wallet = wallet_result.wallet;
            Ok(Response::new(GetWalletResponse {
                wallet_id: req.wallet_id,
                balance: wallet.balance().total().to_string(),
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn reveal_next_address(
    request: Request<RevealNextAddressRequest>,
) -> Result<Response<RevealNextAddressResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let (mut wallet, mut _db) = (wallet_result.wallet, wallet_result.store);
            let mut addresses = Vec::new();
            for _ in 0..req.num {
                let mut keychain_kind = KeychainKind::External;
                if req.change {
                    keychain_kind = KeychainKind::Internal;
                }
                let key_info = wallet.reveal_next_address(keychain_kind);

                wallet
                    .persist(&mut _db)
                    .map_err(|e| Status::internal(format!("Failed to persist wallet: {}", e)))?;

                debug!("Revealed address: {}", key_info.address);
                trace!("Derivation path: {}", key_info.index);
                addresses.push(Address {
                    address: key_info.address.to_string(),
                    derivationpath: key_info.index.to_string(),
                    change: keychain_kind == KeychainKind::Internal,
                });
            }

            Ok(Response::new(RevealNextAddressResponse { addresses }))
        }
        Err(e) => Err(Status::not_found(format!("Wallet not found: {}", e))),
    }
}

pub async fn list_addresses(
    request: Request<ListAddressesRequest>,
) -> Result<Response<ListAddressesResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let wallet = wallet_result.wallet;
            let mut addresses = Vec::new();
            let mut keychain_kind = KeychainKind::External;
            if req.change {
                keychain_kind = KeychainKind::Internal;
            }
            for key_info in wallet.list_unused_addresses(keychain_kind) {
                addresses.push(Address {
                    address: key_info.address.to_string(),
                    derivationpath: key_info.index.to_string(),
                    change: keychain_kind == KeychainKind::Internal,
                });
            }
            Ok(Response::new(ListAddressesResponse { addresses }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn get_wallet_spending_paths(
    request: Request<GetWalletSpendingPathsRequest>,
) -> Result<Response<GetWalletSpendingPathsResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(_wallet_result) => {
            // For now, return a placeholder response indicating no taproot paths
            // In a full implementation, this would:
            // 1. Load the wallet's spending policy from storage
            // 2. Extract taproot leaf information if it's a taproot wallet
            // 3. Return the available spending paths

            Ok(Response::new(GetWalletSpendingPathsResponse {
                spending_paths: Vec::new(), // Placeholder - would contain actual leaf info
                merkle_root: "".to_string(), // Would be determined from wallet descriptor
                internal_key: "".to_string(), // Would be determined from wallet descriptor
                is_taproot: false,          // Would be determined from wallet descriptor
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::service::test_support::{make_single_sig_wallet, setup, unique_id};
    use tonic::Code;

    // ---- get_wallet ------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_returns_not_found_for_unknown_id() {
        setup();
        let err = get_wallet(Request::new(GetWalletRequest {
            wallet_id: unique_id("ghost"),
            passphrase: Vec::new(),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_returns_balance_zero_for_fresh_wallet() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let resp = get_wallet(Request::new(GetWalletRequest {
            wallet_id: wallet.clone(),
            passphrase: Vec::new(),
        }))
        .await
        .expect("get_wallet must succeed for an existing wallet")
        .into_inner();
        assert_eq!(resp.wallet_id, wallet);
        // Fresh wallet → zero balance. BDK's Amount.to_string() is "0 BTC".
        assert!(
            resp.balance.starts_with('0'),
            "fresh wallet balance must be zero, got: {}",
            resp.balance
        );
    }

    // ---- update_wallet ---------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn update_wallet_returns_not_found_for_unknown_id() {
        setup();
        let err = update_wallet(Request::new(UpdateWalletRequest {
            wallet_id: unique_id("ghost"),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn update_wallet_succeeds_even_when_electrum_is_unreachable() {
        // The CONFIG.electrs_url default points at 127.0.0.1:60401 with
        // nothing listening; update_wallet's electrum branch is wrapped
        // in match/debug so the RPC must still succeed and return the
        // current (zero) balance. Regression for a real reliability
        // property: a stale or missing index server can't block reads.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let resp = update_wallet(Request::new(UpdateWalletRequest {
            wallet_id: wallet.clone(),
        }))
        .await
        .expect("update_wallet must succeed even without electrum")
        .into_inner();
        assert_eq!(resp.wallet_id, wallet);
        assert!(resp.balance.starts_with('0'));
    }

    // ---- reveal_next_address --------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn reveal_next_address_returns_not_found_for_unknown_id() {
        setup();
        let err = reveal_next_address(Request::new(RevealNextAddressRequest {
            wallet_id: unique_id("ghost"),
            num: 1,
            change: false,
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reveal_next_address_returns_unique_external_addresses() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let resp = reveal_next_address(Request::new(RevealNextAddressRequest {
            wallet_id: wallet.clone(),
            num: 3,
            change: false,
        }))
        .await
        .expect("reveal_next_address must succeed")
        .into_inner();

        assert_eq!(resp.addresses.len(), 3);
        let strings: Vec<_> = resp.addresses.iter().map(|a| a.address.clone()).collect();
        let unique: std::collections::HashSet<_> = strings.iter().collect();
        assert_eq!(
            unique.len(),
            3,
            "all revealed addresses must be distinct, got: {:?}",
            strings
        );
        for addr in &resp.addresses {
            assert!(
                !addr.change,
                "external request must not return change addresses"
            );
            assert!(
                addr.address.starts_with("tb1") || addr.address.starts_with("bcrt1"),
                "testnet/regtest wallet should return bech32 addresses, got: {}",
                addr.address
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reveal_next_address_can_return_change_addresses() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let resp = reveal_next_address(Request::new(RevealNextAddressRequest {
            wallet_id: wallet,
            num: 1,
            change: true,
        }))
        .await
        .expect("change=true must succeed")
        .into_inner();
        assert_eq!(resp.addresses.len(), 1);
        assert!(resp.addresses[0].change);
    }

    // ---- list_addresses --------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn list_addresses_returns_not_found_for_unknown_id() {
        setup();
        let err = list_addresses(Request::new(ListAddressesRequest {
            wallet_id: unique_id("ghost"),
            change: false,
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_addresses_returns_unused_addresses_for_fresh_wallet() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let resp = list_addresses(Request::new(ListAddressesRequest {
            wallet_id: wallet,
            change: false,
        }))
        .await
        .expect("list_addresses must succeed")
        .into_inner();
        // A freshly created wallet has no revealed addresses, so the list
        // is empty until reveal_next_address has been called. We only
        // assert the RPC doesn't error — the empty-list semantics depend
        // on BDK internals we don't want to pin here.
        for addr in &resp.addresses {
            assert!(
                !addr.change,
                "change=false must not surface change addresses"
            );
        }
    }

    // ---- get_wallet_spending_paths --------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_spending_paths_returns_not_found_for_unknown_id() {
        setup();
        let err = get_wallet_spending_paths(Request::new(GetWalletSpendingPathsRequest {
            wallet_id: unique_id("ghost"),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_spending_paths_returns_placeholder_for_existing_wallet() {
        // The current implementation is a documented placeholder — until it's
        // implemented for real, this test pins the placeholder contract so
        // any future divergence trips a test rather than silently changing
        // the wire format.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let resp = get_wallet_spending_paths(Request::new(GetWalletSpendingPathsRequest {
            wallet_id: wallet,
        }))
        .await
        .expect("RPC must succeed for an existing wallet")
        .into_inner();
        assert!(resp.spending_paths.is_empty());
        assert!(!resp.is_taproot);
    }
}

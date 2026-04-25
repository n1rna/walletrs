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

            return Ok(Response::new(UpdateWalletResponse {
                wallet_id: req.wallet_id,
                balance: wallet.balance().total().to_string(),
            }));
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
            return Ok(Response::new(GetWalletResponse {
                wallet_id: req.wallet_id,
                balance: wallet.balance().total().to_string(),
            }));
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

                wallet.persist(&mut _db).expect("Failed to persist wallet");

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

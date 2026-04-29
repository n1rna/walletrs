use crate::config::CONFIG;
use crate::db;
use crate::proto::pb::{
    AddVerifyTransactionSignatureRequest, AddVerifyTransactionSignatureResponse,
    BroadcastWalletTransactionRequest, BroadcastWalletTransactionResponse,
    FinalizeWalletTransactionRequest, FinalizeWalletTransactionResponse,
    FundWalletTransactionRequest, FundWalletTransactionResponse, GetWalletTransactionsRequest,
    GetWalletTransactionsResponse, GetWalletUtxosRequest, GetWalletUtxosResponse,
    SignWalletTransactionRequest, SignWalletTransactionResponse, Transaction, TransactionInput,
    TransactionOutput, Utxo,
};
use crate::wallet::bdk::BdkWalletManager;
use crate::wallet::signer::{
    add_signers_for_psbt, resolve_policy_path_from_leaf, sign_psbt_with_taproot_support,
};
use crate::LianaDescriptor;
use bdk_wallet::bitcoin::{Address as BitcoinAddress, Psbt};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::KeychainKind;
use hex;
use log::error;
use miniscript::psbt::PsbtExt;
use std::collections::BTreeMap;
use std::str::FromStr;
use tonic::{Request, Response, Status};
use wallet_runtime::ElectrumClient;

/// Load the persisted Liana descriptor for a wallet. Returns `None` for
/// non-Liana wallets (single-sig, plain multisig, taproot multisig with NUMS
/// internal key) and for wallets whose stored value is missing or unparseable.
fn load_liana_descriptor(wallet_id: &str) -> Option<LianaDescriptor> {
    db::get_liana_descriptor(wallet_id)
        .ok()
        .flatten()
        .and_then(|s| LianaDescriptor::from_str(&s).ok())
}

pub async fn get_wallet_transactions(
    request: Request<GetWalletTransactionsRequest>,
) -> Result<Response<GetWalletTransactionsResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let wallet = wallet_result.wallet;
            // Sync the wallet
            let transactions: Vec<Transaction> = wallet
                .transactions()
                .map(|tx| {
                    let block_height = match tx.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.height,
                        _ => 0,
                    };

                    let block_hash = match tx.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.hash.to_string(),
                        _ => "".to_string(),
                    };

                    let txid = tx.tx_node.txid;
                    let chain_position = tx.chain_position;
                    let tx = tx.tx_node.tx.as_ref();
                    let (sent, received) = wallet.sent_and_received(tx);
                    let fee = wallet
                        .calculate_fee(tx)
                        .unwrap_or(bdk_wallet::bitcoin::Amount::from_sat(0));
                    let fee_rate = wallet
                        .calculate_fee_rate(tx)
                        .unwrap_or(bdk_wallet::bitcoin::FeeRate::from_sat_per_kwu(0));

                    Transaction {
                        txid: txid.to_string(),
                        blockheight: block_height,
                        blockhash: block_hash,
                        total_sent: sent.to_sat(),
                        total_received: received.to_sat(),
                        fee: fee.to_sat(),
                        fee_per_kb: fee_rate.to_sat_per_kwu(),
                        version: tx.version.0 as u32,
                        locktime: tx.lock_time.to_consensus_u32(),
                        size: tx.total_size() as u32,
                        vsize: tx.vsize() as u32,
                        status: match chain_position {
                            ChainPosition::Unconfirmed { .. } => "unconfirmed".to_string(),
                            ChainPosition::Confirmed { .. } => "confirmed".to_string(),
                        },
                        coinbase: tx.is_coinbase(),
                        inputs: tx
                            .input
                            .iter()
                            .map(|input| TransactionInput {
                                prev_vout: input.previous_output.vout,
                                prev_txid: input.previous_output.txid.to_string(),
                                address: match wallet.derivation_of_spk(input.script_sig.clone()) {
                                    Some((keychain, derivation_index)) => wallet
                                        .peek_address(keychain, derivation_index)
                                        .address
                                        .to_string(),
                                    None => "".to_string(),
                                },
                                is_mine: wallet.is_mine(input.script_sig.clone()),
                                script: hex::encode(&input.script_sig),
                                script_type: "".to_string(),
                                value: 0,
                            })
                            .collect(),
                        outputs: tx
                            .output
                            .iter()
                            .enumerate()
                            .map(|(i, output)| TransactionOutput {
                                value: output.value.to_sat(),
                                script: hex::encode(&output.script_pubkey),
                                is_mine: wallet.is_mine(output.script_pubkey.clone()),
                                output_n: i as u32,
                                address: match wallet
                                    .derivation_of_spk(output.script_pubkey.clone())
                                {
                                    Some((keychain, derivation_index)) => wallet
                                        .peek_address(keychain, derivation_index)
                                        .address
                                        .to_string(),
                                    None => "".to_string(),
                                },
                            })
                            .collect(),
                    }
                })
                .collect();

            Ok(Response::new(GetWalletTransactionsResponse {
                transactions,
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn get_wallet_utxos(
    request: Request<GetWalletUtxosRequest>,
) -> Result<Response<GetWalletUtxosResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let wallet = wallet_result.wallet;
            // Sync the wallet
            let utxos: Vec<Utxo> = wallet
                .list_unspent()
                .map(|txo| {
                    let block_height = match txo.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.height,
                        _ => 0,
                    };

                    let block_hash = match txo.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.hash.to_string(),
                        _ => "".to_string(),
                    };

                    let utxo = wallet.get_utxo(txo.outpoint).unwrap();

                    Utxo {
                        txid: txo.outpoint.txid.to_string(),
                        vout: txo.outpoint.vout,
                        address: wallet
                            .peek_address(utxo.keychain, utxo.derivation_index)
                            .address
                            .to_string(),
                        value: txo.txout.value.to_sat(),
                        script: txo.txout.script_pubkey.to_string(),
                        spent: utxo.is_spent,
                        script_type: "".to_string(),
                        block_height: block_height,
                        block_hash: block_hash,
                    }
                })
                .collect();

            Ok(Response::new(GetWalletUtxosResponse { utxos: utxos }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn fund_wallet_transaction(
    request: Request<FundWalletTransactionRequest>,
) -> Result<Response<FundWalletTransactionResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let (mut wallet, mut _db) = (wallet_result.wallet, wallet_result.store);
            let destination_address = BitcoinAddress::from_str(&req.destination_address)
                .unwrap()
                .require_network(CONFIG.network())
                .unwrap();

            let send_amount = bdk_wallet::bitcoin::Amount::from_sat(req.destination_value);
            let fee_rate = bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap();

            let policy_path = if !req.selected_leaf_hash.is_empty() {
                log::debug!("Selected leaf hash: {}", req.selected_leaf_hash);
                let liana_desc = load_liana_descriptor(&req.wallet_id);
                resolve_policy_path_from_leaf(
                    &wallet,
                    &req.selected_leaf_hash,
                    liana_desc.as_ref(),
                )?
            } else {
                log::debug!("No specific policy path selected - using default");
                BTreeMap::new()
            };

            log::debug!("Policy path resolved: {:?}", policy_path);

            // Check if wallet has policies (e.g., Taproot with multiple spending paths)
            let has_policies = wallet
                .policies(KeychainKind::External)
                .ok()
                .and_then(|p| p)
                .is_some();

            log::debug!("Wallet has policies: {}", has_policies);

            let mut tx_builder = wallet.build_tx();

            log::debug!("Funding transaction with {} sat", send_amount);
            log::debug!("Destination address: {}", destination_address);

            tx_builder
                .fee_rate(fee_rate)
                .add_recipient(destination_address.script_pubkey(), send_amount);

            if !req.spend_change {
                tx_builder.do_not_spend_change();
            }

            // For wallets with policies (Liana-style Taproot with timelocked recovery paths):
            // Set policy path for both External and Internal keychains
            if has_policies && !policy_path.is_empty() {
                log::debug!("Setting policy path on both keychains: {:?}", policy_path);
                // Set for External keychain (receive addresses)
                tx_builder.policy_path(policy_path.clone(), KeychainKind::External);
                // Also set for Internal keychain (change addresses)
                tx_builder.policy_path(policy_path, KeychainKind::Internal);
            }

            let psbt = match tx_builder.finish() {
                Ok(psbt) => psbt,
                Err(e) => {
                    error!("Failed to build transaction: {:?}", e);
                    return Err(Status::invalid_argument(format!(
                        "Failed to build transaction: {}",
                        e
                    )));
                }
            };

            let pruned_psbt_str = match load_liana_descriptor(&req.wallet_id) {
                Some(liana_desc) => match liana_desc.prune_bip32_derivs_last_avail(psbt.clone()) {
                    Ok(pruned) => {
                        log::info!(
                            "Successfully pruned PSBT BIP32 derivations for wallet {}",
                            req.wallet_id
                        );
                        pruned.to_string()
                    }
                    Err(e) => {
                        log::warn!("Failed to prune PSBT: {}, falling back to full PSBT", e);
                        String::new()
                    }
                },
                None => {
                    log::debug!(
                        "No liana descriptor for wallet {}, skipping pruning",
                        req.wallet_id
                    );
                    String::new()
                }
            };

            wallet.persist(&mut _db).unwrap();

            // Use the new PSBT storage function
            db::save_psbt(
                &req.wallet_id,
                &psbt.unsigned_tx.compute_txid().to_string(),
                &psbt.to_string(),
            )
            .unwrap();

            Ok(Response::new(FundWalletTransactionResponse {
                txid: psbt.unsigned_tx.compute_txid().to_string(),
                psbt: psbt.to_string(),
                network: CONFIG.network().to_string(),
                input_total: psbt
                    .inputs
                    .iter()
                    .map(|input| input.witness_utxo.as_ref().unwrap().value.to_sat())
                    .sum(),
                output_total: psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .map(|output| output.value.to_sat())
                    .sum(),
                fee: 0,
                fee_per_kb: 0,
                size: psbt.unsigned_tx.total_size() as u32,
                tx_raw: psbt.to_string(),
                tx_json: "not implemented".to_string(),
                pruned_psbt: pruned_psbt_str,
                inputs: psbt
                    .unsigned_tx
                    .input
                    .iter()
                    .map(|input| {
                        let utxo = wallet.get_utxo(input.previous_output).unwrap();
                        TransactionInput {
                            prev_vout: input.previous_output.vout,
                            prev_txid: input.previous_output.txid.to_string(),
                            value: utxo.txout.value.to_sat(),
                            address: wallet
                                .peek_address(utxo.keychain, utxo.derivation_index)
                                .address
                                .to_string(),
                            is_mine: true,
                            script: hex::encode(&input.script_sig),
                            script_type: "".to_string(),
                        }
                    })
                    .collect(),
                outputs: psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .enumerate()
                    .map(|(i, output)| TransactionOutput {
                        value: output.value.to_sat(),
                        address: match output.script_pubkey.to_string()
                            == destination_address.script_pubkey().to_string()
                        {
                            true => destination_address.to_string(),
                            false => match wallet.derivation_of_spk(output.script_pubkey.clone()) {
                                Some((keychain, derivation_index)) => wallet
                                    .peek_address(keychain, derivation_index)
                                    .address
                                    .to_string(),
                                None => "".to_string(),
                            },
                        },
                        output_n: i as u32,
                        script: hex::encode(&output.script_pubkey),
                        is_mine: output.script_pubkey.to_string()
                            != destination_address.script_pubkey().to_string(),
                    })
                    .collect(),
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn add_verify_transaction_signature(
    request: Request<AddVerifyTransactionSignatureRequest>,
) -> Result<Response<AddVerifyTransactionSignatureResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let mut _db = wallet_result.store;
            let signed_psbt = Psbt::from_str(&req.signedpsbt)
                .map_err(|e| Status::invalid_argument(format!("Invalid signed PSBT: {}", e)))?;
            let txid = signed_psbt.unsigned_tx.compute_txid().to_string();

            db::save_signed_psbt(
                &req.wallet_id,
                &txid,
                &signed_psbt.to_string(),
                &req.devicefingerprint,
            )
            .unwrap();

            Ok(Response::new(AddVerifyTransactionSignatureResponse {
                txid: req.txid,
                status: "signature added successfully".to_string(),
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn finalize_wallet_transaction(
    request: Request<FinalizeWalletTransactionRequest>,
) -> Result<Response<FinalizeWalletTransactionResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let _wallet = wallet_result.wallet;
            let mut _db = wallet_result.store;

            // Get the signed PSBT from the database
            let signed_psbts = db::get_signed_psbts(&req.wallet_id, &req.txid)
                .map_err(|e| Status::internal(format!("Failed to get signed PSBTs: {:?}", e)))?;

            if signed_psbts.is_empty() {
                return Err(Status::not_found(
                    "No signed PSBT found for this transaction",
                ));
            }

            let base_psbt_str = db::get_original_psbt(&req.wallet_id, &req.txid)
                .map_err(|e| Status::internal(format!("Failed to get original PSBT: {:?}", e)))?;
            let mut base_psbt = Psbt::from_str(&base_psbt_str)
                .map_err(|e| Status::internal(format!("Failed to parse base PSBT: {:?}", e)))?;
            // Merge all signed PSBTs into the base PSBT
            log::info!(
                "Combining {} signed PSBTs from devices: {:?}",
                signed_psbts.len(),
                signed_psbts
                    .iter()
                    .map(|s| &s.device_fingerprint)
                    .collect::<Vec<_>>()
            );
            for psbt in signed_psbts
                .iter()
                .map(|s| Psbt::from_str(&s.psbt_data).unwrap())
            {
                base_psbt
                    .combine(psbt)
                    .map_err(|e| Status::internal(format!("Failed to merge PSBTs: {:?}", e)))?;
            }

            log::info!("🏁 Finalizing PSBT for txid: {}", req.txid);

            for (i, input) in base_psbt.inputs.iter().enumerate() {
                let seq = base_psbt.unsigned_tx.input[i].sequence.0;
                log::debug!(
                    "Input {}: tap_key_sig={}, tap_script_sigs={}, partial_sigs={}, tap_scripts={}, sequence={}",
                    i,
                    input.tap_key_sig.is_some(),
                    input.tap_script_sigs.len(),
                    input.partial_sigs.len(),
                    input.tap_scripts.len(),
                    seq,
                );
            }

            // Use miniscript's PsbtExt::finalize_mut() for finalization.
            // This handles both keypath and script path (including multi-sig tapscript)
            // correctly, unlike wallet.sign() with try_finalize which fails for
            // multi-sig tapscript from combined PSBTs.
            let secp = bdk_wallet::bitcoin::secp256k1::Secp256k1::new();
            let bdk_finalized = match base_psbt.finalize_mut(&secp) {
                Ok(()) => {
                    log::info!("✅ miniscript finalize_mut succeeded");
                    true
                }
                Err(errors) => {
                    log::warn!("⚠️ miniscript finalize_mut returned errors: {:?}", errors);
                    false
                }
            };

            // Verify finalization by attempting to extract the transaction
            match base_psbt.clone().extract_tx() {
                Ok(tx) => {
                    // Successfully extracted - PSBT is truly finalized
                    let finalized_psbt_str = base_psbt.to_string();

                    // Save the finalized PSBT only if extraction succeeded
                    db::save_signed_psbt(
                        &req.wallet_id,
                        &req.txid,
                        &finalized_psbt_str,
                        "finalized",
                    )
                    .map_err(|e| {
                        Status::internal(format!("Failed to save finalized PSBT: {:?}", e))
                    })?;

                    log::info!(
                        "✅ PSBT finalized, extracted, and saved for txid: {}",
                        req.txid
                    );
                    log::info!("   Extracted transaction ID: {}", tx.compute_txid());

                    Ok(Response::new(FinalizeWalletTransactionResponse {
                        txid: req.txid,
                        network: CONFIG.network().to_string(),
                        tx_raw: finalized_psbt_str,
                        tx_json: "not implemented".to_string(),
                    }))
                }
                Err(extract_err) => {
                    // Failed to extract - finalization was not successful
                    log::error!(
                        "❌ Failed to finalize PSBT for txid {}: {}",
                        req.txid,
                        extract_err
                    );

                    // Analyze why finalization failed
                    let mut missing_info = Vec::new();
                    let mut has_signatures = false;

                    for (i, input) in base_psbt.inputs.iter().enumerate() {
                        // Check for signatures
                        if input.tap_key_sig.is_some() || !input.tap_script_sigs.is_empty() {
                            has_signatures = true;
                        }

                        // Check if input is finalized
                        if input.final_script_witness.is_none() && input.final_script_sig.is_none()
                        {
                            missing_info.push(format!("Input {} not finalized", i));

                            // Log detailed info about what's missing
                            log::debug!("Input {} state: tap_key_sig={}, tap_script_sigs={}, final_witness={}",
                                i,
                                input.tap_key_sig.is_some(),
                                input.tap_script_sigs.len(),
                                input.final_script_witness.is_some()
                            );
                        }
                    }

                    let error_msg = if !has_signatures {
                        "PSBT has no signatures - need to sign before finalizing".to_string()
                    } else if !missing_info.is_empty() {
                        format!("Finalization incomplete: {}", missing_info.join(", "))
                    } else {
                        format!("Finalization failed: {}", extract_err)
                    };

                    log::error!("Finalization failure details: {}", error_msg);
                    log::info!("Note: BDK reported finalized_all={}", bdk_finalized);

                    // Do NOT save the PSBT since finalization failed
                    Err(Status::failed_precondition(error_msg))
                }
            }
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn sign_wallet_transaction(
    request: Request<SignWalletTransactionRequest>,
) -> Result<Response<SignWalletTransactionResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let (mut wallet, mut _db) = (wallet_result.wallet, wallet_result.store);
            // Use the new PSBT retrieval function
            let psbt_str = db::get_original_psbt(&req.wallet_id, &req.txid).unwrap();
            let mut psbt = Psbt::from_str(&psbt_str).unwrap();

            // Add signers on-demand based on the UTXOs being spent
            // Use the specific device_id from the request for signing
            let signers_added =
                add_signers_for_psbt(&mut wallet, &psbt, &req.wallet_id, &req.device_id)?;

            // Fail if no signers were added
            if signers_added == 0 {
                return Err(Status::internal(
                    "Failed to add any signers - cannot sign transaction",
                ));
            }

            // Enhanced taproot-aware signing with try_finalize=false for separate finalization
            let signed_psbt =
                match sign_psbt_with_taproot_support(&wallet, &mut psbt, &req.wallet_id)? {
                    Some(signed) => {
                        // Verify that signatures were actually added
                        let has_signatures = signed.inputs.iter().any(|input| {
                            input.tap_key_sig.is_some()
                                || !input.tap_script_sigs.is_empty()
                                || !input.partial_sigs.is_empty()
                                || input.final_script_witness.is_some()
                        });

                        if !has_signatures {
                            return Err(Status::internal(
                                "Signing failed - no signatures were added to PSBT",
                            ));
                        }
                        signed
                    }
                    None => {
                        return Err(Status::internal("Signing failed - unable to sign PSBT"));
                    }
                };

            // Extract the transaction to get the correct txid
            let psbt_txid = signed_psbt.unsigned_tx.compute_txid().to_string();

            // Save as signed PSBT (not finalized yet)
            db::save_signed_psbt(
                &req.wallet_id,
                &psbt_txid,
                &signed_psbt.to_string(),
                &req.device_id,
            )
            .unwrap();

            Ok(Response::new(SignWalletTransactionResponse {
                txid: psbt_txid,
                network: CONFIG.network().to_string(),
                tx_raw: signed_psbt.to_string(),
                tx_json: "not implemented".to_string(),
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

pub async fn broadcast_wallet_transaction(
    request: Request<BroadcastWalletTransactionRequest>,
) -> Result<Response<BroadcastWalletTransactionResponse>, Status> {
    let req = request.into_inner();

    let network = CONFIG.network();
    let bdk_manager = BdkWalletManager::new(network);

    match bdk_manager.load_wallet(&req.wallet_id) {
        Ok(wallet_result) => {
            let mut _db = wallet_result.store;
            let client = ElectrumClient::connect(CONFIG.electrs_url()).map_err(|e| {
                Status::internal(format!("Failed to connect to electrs: {}", e))
            })?;

            // Get the finalized PSBT (must have been finalized via finalize_wallet_transaction)
            let psbt_str = db::get_finalized_psbt(&req.wallet_id, &req.txid).map_err(|e| {
                Status::failed_precondition(format!(
                    "No finalized PSBT found for wallet {} and txid {}. \
                         Call finalize_wallet_transaction first. Error: {}",
                    req.wallet_id, req.txid, e
                ))
            })?;

            log::info!("📡 Broadcasting PSBT for txid: {}", req.txid);
            log::debug!(
                "PSBT string (first 100 chars): {}...",
                &psbt_str[..100.min(psbt_str.len())]
            );

            let psbt = Psbt::from_str(&psbt_str)
                .map_err(|e| Status::invalid_argument(format!("Invalid PSBT format: {}", e)))?;

            let tx = psbt.extract_tx().map_err(|e| {
                Status::failed_precondition(format!(
                    "Failed to extract transaction from finalized PSBT: {}. \
                     The PSBT may not have been properly finalized.",
                    e
                ))
            })?;

            client
                .broadcast(&tx)
                .map_err(|e| Status::internal(format!("Failed to broadcast transaction: {}", e)))?;

            Ok(Response::new(BroadcastWalletTransactionResponse {
                txid: tx.compute_txid().to_string(),
                network: CONFIG.network().to_string(),
            }))
        }
        Err(_) => Err(Status::not_found("Wallet not found")),
    }
}

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
use bdk_wallet::bitcoin::{Address as BitcoinAddress, Network, Psbt};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::KeychainKind;
use hex;
use log::error;
use miniscript::psbt::PsbtExt;
use std::collections::BTreeMap;
use std::str::FromStr;
use tonic::{Request, Response, Status};
use wallet_runtime::ElectrumClient;

/// Load the persisted policy descriptor for a wallet. Returns `None` for
/// flat wallets (single-sig, plain multisig, taproot multisig with NUMS
/// internal key) and for wallets whose stored value is missing.
///
/// A *parse* failure is also folded into `None` so flat-wallet code paths
/// continue to work, but emits a `warn!` so descriptor corruption is
/// observable rather than silent.
fn load_policy_descriptor(wallet_id: &str) -> Option<LianaDescriptor> {
    let stored = match db::get_policy_descriptor(wallet_id) {
        Ok(opt) => opt?,
        Err(e) => {
            log::warn!(
                "load_policy_descriptor({}): storage read failed: {}",
                wallet_id,
                e
            );
            return None;
        }
    };
    match LianaDescriptor::from_str(&stored) {
        Ok(d) => Some(d),
        Err(e) => {
            log::warn!(
                "load_policy_descriptor({}): stored descriptor failed to parse: {}",
                wallet_id,
                e
            );
            None
        }
    }
}

/// Parse a user-supplied destination address and confirm it belongs to
/// `network`. Both failures translate to `Status::invalid_argument` so the
/// caller (and ultimately the gRPC client) never sees a panic on malformed
/// or wrong-network user input.
pub(crate) fn parse_destination_address(
    address_str: &str,
    network: Network,
) -> Result<BitcoinAddress, Status> {
    let unchecked = BitcoinAddress::from_str(address_str).map_err(|e| {
        Status::invalid_argument(format!(
            "Invalid destination address {:?}: {}",
            address_str, e
        ))
    })?;
    unchecked.require_network(network).map_err(|e| {
        Status::invalid_argument(format!(
            "Destination address does not belong to network {}: {}",
            network, e
        ))
    })
}

/// Parse a PSBT string that was loaded from storage. Any parse failure here
/// is a corruption / invariant violation in the storage layer — never a
/// caller error — so it surfaces as `Status::internal`.
pub(crate) fn parse_stored_psbt(
    wallet_id: &str,
    txid: &str,
    psbt_str: &str,
) -> Result<Psbt, Status> {
    Psbt::from_str(psbt_str).map_err(|e| {
        log::error!(
            "stored PSBT failed to parse for wallet {} txid {}: {}",
            wallet_id,
            txid,
            e
        );
        Status::internal(format!(
            "Stored PSBT for txid {} is unparseable; storage may be corrupted",
            txid
        ))
    })
}

/// Translate a storage-layer `io::Error` from a PSBT lookup into the right
/// gRPC status code: `NotFound` for missing rows, `Internal` for everything
/// else.
fn map_psbt_lookup_error(err: std::io::Error, what: &str) -> Status {
    if err.kind() == std::io::ErrorKind::NotFound {
        Status::not_found(format!("{}: {}", what, err))
    } else {
        Status::internal(format!("{}: {}", what, err))
    }
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
                .filter_map(|txo| {
                    let block_height = match txo.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.height,
                        _ => 0,
                    };

                    let block_hash = match txo.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => anchor.block_id.hash.to_string(),
                        _ => "".to_string(),
                    };

                    let utxo = match wallet.get_utxo(txo.outpoint) {
                        Some(u) => u,
                        None => {
                            // Invariant violation: list_unspent yielded an outpoint
                            // the wallet doesn't recognise. Log and skip rather
                            // than crash the whole RPC.
                            log::warn!(
                                "list_unspent yielded outpoint {} that wallet.get_utxo \
                                 cannot resolve; skipping",
                                txo.outpoint
                            );
                            return None;
                        }
                    };

                    Some(Utxo {
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
                        block_height,
                        block_hash,
                    })
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
            let destination_address =
                parse_destination_address(&req.destination_address, CONFIG.network())?;

            let send_amount = bdk_wallet::bitcoin::Amount::from_sat(req.destination_value);
            // 2 sat/vB is a hard-coded constant well within FeeRate's accepted range;
            // the unwrap is genuinely infallible.
            let fee_rate = bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2)
                .expect("FeeRate::from_sat_per_vb(2) is infallible for this constant");

            let policy_path = if !req.selected_leaf_hash.is_empty() {
                log::debug!("Selected leaf hash: {}", req.selected_leaf_hash);
                let policy_desc = load_policy_descriptor(&req.wallet_id);
                resolve_policy_path_from_leaf(
                    &wallet,
                    &req.selected_leaf_hash,
                    policy_desc.as_ref(),
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

            // For wallets with policies (timelocked Taproot with recovery paths):
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

            let pruned_psbt_str = match load_policy_descriptor(&req.wallet_id) {
                Some(policy_desc) => {
                    match policy_desc.prune_bip32_derivs_last_avail(psbt.clone()) {
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
                    }
                }
                None => {
                    log::debug!(
                        "No policy descriptor for wallet {}, skipping pruning",
                        req.wallet_id
                    );
                    String::new()
                }
            };

            wallet
                .persist(&mut _db)
                .map_err(|e| Status::internal(format!("Failed to persist wallet: {}", e)))?;

            // Use the new PSBT storage function
            db::save_psbt(
                &req.wallet_id,
                &psbt.unsigned_tx.compute_txid().to_string(),
                &psbt.to_string(),
            )
            .map_err(|e| Status::internal(format!("Failed to save PSBT: {}", e)))?;

            Ok(Response::new(FundWalletTransactionResponse {
                txid: psbt.unsigned_tx.compute_txid().to_string(),
                psbt: psbt.to_string(),
                network: CONFIG.network().to_string(),
                input_total: psbt
                    .inputs
                    .iter()
                    .map(|input| {
                        // witness_utxo is None for legacy (pre-segwit) inputs.
                        // We default to 0 instead of panicking; the total will
                        // be visibly off in that case, which is the right signal.
                        input
                            .witness_utxo
                            .as_ref()
                            .map(|wu| wu.value.to_sat())
                            .unwrap_or(0)
                    })
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
                        // PSBT inputs we just built from this wallet should
                        // resolve; if not, fall back to empty-value/address
                        // rather than crash the RPC.
                        let utxo = wallet.get_utxo(input.previous_output);
                        let (value, address) = match utxo {
                            Some(u) => (
                                u.txout.value.to_sat(),
                                wallet
                                    .peek_address(u.keychain, u.derivation_index)
                                    .address
                                    .to_string(),
                            ),
                            None => {
                                log::warn!(
                                    "PSBT input {} not found in wallet UTXOs; returning empty",
                                    input.previous_output
                                );
                                (0, String::new())
                            }
                        };
                        TransactionInput {
                            prev_vout: input.previous_output.vout,
                            prev_txid: input.previous_output.txid.to_string(),
                            value,
                            address,
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
            .map_err(|e| Status::internal(format!("Failed to save signed PSBT: {}", e)))?;

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
                .map_err(|e| map_psbt_lookup_error(e, "Original PSBT lookup failed"))?;
            let mut base_psbt = parse_stored_psbt(&req.wallet_id, &req.txid, &base_psbt_str)?;
            // Merge all signed PSBTs into the base PSBT
            log::info!(
                "Combining {} signed PSBTs from devices: {:?}",
                signed_psbts.len(),
                signed_psbts
                    .iter()
                    .map(|s| &s.device_fingerprint)
                    .collect::<Vec<_>>()
            );
            for stored in signed_psbts.iter() {
                let psbt = parse_stored_psbt(&req.wallet_id, &req.txid, &stored.psbt_data)?;
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
            // Load the unsigned PSBT we previously persisted in fund_wallet_transaction.
            let psbt_str = db::get_original_psbt(&req.wallet_id, &req.txid)
                .map_err(|e| map_psbt_lookup_error(e, "Original PSBT lookup failed"))?;
            let mut psbt = parse_stored_psbt(&req.wallet_id, &req.txid, &psbt_str)?;

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
            .map_err(|e| Status::internal(format!("Failed to save signed PSBT: {}", e)))?;

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

            // Check preconditions (PSBT exists, parses, extracts to a tx)
            // *before* paying the cost of an electrs connection. Lets the
            // caller see a useful FailedPrecondition without first being
            // confused by an Internal "can't reach electrs" error.
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

            let psbt = parse_stored_psbt(&req.wallet_id, &req.txid, &psbt_str)?;

            let tx = psbt.extract_tx().map_err(|e| {
                Status::failed_precondition(format!(
                    "Failed to extract transaction from finalized PSBT: {}. \
                     The PSBT may not have been properly finalized.",
                    e
                ))
            })?;

            // Preconditions OK — *now* connect to electrs.
            let client = ElectrumClient::connect(CONFIG.electrs_url())
                .map_err(|e| Status::internal(format!("Failed to connect to electrs: {}", e)))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    // ---- parse_destination_address ---------------------------------------

    #[test]
    fn parse_destination_address_rejects_garbage() {
        let err = parse_destination_address("not-an-address", Network::Regtest)
            .expect_err("garbage must not parse");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("Invalid destination address"),
            "message should describe the failure, got: {}",
            err.message()
        );
    }

    #[test]
    fn parse_destination_address_rejects_empty_string() {
        let err = parse_destination_address("", Network::Regtest)
            .expect_err("empty address must not parse");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn parse_destination_address_rejects_wrong_network() {
        // A real signet/testnet bech32 address — should be rejected on mainnet.
        let testnet_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let err = parse_destination_address(testnet_addr, Network::Bitcoin)
            .expect_err("testnet address must be rejected on mainnet");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("network"),
            "message should mention network mismatch, got: {}",
            err.message()
        );
    }

    #[test]
    fn parse_destination_address_accepts_matching_network() {
        // Same testnet address — should now be accepted on testnet.
        let testnet_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let addr = parse_destination_address(testnet_addr, Network::Testnet)
            .expect("testnet address parses on testnet");
        assert_eq!(addr.to_string(), testnet_addr);
    }

    #[test]
    fn parse_destination_address_rejects_address_with_invalid_checksum() {
        // Mutate last char to break the bech32 checksum.
        let bad = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsy";
        let err = parse_destination_address(bad, Network::Testnet)
            .expect_err("bad checksum must not parse");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // ---- parse_stored_psbt ----------------------------------------------

    #[test]
    fn parse_stored_psbt_rejects_garbage_as_internal() {
        let err = parse_stored_psbt("w1", "tx1", "totally not a psbt")
            .expect_err("garbage PSBT must not parse");
        assert_eq!(err.code(), Code::Internal);
        assert!(
            err.message().contains("Stored PSBT"),
            "message should flag the storage layer, got: {}",
            err.message()
        );
    }

    #[test]
    fn parse_stored_psbt_rejects_empty_string_as_internal() {
        let err = parse_stored_psbt("w1", "tx1", "").expect_err("empty stored PSBT must not parse");
        assert_eq!(err.code(), Code::Internal);
    }

    #[test]
    fn parse_stored_psbt_rejects_truncated_base64_as_internal() {
        // Looks plausible — starts with the PSBT magic in base64 — but
        // is truncated mid-message. The point: any parse failure for stored
        // bytes must be Internal, never InvalidArgument (caller is innocent).
        let err = parse_stored_psbt("w1", "tx1", "cHNidP8BAH4CAAAAA")
            .expect_err("truncated PSBT must not parse");
        assert_eq!(err.code(), Code::Internal);
    }

    // ---- map_psbt_lookup_error ------------------------------------------

    #[test]
    fn map_psbt_lookup_error_translates_notfound() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such psbt");
        let status = map_psbt_lookup_error(err, "Original PSBT lookup failed");
        assert_eq!(status.code(), Code::NotFound);
        assert!(status.message().contains("Original PSBT lookup failed"));
    }

    #[test]
    fn map_psbt_lookup_error_translates_other_as_internal() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let status = map_psbt_lookup_error(err, "PSBT lookup failed");
        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn map_psbt_lookup_error_translates_other_io_error_as_internal() {
        let err = std::io::Error::other("disk fell over");
        let status = map_psbt_lookup_error(err, "Original PSBT lookup failed");
        assert_eq!(status.code(), Code::Internal);
        assert!(status.message().contains("disk fell over"));
    }

    // ============================================================
    // Phase 2 — handler-level integration tests
    // ============================================================
    //
    // Cover error paths for every transaction-handling RPC. Happy paths for
    // Fund / Sign / Finalize / Broadcast require funded UTXOs and an
    // available electrum endpoint — deferred to Phase 3.

    use crate::wallet::service::test_support::{make_single_sig_wallet, setup, unique_id};

    // ---- get_wallet_transactions / get_wallet_utxos ---------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_transactions_returns_not_found_for_unknown_wallet() {
        setup();
        let err = get_wallet_transactions(Request::new(GetWalletTransactionsRequest {
            wallet_id: unique_id("ghost"),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_transactions_returns_empty_for_fresh_wallet() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;
        let resp = get_wallet_transactions(Request::new(GetWalletTransactionsRequest {
            wallet_id: wallet,
        }))
        .await
        .expect("fresh wallet returns OK")
        .into_inner();
        assert!(resp.transactions.is_empty(), "fresh wallet has no txs");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_utxos_returns_not_found_for_unknown_wallet() {
        setup();
        let err = get_wallet_utxos(Request::new(GetWalletUtxosRequest {
            wallet_id: unique_id("ghost"),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_wallet_utxos_returns_empty_for_fresh_wallet() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;
        let resp = get_wallet_utxos(Request::new(GetWalletUtxosRequest { wallet_id: wallet }))
            .await
            .expect("fresh wallet returns OK")
            .into_inner();
        assert!(resp.utxos.is_empty(), "fresh wallet has no utxos");
    }

    // ---- fund_wallet_transaction ----------------------------------------

    fn fund_req(wallet_id: &str, address: &str, value: u64) -> FundWalletTransactionRequest {
        FundWalletTransactionRequest {
            wallet_id: wallet_id.to_string(),
            destination_address: address.to_string(),
            destination_value: value,
            change_address: String::new(),
            fee_per_kb: 0,
            selected_leaf_hash: String::new(),
            spend_change: false,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fund_wallet_transaction_returns_not_found_for_unknown_wallet() {
        setup();
        let err = fund_wallet_transaction(Request::new(fund_req(
            &unique_id("ghost"),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            10_000,
        )))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fund_wallet_transaction_rejects_malformed_address() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        // Phase 1 regression check: a malformed destination used to panic;
        // it must now surface as InvalidArgument.
        let err = fund_wallet_transaction(Request::new(fund_req(
            &wallet,
            "definitely-not-an-address",
            10_000,
        )))
        .await
        .expect_err("malformed address must be InvalidArgument");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().to_lowercase().contains("address"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fund_wallet_transaction_rejects_wrong_network_address() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        // Wallet is testnet (set via test setup); pass a mainnet address.
        let err = fund_wallet_transaction(Request::new(fund_req(
            &wallet,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            10_000,
        )))
        .await
        .expect_err("wrong-network address must be InvalidArgument");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().to_lowercase().contains("network"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fund_wallet_transaction_rejects_insufficient_funds() {
        // Fresh wallet has no UTXOs; tx_builder.finish() should fail with
        // InsufficientFunds, surfacing as Status::invalid_argument per the
        // handler's error mapping.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let err = fund_wallet_transaction(Request::new(fund_req(
            &wallet,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            100_000,
        )))
        .await
        .expect_err("empty wallet cannot fund a transaction");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("Failed to build transaction"),
            "error should reference build failure, got: {}",
            err.message()
        );
    }

    // ---- add_verify_transaction_signature -------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn add_verify_transaction_signature_returns_not_found_for_unknown_wallet() {
        setup();
        let err =
            add_verify_transaction_signature(Request::new(AddVerifyTransactionSignatureRequest {
                wallet_id: unique_id("ghost"),
                txid: String::new(),
                signedpsbt: String::new(),
                devicefingerprint: String::new(),
                devicederivationpath: String::new(),
            }))
            .await
            .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_verify_transaction_signature_rejects_malformed_psbt() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let err =
            add_verify_transaction_signature(Request::new(AddVerifyTransactionSignatureRequest {
                wallet_id: wallet,
                txid: "any-txid".to_string(),
                signedpsbt: "not a real psbt".to_string(),
                devicefingerprint: "deadbeef".to_string(),
                devicederivationpath: String::new(),
            }))
            .await
            .expect_err("malformed PSBT must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("PSBT"));
    }

    // ---- sign_wallet_transaction ----------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_wallet_transaction_returns_not_found_for_unknown_wallet() {
        setup();
        let err = sign_wallet_transaction(Request::new(SignWalletTransactionRequest {
            wallet_id: unique_id("ghost"),
            txid: "any".to_string(),
            device_id: "any".to_string(),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_wallet_transaction_returns_not_found_for_unknown_psbt() {
        // Wallet exists, but we never funded a tx → no original PSBT stored.
        // Phase 1 regression: this used to be Internal (unwrap on missing
        // PSBT) but now surfaces as NotFound via map_psbt_lookup_error.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let err = sign_wallet_transaction(Request::new(SignWalletTransactionRequest {
            wallet_id: wallet,
            txid: "nonexistent-txid".to_string(),
            device_id: device,
        }))
        .await
        .expect_err("missing original PSBT must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
        assert!(err.message().contains("Original PSBT"));
    }

    // ---- finalize_wallet_transaction ------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn finalize_wallet_transaction_returns_not_found_for_unknown_wallet() {
        setup();
        let err = finalize_wallet_transaction(Request::new(FinalizeWalletTransactionRequest {
            wallet_id: unique_id("ghost"),
            txid: "any".to_string(),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finalize_wallet_transaction_returns_not_found_when_no_signed_psbts() {
        // Regression for the Phase-1-prep fix: get_signed_psbts now returns
        // Ok(empty) instead of Err(NotFound), so the handler's is_empty
        // check fires and we get the correct NotFound — not Internal as
        // before.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let err = finalize_wallet_transaction(Request::new(FinalizeWalletTransactionRequest {
            wallet_id: wallet,
            txid: "no-such-tx".to_string(),
        }))
        .await
        .expect_err("no signed PSBTs must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
        assert!(err.message().to_lowercase().contains("signed psbt"));
    }

    // ---- broadcast_wallet_transaction -----------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_wallet_transaction_returns_not_found_for_unknown_wallet() {
        setup();
        let err = broadcast_wallet_transaction(Request::new(BroadcastWalletTransactionRequest {
            wallet_id: unique_id("ghost"),
            txid: "any".to_string(),
        }))
        .await
        .expect_err("missing wallet must be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }

    // ---- proptest invariants --------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// Any *valid* testnet address generated by the BDK library must
        /// round-trip through parse_destination_address(addr.to_string(), Testnet).
        /// Catches future regressions where parse becomes too strict.
        #[test]
        fn prop_parse_destination_round_trips_for_generated_testnet_addresses(
            seed in any::<u64>(),
        ) {
            use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
            use bdk_wallet::bitcoin::secp256k1::Secp256k1;
            use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network};

            // Derive a deterministic compressed pubkey from the seed.
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let secp = Secp256k1::new();
            // Some seeds aren't valid xpriv inputs; skip those.
            let xpriv = match Xpriv::new_master(Network::Testnet, &bytes) {
                Ok(x) => x,
                Err(_) => return Ok(()),
            };
            let xpub = Xpub::from_priv(&secp, &xpriv);
            let pk = CompressedPublicKey(xpub.public_key);
            let addr = Address::p2wpkh(&pk, Network::Testnet);

            let parsed = parse_destination_address(&addr.to_string(), Network::Testnet)
                .expect("self-generated testnet address must parse on testnet");
            prop_assert_eq!(parsed.to_string(), addr.to_string());
        }

        /// Any address that parses on one network must NOT parse on a
        /// *different* network. parse_destination_address's require_network
        /// step is the load-bearing guard against cross-network sends; this
        /// makes sure it can't be silently bypassed.
        #[test]
        fn prop_parse_destination_rejects_address_on_other_network(seed in any::<u64>()) {
            use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
            use bdk_wallet::bitcoin::secp256k1::Secp256k1;
            use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network};

            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            let secp = Secp256k1::new();
            let xpriv = match Xpriv::new_master(Network::Bitcoin, &bytes) {
                Ok(x) => x,
                Err(_) => return Ok(()),
            };
            let xpub = Xpub::from_priv(&secp, &xpriv);
            let pk = CompressedPublicKey(xpub.public_key);
            let mainnet_addr = Address::p2wpkh(&pk, Network::Bitcoin);

            // A bech32 mainnet address (bc1...) must not parse as testnet.
            let err = parse_destination_address(&mainnet_addr.to_string(), Network::Testnet)
                .expect_err("mainnet address must not parse as testnet");
            prop_assert_eq!(err.code(), Code::InvalidArgument);
        }

        /// parse_stored_psbt: any input that is *not* a valid PSBT must
        /// return an Internal status, never panic. We don't try to
        /// construct synthetic PSBTs in the success branch (that's
        /// covered explicitly above); this test is the "no panic on
        /// garbage" property.
        #[test]
        fn prop_parse_stored_psbt_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            // Try as a string; non-utf8 inputs are also fine, just take the lossy form.
            let s = String::from_utf8_lossy(&bytes);
            // Either Ok or Err is fine — what we're checking is the
            // *absence* of a panic. The function returns Result; if it
            // ever panics, this test will fail.
            let _ = parse_stored_psbt("w", "tx", &s);
        }

        /// parse_destination_address: arbitrary bytes (string-form) must
        /// never panic — only Ok(addr) or Err(Status::invalid_argument).
        /// The Phase 1 fix at transaction_handling.rs:203 replaced an
        /// `.unwrap()` here; this property locks the contract.
        #[test]
        fn prop_parse_destination_address_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
            net_idx in 0u8..4u8,
        ) {
            use bdk_wallet::bitcoin::Network as N;
            let s = String::from_utf8_lossy(&bytes);
            let net = match net_idx {
                0 => N::Bitcoin,
                1 => N::Testnet,
                2 => N::Signet,
                _ => N::Regtest,
            };
            let _ = parse_destination_address(&s, net);
        }

        /// parse_destination_address: longer inputs that contain only the
        /// bech32 character set must also never panic. This is the
        /// "looks-like-an-address-but-isn't" attack surface.
        #[test]
        fn prop_parse_destination_address_never_panics_on_bech32ish_inputs(
            s in "[a-z0-9]{0,128}",
        ) {
            use bdk_wallet::bitcoin::Network as N;
            for net in [N::Bitcoin, N::Testnet, N::Signet, N::Regtest] {
                let _ = parse_destination_address(&s, net);
            }
        }

        /// LianaDescriptor::from_str (used in `load_policy_descriptor`)
        /// must never panic on arbitrary bytes. The function is fed
        /// values loaded from storage; if storage is ever corrupted,
        /// we want a `None` return + warn log, not a process crash.
        #[test]
        fn prop_liana_descriptor_parse_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let s = String::from_utf8_lossy(&bytes);
            let _ = crate::LianaDescriptor::from_str(&s);
        }

        /// LianaDescriptor::from_str must also handle descriptor-like
        /// inputs (start with `wsh(` / `tr(` / `wpkh(`) without panicking.
        /// Targets the "almost valid" surface that's most likely to
        /// trigger an unwrap deep inside miniscript.
        #[test]
        fn prop_liana_descriptor_parse_never_panics_on_descriptor_shaped_inputs(
            prefix in prop_oneof![
                Just("wsh(".to_string()),
                Just("wpkh(".to_string()),
                Just("tr(".to_string()),
                Just("sh(".to_string()),
            ],
            body in "[A-Za-z0-9,()<>:_/'*]{0,256}",
        ) {
            let s = format!("{}{})", prefix, body);
            let _ = crate::LianaDescriptor::from_str(&s);
        }

        /// map_psbt_lookup_error: for every io::ErrorKind we might see
        /// from the storage layer, the function returns a Status that's
        /// either NotFound (only for ErrorKind::NotFound) or Internal.
        /// No other gRPC code, ever — that would be a surprise to callers.
        #[test]
        fn prop_map_psbt_lookup_error_only_returns_notfound_or_internal(
            kind_idx in 0u8..16u8,
        ) {
            use std::io::ErrorKind;
            let kind = match kind_idx {
                0 => ErrorKind::NotFound,
                1 => ErrorKind::PermissionDenied,
                2 => ErrorKind::ConnectionRefused,
                3 => ErrorKind::ConnectionReset,
                4 => ErrorKind::ConnectionAborted,
                5 => ErrorKind::NotConnected,
                6 => ErrorKind::AddrInUse,
                7 => ErrorKind::AddrNotAvailable,
                8 => ErrorKind::BrokenPipe,
                9 => ErrorKind::AlreadyExists,
                10 => ErrorKind::WouldBlock,
                11 => ErrorKind::InvalidInput,
                12 => ErrorKind::InvalidData,
                13 => ErrorKind::TimedOut,
                14 => ErrorKind::WriteZero,
                _ => ErrorKind::Other,
            };
            let err = std::io::Error::new(kind, "test");
            let status = map_psbt_lookup_error(err, "test op");
            if kind == ErrorKind::NotFound {
                prop_assert_eq!(status.code(), Code::NotFound);
            } else {
                prop_assert_eq!(status.code(), Code::Internal);
            }
        }
    }

    // ---- handler tests (continued) --------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_wallet_transaction_rejects_missing_finalized_psbt() {
        // No finalize step has run for this wallet — the handler returns
        // FailedPrecondition pointing the caller at finalize_*.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        let err = broadcast_wallet_transaction(Request::new(BroadcastWalletTransactionRequest {
            wallet_id: wallet,
            txid: "no-such-tx".to_string(),
        }))
        .await
        .expect_err("missing finalized PSBT must error");
        // The handler maps the underlying io::Error to FailedPrecondition
        // (it points the caller at finalize_wallet_transaction first).
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("finalize_wallet_transaction"));
    }

    // ============================================================
    // Phase 3 — full lifecycle happy paths (UTXO injection)
    // ============================================================
    //
    // These tests exercise the Fund → Sign → Finalize pipeline end-to-end
    // using `inject_unconfirmed_utxo` from test_support. Broadcast is
    // skipped because it requires a live electrs.

    use crate::wallet::service::test_support::inject_unconfirmed_utxo;

    /// External-pay address we send to in the happy-path lifecycle tests.
    /// Real testnet bech32 address that isn't owned by any test wallet.
    const EXTERNAL_TESTNET_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    #[tokio::test(flavor = "multi_thread")]
    async fn lifecycle_single_sig_fund_sign_finalize_produces_extractable_tx() {
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;
        let _funding_txid = inject_unconfirmed_utxo(&wallet, 200_000).await;

        // FUND
        let fund_resp = fund_wallet_transaction(Request::new(FundWalletTransactionRequest {
            wallet_id: wallet.clone(),
            destination_address: EXTERNAL_TESTNET_ADDRESS.to_string(),
            destination_value: 50_000,
            change_address: String::new(),
            fee_per_kb: 0,
            selected_leaf_hash: String::new(),
            spend_change: false,
        }))
        .await
        .expect("fund_wallet_transaction must succeed with a funded wallet")
        .into_inner();
        assert!(
            !fund_resp.psbt.is_empty(),
            "fund response must include a PSBT"
        );
        assert!(
            !fund_resp.txid.is_empty(),
            "fund response must include a txid"
        );
        // Input total must be >= destination + fee. We picked 200k for
        // funding and want 50k out; whatever's left covers fee + change.
        assert!(
            fund_resp.input_total >= 50_000,
            "input total must cover the spend, got {}",
            fund_resp.input_total
        );

        // SIGN
        let sign_resp = sign_wallet_transaction(Request::new(SignWalletTransactionRequest {
            wallet_id: wallet.clone(),
            txid: fund_resp.txid.clone(),
            device_id: device.clone(),
        }))
        .await
        .expect("sign_wallet_transaction must succeed for system-managed device")
        .into_inner();
        assert!(
            !sign_resp.tx_raw.is_empty(),
            "sign response must include the signed PSBT"
        );

        // Verify the signed PSBT actually has signatures (Phase 1 handler
        // checks this internally but assert at the integration boundary).
        let signed = Psbt::from_str(&sign_resp.tx_raw).expect("sign tx_raw is valid PSBT");
        assert!(
            signed.inputs.iter().any(|i| !i.partial_sigs.is_empty()
                || i.tap_key_sig.is_some()
                || !i.tap_script_sigs.is_empty()),
            "signed PSBT must carry at least one signature"
        );

        // FINALIZE
        let final_resp =
            finalize_wallet_transaction(Request::new(FinalizeWalletTransactionRequest {
                wallet_id: wallet,
                txid: fund_resp.txid,
            }))
            .await
            .expect("finalize_wallet_transaction must succeed with a fully-signed PSBT")
            .into_inner();
        assert!(!final_resp.tx_raw.is_empty(), "finalize must return a PSBT");

        // Extract the actual transaction — proves finalize produced a
        // chain-ready tx, which is the whole point of the pipeline.
        let finalized = Psbt::from_str(&final_resp.tx_raw).expect("finalize tx_raw is valid PSBT");
        let extracted = finalized
            .extract_tx()
            .expect("finalized PSBT must extract to a valid transaction");
        assert!(
            !extracted.input.is_empty(),
            "extracted transaction must have inputs"
        );
        assert!(
            extracted.output.iter().any(|o| o.value.to_sat() == 50_000),
            "extracted transaction must include the 50k-sat destination output, got: {:?}",
            extracted
                .output
                .iter()
                .map(|o| o.value.to_sat())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lifecycle_single_sig_fund_fails_when_only_dust_is_available() {
        // Inject a tiny UTXO that can't even cover the requested spend +
        // fee. Confirms the build-failure path is reached cleanly when the
        // wallet *does* have UTXOs but they're inadequate (distinct
        // failure mode from "no UTXOs at all" already tested above).
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;
        let _ = inject_unconfirmed_utxo(&wallet, 1_000).await;

        let err = fund_wallet_transaction(Request::new(FundWalletTransactionRequest {
            wallet_id: wallet,
            destination_address: EXTERNAL_TESTNET_ADDRESS.to_string(),
            destination_value: 100_000,
            change_address: String::new(),
            fee_per_kb: 0,
            selected_leaf_hash: String::new(),
            spend_change: false,
        }))
        .await
        .expect_err("1000 sat UTXO can't fund a 100k spend");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lifecycle_funded_wallet_lists_one_utxo() {
        // Regression check on the get_wallet_utxos handler that
        // previously panicked on `wallet.get_utxo(...).unwrap()` (fixed
        // in Phase 1). With an injected UTXO present, the handler must
        // return one entry with the right value.
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;
        let _ = inject_unconfirmed_utxo(&wallet, 123_456).await;

        let resp = get_wallet_utxos(Request::new(GetWalletUtxosRequest { wallet_id: wallet }))
            .await
            .expect("get_wallet_utxos with an injected UTXO must succeed")
            .into_inner();
        assert_eq!(resp.utxos.len(), 1, "exactly one injected UTXO expected");
        assert_eq!(resp.utxos[0].value, 123_456);
    }
}

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
}

use crate::db::StoredWallet;
use crate::wallet::advanced::descriptor::{self, DescriptorPair};
use crate::wallet::advanced::error::WalletCreationError;
use crate::wallet::advanced::shape::{self, WalletShape};
use crate::wallet::advanced::spec::WalletSpec;
use crate::wallet::advanced::taproot::{self, TaprootLeafInfo};
use crate::wallet::bdk::BdkWalletManager;

#[derive(Debug, Clone)]
pub struct WalletBuildResult {
    pub wallet_id: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    /// Canonical Liana descriptor for `TimelockedPolicy` wallets. `None` for
    /// flat single-sig / multisig / taproot-multisig wallets — those have no
    /// Liana descriptor to persist, and downstream code (PSBT pruning, leaf
    /// resolution in the signer) treats `None` as "skip Liana steps".
    pub liana_descriptor: Option<String>,
    pub taproot_leaf_info: Vec<TaprootLeafInfo>,
    pub merkle_root: Option<String>,
    pub internal_key: Option<String>,
}

/// Drive the full wallet-creation pipeline:
/// validate spec → classify into a `WalletShape` → build descriptors →
/// persist BDK wallet state → extract taproot metadata when applicable.
pub fn build_wallet(
    spec: &WalletSpec,
    stored_wallet: &StoredWallet,
) -> Result<WalletBuildResult, WalletCreationError> {
    if stored_wallet.wallet_id.is_empty() {
        return Err(WalletCreationError::InvalidPolicy(
            "Wallet ID is required".to_string(),
        ));
    }

    spec.validate()?;
    let shape = shape::classify(spec)?;
    let DescriptorPair {
        external,
        internal,
        liana,
    } = descriptor::build(&shape)?;

    log::info!(
        "Built wallet shape {:?} for wallet {}",
        shape_label(&shape),
        stored_wallet.wallet_id
    );

    BdkWalletManager::new(spec.network).create_wallet_with_descriptors(
        stored_wallet,
        &external,
        &internal,
    )?;

    let metadata = match (&shape, liana.as_ref()) {
        (
            WalletShape::TimelockedPolicy {
                primary_id,
                primary,
                recoveries,
            },
            Some(desc),
        ) => taproot::extract(primary_id, primary, recoveries, desc)?,
        _ => taproot::TaprootMetadata::default(),
    };

    Ok(WalletBuildResult {
        wallet_id: stored_wallet.wallet_id.clone(),
        external_descriptor: external,
        internal_descriptor: internal,
        liana_descriptor: liana.map(|d| d.to_string()),
        taproot_leaf_info: metadata.leaves,
        merkle_root: metadata.merkle_root,
        internal_key: metadata.internal_key,
    })
}

fn shape_label(shape: &WalletShape) -> &'static str {
    match shape {
        WalletShape::SingleSig { .. } => "SingleSig",
        WalletShape::Multisig { .. } => "Multisig",
        WalletShape::TimelockedPolicy { .. } => "TimelockedPolicy",
    }
}

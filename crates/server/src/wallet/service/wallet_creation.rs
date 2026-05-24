use std::collections::BTreeMap;

use tonic::{Request, Response, Status};

use crate::db::{self, StoredManagedKey};
use crate::proto::pb::{
    CreateGenericWalletRequest, CreateGenericWalletResponse, PolicyType as ProtoPolicyType,
    SpendingCondition as ProtoSpendingCondition, TaprootLeafInfo as ProtoTaprootLeafInfo,
};
use crate::wallet::advanced::{
    self, ManagedKey, PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
};

pub async fn create_generic_wallet(
    request: Request<CreateGenericWalletRequest>,
) -> Result<Response<CreateGenericWalletResponse>, Status> {
    let req = request.into_inner();

    if req.wallet_id.is_empty() {
        return Err(Status::invalid_argument("wallet_id is required"));
    }
    if req.user_id.is_empty() {
        return Err(Status::invalid_argument("user_id is required"));
    }
    if req.spending_conditions.is_empty() {
        return Err(Status::invalid_argument(
            "at least one spending condition is required",
        ));
    }

    let conditions = req
        .spending_conditions
        .iter()
        .map(condition_from_proto)
        .collect::<Result<Vec<_>, _>>()?;

    let managed_keys = load_managed_keys(&req.user_id, &conditions)
        .map_err(|e| Status::internal(format!("Failed to load managed keys: {}", e)))?;

    let network = crate::config::CONFIG.network();
    let spec = WalletSpec {
        network,
        conditions,
        managed_keys,
        preferred_script_type: preferred_script_type_from_proto(req.preferred_script_type),
    };

    let stored_wallet = db::create_wallet(
        &req.user_id,
        &req.wallet_id,
        "Advanced Wallet",
        &network.to_string(),
        "advanced",
    )?;

    let result = advanced::build_wallet(&spec, &stored_wallet)
        .map_err(|e| Status::internal(format!("Wallet creation failed: {}", e)))?;

    if let Some(ref policy_desc) = result.policy_descriptor {
        log::info!("Persisting policy descriptor for wallet {}", req.wallet_id);
        let updated_wallet = stored_wallet.with_policy_descriptor(policy_desc);
        if let Err(e) = updated_wallet.store() {
            log::warn!("Failed to persist policy descriptor: {}", e);
        }
    }

    let taproot_leaf_info = result
        .taproot_leaf_info
        .into_iter()
        .map(|leaf| ProtoTaprootLeafInfo {
            leaf_hash: leaf.leaf_hash,
            spending_condition_id: leaf.spending_condition_id,
            script_path: leaf.script_path,
            timelock: leaf.timelock.map(|t| t as u32).unwrap_or(0),
            policy_type: match leaf.policy_type {
                PolicyType::Single => "single".to_string(),
                PolicyType::Multi => "multi".to_string(),
            },
            threshold: leaf.threshold.map(|t| t as u32).unwrap_or(1),
            description: leaf.description,
        })
        .collect();

    Ok(Response::new(CreateGenericWalletResponse {
        wallet_id: result.wallet_id,
        external_descriptor: result.external_descriptor,
        internal_descriptor: result.internal_descriptor,
        status: "success".to_string(),
        message: "Wallet created successfully".to_string(),
        taproot_leaf_info,
        merkle_root: result.merkle_root.unwrap_or_default(),
        internal_key: result.internal_key.unwrap_or_default(),
    }))
}

fn preferred_script_type_from_proto(value: i32) -> PreferredScriptType {
    match value {
        1 => PreferredScriptType::Taproot,
        2 => PreferredScriptType::SegwitV0,
        _ => PreferredScriptType::Auto,
    }
}

fn condition_from_proto(proto: &ProtoSpendingCondition) -> Result<SpendingCondition, Status> {
    let policy = match proto.policy() {
        ProtoPolicyType::Single => PolicyType::Single,
        ProtoPolicyType::Multi => PolicyType::Multi,
    };

    Ok(SpendingCondition {
        id: proto.id.clone(),
        is_primary: proto.is_primary,
        timelock: proto.timelock as u16,
        threshold: proto.threshold as usize,
        policy,
        managed_key_ids: proto.managed_key_ids.clone(),
        is_unspendable: proto.is_unspendable,
    })
}

fn load_managed_keys(
    user_id: &str,
    conditions: &[SpendingCondition],
) -> Result<BTreeMap<String, ManagedKey>, String> {
    let mut device_ids: Vec<String> = conditions
        .iter()
        .flat_map(|c| c.managed_key_ids.iter().cloned())
        .collect();
    device_ids.sort();
    device_ids.dedup();

    let mut managed_keys = BTreeMap::new();
    for device_id in device_ids {
        let key = lookup_managed_key(user_id, &device_id)?;
        managed_keys.insert(device_id, key.to_managed_key());
    }

    if managed_keys.is_empty() {
        return Err("No managed keys found for specified devices".to_string());
    }

    Ok(managed_keys)
}

fn lookup_managed_key(user_id: &str, device_id: &str) -> Result<StoredManagedKey, String> {
    if let Some(key) =
        db::get_managed_key(user_id, device_id, "customer").map_err(|e| e.to_string())?
    {
        return Ok(key);
    }
    if let Some(key) =
        db::get_managed_key(user_id, device_id, "system").map_err(|e| e.to_string())?
    {
        return Ok(key);
    }
    Err(format!("Managed key not found for device {}", device_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::service::test_support::{
        make_customer_key, make_single_sig_wallet, make_system_key, setup, unique_id,
    };
    use tonic::Code;

    fn cond(
        id: &str,
        primary: bool,
        timelock: u32,
        policy: ProtoPolicyType,
        threshold: u32,
        keys: &[&str],
    ) -> ProtoSpendingCondition {
        ProtoSpendingCondition {
            id: id.to_string(),
            is_primary: primary,
            timelock,
            threshold,
            policy: policy as i32,
            managed_key_ids: keys.iter().map(|s| s.to_string()).collect(),
            is_unspendable: false,
        }
    }

    // ---- input validation ------------------------------------------------

    #[tokio::test]
    async fn create_generic_wallet_rejects_empty_wallet_id() {
        setup();
        let err = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: unique_id("user"),
            wallet_id: String::new(),
            spending_conditions: vec![cond(
                "primary",
                true,
                0,
                ProtoPolicyType::Single,
                1,
                &["dev"],
            )],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect_err("empty wallet_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("wallet_id"));
    }

    #[tokio::test]
    async fn create_generic_wallet_rejects_empty_user_id() {
        setup();
        let err = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: String::new(),
            wallet_id: unique_id("wallet"),
            spending_conditions: vec![cond(
                "primary",
                true,
                0,
                ProtoPolicyType::Single,
                1,
                &["dev"],
            )],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect_err("empty user_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("user_id"));
    }

    #[tokio::test]
    async fn create_generic_wallet_rejects_no_spending_conditions() {
        setup();
        let err = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: unique_id("user"),
            wallet_id: unique_id("wallet"),
            spending_conditions: vec![],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect_err("empty conditions must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("spending condition"));
    }

    #[tokio::test]
    async fn create_generic_wallet_rejects_missing_managed_key() {
        setup();
        let user = unique_id("user");
        // Don't create the referenced key — RPC must report the lookup failure.
        let err = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: user,
            wallet_id: unique_id("wallet"),
            spending_conditions: vec![cond(
                "primary",
                true,
                0,
                ProtoPolicyType::Single,
                1,
                &["ghost-device"],
            )],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect_err("missing managed key must be rejected");
        assert_eq!(err.code(), Code::Internal);
        assert!(
            err.message().contains("not found") || err.message().contains("Managed key"),
            "error must reference the missing key, got: {}",
            err.message()
        );
    }

    // ---- happy paths -----------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn create_generic_wallet_single_sig_succeeds_via_fixture() {
        // Exercises the wallet-creation RPC end-to-end via the test fixture
        // (which itself calls the real create_generic_wallet handler).
        let user = unique_id("user");
        let wallet = unique_id("wallet");
        let device = unique_id("dev");
        make_single_sig_wallet(&user, &wallet, &device).await;

        // Sanity check that the wallet is queryable via db (downstream RPCs
        // would discover it the same way).
        let stored = db::get_wallet(&wallet).expect("wallet must be stored");
        assert_eq!(stored.wallet_id, wallet);
        assert_eq!(stored.user_id, user);
        assert_eq!(stored.wallet_type, "advanced");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_generic_wallet_multisig_returns_descriptor() {
        setup();
        let user = unique_id("user");
        let dev1 = unique_id("dev");
        let dev2 = unique_id("dev");
        let dev3 = unique_id("dev");
        let _ = make_system_key(&user, &dev1).await;
        let _ = make_system_key(&user, &dev2).await;
        let _ = make_system_key(&user, &dev3).await;

        let wallet_id = unique_id("wallet");
        let resp = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: user,
            wallet_id: wallet_id.clone(),
            spending_conditions: vec![cond(
                "primary",
                true,
                0,
                ProtoPolicyType::Multi,
                2,
                &[&dev1, &dev2, &dev3],
            )],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect("2-of-3 multisig must succeed")
        .into_inner();

        assert_eq!(resp.wallet_id, wallet_id);
        assert_eq!(resp.status, "success");
        assert!(
            resp.external_descriptor.starts_with("wsh(sortedmulti(2,"),
            "2-of-3 must use wsh+sortedmulti, got: {}",
            resp.external_descriptor
        );
        assert!(
            resp.taproot_leaf_info.is_empty(),
            "flat multisig has no taproot leaves"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_generic_wallet_timelocked_policy_returns_taproot_metadata() {
        setup();
        let user = unique_id("user");
        let dev_primary_a = unique_id("dev");
        let dev_primary_b = unique_id("dev");
        let dev_recovery = unique_id("dev");
        let _ = make_system_key(&user, &dev_primary_a).await;
        let _ = make_system_key(&user, &dev_primary_b).await;
        let _ = make_system_key(&user, &dev_recovery).await;

        let wallet_id = unique_id("wallet");
        let resp = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: user,
            wallet_id: wallet_id.clone(),
            spending_conditions: vec![
                cond(
                    "primary",
                    true,
                    0,
                    ProtoPolicyType::Multi,
                    2,
                    &[&dev_primary_a, &dev_primary_b],
                ),
                cond(
                    "recovery",
                    false,
                    144,
                    ProtoPolicyType::Single,
                    1,
                    &[&dev_recovery],
                ),
            ],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect("timelocked policy must succeed")
        .into_inner();

        assert_eq!(resp.wallet_id, wallet_id);
        assert_eq!(resp.status, "success");
        assert!(
            !resp.taproot_leaf_info.is_empty(),
            "timelocked policy must expose taproot leaves"
        );
        let leaf_ids: Vec<_> = resp
            .taproot_leaf_info
            .iter()
            .map(|l| l.spending_condition_id.as_str())
            .collect();
        assert!(leaf_ids.contains(&"primary"));
        assert!(leaf_ids.contains(&"recovery"));
        assert!(
            !resp.merkle_root.is_empty(),
            "taproot wallet must expose merkle root in response"
        );
        assert!(
            !resp.internal_key.is_empty(),
            "taproot wallet must expose internal key in response"
        );

        // Confirm policy descriptor was persisted (load_policy_descriptor in
        // the signer path will pick it up).
        let stored = db::get_wallet(&wallet_id).expect("wallet stored");
        assert!(
            stored.policy_descriptor.is_some(),
            "TimelockedPolicy wallet must persist its policy descriptor"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_generic_wallet_accepts_customer_key() {
        // Customer keys (xpub-only) should be usable as the sole device in a
        // single-sig wallet exactly the same as system keys.
        setup();
        let user = unique_id("user");
        let device = unique_id("dev");
        make_customer_key(&user, &device, 8001).await;

        let wallet_id = unique_id("wallet");
        let resp = create_generic_wallet(Request::new(CreateGenericWalletRequest {
            user_id: user,
            wallet_id: wallet_id.clone(),
            spending_conditions: vec![cond(
                "primary",
                true,
                0,
                ProtoPolicyType::Single,
                1,
                &[&device],
            )],
            network: "testnet".to_string(),
            preferred_script_type: 0,
        }))
        .await
        .expect("single-sig customer-key wallet must succeed")
        .into_inner();

        assert_eq!(resp.wallet_id, wallet_id);
        assert_eq!(resp.status, "success");
    }
}

use std::collections::BTreeMap;

use tonic::{Request, Response, Status};

use crate::db::{self, StoredManagedKey};
use crate::proto::pb::{
    CreateGenericWalletRequest, CreateGenericWalletResponse, PolicyType as ProtoPolicyType,
    SpendingCondition as ProtoSpendingCondition, TaprootLeafInfo as ProtoTaprootLeafInfo,
};
use crate::wallet::advanced::{
    self, PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
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

    if let Some(ref liana_desc) = result.liana_descriptor {
        log::info!(
            "Persisting Liana descriptor for wallet {}",
            req.wallet_id
        );
        let updated_wallet = stored_wallet.with_liana_descriptor(liana_desc);
        if let Err(e) = updated_wallet.store() {
            log::warn!("Failed to persist liana descriptor: {}", e);
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
    })
}

fn load_managed_keys(
    user_id: &str,
    conditions: &[SpendingCondition],
) -> Result<BTreeMap<String, StoredManagedKey>, String> {
    let mut device_ids: Vec<String> = conditions
        .iter()
        .flat_map(|c| c.managed_key_ids.iter().cloned())
        .collect();
    device_ids.sort();
    device_ids.dedup();

    let mut managed_keys = BTreeMap::new();
    for device_id in device_ids {
        let key = lookup_managed_key(user_id, &device_id)?;
        managed_keys.insert(device_id, key);
    }

    if managed_keys.is_empty() {
        return Err("No managed keys found for specified devices".to_string());
    }

    Ok(managed_keys)
}

fn lookup_managed_key(user_id: &str, device_id: &str) -> Result<StoredManagedKey, String> {
    if let Some(key) = db::get_managed_key(user_id, device_id, "customer")
        .map_err(|e| e.to_string())?
    {
        return Ok(key);
    }
    if let Some(key) = db::get_managed_key(user_id, device_id, "system")
        .map_err(|e| e.to_string())?
    {
        return Ok(key);
    }
    Err(format!("Managed key not found for device {}", device_id))
}

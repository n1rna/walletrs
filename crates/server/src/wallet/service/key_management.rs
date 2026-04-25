use crate::config::CONFIG;
use crate::db;
use crate::proto::pb::{
    CreateCustomerManagedKeyRequest, CreateCustomerManagedKeyResponse,
    CreateSystemManagedKeysRequest, CreateSystemManagedKeysResponse, GetManagedKeyRequest,
    GetManagedKeyResponse, ListManagedKeysRequest, ListManagedKeysResponse, ManagedKeyInfo,
};
use tonic::{Request, Response, Status};

pub async fn create_system_managed_key(
    request: Request<CreateSystemManagedKeysRequest>,
) -> Result<Response<CreateSystemManagedKeysResponse>, Status> {
    use crate::wallet::bdk::KeyUtils;
    use bdk_wallet::bitcoin::{bip32, secp256k1};

    let req = request.into_inner();

    // Validate required fields
    if req.user_id.is_empty() {
        return Err(Status::invalid_argument("user_id is required"));
    }
    if req.device_id.is_empty() {
        return Err(Status::invalid_argument("device_id is required"));
    }

    // Generate a unique key name if not provided
    let key_name = if req.key_name.is_empty() {
        "system".to_string()
    } else {
        req.key_name
    };

    // Get network from environment
    let network = CONFIG.network();

    // Initialize crypto context - same as CLI
    let secp: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();

    // Generate complete key set using new utilities
    let key_result = KeyUtils::generate_complete_key_set(network);
    let primary_path = KeyUtils::get_primary_derivation_path(network);

    // Derive account keys - same as CLI
    let tprv = match key_result.xprv.derive_priv(&secp, &primary_path) {
        Ok(key) => key,
        Err(e) => {
            return Err(Status::internal(format!(
                "Failed to derive private key: {}",
                e
            )))
        }
    };
    let tpub = bip32::Xpub::from_priv(&secp, &tprv);

    // Get the fingerprint for this key - same as CLI
    let fingerprint = tprv.fingerprint(&secp).to_string();

    // Format the keys with the derivation paths - same as CLI
    let _tprv_formatted = KeyUtils::format_key_with_fingerprint(&fingerprint, &tprv.to_string());
    let _tpub_formatted = KeyUtils::format_key_with_fingerprint(&fingerprint, &tpub.to_string());

    // Format xpub for Liana (with multipath derivation and full key origin)
    let tpub_liana_format =
        KeyUtils::format_key_for_liana(&fingerprint, &primary_path.to_string(), &tpub.to_string());

    // Store the system key with proper separation of root and account keys
    // xpriv/xpub: Root keys (m/) - for potential future derivations
    // tpriv/tpub: Account keys (m/84'/1'/0') - what we actually use for signing
    match db::store_system_key(
        &req.user_id,
        &req.device_id,
        &key_name,
        &key_result.xprv.to_string(), // Store root xpriv (m/)
        &key_result.xpub.to_string(), // Store root xpub (m/)
        &fingerprint,
        &primary_path.to_string(),
        &key_result.words.join(" "),
        &tprv.to_string(),  // Store account xpriv (m/84'/1'/0')
        &tpub_liana_format, // Store Liana-formatted account xpub
    ) {
        Ok(_) => Ok(Response::new(CreateSystemManagedKeysResponse {
            user_id: req.user_id,
            device_id: req.device_id,
            xpub: tpub_liana_format.clone(), // Return the Liana-formatted xpub
            fingerprint: fingerprint,
            derivation_path: primary_path.to_string(),
            status: "success".to_string(),
            message: format!("System managed key '{}' created successfully", key_name),
        })),
        Err(e) => Err(Status::internal(format!(
            "Failed to store system key: {}",
            e
        ))),
    }
}

pub async fn create_customer_managed_key(
    request: Request<CreateCustomerManagedKeyRequest>,
) -> Result<Response<CreateCustomerManagedKeyResponse>, Status> {
    let req = request.into_inner();

    // Validate required fields
    if req.user_id.is_empty() {
        return Err(Status::invalid_argument("user_id is required"));
    }
    if req.device_id.is_empty() {
        return Err(Status::invalid_argument("device_id is required"));
    }
    if req.xpub.is_empty() {
        return Err(Status::invalid_argument("xpub is required"));
    }
    if req.fingerprint.is_empty() {
        return Err(Status::invalid_argument("fingerprint is required"));
    }

    match db::store_customer_key(
        &req.user_id,
        &req.device_id,
        &req.key_name,
        &req.xpub,
        &req.fingerprint,
        &req.derivation_path,
    ) {
        Ok(_) => Ok(Response::new(CreateCustomerManagedKeyResponse {
            user_id: req.user_id,
            device_id: req.device_id,
            status: "success".to_string(),
            message: "Customer managed key created successfully".to_string(),
        })),
        Err(e) => Err(Status::internal(format!(
            "Failed to create customer managed key: {}",
            e
        ))),
    }
}

pub async fn get_managed_key(
    request: Request<GetManagedKeyRequest>,
) -> Result<Response<GetManagedKeyResponse>, Status> {
    let req = request.into_inner();

    if req.user_id.is_empty() {
        return Err(Status::invalid_argument("user_id is required"));
    }
    if req.device_id.is_empty() {
        return Err(Status::invalid_argument("device_id is required"));
    }
    if req.key_type.is_empty() {
        return Err(Status::invalid_argument("key_type is required"));
    }

    match db::get_managed_key(&req.user_id, &req.device_id, &req.key_type) {
        Ok(Some(key)) => Ok(Response::new(GetManagedKeyResponse {
            key: Some(ManagedKeyInfo {
                user_id: key.user_id,
                device_id: key.device_id,
                key_name: key.key_name,
                key_type: key.key_type,
                xpub: key.tpub.clone().unwrap_or(key.xpub), // For system keys, use tpub (Liana-formatted); for customer keys, use xpub
                fingerprint: key.fingerprint,
                derivation_path: key.derivation_path,
                created_at: key.created_at,
            }),
            found: true,
        })),
        Ok(None) => Ok(Response::new(GetManagedKeyResponse {
            key: None,
            found: false,
        })),
        Err(e) => Err(Status::internal(format!(
            "Failed to get managed key: {}",
            e
        ))),
    }
}

pub async fn list_managed_keys(
    request: Request<ListManagedKeysRequest>,
) -> Result<Response<ListManagedKeysResponse>, Status> {
    let req = request.into_inner();

    // Convert empty strings to None for optional filters
    let user_id_filter = if req.user_id.is_empty() {
        None
    } else {
        Some(req.user_id.as_str())
    };
    let key_type_filter = if req.key_type.is_empty() {
        None
    } else {
        Some(req.key_type.as_str())
    };

    match db::list_managed_keys(user_id_filter, key_type_filter) {
        Ok(keys) => {
            let key_infos: Vec<ManagedKeyInfo> = keys
                .into_iter()
                .map(|key| ManagedKeyInfo {
                    user_id: key.user_id,
                    device_id: key.device_id,
                    key_name: key.key_name,
                    key_type: key.key_type,
                    xpub: key.tpub.clone().unwrap_or(key.xpub), // For system keys, use tpub (Liana-formatted); for customer keys, use xpub
                    fingerprint: key.fingerprint,
                    derivation_path: key.derivation_path,
                    created_at: key.created_at,
                })
                .collect();

            Ok(Response::new(ListManagedKeysResponse { keys: key_infos }))
        }
        Err(e) => Err(Status::internal(format!(
            "Failed to list managed keys: {}",
            e
        ))),
    }
}

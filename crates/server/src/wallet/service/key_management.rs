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

    // Format xpub for descriptor use (with multipath derivation and full key origin)
    let tpub_descriptor_format = KeyUtils::format_key_for_descriptor(
        &fingerprint,
        &primary_path.to_string(),
        &tpub.to_string(),
    );

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
        &tprv.to_string(),       // Store account xpriv (m/84'/1'/0')
        &tpub_descriptor_format, // Store descriptor-formatted account xpub
    ) {
        Ok(_) => Ok(Response::new(CreateSystemManagedKeysResponse {
            user_id: req.user_id,
            device_id: req.device_id,
            xpub: tpub_descriptor_format.clone(), // Return the descriptor-formatted xpub
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
                xpub: key.tpub.clone().unwrap_or(key.xpub), // For system keys, use tpub (descriptor-formatted); for customer keys, use xpub
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

    // The managed-keys storage scope is per-user; listing without a
    // user_id is meaningless and would only succeed for an admin tool
    // we don't expose here. Reject up front so the failure is the right
    // gRPC code (InvalidArgument, not Internal masquerading as a storage
    // error from a layer below).
    if req.user_id.is_empty() {
        return Err(Status::invalid_argument(
            "user_id is required to list managed keys",
        ));
    }
    let user_id_filter = Some(req.user_id.as_str());
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
                    xpub: key.tpub.clone().unwrap_or(key.xpub), // For system keys, use tpub (descriptor-formatted); for customer keys, use xpub
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::service::test_support::{
        make_customer_key, make_system_key, setup, test_xpub, unique_id,
    };
    use tonic::Code;

    // ---- create_system_managed_key ---------------------------------------

    #[tokio::test]
    async fn create_system_managed_key_rejects_empty_user_id() {
        setup();
        let err = create_system_managed_key(Request::new(CreateSystemManagedKeysRequest {
            user_id: String::new(),
            device_id: "any-device".to_string(),
            key_name: String::new(),
        }))
        .await
        .expect_err("empty user_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("user_id"));
    }

    #[tokio::test]
    async fn create_system_managed_key_rejects_empty_device_id() {
        setup();
        let err = create_system_managed_key(Request::new(CreateSystemManagedKeysRequest {
            user_id: unique_id("user"),
            device_id: String::new(),
            key_name: String::new(),
        }))
        .await
        .expect_err("empty device_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("device_id"));
    }

    #[tokio::test]
    async fn create_system_managed_key_persists_descriptor_formatted_xpub() {
        setup();
        let user = unique_id("user");
        let device = unique_id("dev");
        let resp = create_system_managed_key(Request::new(CreateSystemManagedKeysRequest {
            user_id: user.clone(),
            device_id: device.clone(),
            key_name: "primary-system".to_string(),
        }))
        .await
        .expect("create_system_managed_key happy path")
        .into_inner();

        assert_eq!(resp.user_id, user);
        assert_eq!(resp.device_id, device);
        assert_eq!(resp.status, "success");
        assert_eq!(resp.fingerprint.len(), 8, "fingerprint must be 8 hex chars");
        assert!(
            resp.xpub.starts_with('['),
            "descriptor xpub must include origin prefix `[fp/path]xpub...`, got: {}",
            resp.xpub
        );
        assert!(
            resp.xpub.ends_with("/*"),
            "system key must store a multipath xpub, got: {}",
            resp.xpub
        );

        // Round-trip via get_managed_key.
        let fetched = get_managed_key(Request::new(GetManagedKeyRequest {
            user_id: user,
            device_id: device,
            key_type: "system".to_string(),
        }))
        .await
        .expect("get_managed_key after create")
        .into_inner();
        assert!(fetched.found);
        let key = fetched.key.expect("key present");
        assert_eq!(key.fingerprint, resp.fingerprint);
    }

    // ---- create_customer_managed_key -------------------------------------

    #[tokio::test]
    async fn create_customer_managed_key_rejects_empty_user_id() {
        setup();
        let (fp, xpub) = test_xpub(7001);
        let err = create_customer_managed_key(Request::new(CreateCustomerManagedKeyRequest {
            user_id: String::new(),
            device_id: "any-device".to_string(),
            key_name: String::new(),
            xpub,
            fingerprint: fp,
            derivation_path: "m/84'/1'/0'".to_string(),
        }))
        .await
        .expect_err("empty user_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_customer_managed_key_rejects_empty_device_id() {
        setup();
        let (fp, xpub) = test_xpub(7002);
        let err = create_customer_managed_key(Request::new(CreateCustomerManagedKeyRequest {
            user_id: unique_id("user"),
            device_id: String::new(),
            key_name: String::new(),
            xpub,
            fingerprint: fp,
            derivation_path: "m/84'/1'/0'".to_string(),
        }))
        .await
        .expect_err("empty device_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_customer_managed_key_rejects_empty_xpub() {
        setup();
        let err = create_customer_managed_key(Request::new(CreateCustomerManagedKeyRequest {
            user_id: unique_id("user"),
            device_id: unique_id("dev"),
            key_name: String::new(),
            xpub: String::new(),
            fingerprint: "deadbeef".to_string(),
            derivation_path: "m/84'/1'/0'".to_string(),
        }))
        .await
        .expect_err("empty xpub must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_customer_managed_key_rejects_empty_fingerprint() {
        setup();
        let (_, xpub) = test_xpub(7003);
        let err = create_customer_managed_key(Request::new(CreateCustomerManagedKeyRequest {
            user_id: unique_id("user"),
            device_id: unique_id("dev"),
            key_name: String::new(),
            xpub,
            fingerprint: String::new(),
            derivation_path: "m/84'/1'/0'".to_string(),
        }))
        .await
        .expect_err("empty fingerprint must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_customer_managed_key_happy_path_round_trips() {
        let user = unique_id("user");
        let device = unique_id("dev");
        make_customer_key(&user, &device, 7100).await;

        let fetched = get_managed_key(Request::new(GetManagedKeyRequest {
            user_id: user.clone(),
            device_id: device.clone(),
            key_type: "customer".to_string(),
        }))
        .await
        .expect("get_managed_key after create")
        .into_inner();
        assert!(fetched.found, "customer key must be retrievable");
        let key = fetched.key.expect("key present");
        assert_eq!(key.user_id, user);
        assert_eq!(key.device_id, device);
        assert_eq!(key.key_type, "customer");
    }

    // ---- get_managed_key -------------------------------------------------

    #[tokio::test]
    async fn get_managed_key_rejects_empty_user_id() {
        setup();
        let err = get_managed_key(Request::new(GetManagedKeyRequest {
            user_id: String::new(),
            device_id: "d".to_string(),
            key_type: "system".to_string(),
        }))
        .await
        .expect_err("empty user_id must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_managed_key_rejects_empty_key_type() {
        setup();
        let err = get_managed_key(Request::new(GetManagedKeyRequest {
            user_id: "u".to_string(),
            device_id: "d".to_string(),
            key_type: String::new(),
        }))
        .await
        .expect_err("empty key_type must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_managed_key_returns_found_false_for_unknown_device() {
        setup();
        let resp = get_managed_key(Request::new(GetManagedKeyRequest {
            user_id: unique_id("user"),
            device_id: unique_id("nonexistent"),
            key_type: "system".to_string(),
        }))
        .await
        .expect("missing device returns Ok(not-found) not an error")
        .into_inner();
        assert!(!resp.found, "missing device must surface as found=false");
        assert!(resp.key.is_none());
    }

    // ---- list_managed_keys -----------------------------------------------

    #[tokio::test]
    async fn list_managed_keys_filters_by_user_and_key_type() {
        let user = unique_id("user");
        let other_user = unique_id("other-user");

        let device_sys = unique_id("dev-sys");
        let device_cust = unique_id("dev-cust");
        let _ = make_system_key(&user, &device_sys).await;
        make_customer_key(&user, &device_cust, 7200).await;
        // Pollute with a key for a different user to ensure filtering works.
        let _ = make_system_key(&other_user, &unique_id("dev-other")).await;

        // user-scoped list returns both of this user's keys.
        let all_for_user = list_managed_keys(Request::new(ListManagedKeysRequest {
            user_id: user.clone(),
            key_type: String::new(),
        }))
        .await
        .expect("list by user")
        .into_inner();
        let our_devices: Vec<_> = all_for_user
            .keys
            .iter()
            .map(|k| k.device_id.as_str())
            .collect();
        assert!(
            our_devices.contains(&device_sys.as_str()),
            "user list should include system key, got: {:?}",
            our_devices
        );
        assert!(
            our_devices.contains(&device_cust.as_str()),
            "user list should include customer key, got: {:?}",
            our_devices
        );
        // Filtered: must NOT include the other user's device.
        for k in &all_for_user.keys {
            assert_eq!(k.user_id, user, "user filter must be respected");
        }

        // user + key_type=system returns only the system key.
        let only_sys = list_managed_keys(Request::new(ListManagedKeysRequest {
            user_id: user.clone(),
            key_type: "system".to_string(),
        }))
        .await
        .expect("list by user+type")
        .into_inner();
        assert!(only_sys.keys.iter().all(|k| k.key_type == "system"));
        assert!(only_sys.keys.iter().any(|k| k.device_id == device_sys));
        assert!(only_sys.keys.iter().all(|k| k.device_id != device_cust));
    }

    #[tokio::test]
    async fn list_managed_keys_rejects_empty_user_id() {
        setup();
        let err = list_managed_keys(Request::new(ListManagedKeysRequest {
            user_id: String::new(),
            key_type: String::new(),
        }))
        .await
        .expect_err("empty user_id must be rejected with InvalidArgument");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("user_id"),
            "error must explain that user_id is required, got: {}",
            err.message()
        );
    }
}

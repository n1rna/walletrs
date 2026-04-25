use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use bdk_wallet::bitcoin::bip32;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::secp256k1;
use bdk_wallet::keys::bip39;
use bdk_wallet::SignOptions;
use clap::{Parser, Subcommand};
use prettytable::{format, row, Table};
use uuid::Uuid;

use walletrs_lib::db;
use walletrs_lib::storage::StorageBackend;
use walletrs_lib::KeyUtils;

#[derive(Parser)]
#[command(name = "walletrs-cli")]
#[command(about = "CLI utility for wallet operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a device key file for multi-sig wallet testing
    GenerateDevice {
        /// Name of the wallet this device belongs to
        #[arg(short, long, required = true)]
        wallet: String,

        /// Name of the device (e.g. device1, device2)
        #[arg(short, long)]
        name: Option<String>,

        /// Print the private key (use with caution!)
        #[arg(short, long)]
        show_private: bool,
    },

    /// List devices for a specific wallet
    ListDevices {
        /// Name of the wallet
        #[arg(short, long, required = true)]
        wallet: String,
    },

    /// Sign a PSBT with a specified key
    Sign {
        /// Key name or ID to use for signing
        // #[arg(short, long)]
        // key_id: String,

        /// Path to PSBT file
        #[arg(short, long)]
        psbt_path: PathBuf,
    },

    /// Test unified naming conventions for managed keys
    TestUnifiedKeys,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct KeyInfo {
    name: String,
    xpub: String,
    xprv: Option<String>,
    fingerprint: String,
    path: String,
    mnemonic: Option<Vec<String>>,
    tpriv: Option<String>,
    tpub: String,
    network: String,
}

fn device_key_path(wallet_name: &str, device_name: &str) -> String {
    format!("wallets/{}/devices/{}.json", wallet_name, device_name)
}

fn devices_prefix(wallet_name: &str) -> String {
    format!("wallets/{}/devices/", wallet_name)
}

fn save_device_key(wallet_name: &str, device_name: &str, info: KeyInfo) -> Result<()> {
    let path = device_key_path(wallet_name, device_name);
    let json = serde_json::to_string_pretty(&info)?;
    db::get_storage_manager()
        .backend()
        .write_bytes(&path, json.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to write device key: {}", e))?;
    println!("📝 Device key saved to {}", path);
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateDevice {
            wallet,
            name,
            show_private,
        } => {
            let key_info = generate_device_key(wallet, name.clone())?;
            print_key_info(&key_info, *show_private);
            Ok(())
        }
        Commands::ListDevices { wallet } => {
            list_devices(wallet)?;
            Ok(())
        }
        Commands::Sign { psbt_path } => sign_psbt(psbt_path),
        Commands::TestUnifiedKeys => test_unified_keys(),
        // Commands::TestWalletStorage => test_wallet_storage(),
    }
}

fn generate_device_key(wallet_name: &str, name_opt: Option<String>) -> Result<KeyInfo> {
    db::init_all_storage()?;

    // Generate a name for the device if not provided
    let name = name_opt.unwrap_or_else(|| {
        format!(
            "device{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        )
    });
    log::info!(
        "Generating device key with name: {} for wallet: {}",
        name,
        wallet_name
    );

    // Get the current network
    let network = walletrs_lib::config::CONFIG.network();

    // Initialize crypto context
    let secp: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();

    // Generate complete key set using new utilities
    let key_result = KeyUtils::generate_complete_key_set(network);

    // Get the derivation path for this network
    let primary_path = KeyUtils::get_primary_derivation_path(network);

    // Derive account keys
    let _account_xprv = KeyUtils::generate_account_extended_key(key_result.xprv, network);
    let tpriv = key_result.xprv.derive_priv(&secp, &primary_path).unwrap();
    let tpub = bip32::Xpub::from_priv(&secp, &tpriv);

    // Get the fingerprint for this key
    let fingerprint = tpriv.fingerprint(&secp).to_string();

    // Format the keys with the derivation paths
    let tpriv_formatted = KeyUtils::format_key_with_fingerprint(&fingerprint, &tpriv.to_string());
    let tpub_formatted = KeyUtils::format_key_with_fingerprint(&fingerprint, &tpub.to_string());

    // Convert network to string for storage
    let network_str = network.to_string();

    // Create the key info structure
    let key_info = KeyInfo {
        name: name.clone(),
        xpub: tpub.to_string(),
        xprv: Some(key_result.xprv.to_string()),
        fingerprint: fingerprint.clone(),
        path: primary_path.to_string(),
        mnemonic: Some(key_result.words.clone()),
        tpriv: Some(tpriv_formatted),
        tpub: tpub_formatted,
        network: network_str,
    };

    // Save the device key info to a JSON file
    save_device_key(wallet_name, &name, key_info.clone())?;

    // Return the key info for display
    Ok(key_info)
}

fn print_key_info(key_info: &KeyInfo, show_private: bool) {
    println!("🔑 Key Generated Successfully 🔑");
    println!("==============================");
    println!("Name/ID: {}", key_info.name);
    println!("Fingerprint: {}", key_info.fingerprint);
    println!("Path: {}", key_info.path);

    if let Some(mnemonic) = &key_info.mnemonic {
        println!("\n🔐 Mnemonic 🔐");
        println!("{}", mnemonic.join(" "));
    }

    println!("\n🔑 Master Keys 🔑");
    println!("Master xpub: {}", key_info.xpub);
    println!("Master tpub: {}", key_info.tpub);

    if show_private {
        println!("\n⚠️ PRIVATE KEY INFORMATION ⚠️");
        if let Some(xprv) = &key_info.xprv {
            println!("Master xprv: {}", xprv);
        }
        if let Some(tpriv) = &key_info.tpriv {
            println!("Master tprv: {}", tpriv);
        }
        println!("DO NOT SHARE THIS WITH ANYONE!");
    }
}

fn list_devices(wallet_name: &str) -> Result<()> {
    let backend = db::get_storage_manager().backend();
    let prefix = devices_prefix(wallet_name);

    let keys = backend
        .list_files(&prefix)
        .map_err(|e| anyhow::anyhow!("Failed to list device keys: {}", e))?;

    let mut device_infos = Vec::new();
    for key in keys {
        if !key.ends_with(".json") {
            continue;
        }
        let bytes = backend
            .read_bytes(&key)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", key, e))?;
        let device_info: KeyInfo = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to parse device key JSON from {}", key))?;
        device_infos.push(device_info);
    }

    if device_infos.is_empty() {
        println!("No devices found for wallet: {}", wallet_name);
        return Ok(());
    }

    // Create a nice table output
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);
    table.set_titles(row![
        "Device Name",
        "Fingerprint",
        "Path",
        "Private Key",
        "Network"
    ]);

    for device_info in device_infos {
        table.add_row(row![
            device_info.name,
            device_info.fingerprint,
            device_info.path,
            if device_info.xprv.is_some() {
                "✅"
            } else {
                "❌"
            },
            device_info.network
        ]);
    }

    table.printstd();
    Ok(())
}

fn sign_psbt(psbt_path: &PathBuf) -> Result<()> {
    let network = walletrs_lib::config::CONFIG.network();

    let secp = secp256k1::Secp256k1::new();
    let primary_path = bip32::DerivationPath::from_str("m/84'/1'/0'").unwrap();

    let dev1_mnemonic = "rebuild stone rule infant zero degree suggest blade young ocean hood write worry firm access february world under bacon obey another link vendor noodle";
    let dev2_mnemonic = "empty jar kid acquire outer original human giggle friend wish cinnamon calm tuna imitate hamster mercy wink tube motion rubber attack once enjoy limit";

    let dev1_mnemonic = bip39::Mnemonic::from_str(dev1_mnemonic).unwrap();
    let dev2_mnemonic = bip39::Mnemonic::from_str(dev2_mnemonic).unwrap();

    let dev1_seed = dev1_mnemonic.to_seed("");
    let dev2_seed = dev2_mnemonic.to_seed("");

    let dev1_xprv =
        bip32::Xpriv::new_master(network, &dev1_seed).expect("Failed to create master key");
    let dev2_xprv =
        bip32::Xpriv::new_master(network, &dev2_seed).expect("Failed to create master key");

    let dev1_tprv = dev1_xprv.derive_priv(&secp, &primary_path).unwrap();
    let dev2_tprv = dev2_xprv.derive_priv(&secp, &primary_path).unwrap();

    let dev1_external_descriptor = format!("wsh(thresh(2,pk([9adc0404/84'/1'/0']tpubDCDi6eQ3SYBXp1YSvxzPUXtn4WcUV4tYsgwqeTqwQcaxv6ACqK35QK4kQpU9HJbtbYtbP5SGVtfxMm1xA3vwvHpkvmYbqYWrYkjpiBf8L88/0/*),s:pk([da5cc276/84'/1'/0']{}/0/*),s:pk([cd03aa2f/84'/1'/0']tpubDDUwNN3dNB2UyaXrDAYd51iXnRRKGeozYW8aGRsNwT3Rb1sdFQQ1SWB4XpqK9hcd99fjyxWzmgGXzzkPoZA47FHHhsNFnVeFRtRqmDDfVQp/0/*)))", dev1_tprv);
    let dev1_internal_descriptor = format!("wsh(thresh(2,pk([9adc0404/84'/1'/0']tpubDCDi6eQ3SYBXp1YSvxzPUXtn4WcUV4tYsgwqeTqwQcaxv6ACqK35QK4kQpU9HJbtbYtbP5SGVtfxMm1xA3vwvHpkvmYbqYWrYkjpiBf8L88/1/*),s:pk([da5cc276/84'/1'/0']{}/1/*),s:pk([cd03aa2f/84'/1'/0']tpubDDUwNN3dNB2UyaXrDAYd51iXnRRKGeozYW8aGRsNwT3Rb1sdFQQ1SWB4XpqK9hcd99fjyxWzmgGXzzkPoZA47FHHhsNFnVeFRtRqmDDfVQp/1/*)))", dev1_tprv);

    let dev2_external_descriptor = format!("wsh(thresh(2,pk([9adc0404/84'/1'/0']tpubDCDi6eQ3SYBXp1YSvxzPUXtn4WcUV4tYsgwqeTqwQcaxv6ACqK35QK4kQpU9HJbtbYtbP5SGVtfxMm1xA3vwvHpkvmYbqYWrYkjpiBf8L88/0/*),s:pk([da5cc276/84'/1'/0']tpubDCVafo6EE7sBXJwUesPDyv3AcX47eddPSXzLTFeKgcd6hJY8mgxLLCdFfH8JcmhUYCaaXvpLWeaGV29h8SNomc7jVt4naxyQXfAjSQaVixq/0/*),s:pk([cd03aa2f/84'/1'/0']{}/0/*)))", dev2_tprv);
    let dev2_internal_descriptor = format!("wsh(thresh(2,pk([9adc0404/84'/1'/0']tpubDCDi6eQ3SYBXp1YSvxzPUXtn4WcUV4tYsgwqeTqwQcaxv6ACqK35QK4kQpU9HJbtbYtbP5SGVtfxMm1xA3vwvHpkvmYbqYWrYkjpiBf8L88/1/*),s:pk([da5cc276/84'/1'/0']tpubDCVafo6EE7sBXJwUesPDyv3AcX47eddPSXzLTFeKgcd6hJY8mgxLLCdFfH8JcmhUYCaaXvpLWeaGV29h8SNomc7jVt4naxyQXfAjSQaVixq/1/*),s:pk([cd03aa2f/84'/1'/0']{}/1/*)))", dev2_tprv);

    // Create a temporary wallet with the key
    let dev1_wallet =
        bdk_wallet::Wallet::create(dev1_external_descriptor, dev1_internal_descriptor)
            .network(walletrs_lib::config::CONFIG.network())
            .create_wallet_no_persist()
            .unwrap();

    let dev2_wallet =
        bdk_wallet::Wallet::create(dev2_external_descriptor, dev2_internal_descriptor)
            .network(walletrs_lib::config::CONFIG.network())
            .create_wallet_no_persist()
            .unwrap();

    // Read and parse PSBT
    let psbt_data = std::fs::read_to_string(psbt_path)
        .context(format!("Failed to read PSBT file: {:?}", psbt_path))?;

    let mut psbt = if psbt_data.starts_with("cHNi") {
        // Base64 encoded PSBT
        Psbt::from_str(&psbt_data).context("Failed to parse base64 PSBT")?
    } else {
        // Hex encoded PSBT
        let psbt_bytes = hex::decode(&psbt_data).context("Failed to decode hex PSBT")?;
        Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?
    };

    let mut original_psbt = psbt.clone();

    println!("PSBT Before: {:?}", psbt.to_string());

    let signed = dev1_wallet.sign(&mut psbt, SignOptions::default()).unwrap();

    println!("Dev1 PSBT signing result: {}", signed);
    println!("Dev2 PSBT Signed: {:?}", psbt.to_string());

    let signed = dev2_wallet
        .sign(&mut original_psbt, SignOptions::default())
        .unwrap();

    println!("Dev2 PSBT signing result: {}", signed);
    println!("Dev2 PSBT Signed: {:?}", psbt.to_string());

    // Sign the PSBT
    // let finalized = wallet.sign_psbt(&mut psbt, SignOptions::default())?;

    // println!(
    //     "PSBT signing result: {}",
    //     if finalized {
    //         "Finalized"
    //     } else {
    //         "Partially signed"
    //     }
    // );

    // // Serialize and save the signed PSBT
    // let signed_psbt_hex = hex::encode(psbt.serialize());
    // std::fs::write(output_path, signed_psbt_hex)?;

    // println!("Signed PSBT saved to: {:?}", output_path);

    // // Clean up temporary wallet
    // let _ = std::fs::remove_file(temp_db_path);

    Ok(())
}

fn test_unified_keys() -> Result<()> {
    println!("Testing unified naming conventions for managed keys...");

    db::init_all_storage()?;
    println!("✓ Initialized managed keys storage");

    // Test 1: Store a customer managed key
    println!("\n--- Test 1: Customer Managed Key ---");
    let user_id = "user123";
    let device_id = "device456";
    let key_name = "my_key";
    let xpub = "tpubD6NzVbkrYhZ4XfeFDj8QdPsZEgTDgGkJHrBUJzQdwJ1Bd8GdZhKrYX1FgHyJoQg7MNmKaGJgBK6cRnVzEEQHNzV5zJRoJfvN6qVv";
    let fingerprint = "abcd1234";
    let derivation_path = "m/84'/1'/0'";

    db::store_customer_key(
        user_id,
        device_id,
        key_name,
        xpub,
        fingerprint,
        derivation_path,
    )?;
    println!("✓ Stored customer managed key");

    // Test 2: Retrieve the customer managed key
    let retrieved_key = db::get_managed_key(user_id, device_id, "customer")?;
    match retrieved_key {
        Some(key) => {
            println!(
                "✓ Retrieved customer key: identifier = {}",
                key.get_key_identifier()
            );
            assert_eq!(key.user_id, user_id);
            assert_eq!(key.device_id, device_id);
            assert_eq!(key.key_type, "customer");
            assert_eq!(key.xpub, xpub);
            assert_eq!(key.fingerprint, fingerprint);
        }
        None => {
            anyhow::bail!("Failed to retrieve customer managed key");
        }
    }

    // Test 3: Store a system managed key
    println!("\n--- Test 2: System Managed Key ---");
    let system_user_id = "user789";
    let system_device_id = "device101";
    let system_key_name = "system_key";
    let xpriv =
        "tprv8ZgxMEccqh5fKjJT7B8BnzfQHkJQoHrzrXDpF8BZF4K1xJ8MRhvYqE3YvF2Z4H2gZnbGhDWE9S7GJ9a9K";
    let system_xpub = "tpubD6NzVbkrYhZ4XfeFDj8QdPsZEgTDgGkJHrBUJzQdwJ1Bd8GdZhKrYX1FgHyJoQg7MNmKaGJgBK6cRnVzEEQHNzV5zJRoJfvN6qVv";
    let system_fingerprint = "efgh5678";
    let system_derivation_path = "m/84'/1'/0'";
    let mnemonic = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";
    let tpriv = "[efgh5678/84'/1'/0']tprv8ZgxMEccqh5fKjJT7B8BnzfQHkJQoHrzrXDpF8BZF4K1xJ8MRhvYqE3YvF2Z4H2gZnbGhDWE9S7GJ9a9K";
    let tpub = "[efgh5678/84'/1'/0']tpubD6NzVbkrYhZ4XfeFDj8QdPsZEgTDgGkJHrBUJzQdwJ1Bd8GdZhKrYX1FgHyJoQg7MNmKaGJgBK6cRnVzEEQHNzV5zJRoJfvN6qVv";

    db::store_system_key(
        system_user_id,
        system_device_id,
        system_key_name,
        xpriv,
        system_xpub,
        system_fingerprint,
        system_derivation_path,
        mnemonic,
        tpriv,
        tpub,
    )?;
    println!("✓ Stored system managed key");

    // Test 4: Retrieve the system managed key
    let retrieved_system_key = db::get_managed_key(system_user_id, system_device_id, "system")?;
    match retrieved_system_key {
        Some(key) => {
            println!(
                "✓ Retrieved system key: identifier = {}",
                key.get_key_identifier()
            );
            assert_eq!(key.user_id, system_user_id);
            assert_eq!(key.device_id, system_device_id);
            assert_eq!(key.key_type, "system");
            assert_eq!(key.xpub, system_xpub);
            assert_eq!(key.fingerprint, system_fingerprint);
            // System keys should have private key fields populated
            assert!(key.xpriv.is_some());
            assert!(key.mnemonic.is_some());
            assert!(key.tpriv.is_some());
            assert!(key.tpub.is_some());
        }
        None => {
            anyhow::bail!("Failed to retrieve system managed key");
        }
    }

    // Test 5: List keys for first user
    println!("\n--- Test 3: List Keys for User1 ---");
    let user1_keys = db::list_managed_keys(Some(user_id), None)?;
    assert_eq!(user1_keys.len(), 1);
    assert_eq!(user1_keys[0].user_id, user_id);
    println!("✓ Found {} keys for user {}", user1_keys.len(), user_id);

    for key in &user1_keys {
        println!(
            "  - Key: {} (type: {})",
            key.get_key_identifier(),
            key.key_type
        );
    }

    // Test 6: List keys for second user
    println!("\n--- Test 4: List Keys for User2 ---");
    let user2_keys = db::list_managed_keys(Some(system_user_id), None)?;
    assert_eq!(user2_keys.len(), 1);
    assert_eq!(user2_keys[0].user_id, system_user_id);
    println!(
        "✓ Found {} keys for user {}",
        user2_keys.len(),
        system_user_id
    );

    // Test 7: List keys filtered by key_type for user1
    let customer_keys = db::list_managed_keys(Some(user_id), Some("customer"))?;
    assert_eq!(customer_keys.len(), 1);
    assert_eq!(customer_keys[0].key_type, "customer");
    println!(
        "✓ Found {} customer keys for user {}",
        customer_keys.len(),
        user_id
    );

    let system_keys = db::list_managed_keys(Some(system_user_id), Some("system"))?;
    assert_eq!(system_keys.len(), 1);
    assert_eq!(system_keys[0].key_type, "system");
    println!("✓ Found {} system keys", system_keys.len());

    println!("\n🎉 All tests passed! Unified naming conventions are working correctly.");

    Ok(())
}

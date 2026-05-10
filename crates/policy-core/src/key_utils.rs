use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{ChainCode, DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::{self, Secp256k1};
use bdk_wallet::bitcoin::Network;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::GeneratableKey;
use bdk_wallet::miniscript;

/// BIP-341 NUMS point. Provably nobody knows the discrete log.
/// Same constant `descriptor.rs::NUMS_KEY` uses for taproot internal-key
/// suppression in `tr(NUMS, multi_a(...))`. Exposed here too because
/// `unspendable_primary_xpub` builds an Xpub on top of it.
pub const BIP341_NUMS_HEX: &str =
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Build the deterministic NUMS-derived Xpub Liana uses for a wallet's
/// "unspendable primary" path (QBL-235). Construction mirrors
/// `liana::descriptors::analysis::unspendable_internal_xpub` so the
/// resulting wallet is recognised as unspendable-primary by Liana's
/// own policy parser too.
///
/// The chain code is `sha256(concat(serialize(pubkey) for each
/// recovery xpub))` — this is what makes it deterministic from the
/// recovery key set, so the same wallet config always reproduces the
/// same primary key. Depth, parent fingerprint, and child number are
/// all zeroed; the public key is the BIP-341 NUMS point.
///
/// Caller passes the recovery xpubs in the order they'll appear in
/// the descriptor (typically: ascending timelock, multi-key paths
/// flattened in their declared order). Mismatching the order produces
/// a different chain code — different but still unspendable, just not
/// the canonical one.
pub fn unspendable_primary_xpub(recovery_xpubs: &[Xpub], network: Network) -> Xpub {
    let mut concat = Vec::with_capacity(recovery_xpubs.len() * 33);
    for xpub in recovery_xpubs {
        concat.extend_from_slice(&xpub.public_key.serialize());
    }
    let chain_code = ChainCode::from(sha256::Hash::hash(&concat).as_byte_array());
    let public_key = secp256k1::PublicKey::from_str(BIP341_NUMS_HEX)
        .expect("BIP341_NUMS_HEX is a valid compressed pubkey");
    Xpub {
        public_key,
        chain_code,
        depth: 0,
        parent_fingerprint: [0u8; 4].into(),
        child_number: 0u32.into(),
        network: network.into(),
    }
}

#[derive(Debug, Clone)]
pub struct KeyGenerationResult {
    pub xprv: Xpriv,
    pub words: Vec<String>,
    pub xpub: Xpub,
    pub fingerprint: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
}

pub struct KeyUtils;

impl KeyUtils {
    pub fn generate_private_key(network: Network) -> (Xpriv, Vec<String>) {
        let mnemonic: bdk_wallet::keys::GeneratedKey<Mnemonic, miniscript::Segwitv0> =
            Mnemonic::generate((WordCount::Words24, Language::English)).unwrap();
        let seed = mnemonic.to_seed("");
        let xprv: Xpriv = Xpriv::new_master(network, &seed).expect("Failed to create master key");

        let words = mnemonic.words().map(|w| w.to_string()).collect();
        (xprv, words)
    }

    pub fn generate_account_extended_key(xprv: Xpriv, network: Network) -> Xpriv {
        let secp = Secp256k1::new();
        let derivation_path = Self::get_primary_derivation_path(network);

        xprv.derive_priv(&secp, &derivation_path)
            .expect("Failed to derive account extended key")
    }

    pub fn get_account_extended_descriptor(xprv: Xpriv) -> (String, String, Xpub, String) {
        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xprv);
        let fingerprint = xprv.fingerprint(&secp).to_string();

        let external_descriptor = format!("wpkh({}/0/*)", xpub);
        let internal_descriptor = format!("wpkh({}/1/*)", xpub);

        (external_descriptor, internal_descriptor, xpub, fingerprint)
    }

    pub fn get_primary_derivation_path(network: Network) -> DerivationPath {
        match network {
            Network::Bitcoin => DerivationPath::from_str("m/84'/0'/0'").unwrap(),
            Network::Testnet => DerivationPath::from_str("m/84'/1'/0'").unwrap(),
            Network::Regtest => DerivationPath::from_str("m/84'/1'/0'").unwrap(),
            Network::Signet => DerivationPath::from_str("m/84'/1'/0'").unwrap(),
            _ => DerivationPath::from_str("m/84'/1'/0'").unwrap(), // Default to testnet for unknown networks
        }
    }

    pub fn format_key_with_fingerprint(fingerprint: &str, key: &str) -> String {
        format!("[{}]{}", fingerprint, key)
    }

    pub fn format_key_for_liana(fingerprint: &str, derivation_path: &str, key: &str) -> String {
        let path = derivation_path
            .strip_prefix("m/")
            .or_else(|| derivation_path.strip_prefix("m"))
            .unwrap_or(derivation_path);
        if path.is_empty() {
            format!("[{}]{}/<0;1>/*", fingerprint, key)
        } else {
            format!("[{}/{}]{}/<0;1>/*", fingerprint, path, key)
        }
    }

    pub fn generate_complete_key_set(network: Network) -> KeyGenerationResult {
        let (xprv, words) = Self::generate_private_key(network);
        let account_xprv = Self::generate_account_extended_key(xprv, network);
        let (external_descriptor, internal_descriptor, xpub, fingerprint) =
            Self::get_account_extended_descriptor(account_xprv);

        KeyGenerationResult {
            xprv,
            words,
            xpub,
            fingerprint,
            external_descriptor,
            internal_descriptor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let result = KeyUtils::generate_complete_key_set(Network::Testnet);

        assert_eq!(result.words.len(), 24);
        assert!(!result.xprv.to_string().is_empty());
        assert!(result.external_descriptor.contains("wpkh"));
        assert!(result.internal_descriptor.contains("wpkh"));
        assert!(!result.xpub.to_string().is_empty());
        assert!(!result.fingerprint.is_empty());
    }

    #[test]
    fn test_derivation_paths() {
        let bitcoin_path = KeyUtils::get_primary_derivation_path(Network::Bitcoin);
        let testnet_path = KeyUtils::get_primary_derivation_path(Network::Testnet);

        assert_eq!(bitcoin_path.to_string(), "84'/0'/0'");
        assert_eq!(testnet_path.to_string(), "84'/1'/0'");
    }

    #[test]
    fn test_format_key_with_fingerprint() {
        let formatted = KeyUtils::format_key_with_fingerprint("12345678", "xpub123...");
        assert_eq!(formatted, "[12345678]xpub123...");
    }

    #[test]
    fn test_unspendable_primary_xpub_is_deterministic() {
        // Two synthetic recovery xpubs, same set both times → same
        // chain code → same xpub. This is the property Liana's
        // policy parser relies on to detect unspendable-primary.
        let xpub_a = KeyUtils::generate_complete_key_set(Network::Regtest).xpub;
        let xpub_b = KeyUtils::generate_complete_key_set(Network::Regtest).xpub;
        let recoveries = vec![xpub_a, xpub_b];
        let first = unspendable_primary_xpub(&recoveries, Network::Regtest);
        let second = unspendable_primary_xpub(&recoveries, Network::Regtest);
        assert_eq!(first, second);
    }

    #[test]
    fn test_unspendable_primary_xpub_uses_nums_pubkey() {
        let recoveries = vec![KeyUtils::generate_complete_key_set(Network::Regtest).xpub];
        let xpub = unspendable_primary_xpub(&recoveries, Network::Regtest);
        let nums_pk =
            secp256k1::PublicKey::from_str(BIP341_NUMS_HEX).expect("valid NUMS hex");
        assert_eq!(xpub.public_key, nums_pk);
        assert_eq!(xpub.depth, 0);
        assert_eq!(u32::from(xpub.child_number), 0);
    }

    #[test]
    fn test_unspendable_primary_xpub_changes_with_recoveries() {
        let xpub_a = KeyUtils::generate_complete_key_set(Network::Regtest).xpub;
        let xpub_b = KeyUtils::generate_complete_key_set(Network::Regtest).xpub;
        let one = unspendable_primary_xpub(&[xpub_a], Network::Regtest);
        let two = unspendable_primary_xpub(&[xpub_a, xpub_b], Network::Regtest);
        assert_ne!(one.chain_code, two.chain_code);
    }
}

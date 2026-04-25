use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::GeneratableKey;
use bdk_wallet::miniscript;

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
}

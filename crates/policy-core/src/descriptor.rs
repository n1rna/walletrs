use std::collections::BTreeMap;

use liana::descriptors::{LianaDescriptor, LianaPolicy, PathInfo};
use miniscript::descriptor::DescriptorPublicKey;

use crate::error::PolicyError;
use crate::shape::{PolicyPath, RecoveryPath, ScriptKind, WalletShape};

/// Output of descriptor construction. `external` is the receive descriptor,
/// `internal` is the change descriptor. `liana` is populated only for the
/// `TimelockedPolicy` shape so callers can persist the canonical Liana
/// descriptor for later PSBT pruning and leaf-hash resolution.
#[derive(Debug, Clone)]
pub struct DescriptorPair {
    pub external: String,
    pub internal: String,
    pub liana: Option<LianaDescriptor>,
}

/// NUMS point (BIP-341): provably-unspendable internal key used as the
/// taproot internal key in pure-multisig taproot wallets, so spending must
/// take the script path.
const NUMS_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub fn build(shape: &WalletShape) -> Result<DescriptorPair, PolicyError> {
    match shape {
        WalletShape::SingleSig {
            kind: ScriptKind::SegwitV0,
            key,
        } => single_sig_segwit(key),
        WalletShape::SingleSig {
            kind: ScriptKind::Taproot,
            key,
        } => single_sig_taproot(key),
        WalletShape::Multisig {
            kind: ScriptKind::SegwitV0,
            threshold,
            keys,
        } => multisig_segwit(*threshold, keys),
        WalletShape::Multisig {
            kind: ScriptKind::Taproot,
            threshold,
            keys,
        } => multisig_taproot(*threshold, keys),
        WalletShape::TimelockedPolicy {
            primary,
            recoveries,
            ..
        } => timelocked_policy(primary, recoveries),
    }
}

fn single_sig_segwit(key: &DescriptorPublicKey) -> Result<DescriptorPair, PolicyError> {
    Ok(pair_from_keys(&[key], |k| format!("wpkh({})", k)))
}

fn single_sig_taproot(key: &DescriptorPublicKey) -> Result<DescriptorPair, PolicyError> {
    Ok(pair_from_keys(&[key], |k| format!("tr({})", k)))
}

fn multisig_segwit(
    threshold: usize,
    keys: &[DescriptorPublicKey],
) -> Result<DescriptorPair, PolicyError> {
    validate_multisig(threshold, keys.len())?;
    let refs: Vec<&DescriptorPublicKey> = keys.iter().collect();
    Ok(pair_from_keys(&refs, |joined| {
        format!("wsh(sortedmulti({},{}))", threshold, joined)
    }))
}

fn multisig_taproot(
    threshold: usize,
    keys: &[DescriptorPublicKey],
) -> Result<DescriptorPair, PolicyError> {
    validate_multisig(threshold, keys.len())?;
    let refs: Vec<&DescriptorPublicKey> = keys.iter().collect();
    Ok(pair_from_keys(&refs, |joined| {
        format!("tr({},multi_a({},{}))", NUMS_KEY, threshold, joined)
    }))
}

fn timelocked_policy(
    primary: &PolicyPath,
    recoveries: &[RecoveryPath],
) -> Result<DescriptorPair, PolicyError> {
    let primary_path = path_info(primary);
    let recovery_paths: BTreeMap<u16, PathInfo> = recoveries
        .iter()
        .map(|r| (r.timelock, path_info(&r.path)))
        .collect();

    let policy = LianaPolicy::new(primary_path, recovery_paths)
        .map_err(|e| PolicyError::LianaIntegration(e.to_string()))?;
    let descriptor = LianaDescriptor::new(policy);

    Ok(DescriptorPair {
        external: descriptor.receive_descriptor().to_string(),
        internal: descriptor.change_descriptor().to_string(),
        liana: Some(descriptor),
    })
}

fn path_info(path: &PolicyPath) -> PathInfo {
    match path {
        PolicyPath::Single(k) => PathInfo::Single(k.clone()),
        PolicyPath::Multi { threshold, keys } => PathInfo::Multi(*threshold, keys.clone()),
    }
}

fn validate_multisig(threshold: usize, key_count: usize) -> Result<(), PolicyError> {
    if threshold == 0 || threshold > key_count {
        return Err(PolicyError::DescriptorGeneration(format!(
            "Invalid threshold {} for {} keys",
            threshold, key_count
        )));
    }
    Ok(())
}

/// Build a `(receive, change)` pair by deriving each key down `/0/*` and
/// `/1/*` respectively, then handing the comma-joined key list to a wrapper
/// function that supplies the descriptor type (e.g. `wpkh`, `wsh(sortedmulti)`).
fn pair_from_keys<F>(keys: &[&DescriptorPublicKey], wrap: F) -> DescriptorPair
where
    F: Fn(&str) -> String,
{
    let receive_keys: Vec<String> = keys.iter().map(|k| key_at_child(k, 0)).collect();
    let change_keys: Vec<String> = keys.iter().map(|k| key_at_child(k, 1)).collect();
    DescriptorPair {
        external: wrap(&receive_keys.join(",")),
        internal: wrap(&change_keys.join(",")),
        liana: None,
    }
}

/// Convert a multipath descriptor public key into its single-path form for the
/// given child index. Stripping `/<0;1>/*` and re-appending `/N/*` matches
/// what BDK 1.x consumes when parsing `wpkh`/`wsh`/`tr` descriptors. Keys that
/// are already single-path (no multipath suffix) are passed through with the
/// child suffix appended.
fn key_at_child(key: &DescriptorPublicKey, child: u32) -> String {
    let s = key.to_string();
    let base = s.strip_suffix("/<0;1>/*").unwrap_or(&s);
    format!("{}/{}/*", base, child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn key_at_child_appends_path_when_multipath() {
        let key = DescriptorPublicKey::from_str(
            "[eb880a46/84'/1'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*",
        )
        .expect("valid multipath key");
        let external = key_at_child(&key, 0);
        let internal = key_at_child(&key, 1);
        assert!(external.ends_with("/0/*"));
        assert!(internal.ends_with("/1/*"));
        assert!(!external.contains("<0;1>"));
        assert!(!internal.contains("<0;1>"));
    }

    #[test]
    fn key_at_child_appends_path_when_not_multipath() {
        let key = DescriptorPublicKey::from_str(
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        )
        .expect("valid xpub");
        let external = key_at_child(&key, 0);
        let internal = key_at_child(&key, 1);
        assert!(external.ends_with("/0/*"));
        assert!(internal.ends_with("/1/*"));
    }

    #[test]
    fn rejects_invalid_threshold() {
        let key = DescriptorPublicKey::from_str(
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        )
        .expect("valid xpub");
        let keys = vec![key];
        assert!(multisig_segwit(0, &keys).is_err());
        assert!(multisig_segwit(2, &keys).is_err());
    }
}

use std::collections::BTreeMap;
use std::str::FromStr;

use miniscript::descriptor::DescriptorPublicKey;

use crate::db::StoredManagedKey;
use crate::wallet::advanced::error::WalletCreationError;
use crate::wallet::advanced::spec::{
    PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    SegwitV0,
    Taproot,
}

#[derive(Debug, Clone)]
pub enum PolicyPath {
    Single(DescriptorPublicKey),
    Multi {
        threshold: usize,
        keys: Vec<DescriptorPublicKey>,
    },
}

impl PolicyPath {
    pub fn keys(&self) -> Vec<&DescriptorPublicKey> {
        match self {
            PolicyPath::Single(k) => vec![k],
            PolicyPath::Multi { keys, .. } => keys.iter().collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryPath {
    pub id: String,
    pub timelock: u16,
    pub path: PolicyPath,
}

#[derive(Debug, Clone)]
pub enum WalletShape {
    SingleSig {
        kind: ScriptKind,
        key: DescriptorPublicKey,
    },
    Multisig {
        kind: ScriptKind,
        threshold: usize,
        keys: Vec<DescriptorPublicKey>,
    },
    /// Liana-style policy with a primary spending path and zero-or-more
    /// time-locked recovery paths. Always taproot (P2WSH variant unsupported
    /// here; SegwitV0 callers are rejected at classify time).
    TimelockedPolicy {
        primary_id: String,
        primary: PolicyPath,
        recoveries: Vec<RecoveryPath>,
    },
}

/// Pick the wallet shape that best fits the user's spec.
///
/// Order of detection:
/// 1. Smart-combine: when `Auto` is requested and every condition has
///    `timelock == 0`, fold all keys (primary + recoveries) into one taproot
///    multisig using the primary's threshold. This matches clients that model
///    multisigs as multiple zero-timelock conditions; Liana would reject the
///    raw shape anyway because recovery paths need a non-zero timelock.
/// 2. Single-condition fast path: one primary, zero timelock → either a single
///    sig wallet or a flat multisig in the requested script kind.
/// 3. Otherwise: a Liana taproot policy. P2WSH (SegwitV0) is not supported for
///    timelocked policies in this build.
pub fn classify(spec: &WalletSpec) -> Result<WalletShape, WalletCreationError> {
    let resolved = resolve_conditions(spec)?;

    if can_combine_taproot_multisig(spec, &resolved) {
        return Ok(combine_taproot_multisig(&resolved));
    }

    if let Some(shape) = try_single_condition_shape(spec, &resolved) {
        return Ok(shape);
    }

    if spec.preferred_script_type == PreferredScriptType::SegwitV0 {
        return Err(WalletCreationError::InvalidPolicy(
            "SegWit v0 is not supported for policy-based wallets with timelocks".to_string(),
        ));
    }

    build_timelocked_policy(resolved)
}

struct ResolvedCondition {
    id: String,
    is_primary: bool,
    timelock: u16,
    path: PolicyPath,
}

fn resolve_conditions(
    spec: &WalletSpec,
) -> Result<Vec<ResolvedCondition>, WalletCreationError> {
    spec.conditions
        .iter()
        .map(|cond| resolve_condition(cond, &spec.managed_keys))
        .collect()
}

fn resolve_condition(
    cond: &SpendingCondition,
    managed_keys: &BTreeMap<String, StoredManagedKey>,
) -> Result<ResolvedCondition, WalletCreationError> {
    let path = match cond.policy {
        PolicyType::Single => {
            let key = resolve_key(managed_keys, &cond.managed_key_ids[0])?;
            PolicyPath::Single(key)
        }
        PolicyType::Multi => {
            let keys = cond
                .managed_key_ids
                .iter()
                .map(|id| resolve_key(managed_keys, id))
                .collect::<Result<Vec<_>, _>>()?;
            PolicyPath::Multi {
                threshold: cond.threshold,
                keys,
            }
        }
    };
    Ok(ResolvedCondition {
        id: cond.id.clone(),
        is_primary: cond.is_primary,
        timelock: cond.timelock,
        path,
    })
}

fn resolve_key(
    managed_keys: &BTreeMap<String, StoredManagedKey>,
    device_id: &str,
) -> Result<DescriptorPublicKey, WalletCreationError> {
    let key = managed_keys.get(device_id).ok_or_else(|| {
        WalletCreationError::KeyManagement(format!("Key not found for device {}", device_id))
    })?;

    let xpub_str = key.tpub.as_deref().unwrap_or(&key.xpub);
    let xpub_str = ensure_key_origin_has_path(xpub_str, &key.fingerprint, &key.derivation_path);

    DescriptorPublicKey::from_str(&xpub_str)
        .map_err(|e| WalletCreationError::KeyManagement(format!("Invalid xpub: {}", e)))
}

/// Inject `derivation_path` into the `[fingerprint]` origin block of an xpub
/// when the stored key omits it. Strings already carrying a full origin
/// `[fp/path]xpub` are returned unchanged.
fn ensure_key_origin_has_path(xpub: &str, fingerprint: &str, derivation_path: &str) -> String {
    if fingerprint.is_empty() {
        return xpub.to_string();
    }

    let path = derivation_path
        .trim_start_matches('m')
        .trim_start_matches('/');
    if path.is_empty() {
        return xpub.to_string();
    }

    let fingerprint_only = format!("[{}]", fingerprint);
    if !xpub.starts_with(&fingerprint_only) {
        return xpub.to_string();
    }

    let replacement = format!("[{}/{}]", fingerprint, path);
    format!("{}{}", replacement, &xpub[fingerprint_only.len()..])
}

fn can_combine_taproot_multisig(spec: &WalletSpec, resolved: &[ResolvedCondition]) -> bool {
    if spec.preferred_script_type != PreferredScriptType::Auto {
        return false;
    }
    let has_primary = resolved.iter().any(|c| c.is_primary);
    let has_recovery = resolved.iter().any(|c| !c.is_primary);
    let all_zero_timelock = resolved.iter().all(|c| c.timelock == 0);
    has_primary && has_recovery && all_zero_timelock
}

fn combine_taproot_multisig(resolved: &[ResolvedCondition]) -> WalletShape {
    let mut all_keys: Vec<DescriptorPublicKey> = Vec::new();
    let mut threshold = 1usize;

    for cond in resolved {
        match &cond.path {
            PolicyPath::Single(k) => all_keys.push(k.clone()),
            PolicyPath::Multi { keys, threshold: t } => {
                all_keys.extend(keys.iter().cloned());
                if cond.is_primary {
                    threshold = *t;
                }
            }
        }
    }

    let total = all_keys.len();
    let effective_threshold = std::cmp::min(threshold, total).max(1);

    WalletShape::Multisig {
        kind: ScriptKind::Taproot,
        threshold: effective_threshold,
        keys: all_keys,
    }
}

fn try_single_condition_shape(
    spec: &WalletSpec,
    resolved: &[ResolvedCondition],
) -> Option<WalletShape> {
    if resolved.len() != 1 {
        return None;
    }
    let cond = &resolved[0];
    if !cond.is_primary || cond.timelock != 0 {
        return None;
    }

    let kind = match spec.preferred_script_type {
        PreferredScriptType::Taproot => ScriptKind::Taproot,
        _ => ScriptKind::SegwitV0,
    };

    match &cond.path {
        PolicyPath::Single(key) => Some(WalletShape::SingleSig {
            kind,
            key: key.clone(),
        }),
        PolicyPath::Multi { threshold, keys } if *threshold > 1 => Some(WalletShape::Multisig {
            kind,
            threshold: *threshold,
            keys: keys.clone(),
        }),
        _ => None,
    }
}

/// Build a timelocked policy shape. If no condition is marked primary, the
/// first recovery is promoted to primary (matching original Liana adapter
/// behavior). Recoveries with `timelock == 0` are assigned default timelocks
/// of `144 * (idx + 1)` blocks (~1 day per slot) and the recovery list is
/// sorted by effective timelock so it matches Liana's BTreeMap iteration order.
fn build_timelocked_policy(
    resolved: Vec<ResolvedCondition>,
) -> Result<WalletShape, WalletCreationError> {
    let mut primary: Option<(String, PolicyPath)> = None;
    let mut recoveries: Vec<RecoveryPath> = Vec::new();

    for cond in resolved {
        if cond.is_primary {
            primary = Some((cond.id, cond.path));
        } else {
            recoveries.push(RecoveryPath {
                id: cond.id,
                timelock: cond.timelock,
                path: cond.path,
            });
        }
    }

    let (primary_id, primary_path) = match primary {
        Some(p) => p,
        None => {
            if recoveries.is_empty() {
                return Err(WalletCreationError::InvalidPolicy(
                    "Must have either primary path or recovery conditions".to_string(),
                ));
            }
            let first = recoveries.remove(0);
            (first.id, first.path)
        }
    };

    for (idx, rec) in recoveries.iter_mut().enumerate() {
        if rec.timelock == 0 {
            rec.timelock = 144 + (idx as u16) * 144;
        }
    }
    recoveries.sort_by_key(|r| r.timelock);

    Ok(WalletShape::TimelockedPolicy {
        primary_id,
        primary: primary_path,
        recoveries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_key_origin_injects_path() {
        let xpub = "[eb880a46]tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "eb880a46", "m/84'/1'/0'");
        assert_eq!(result, "[eb880a46/84'/1'/0']tpubDCT3mock/<0;1>/*");
    }

    #[test]
    fn ensure_key_origin_already_has_path() {
        let xpub = "[eb880a46/84'/1'/0']tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "eb880a46", "m/84'/1'/0'");
        assert_eq!(result, xpub);
    }

    #[test]
    fn ensure_key_origin_empty_derivation_path() {
        let xpub = "[eb880a46]tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "eb880a46", "");
        assert_eq!(result, xpub);
    }

    #[test]
    fn ensure_key_origin_m_only_derivation_path() {
        let xpub = "[eb880a46]tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "eb880a46", "m");
        assert_eq!(result, xpub);
    }

    #[test]
    fn ensure_key_origin_no_origin_prefix() {
        let xpub = "tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "eb880a46", "m/84'/1'/0'");
        assert_eq!(result, xpub);
    }

    #[test]
    fn ensure_key_origin_path_without_m_prefix() {
        let xpub = "[eb880a46]tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "eb880a46", "84'/1'/0'");
        assert_eq!(result, "[eb880a46/84'/1'/0']tpubDCT3mock/<0;1>/*");
    }

    #[test]
    fn ensure_key_origin_empty_fingerprint() {
        let xpub = "[eb880a46]tpubDCT3mock/<0;1>/*";
        let result = ensure_key_origin_has_path(xpub, "", "m/84'/1'/0'");
        assert_eq!(result, xpub);
    }
}

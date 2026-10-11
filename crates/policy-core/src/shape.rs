use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::Xpub;
use bdk_wallet::bitcoin::Network;
use miniscript::descriptor::DescriptorPublicKey;

use crate::error::PolicyError;
use crate::key_utils::{unspendable_primary_xpub, KeyUtils};
use crate::managed_key::ManagedKey;
use crate::spec::{PolicyType, PreferredScriptType, SpendingCondition, WalletSpec};

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
    /// Timelocked policy with a primary spending path and one or more
    /// time-locked recovery paths, compiled to taproot.
    TimelockedPolicy {
        primary_id: String,
        primary: PolicyPath,
        recoveries: Vec<RecoveryPath>,
    },
    /// The same policy as `TimelockedPolicy`, compiled to P2WSH for
    /// signers that cannot spend taproot script paths. Has no unspendable
    /// primary: there is no internal key to replace.
    SegwitTimelockedPolicy {
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
///    multisigs as multiple zero-timelock conditions; the timelocked
///    builder would reject the raw shape anyway because recovery paths
///    need a non-zero timelock.
/// 2. Single-condition fast path: one primary, zero timelock → either a single
///    sig wallet or a flat k-of-n multisig (any `1 <= k <= n`, `n >= 2`) in
///    the requested script kind.
/// 3. Otherwise: a timelocked policy, taproot unless SegWit v0 was asked
///    for.
///
/// A device may appear in more than one condition (never twice in the
/// same one). Each further use gets the next multipath step of its xpub,
/// `<2;3>`, `<4;5>`, …, so every condition holds a distinct key, which
/// is how a decaying multisig over one set of signers is expressed.
pub fn classify(spec: &WalletSpec) -> Result<WalletShape, PolicyError> {
    let (resolved, reuses_keys) = resolve_conditions(spec)?;

    if can_combine_taproot_multisig(spec, &resolved) {
        if reuses_keys {
            return Err(PolicyError::InvalidPolicy(
                "A key can only be used in more than one condition when the recovery \
                 conditions are timelocked"
                    .to_string(),
            ));
        }
        return Ok(combine_taproot_multisig(&resolved));
    }

    if let Some(shape) = try_single_condition_shape(spec, &resolved) {
        return Ok(shape);
    }

    let segwit = spec.preferred_script_type == PreferredScriptType::SegwitV0;
    if segwit && resolved.iter().any(|c| c.is_unspendable) {
        return Err(PolicyError::InvalidPolicy(
            "An unspendable primary requires taproot; SegWit v0 has no internal key to replace"
                .to_string(),
        ));
    }

    match build_timelocked_policy(resolved, spec.network)? {
        WalletShape::TimelockedPolicy {
            primary_id,
            primary,
            recoveries,
        } if segwit => Ok(WalletShape::SegwitTimelockedPolicy {
            primary_id,
            primary,
            recoveries,
        }),
        shape => Ok(shape),
    }
}

const FIRST_MULTIPATH_STEP: &str = "/<0;1>/*";

struct ResolvedCondition {
    id: String,
    is_primary: bool,
    is_unspendable: bool,
    timelock: u16,
    /// `None` only when `is_unspendable` is true — the actual key is
    /// substituted in `build_timelocked_policy` once we know all the
    /// recovery xpubs (the unspendable xpub's chain code derives from
    /// them).
    path: Option<PolicyPath>,
}

/// Resolve every condition's keys. The flag says whether any device is
/// used by more than one condition.
fn resolve_conditions(spec: &WalletSpec) -> Result<(Vec<ResolvedCondition>, bool), PolicyError> {
    let mut uses: BTreeMap<String, u32> = BTreeMap::new();
    let resolved = spec
        .conditions
        .iter()
        .map(|cond| resolve_condition(cond, &spec.managed_keys, &mut uses))
        .collect::<Result<Vec<_>, _>>()?;
    let reuses_keys = uses.values().any(|count| *count > 1);
    Ok((resolved, reuses_keys))
}

fn resolve_condition(
    cond: &SpendingCondition,
    managed_keys: &BTreeMap<String, ManagedKey>,
    uses: &mut BTreeMap<String, u32>,
) -> Result<ResolvedCondition, PolicyError> {
    if cond.is_unspendable {
        return Ok(ResolvedCondition {
            id: cond.id.clone(),
            is_primary: cond.is_primary,
            is_unspendable: true,
            timelock: cond.timelock,
            path: None,
        });
    }
    for (idx, id) in cond.managed_key_ids.iter().enumerate() {
        if cond.managed_key_ids[..idx].contains(id) {
            return Err(PolicyError::InvalidPolicy(format!(
                "Condition '{}' lists device {} more than once",
                cond.id, id
            )));
        }
    }
    let mut next_key = |id: &String| {
        let nth_use = uses.entry(id.clone()).or_insert(0);
        let key = resolve_key(managed_keys, id, *nth_use);
        *nth_use += 1;
        key
    };
    let path = match cond.policy {
        PolicyType::Single => PolicyPath::Single(next_key(&cond.managed_key_ids[0])?),
        // A 1-of-1 "multi" is a single key.
        PolicyType::Multi if cond.managed_key_ids.len() == 1 => {
            PolicyPath::Single(next_key(&cond.managed_key_ids[0])?)
        }
        PolicyType::Multi => {
            let keys = cond
                .managed_key_ids
                .iter()
                .map(&mut next_key)
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
        is_unspendable: false,
        timelock: cond.timelock,
        path: Some(path),
    })
}

/// `nth_use` counts the conditions that already hold this device's key:
/// use 0 keeps the stored `<0;1>` multipath step, use `n` moves to
/// `<2n;2n+1>`.
fn resolve_key(
    managed_keys: &BTreeMap<String, ManagedKey>,
    device_id: &str,
    nth_use: u32,
) -> Result<DescriptorPublicKey, PolicyError> {
    let key = managed_keys.get(device_id).ok_or_else(|| {
        PolicyError::KeyManagement(format!("Key not found for device {}", device_id))
    })?;

    let xpub_str = key.tpub.as_deref().unwrap_or(&key.xpub);
    let xpub_str = ensure_key_origin_has_path(xpub_str, &key.fingerprint, &key.derivation_path);
    let xpub_str = if nth_use == 0 {
        xpub_str
    } else {
        let base = xpub_str.strip_suffix(FIRST_MULTIPATH_STEP).ok_or_else(|| {
            PolicyError::KeyManagement(format!(
                "Device {} is used by more than one condition, which needs a key ending in {}",
                device_id, FIRST_MULTIPATH_STEP
            ))
        })?;
        format!("{}/<{};{}>/*", base, 2 * nth_use, 2 * nth_use + 1)
    };

    DescriptorPublicKey::from_str(&xpub_str)
        .map_err(|e| PolicyError::KeyManagement(format!("Invalid xpub: {}", e)))
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

/// Compute the deterministic NUMS-derived xpub used for unspendable
/// primary paths (matches Liana Desktop's construction so descriptors
/// stay interoperable), sourcing the chain-code material from every
/// resolved recovery key. Returns a `DescriptorPublicKey` formatted
/// as a descriptor key expression at fingerprint `00000000` so it
/// slots into `PolicyPath::Single` like any other key.
fn build_unspendable_primary_xpub(
    recoveries: &[RecoveryPath],
    network: Network,
) -> Result<DescriptorPublicKey, PolicyError> {
    let mut xpubs: Vec<Xpub> = Vec::new();
    for rec in recoveries {
        for key in rec.path.keys() {
            let xpub = match key {
                DescriptorPublicKey::XPub(x) => x.xkey,
                DescriptorPublicKey::MultiXPub(m) => m.xkey,
                DescriptorPublicKey::Single(_) => {
                    return Err(PolicyError::InvalidPolicy(
                        "Unspendable primary requires xpub recovery keys; single pubkeys not supported".to_string(),
                    ));
                }
            };
            xpubs.push(xpub);
        }
    }
    let xpub = unspendable_primary_xpub(&xpubs, network);
    let formatted = KeyUtils::format_key_for_descriptor("00000000", "", &xpub.to_string());
    DescriptorPublicKey::from_str(&formatted).map_err(|e| {
        PolicyError::InvalidPolicy(format!("unspendable primary descriptor key: {}", e))
    })
}

fn can_combine_taproot_multisig(spec: &WalletSpec, resolved: &[ResolvedCondition]) -> bool {
    if spec.preferred_script_type != PreferredScriptType::Auto {
        return false;
    }
    // An unspendable primary's intent is "recovery-only" — folding it
    // into a flat multisig would silently drop the primary slot and
    // produce a different wallet shape than the user asked for. Skip
    // the smart-combine entirely when one is present.
    if resolved.iter().any(|c| c.is_unspendable) {
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
        // `can_combine_taproot_multisig` already rules out unspendable
        // conditions; expect a real path here.
        let path = cond
            .path
            .as_ref()
            .expect("combine_taproot_multisig: unspendable conditions are filtered upstream");
        match path {
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
    // A lone unspendable condition would have no key and no recovery to
    // promote; validate() rejects that case, but guard here too.
    if cond.is_unspendable {
        return None;
    }

    let kind = match spec.preferred_script_type {
        PreferredScriptType::Taproot => ScriptKind::Taproot,
        _ => ScriptKind::SegwitV0,
    };

    let path = cond.path.as_ref()?;
    match path {
        PolicyPath::Single(key) => Some(WalletShape::SingleSig {
            kind,
            key: key.clone(),
        }),
        // Any k-of-n over two or more keys is a flat multisig, 1-of-n
        // included: with no recovery condition there is nothing for the
        // timelocked builder to work with, and it rejects the spec.
        PolicyPath::Multi { threshold, keys } if keys.len() >= 2 => Some(WalletShape::Multisig {
            kind,
            threshold: *threshold,
            keys: keys.clone(),
        }),
        _ => None,
    }
}

/// Build a timelocked policy shape. If no condition is marked primary,
/// the first recovery is promoted to primary. Recoveries with
/// `timelock == 0` are assigned default timelocks of `144 * (idx + 1)`
/// blocks (~1 day per slot) and the recovery list is sorted by effective
/// timelock so it matches the upstream `LianaPolicy` BTreeMap iteration
/// order.
///
/// `network` is needed to construct the unspendable primary's Xpub when
/// a condition is flagged `is_unspendable` — the chain code derives
/// deterministically from the recovery key set, but the Xpub network
/// byte must match the wallet.
fn build_timelocked_policy(
    resolved: Vec<ResolvedCondition>,
    network: Network,
) -> Result<WalletShape, PolicyError> {
    let mut primary: Option<(String, Option<PolicyPath>, bool)> = None;
    let mut recoveries: Vec<RecoveryPath> = Vec::new();

    for cond in resolved {
        if cond.is_primary {
            primary = Some((cond.id, cond.path, cond.is_unspendable));
        } else {
            // Non-primary conditions are never unspendable (validate()
            // rejects that combination); their path is always Some.
            let path = cond.path.ok_or_else(|| {
                PolicyError::InvalidPolicy(format!(
                    "non-primary condition '{}' is missing its resolved path",
                    cond.id
                ))
            })?;
            recoveries.push(RecoveryPath {
                id: cond.id,
                timelock: cond.timelock,
                path,
            });
        }
    }

    let (primary_id, primary_path) = match primary {
        Some((id, Some(path), false)) => (id, path),
        Some((id, None, true)) => {
            // Unspendable primary: substitute a NUMS-derived xpub
            // computed from the recovery keys. Validate() guarantees
            // recoveries.is_empty() == false here.
            let xpub = build_unspendable_primary_xpub(&recoveries, network)?;
            (id, PolicyPath::Single(xpub))
        }
        Some((id, _, true)) => {
            // Shouldn't happen — resolve_condition leaves path = None
            // for unspendable. Treat as a logic error.
            return Err(PolicyError::InvalidPolicy(format!(
                "unspendable primary condition '{}' unexpectedly carries a resolved path",
                id
            )));
        }
        Some((id, None, false)) => {
            return Err(PolicyError::InvalidPolicy(format!(
                "non-unspendable primary condition '{}' is missing its resolved path",
                id
            )));
        }
        None => {
            if recoveries.is_empty() {
                return Err(PolicyError::InvalidPolicy(
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
    // The descriptor keys recovery paths by timelock; a duplicate would
    // silently drop one of them.
    if let Some(pair) = recoveries
        .windows(2)
        .find(|w| w[0].timelock == w[1].timelock)
    {
        return Err(PolicyError::InvalidPolicy(format!(
            "Recovery conditions '{}' and '{}' share the {}-block timelock; each recovery needs \
             its own (a block apart is enough)",
            pair[0].id, pair[1].id, pair[0].timelock
        )));
    }

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

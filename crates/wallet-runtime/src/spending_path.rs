//! Spending-path enumeration for arbitrary descriptors.
//!
//! Given a descriptor string, classify it into one of the known shapes
//! (single-sig, multisig, Liana timelocked, taproot multi-leaf) and emit
//! a flat list of `SpendingPath`s the caller can present to a user. Each
//! path carries the metadata needed to (a) label it in the UI, (b) build
//! a PSBT that targets it (`policy_path` for `TxBuilder::policy_path`),
//! and (c) decide which fingerprints can sign it.
//!
//! This is the path-discovery primitive that complements
//! `policy_path::resolve_policy_path_from_leaf` (which goes the other
//! direction — from a chosen leaf hash back to a `policy_path` map).

use std::collections::BTreeMap;
use std::str::FromStr;

use liana::descriptors::LianaDescriptor;

use crate::error::WalletRuntimeError;

/// One spending option for the user. Single-sig and multisig
/// descriptors emit a single path; Liana descriptors emit one path per
/// branch (primary + each recovery, ordered by ascending timelock).
#[derive(Debug, Clone)]
pub struct SpendingPath {
    /// Stable identifier; safe to use as a dictionary key in storage or
    /// to round-trip through the frontend.
    pub id: String,
    /// One-line label. The caller controls capitalisation/style; this
    /// is the canonical text used by both the path picker and the
    /// signing-progress UI.
    pub label: String,
    /// Optional longer description. Currently used for Liana recovery
    /// paths to explain timelock semantics.
    pub description: Option<String>,
    /// Threshold (M) for this path. `1` for single-sig, `M` for
    /// `M-of-N`, the path's threshold for Liana branches.
    pub threshold: u32,
    /// All fingerprints that can contribute a signature to this path.
    /// `(threshold, fingerprints.len())` is the M / N for the UI.
    pub fingerprints: Vec<String>,
    /// Relative-time CSV value in blocks for Liana recoveries; `None`
    /// for primary / single-sig / multisig paths.
    pub timelock_blocks: Option<u32>,
    /// BDK policy-path map — what `TxBuilder::policy_path` consumes when
    /// building a PSBT that targets this branch. `None` for descriptors
    /// that don't have multiple branches (single-sig, multisig — BDK
    /// will pick the only option automatically).
    pub policy_path: Option<BTreeMap<String, Vec<usize>>>,
}

/// Classify the descriptor and emit one `SpendingPath` per spendable
/// branch. Pass `policies` from the wallet (for non-Liana descriptors
/// only the policy id is read — the value comes from
/// `wallet.policies(KeychainKind::External)`); for Liana descriptors,
/// pass `external_policy_id` so we can populate `policy_path`.
///
/// `policy_type` is the wallet manager's stored policy_type string, used
/// to pick the right classification path. For descriptor-only wallets
/// (where the wallet manager doesn't know the shape up front), pass
/// `"descriptor"` and we'll attempt to parse it as Liana first, falling
/// back to a single "Default" path.
pub fn list_spending_paths(
    policy_type: &str,
    external_descriptor: &str,
    fingerprints: &[String],
    external_policy_id: Option<&str>,
) -> Result<Vec<SpendingPath>, WalletRuntimeError> {
    match policy_type {
        "singlesig" | "singlesig_hardware" => Ok(vec![SpendingPath {
            id: "default".to_string(),
            label: "Default".to_string(),
            description: None,
            threshold: 1,
            fingerprints: fingerprints.to_vec(),
            timelock_blocks: None,
            policy_path: None,
        }]),

        "multisig" => {
            let threshold = parse_sortedmulti_threshold(external_descriptor).ok_or_else(|| {
                WalletRuntimeError::PolicyPath(format!(
                    "could not parse multisig threshold from descriptor: {}",
                    external_descriptor
                ))
            })?;
            Ok(vec![SpendingPath {
                id: "default".to_string(),
                label: format!("{}-of-{}", threshold, fingerprints.len()),
                description: None,
                threshold,
                fingerprints: fingerprints.to_vec(),
                timelock_blocks: None,
                policy_path: None,
            }])
        }

        "liana" | "descriptor" => {
            // Try Liana parsing first; if it succeeds, enumerate
            // primary + recoveries. Otherwise fall back to a single
            // default path (descriptor-only wallets that aren't Liana —
            // bare wpkh, multisig the manager didn't tag, etc.).
            match LianaDescriptor::from_str(external_descriptor) {
                Ok(desc) => liana_paths(&desc, external_policy_id),
                Err(_) if policy_type == "descriptor" => Ok(vec![SpendingPath {
                    id: "default".to_string(),
                    label: "Default".to_string(),
                    description: None,
                    threshold: 1,
                    fingerprints: fingerprints.to_vec(),
                    timelock_blocks: None,
                    policy_path: None,
                }]),
                Err(e) => Err(WalletRuntimeError::PolicyPath(format!(
                    "expected Liana descriptor for policy_type=liana but parse failed: {}",
                    e
                ))),
            }
        }

        "watch_only" => {
            // Watch-only wallets cannot spend — return no paths. Callers
            // should gate the Send flow on a non-empty result.
            Ok(Vec::new())
        }

        other => Err(WalletRuntimeError::PolicyPath(format!(
            "unsupported policy_type for spending-path enumeration: {}",
            other
        ))),
    }
}

fn liana_paths(
    desc: &LianaDescriptor,
    external_policy_id: Option<&str>,
) -> Result<Vec<SpendingPath>, WalletRuntimeError> {
    let policy = desc.policy();
    let mut out = Vec::new();

    // Primary path.
    let (p_thresh, p_origins) = policy.primary_path().thresh_origins();
    let p_fps: Vec<String> = p_origins.keys().map(|fp| fp.to_string()).collect();
    out.push(SpendingPath {
        id: "primary".to_string(),
        label: if p_origins.len() == 1 && p_thresh == 1 {
            "Primary".to_string()
        } else {
            format!("Primary ({}-of-{})", p_thresh, p_origins.len())
        },
        description: Some("Spendable immediately, no timelock.".to_string()),
        threshold: p_thresh as u32,
        fingerprints: p_fps,
        timelock_blocks: None,
        policy_path: external_policy_id.map(|id| {
            let mut m = BTreeMap::new();
            m.insert(id.to_string(), vec![0]);
            m
        }),
    });

    // Recovery paths in ascending-timelock order, matching BDK's
    // policy-child indexing (see policy_path.rs).
    for (idx, (timelock, path_info)) in policy.recovery_paths().iter().enumerate() {
        let (thresh, origins) = path_info.thresh_origins();
        let fps: Vec<String> = origins.keys().map(|fp| fp.to_string()).collect();
        let blocks = *timelock as u32;
        let label = if origins.len() == 1 && thresh == 1 {
            format!("Recovery (after {})", format_timelock(blocks))
        } else {
            format!(
                "Recovery {}-of-{} (after {})",
                thresh,
                origins.len(),
                format_timelock(blocks)
            )
        };
        out.push(SpendingPath {
            id: format!("recovery_{}", idx),
            label,
            description: Some(format!(
                "Activates {} blocks (~{}) after the most recent confirmed spend or coin receipt.",
                blocks,
                format_timelock(blocks)
            )),
            threshold: thresh as u32,
            fingerprints: fps,
            timelock_blocks: Some(blocks),
            policy_path: external_policy_id.map(|id| {
                let mut m = BTreeMap::new();
                m.insert(id.to_string(), vec![idx + 1]);
                m
            }),
        });
    }

    Ok(out)
}

/// Approximate human-readable timelock. Bitcoin block intervals are 10
/// minutes on average; the rounding is intentional — exact block counts
/// are shown separately in the description.
fn format_timelock(blocks: u32) -> String {
    let minutes = blocks as u64 * 10;
    let hours = minutes / 60;
    let days = hours / 24;
    let weeks = days / 7;
    let months = days / 30;
    let years = days / 365;
    if years >= 1 {
        format!("~{} year{}", years, if years == 1 { "" } else { "s" })
    } else if months >= 1 {
        format!("~{} month{}", months, if months == 1 { "" } else { "s" })
    } else if weeks >= 1 {
        format!("~{} week{}", weeks, if weeks == 1 { "" } else { "s" })
    } else if days >= 1 {
        format!("~{} day{}", days, if days == 1 { "" } else { "s" })
    } else if hours >= 1 {
        format!("~{} hour{}", hours, if hours == 1 { "" } else { "s" })
    } else {
        format!("{} block{}", blocks, if blocks == 1 { "" } else { "s" })
    }
}

/// Parse the threshold M out of a `wsh(sortedmulti(M, ...))` or
/// `wsh(multi(M, ...))` descriptor. Returns `None` if the string
/// doesn't match either shape.
fn parse_sortedmulti_threshold(descriptor: &str) -> Option<u32> {
    let after_open = descriptor
        .find("sortedmulti(")
        .map(|i| i + "sortedmulti(".len())
        .or_else(|| descriptor.find("multi(").map(|i| i + "multi(".len()))?;
    let comma = descriptor[after_open..].find(',')?;
    descriptor[after_open..after_open + comma]
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sortedmulti_threshold() {
        assert_eq!(
            parse_sortedmulti_threshold("wsh(sortedmulti(2,a,b,c))"),
            Some(2)
        );
        assert_eq!(
            parse_sortedmulti_threshold("wsh(multi(3,a,b,c,d))"),
            Some(3)
        );
        assert_eq!(parse_sortedmulti_threshold("wpkh(xpub...)"), None);
    }

    #[test]
    fn singlesig_emits_one_default_path() {
        let paths = list_spending_paths(
            "singlesig",
            "wpkh([fp/84'/1'/0']xpub.../0/*)",
            &["12345678".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].id, "default");
        assert_eq!(paths[0].threshold, 1);
        assert_eq!(paths[0].timelock_blocks, None);
        assert!(paths[0].policy_path.is_none());
    }

    #[test]
    fn multisig_emits_one_path_with_threshold() {
        let paths = list_spending_paths(
            "multisig",
            "wsh(sortedmulti(2,xpub_a/0/*,xpub_b/0/*,xpub_c/0/*))",
            &["aa".to_string(), "bb".to_string(), "cc".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].threshold, 2);
        assert_eq!(paths[0].label, "2-of-3");
    }

    #[test]
    fn watch_only_returns_empty() {
        let paths = list_spending_paths("watch_only", "wpkh(xpub.../0/*)", &[], None).unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn format_timelock_picks_right_unit() {
        assert_eq!(format_timelock(1), "1 block");
        assert_eq!(format_timelock(6), "~1 hour");
        assert_eq!(format_timelock(144), "~1 day");
        assert_eq!(format_timelock(1008), "~1 week");
        assert_eq!(format_timelock(4320), "~1 month");
        assert_eq!(format_timelock(52560), "~1 year");
    }
}

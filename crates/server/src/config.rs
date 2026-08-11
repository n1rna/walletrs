use bdk_wallet::bitcoin::Network;
use once_cell::sync::Lazy;
use std::env;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageKind {
    Local,
    S3,
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub prefix: String,
    pub force_path_style: bool,
}

pub struct Config {
    pub host: String,
    pub port: u16,
    pub http_port: u16,
    pub electrs_url: String,
    pub bitcoin_network: String,
    pub storage_base_path: String,
    pub storage_kind: StorageKind,
    pub s3: Option<S3Config>,
    pub kek_b64: Option<String>,
    pub auth_disabled: bool,
    pub auth_token: Option<String>,
}

impl Config {
    fn new() -> Self {
        let storage_kind = match env::var("WALLETRS_STORAGE_KIND")
            .unwrap_or_else(|_| "local".to_string())
            .to_lowercase()
            .as_str()
        {
            "s3" | "r2" => StorageKind::S3,
            _ => StorageKind::Local,
        };

        let s3 = if storage_kind == StorageKind::S3 {
            Some(S3Config {
                endpoint: env::var("WALLETRS_S3_ENDPOINT").ok(),
                bucket: env::var("WALLETRS_S3_BUCKET")
                    .expect("WALLETRS_S3_BUCKET must be set when WALLETRS_STORAGE_KIND=s3"),
                region: env::var("WALLETRS_S3_REGION").unwrap_or_else(|_| "auto".to_string()),
                access_key_id: env::var("WALLETRS_S3_ACCESS_KEY_ID").ok(),
                secret_access_key: env::var("WALLETRS_S3_SECRET_ACCESS_KEY").ok(),
                prefix: env::var("WALLETRS_S3_PREFIX").unwrap_or_default(),
                force_path_style: env::var("WALLETRS_S3_FORCE_PATH_STYLE")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true),
            })
        } else {
            None
        };

        let auth_disabled = env::var("WALLETRS_AUTH_DISABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let auth_token = env::var("WALLETRS_AUTH_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());

        let port = env::var("WALLETRS_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(50051);
        let http_port = env::var("WALLETRS_HTTP_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(8080);
        let host = env::var("WALLETRS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        // In test builds, give CONFIG fields safe defaults even when env
        // vars aren't set. This is a belt-and-braces alongside
        // `__test_init_config`: if some test code path triggers
        // `CONFIG.foo()` before `test_support::setup()` had a chance to
        // pre-seed CONFIG, we still end up with a usable KEK and a
        // testnet network. Production builds are unaffected.
        let kek_b64 = env::var("WALLETRS_KEK").ok();
        #[cfg(test)]
        let kek_b64 = kek_b64.or_else(|| {
            // 32 zero bytes, base64-encoded. Tests don't rely on the value,
            // only on it satisfying `EnvelopeCipher::from_base64`'s
            // length check.
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string())
        });

        #[cfg(test)]
        let bitcoin_network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "testnet".to_string());
        #[cfg(not(test))]
        let bitcoin_network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "regtest".to_string());

        // Refuse to boot on an unrecognised network rather than silently
        // falling back. A typo here would otherwise derive regtest keys and
        // addresses on a live public network.
        if parse_network_str(&bitcoin_network).is_none() {
            panic!(
                "BITCOIN_NETWORK={bitcoin_network:?} is not a supported network \
                 (expected one of: mainnet, bitcoin, testnet, testnet4, signet, regtest)"
            );
        }

        Self {
            host,
            port,
            http_port,
            electrs_url: env::var("ELECTRS_URL").unwrap_or_else(|_| "127.0.0.1:60401".to_string()),
            bitcoin_network,
            storage_base_path: env::var("WALLETRS_STORAGE_PATH")
                .unwrap_or_else(|_| "./data".to_string()),
            storage_kind,
            s3,
            kek_b64,
            auth_disabled,
            auth_token,
        }
    }

    pub fn kek_b64(&self) -> Option<&str> {
        self.kek_b64.as_deref()
    }

    pub fn electrs_url(&self) -> &str {
        &self.electrs_url
    }

    pub fn bitcoin_network(&self) -> &str {
        &self.bitcoin_network
    }

    pub fn storage_base_path(&self) -> &str {
        &self.storage_base_path
    }

    pub fn storage_kind(&self) -> &StorageKind {
        &self.storage_kind
    }

    pub fn s3(&self) -> Option<&S3Config> {
        self.s3.as_ref()
    }

    pub fn network(&self) -> Network {
        // `Config::new` rejects unparseable values, so this cannot fail for a
        // config that was actually constructed from the environment.
        parse_network_str(&self.bitcoin_network).expect("bitcoin_network validated at construction")
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    pub fn auth_disabled(&self) -> bool {
        self.auth_disabled
    }

    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }
}

/// Parse a network string into a Network enum
pub fn parse_network_str(network_str: &str) -> Option<Network> {
    match network_str {
        "testnet" => Some(Network::Testnet),
        "testnet4" => Some(Network::Testnet4),
        "regtest" => Some(Network::Regtest),
        "signet" => Some(Network::Signet),
        "mainnet" | "bitcoin" => Some(Network::Bitcoin),
        _ => None,
    }
}

/// Backing cell for the global `Config`. Tests can race to populate this
/// via `__test_init_config` *before* any production code path calls
/// `Config::new()`; the production path is the lazy `get_or_init` below.
static CONFIG_CELL: OnceLock<Config> = OnceLock::new();

/// Global config instance. Kept as a `Lazy<&'static Config>` so existing
/// `CONFIG.foo()` call sites compile unchanged — `Lazy` derefs to `&&Config`
/// which auto-derefs again to `&Config` for method calls. The actual storage
/// lives in `CONFIG_CELL`, which tests can pre-seed.
pub static CONFIG: Lazy<&'static Config> = Lazy::new(|| CONFIG_CELL.get_or_init(Config::new));

/// Test-only: install a `Config` into the global cell before the production
/// `Lazy` initializer runs. Returns `true` if this caller actually set the
/// config, `false` if it was already set (by another test, or because some
/// other call path already touched `CONFIG`). Tests should not rely on the
/// boolean — use it to detect ordering bugs, not to gate behavior.
///
/// Pair this with `db::__test_init_storage_with_path` for a complete
/// test-environment bootstrap.
#[cfg(test)]
pub fn __test_init_config(cfg: Config) -> bool {
    CONFIG_CELL.set(cfg).is_ok()
}

#[cfg(test)]
impl Config {
    /// Build a minimal `Config` suitable for tests: local filesystem
    /// storage rooted at `storage_base_path`, no S3, no KEK, no auth,
    /// testnet by default. Tests that need different values should mutate
    /// the returned struct before passing it to `__test_init_config`.
    pub fn for_tests(storage_base_path: impl Into<String>) -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 0,
            http_port: 0,
            electrs_url: "127.0.0.1:60401".into(),
            bitcoin_network: "testnet".into(),
            storage_base_path: storage_base_path.into(),
            storage_kind: StorageKind::Local,
            s3: None,
            kek_b64: None,
            auth_disabled: true,
            auth_token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_recognises_canonical_strings() {
        assert_eq!(parse_network_str("mainnet"), Some(Network::Bitcoin));
        assert_eq!(parse_network_str("bitcoin"), Some(Network::Bitcoin));
        assert_eq!(parse_network_str("testnet"), Some(Network::Testnet));
        assert_eq!(parse_network_str("testnet4"), Some(Network::Testnet4));
        assert_eq!(parse_network_str("signet"), Some(Network::Signet));
        assert_eq!(parse_network_str("regtest"), Some(Network::Regtest));
    }

    #[test]
    fn parse_network_rejects_unknown_strings() {
        assert_eq!(parse_network_str(""), None);
        assert_eq!(parse_network_str("MAINNET"), None);
        assert_eq!(parse_network_str("liquid"), None);
        assert_eq!(parse_network_str("testnet5"), None);
    }

    /// Wallet records persist `CONFIG.network().to_string()`, and
    /// `Wallet::validate` re-parses that string. The two must agree for every
    /// supported network or a wallet fails to save on the filesystem backend.
    #[test]
    fn network_display_round_trips_through_parse() {
        for network in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            assert_eq!(
                parse_network_str(&network.to_string()),
                Some(network),
                "{network} does not round-trip"
            );
        }
    }
}

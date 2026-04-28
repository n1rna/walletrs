use bdk_wallet::bitcoin::Network;
use once_cell::sync::Lazy;
use std::env;

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

        Self {
            host,
            port,
            http_port,
            electrs_url: env::var("ELECTRS_URL").unwrap_or_else(|_| "127.0.0.1:60401".to_string()),
            bitcoin_network: env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "regtest".to_string()),
            storage_base_path: env::var("WALLETRS_STORAGE_PATH")
                .unwrap_or_else(|_| "./data".to_string()),
            storage_kind,
            s3,
            kek_b64: env::var("WALLETRS_KEK").ok(),
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
        parse_network_str(&self.bitcoin_network).unwrap_or(Network::Regtest)
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
        "regtest" => Some(Network::Regtest),
        "signet" => Some(Network::Signet),
        "mainnet" | "bitcoin" => Some(Network::Bitcoin),
        _ => None,
    }
}

/// Global config instance
pub static CONFIG: Lazy<Config> = Lazy::new(Config::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_recognises_canonical_strings() {
        assert_eq!(parse_network_str("mainnet"), Some(Network::Bitcoin));
        assert_eq!(parse_network_str("bitcoin"), Some(Network::Bitcoin));
        assert_eq!(parse_network_str("testnet"), Some(Network::Testnet));
        assert_eq!(parse_network_str("signet"), Some(Network::Signet));
        assert_eq!(parse_network_str("regtest"), Some(Network::Regtest));
    }

    #[test]
    fn parse_network_rejects_unknown_strings() {
        assert_eq!(parse_network_str(""), None);
        assert_eq!(parse_network_str("MAINNET"), None);
        assert_eq!(parse_network_str("liquid"), None);
    }
}

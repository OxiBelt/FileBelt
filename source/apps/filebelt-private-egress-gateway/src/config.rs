// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use filebelt_control_protocol::BackendServerTlsConfig;
use serde::Deserialize;
use url::Url;

use crate::MAX_RESPONSE_BYTES;

const CONFIG_VERSION: u32 = 1;
const MAX_RELAY_ADDRESSES: usize = 8;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENCY: usize = 64;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 60;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 3_600;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayMode {
    Mcp,
    OnlyofficeOutput,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub version: u32,
    pub mode: GatewayMode,
    pub listen_address: SocketAddr,
    pub operations_address: SocketAddr,
    pub server_tls: BackendServerTlsConfig,
    pub relay: RelayConfig,
    pub limits: Limits,
    #[serde(default)]
    pub mcp: Option<McpTarget>,
    #[serde(default)]
    pub onlyoffice_output: Option<OnlyofficeTarget>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub addresses: Vec<SocketAddr>,
    pub server_name: String,
    pub ca_file: PathBuf,
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_concurrency: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTarget {
    pub canonical_url: String,
    pub trust_profile: String,
    pub server_name: String,
    pub ca_file: PathBuf,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnlyofficeTarget {
    pub canonical_origin: String,
    pub path_prefix: String,
    pub server_name: String,
    pub ca_file: PathBuf,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub enum TargetPolicy {
    Mcp {
        url: Url,
        trust_profile: String,
        server_name: String,
        ca_file: PathBuf,
    },
    OnlyofficeOutput {
        origin: Url,
        path_prefix: String,
        server_name: String,
        ca_file: PathBuf,
    },
}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let source = fs::read_to_string(path).map_err(|_| "cannot read gateway config")?;
        let config: Self = toml::from_str(&source).map_err(|_| "invalid gateway config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != CONFIG_VERSION {
            return Err("unsupported gateway config version".into());
        }
        if !self.server_tls.allowed_client_trust_domains.is_empty() {
            return Err("gateway client authorization requires exact URI SANs".into());
        }
        self.relay.validate()?;
        self.limits.validate()?;
        match (self.mode, &self.mcp, &self.onlyoffice_output) {
            (GatewayMode::Mcp, Some(target), None) => {
                let _ = target.policy()?;
            }
            (GatewayMode::OnlyofficeOutput, None, Some(target)) => {
                let _ = target.policy()?;
            }
            _ => return Err("gateway mode must have exactly one matching target section".into()),
        }
        Ok(())
    }

    pub fn target_policy(&self) -> Result<TargetPolicy, String> {
        match self.mode {
            GatewayMode::Mcp => self
                .mcp
                .as_ref()
                .ok_or_else(|| "MCP target is absent".to_owned())?
                .policy(),
            GatewayMode::OnlyofficeOutput => self
                .onlyoffice_output
                .as_ref()
                .ok_or_else(|| "ONLYOFFICE target is absent".to_owned())?
                .policy(),
        }
    }
}

impl RelayConfig {
    fn validate(&self) -> Result<(), String> {
        if self.addresses.is_empty() || self.addresses.len() > MAX_RELAY_ADDRESSES {
            return Err("relay address count is outside the allowed range".into());
        }
        if self.addresses.iter().any(|address| address.port() == 0) {
            return Err("relay address port must be nonzero".into());
        }
        validate_server_name(&self.server_name)
    }
}

impl Limits {
    fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_CONCURRENCY).contains(&self.max_concurrency) {
            return Err("gateway concurrency is outside the allowed range".into());
        }
        if !(1..=MAX_REQUEST_BYTES).contains(&self.max_request_bytes) {
            return Err("gateway request limit is outside the allowed range".into());
        }
        if !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err("gateway response limit is outside the allowed range".into());
        }
        if !(1..=MAX_CONNECT_TIMEOUT_SECONDS).contains(&self.connect_timeout_seconds) {
            return Err("gateway connect timeout is outside the allowed range".into());
        }
        if !(1..=MAX_REQUEST_TIMEOUT_SECONDS).contains(&self.request_timeout_seconds) {
            return Err("gateway request timeout is outside the allowed range".into());
        }
        Ok(())
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_seconds)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }
}

impl McpTarget {
    fn policy(&self) -> Result<TargetPolicy, String> {
        let url = exact_https_url(&self.canonical_url, self.port, false)?;
        validate_target_identity(&url, &self.server_name)?;
        if self.trust_profile.len() > 128
            || !self
                .trust_profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
        {
            return Err("MCP trust profile is invalid".into());
        }
        Ok(TargetPolicy::Mcp {
            url,
            trust_profile: self.trust_profile.clone(),
            server_name: self.server_name.clone(),
            ca_file: self.ca_file.clone(),
        })
    }
}

impl OnlyofficeTarget {
    fn policy(&self) -> Result<TargetPolicy, String> {
        let origin = exact_https_url(&self.canonical_origin, self.port, true)?;
        validate_target_identity(&origin, &self.server_name)?;
        if self.path_prefix.len() > 256
            || !self.path_prefix.starts_with('/')
            || !self.path_prefix.ends_with('/')
            || self.path_prefix.contains('%')
            || self.path_prefix.contains('\\')
            || self
                .path_prefix
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err("ONLYOFFICE path prefix is invalid".into());
        }
        Ok(TargetPolicy::OnlyofficeOutput {
            origin,
            path_prefix: self.path_prefix.clone(),
            server_name: self.server_name.clone(),
            ca_file: self.ca_file.clone(),
        })
    }
}

fn exact_https_url(value: &str, port: u16, bare_origin: bool) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "target URL is invalid")?;
    if url.as_str() != value
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(port)
        || (bare_origin && (url.path() != "/" || url.query().is_some()))
    {
        return Err("target URL is not the configured canonical HTTPS form".into());
    }
    Ok(url)
}

fn validate_target_identity(url: &Url, server_name: &str) -> Result<(), String> {
    validate_server_name(server_name)?;
    let matches = match url.host() {
        Some(url::Host::Domain(host)) => host == server_name,
        Some(url::Host::Ipv4(host)) => host.to_string() == server_name,
        Some(url::Host::Ipv6(host)) => host.to_string() == server_name,
        None => false,
    };
    if !matches {
        return Err("target TLS server name must equal the canonical URL host".into());
    }
    Ok(())
}

fn validate_server_name(server_name: &str) -> Result<(), String> {
    if server_name.is_empty()
        || server_name.len() > 253
        || server_name.ends_with('.')
        || server_name.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err("TLS server name is invalid".into());
    }
    rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map(|_| ())
        .map_err(|_| "TLS server name is invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMON: &str = r#"
version = 1
mode = "mcp"
listen_address = "0.0.0.0:8443"
operations_address = "0.0.0.0:9090"

[server_tls]
certificate_chain_file = "/secrets/server.crt"
private_key_file = "/secrets/server.key"
client_ca_file = "/secrets/client-ca.crt"
allowed_client_uri_sans = ["spiffe://filebelt/mcp-broker"]

[relay]
addresses = ["10.0.0.8:9443"]
server_name = "relay.filebelt.svc"
ca_file = "/secrets/relay-ca.crt"
certificate_chain_file = "/secrets/client.crt"
private_key_file = "/secrets/client.key"

[limits]
max_concurrency = 4
max_request_bytes = 4194304
max_response_bytes = 104857600
connect_timeout_seconds = 5
request_timeout_seconds = 60

[mcp]
canonical_url = "https://llm.private.example/mcp"
trust_profile = "private-ca-v1"
server_name = "llm.private.example"
ca_file = "/secrets/target-ca.crt"
port = 443
"#;

    #[test]
    fn strict_toml_rejects_unknown_and_inline_secret_fields() {
        assert!(toml::from_str::<GatewayConfig>(COMMON).is_ok());
        assert!(
            toml::from_str::<GatewayConfig>(&COMMON.replace(
                "private_key_file = \"/secrets/client.key\"",
                "private_key_file = \"/secrets/client.key\"\nprivate_key = \"secret\"",
            ))
            .is_err()
        );
    }

    #[test]
    fn trust_domain_client_authorization_is_rejected() {
        let mut config: GatewayConfig = toml::from_str(COMMON).unwrap();
        config.server_tls.allowed_client_trust_domains = vec!["filebelt".into()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn mode_and_limits_fail_closed() {
        let mut config: GatewayConfig = toml::from_str(COMMON).unwrap();
        config.mode = GatewayMode::OnlyofficeOutput;
        assert!(config.validate().is_err());
        config.mode = GatewayMode::Mcp;
        config.limits.max_response_bytes = MAX_RESPONSE_BYTES + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn target_must_be_canonical_and_match_sni_and_port() {
        let mut config: GatewayConfig = toml::from_str(COMMON).unwrap();
        config.mcp.as_mut().unwrap().canonical_url = "https://llm.private.example:443/mcp".into();
        assert!(config.validate().is_err());
        config.mcp.as_mut().unwrap().canonical_url = "https://llm.private.example/mcp".into();
        config.mcp.as_mut().unwrap().server_name = "other.private.example".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_default_mcp_trust_profile_is_matched_explicitly() {
        let mut config: GatewayConfig = toml::from_str(COMMON).unwrap();
        config.mcp.as_mut().unwrap().trust_profile.clear();
        assert!(config.validate().is_ok());
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use filebelt_control_protocol::BackendServerTlsConfig;
use serde::Deserialize;

const CONFIG_VERSION: u32 = 1;
const MAX_TARGET_ADDRESSES: usize = 16;
const MAX_CONNECTIONS: usize = 4_096;
const MAX_TIMEOUT_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub version: u32,
    pub listen_address: SocketAddr,
    pub operations_address: SocketAddr,
    pub server_tls: BackendServerTlsConfig,
    pub target_addresses: Vec<SocketAddr>,
    #[serde(default)]
    pub socks5_proxy: Option<SocketAddr>,
    pub limits: RelayLimits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLimits {
    pub max_connections: usize,
    pub handshake_timeout_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub inactivity_timeout_seconds: u64,
    pub drain_timeout_seconds: u64,
}

impl RelayConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let source = fs::read_to_string(path).map_err(|_| "cannot read relay config")?;
        let config: Self = toml::from_str(&source).map_err(|_| "invalid relay config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != CONFIG_VERSION {
            return Err("unsupported relay config version".into());
        }
        if !self.server_tls.allowed_client_trust_domains.is_empty() {
            return Err("relay client authorization requires exact URI SANs".into());
        }
        if self.target_addresses.is_empty() || self.target_addresses.len() > MAX_TARGET_ADDRESSES {
            return Err("target address count is outside the allowed range".into());
        }
        let port = self.target_addresses[0].port();
        if port == 0
            || self
                .target_addresses
                .iter()
                .any(|address| address.port() != port)
        {
            return Err("all target addresses must use one nonzero fixed port".into());
        }
        if self
            .target_addresses
            .iter()
            .any(|address| invalid_target_ip(address.ip()))
        {
            return Err("target address is not a usable unicast IP".into());
        }
        if self.target_addresses.iter().collect::<HashSet<_>>().len() != self.target_addresses.len()
        {
            return Err("target addresses must be unique".into());
        }
        if self
            .socks5_proxy
            .is_some_and(|proxy| proxy.port() == 0 || !proxy.ip().is_loopback())
        {
            return Err("SOCKS5 proxy must be a loopback address with a nonzero port".into());
        }
        self.limits.validate()
    }
}

impl RelayLimits {
    fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err("relay connection limit is outside the allowed range".into());
        }
        for seconds in [
            self.handshake_timeout_seconds,
            self.connect_timeout_seconds,
            self.inactivity_timeout_seconds,
            self.drain_timeout_seconds,
        ] {
            if !(1..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
                return Err("relay timeout is outside the allowed range".into());
            }
        }
        Ok(())
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_seconds)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_seconds)
    }

    pub fn inactivity_timeout(&self) -> Duration {
        Duration::from_secs(self.inactivity_timeout_seconds)
    }

    pub fn drain_timeout(&self) -> Duration {
        Duration::from_secs(self.drain_timeout_seconds)
    }
}

fn invalid_target_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address == std::net::Ipv4Addr::BROADCAST
                || matches!(address.octets(), [100, 100, 100, 200] | [192, 0, 0, 192])
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| invalid_target_ip(IpAddr::V4(mapped)))
                || address == std::net::Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
version = 1
listen_address = "0.0.0.0:9443"
operations_address = "0.0.0.0:9090"
target_addresses = ["10.40.0.10:443", "[fd00:40::10]:443"]

[server_tls]
certificate_chain_file = "/secrets/server.crt"
private_key_file = "/secrets/server.key"
client_ca_file = "/secrets/client-ca.crt"
allowed_client_uri_sans = ["spiffe://filebelt/private-egress-gateway"]

[limits]
max_connections = 64
handshake_timeout_seconds = 10
connect_timeout_seconds = 5
inactivity_timeout_seconds = 300
drain_timeout_seconds = 30
"#;

    #[test]
    fn config_accepts_only_numeric_fixed_port_targets() {
        let config: RelayConfig = toml::from_str(CONFIG).unwrap();
        assert!(config.validate().is_ok());
        let mut mixed = config.clone();
        mixed
            .target_addresses
            .push("10.40.0.11:8443".parse().unwrap());
        assert!(mixed.validate().is_err());
        assert!(
            toml::from_str::<RelayConfig>(
                &CONFIG.replace("10.40.0.10:443", "llm.private.example:443",)
            )
            .is_err()
        );
    }

    #[test]
    fn config_has_no_caller_selected_destination_or_inline_key() {
        assert!(
            toml::from_str::<RelayConfig>(&CONFIG.replace(
                "target_addresses =",
                "destination = \"10.0.0.1:443\"\ntarget_addresses =",
            ))
            .is_err()
        );
        assert!(
            toml::from_str::<RelayConfig>(&CONFIG.replace(
                "private_key_file = \"/secrets/server.key\"",
                "private_key_file = \"/secrets/server.key\"\nprivate_key = \"secret\"",
            ))
            .is_err()
        );
    }

    #[test]
    fn trust_domain_client_authorization_is_rejected() {
        let mut config: RelayConfig = toml::from_str(CONFIG).unwrap();
        config.server_tls.allowed_client_trust_domains = vec!["filebelt".into()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn unusable_and_duplicate_targets_fail_closed() {
        let mut config: RelayConfig = toml::from_str(CONFIG).unwrap();
        config.target_addresses = vec!["0.0.0.0:443".parse().unwrap()];
        assert!(config.validate().is_err());
        config.target_addresses = vec![
            "10.40.0.10:443".parse().unwrap(),
            "10.40.0.10:443".parse().unwrap(),
        ];
        assert!(config.validate().is_err());
    }

    #[test]
    fn target_rejects_local_and_metadata_ranges_but_allows_tailnet() {
        let mut config: RelayConfig = toml::from_str(CONFIG).unwrap();
        for target in [
            "127.0.0.1:443",
            "169.254.169.254:443",
            "100.100.100.200:443",
            "192.0.0.192:443",
            "224.0.0.1:443",
            "[::1]:443",
            "[fe80::1]:443",
            "[fd00:ec2::254]:443",
        ] {
            config.target_addresses = vec![target.parse().unwrap()];
            assert!(config.validate().is_err());
        }
        config.target_addresses = vec!["100.100.100.100:443".parse().unwrap()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn socks5_proxy_is_optional_and_loopback_only() {
        let mut config: RelayConfig = toml::from_str(CONFIG).unwrap();
        assert!(config.socks5_proxy.is_none());
        config.socks5_proxy = Some("127.0.0.1:1055".parse().unwrap());
        assert!(config.validate().is_ok());
        config.socks5_proxy = Some("10.0.0.1:1055".parse().unwrap());
        assert!(config.validate().is_err());
    }
}

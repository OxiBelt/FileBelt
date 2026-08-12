// SPDX-License-Identifier: LGPL-3.0-or-later

//! Strict, adapter-local bridge configuration.

use serde::Deserialize;
use std::fs::{self, File};
use std::io::{Read, Take};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CONFIG_FORMAT: u32 = 1;
pub const DEFAULT_CONFIG_PATH: &str = "/etc/filebelt-nfs/bridge.toml";
pub const REQUIRED_GATEWAY_URI_SAN: &str = "spiffe://filebelt/nfs-gateway/vfs";
pub const EXPECTED_VFS_HOSTNAME_ENV: &str = "FILEBELT_NFS_EXPECTED_VFS_HOSTNAME";
const MAX_CONFIG_BYTES: u64 = 65_536;

const REQUIRED_IPC_SOCKET: &str = "/run/filebelt-nfs/bridge.sock";
const REQUIRED_CONTROL_SOCKET: &str = "/run/filebelt-nfs/ganesha-control.sock";
const REQUIRED_STATE_FILE: &str = "/run/filebelt-nfs/gateway.state";
const REQUIRED_TLS_CERTIFICATE: &str = "/run/secrets/nfs-bridge-vfs-client-tls/tls.crt";
const REQUIRED_TLS_PRIVATE_KEY: &str = "/run/secrets/nfs-bridge-vfs-client-tls/tls.key";
const REQUIRED_TLS_SERVER_CA: &str = "/run/secrets/nfs-bridge-vfs-client-tls/server-ca.crt";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    pub format: u32,
    pub tenant_slug: String,
    pub kerberos_realm: String,
    pub release_revision: String,
    pub vfs_url: String,
    pub ipc_socket: PathBuf,
    pub ganesha_control_socket: PathBuf,
    pub state_file: PathBuf,
    pub tls: ClientTlsConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientTlsConfig {
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
    pub server_ca_file: PathBuf,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("bridge configuration is inaccessible or not a regular file")]
    Inaccessible,
    #[error("bridge configuration exceeds its size bound")]
    TooLarge,
    #[error("bridge configuration is invalid")]
    Invalid,
    #[error("bridge process received a forbidden secret or authority input")]
    ForbiddenAuthority,
}

impl BridgeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        require_regular_file(path, false)?;
        let file = File::open(path).map_err(|_| ConfigError::Inaccessible)?;
        let mut reader: Take<File> = file.take(MAX_CONFIG_BYTES + 1);
        let mut encoded = Vec::new();
        reader
            .read_to_end(&mut encoded)
            .map_err(|_| ConfigError::Inaccessible)?;
        if encoded.len() > MAX_CONFIG_BYTES as usize {
            return Err(ConfigError::TooLarge);
        }
        let config: Self = toml::from_slice(&encoded).map_err(|_| ConfigError::Invalid)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let expected_hostname =
            required_expected_vfs_hostname(std::env::var(EXPECTED_VFS_HOSTNAME_ENV))?;
        self.validate_against_expected_hostname(&expected_hostname)
    }

    fn validate_against_expected_hostname(
        &self,
        expected_hostname: &str,
    ) -> Result<(), ConfigError> {
        if self.format != CONFIG_FORMAT
            || !valid_tenant_slug(&self.tenant_slug)
            || !valid_realm(&self.kerberos_realm)
            || !stable_revision(&self.release_revision)
            || self.ipc_socket != Path::new(REQUIRED_IPC_SOCKET)
            || self.ganesha_control_socket != Path::new(REQUIRED_CONTROL_SOCKET)
            || self.state_file != Path::new(REQUIRED_STATE_FILE)
            || self.tls.certificate_chain_file != Path::new(REQUIRED_TLS_CERTIFICATE)
            || self.tls.private_key_file != Path::new(REQUIRED_TLS_PRIVATE_KEY)
            || self.tls.server_ca_file != Path::new(REQUIRED_TLS_SERVER_CA)
        {
            return Err(ConfigError::Invalid);
        }
        let endpoint = reqwest::Url::parse(&self.vfs_url).map_err(|_| ConfigError::Invalid)?;
        if endpoint.scheme() != "https"
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/internal/v1/vfs/execute"
            || !endpoint_matches_expected_hostname(&self.vfs_url, &endpoint, &expected_hostname)
        {
            return Err(ConfigError::Invalid);
        }
        Ok(())
    }

    pub fn reject_forbidden_authority_environment() -> Result<(), ConfigError> {
        const FORBIDDEN: &[&str] = &[
            "DATABASE_URL",
            "FILEBELT_DATABASE_URL_FILE",
            "FILEBELT_PAYLOAD_ROOT",
            "FILEBELT_MOUNT_VAULT_KEYRING_FILE",
            "FILEBELT_NFS_HANDLE_KEYRING_FILE",
            "FILEBELT_CAPABILITY_PRIVATE_KEY_FILE",
            "FILEBELT_CAPABILITY_KEYSET_FILE",
            "KRB5_KTNAME",
        ];
        if FORBIDDEN
            .iter()
            .any(|name| std::env::var_os(name).is_some())
        {
            return Err(ConfigError::ForbiddenAuthority);
        }
        Ok(())
    }
}

pub fn require_regular_file(path: &Path, private: bool) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::Inaccessible);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigError::Inaccessible)?;
    if !metadata.file_type().is_file() {
        return Err(ConfigError::Inaccessible);
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o022 != 0 || private && mode & 0o037 != 0 {
        return Err(ConfigError::Inaccessible);
    }
    Ok(())
}

fn valid_tenant_slug(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_realm(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn stable_revision(value: &str) -> bool {
    (7..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_expected_vfs_hostname(value: &str) -> bool {
    let mut labels = value.split('.');
    labels.next() == Some("filebelt-vfs")
        && labels.next().is_some_and(valid_dns_label)
        && labels.next() == Some("svc")
        && labels.next().is_none()
}

fn required_expected_vfs_hostname(
    value: Result<String, std::env::VarError>,
) -> Result<String, ConfigError> {
    let value = value.map_err(|_| ConfigError::Invalid)?;
    valid_expected_vfs_hostname(&value)
        .then_some(value)
        .ok_or(ConfigError::Invalid)
}

fn valid_dns_label(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn endpoint_matches_expected_hostname(
    encoded: &str,
    endpoint: &reqwest::Url,
    expected_hostname: &str,
) -> bool {
    // `Url` normalizes case, trailing dots, and IDNA. Compare both its domain
    // variant and the literal authority host so an alternate spelling cannot
    // enter the mTLS trust boundary.
    endpoint.domain() == Some(expected_hostname)
        && raw_authority_hostname(encoded) == Some(expected_hostname)
}

fn raw_authority_hostname(encoded: &str) -> Option<&str> {
    let authority = encoded
        .strip_prefix("https://")?
        .split(['/', '?', '#'])
        .next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((hostname, port)) if !hostname.is_empty() && !port.is_empty() => port
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then_some(hostname),
        Some(_) => None,
        None => Some(authority),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> BridgeConfig {
        BridgeConfig {
            format: CONFIG_FORMAT,
            tenant_slug: "tenant-one".into(),
            kerberos_realm: "EXAMPLE.COM".into(),
            release_revision: "952fb93373a6".into(),
            vfs_url: "https://filebelt-vfs.filebelt.svc:8087/internal/v1/vfs/execute".into(),
            ipc_socket: REQUIRED_IPC_SOCKET.into(),
            ganesha_control_socket: REQUIRED_CONTROL_SOCKET.into(),
            state_file: REQUIRED_STATE_FILE.into(),
            tls: ClientTlsConfig {
                certificate_chain_file: REQUIRED_TLS_CERTIFICATE.into(),
                private_key_file: REQUIRED_TLS_PRIVATE_KEY.into(),
                server_ca_file: REQUIRED_TLS_SERVER_CA.into(),
            },
        }
    }

    #[test]
    fn accepts_only_the_pinned_runtime_shape() {
        valid()
            .validate_against_expected_hostname("filebelt-vfs.filebelt.svc")
            .expect("valid config");
        for invalid in ["Tenant", "tenant-", "-tenant", "tenant_one", ""] {
            let mut config = valid();
            config.tenant_slug = invalid.into();
            assert!(
                config
                    .validate_against_expected_hostname("filebelt-vfs.filebelt.svc")
                    .is_err(),
                "tenant slug {invalid:?}"
            );
        }
        for invalid in ["example.com", "EXAMPLE_COM", ".EXAMPLE", "EXAMPLE."] {
            let mut config = valid();
            config.kerberos_realm = invalid.into();
            assert!(
                config
                    .validate_against_expected_hostname("filebelt-vfs.filebelt.svc")
                    .is_err(),
                "realm {invalid:?}"
            );
        }
    }

    #[test]
    fn rejects_downgraded_endpoints_and_secret_path_substitution() {
        for endpoint in [
            "http://filebelt-vfs/internal/v1/vfs/execute",
            "https://user@filebelt-vfs/internal/v1/vfs/execute",
            "https://filebelt-vfs/internal/v1/vfs/execute?tenant=other",
            "https://filebelt-vfs/other",
        ] {
            let mut config = valid();
            config.vfs_url = endpoint.into();
            assert!(
                config
                    .validate_against_expected_hostname("filebelt-vfs.filebelt.svc")
                    .is_err(),
                "endpoint {endpoint:?}"
            );
        }
        let mut config = valid();
        config.tls.private_key_file = "/tmp/key.pem".into();
        assert!(
            config
                .validate_against_expected_hostname("filebelt-vfs.filebelt.svc")
                .is_err()
        );
    }

    #[test]
    fn vfs_endpoint_requires_the_exact_injected_service_hostname() {
        let expected = "filebelt-vfs.filebelt.svc";
        valid()
            .validate_against_expected_hostname(expected)
            .expect("exact service hostname");
        for hostname in [
            "filebelt-vfs",
            "127.0.0.1",
            "filebelt-vfs.filebelt.svc.",
            "FILEBELT-VFS.filebelt.svc",
            "filebelt-vfs.other.svc",
            "xn--filebelt-vfs-9za.filebelt.svc",
        ] {
            let mut config = valid();
            config.vfs_url = format!("https://{hostname}:8087/internal/v1/vfs/execute");
            assert!(
                config.validate_against_expected_hostname(expected).is_err(),
                "endpoint hostname {hostname:?}"
            );
        }
        for invalid in [
            "filebelt-vfs",
            "127.0.0.1",
            "filebelt-vfs.filebelt.svc.",
            "FILEBELT-VFS.filebelt.svc",
            "filebelt-vfs.filebelt.cluster.local",
        ] {
            assert!(
                !valid_expected_vfs_hostname(invalid),
                "expected hostname {invalid:?}"
            );
        }
    }

    #[test]
    fn expected_vfs_hostname_environment_is_required_and_service_shaped() {
        assert!(matches!(
            required_expected_vfs_hostname(Err(std::env::VarError::NotPresent)),
            Err(ConfigError::Invalid)
        ));
        assert_eq!(
            required_expected_vfs_hostname(Ok("filebelt-vfs.filebelt.svc".into())).unwrap(),
            "filebelt-vfs.filebelt.svc"
        );
        assert!(matches!(
            required_expected_vfs_hostname(Ok("filebelt-vfs".into())),
            Err(ConfigError::Invalid)
        ));
    }

    #[test]
    fn unknown_fields_are_not_accepted() {
        let encoded = r#"
format = 1
tenant_slug = "tenant-one"
kerberos_realm = "EXAMPLE.COM"
release_revision = "952fb93373a6"
vfs_url = "https://filebelt-vfs/internal/v1/vfs/execute"
ipc_socket = "/run/filebelt-nfs/bridge.sock"
ganesha_control_socket = "/run/filebelt-nfs/ganesha-control.sock"
state_file = "/run/filebelt-nfs/gateway.state"
database_url = "postgres://forbidden"
[tls]
certificate_chain_file = "/run/secrets/nfs-bridge-vfs-client-tls/tls.crt"
private_key_file = "/run/secrets/nfs-bridge-vfs-client-tls/tls.key"
server_ca_file = "/run/secrets/nfs-bridge-vfs-client-tls/server-ca.crt"
"#;
        assert!(toml::from_str::<BridgeConfig>(encoded).is_err());
    }
}

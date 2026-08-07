// SPDX-License-Identifier: Apache-2.0

//! Versioned, typed FileBelt runtime configuration.

#![deny(unsafe_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const CONFIG_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub deployment: DeploymentConfig,
    pub public_origin: Url,
    pub tenant: TenantConfig,
    pub database: DatabaseConfig,
    pub oidc: OidcConfig,
    pub storage: StorageConfig,
    pub keys: KeyConfig,
    #[serde(default)]
    pub backend_tls: Option<BackendTlsConfig>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub listeners: ListenerConfig,
    #[serde(default)]
    pub limits: LimitConfig,
    #[serde(default)]
    pub iggy: Option<IggyConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    Development,
    Kubernetes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub mode: DeploymentMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub slug: String,
    #[serde(default)]
    pub administrator: Vec<ExternalSubject>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSubject {
    pub issuer: Url,
    pub subject: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url_file: PathBuf,
    #[serde(default = "default_database_connections")]
    pub max_connections: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: Url,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    #[serde(default = "default_callback_path")]
    pub callback_path: String,
    #[serde(default)]
    pub required_acr: Option<String>,
    #[serde(default)]
    pub custom_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub egress_proxy_url: Option<Url>,
    #[serde(default)]
    pub development_allow_insecure: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendTlsConfig {
    pub api: BackendServerTlsConfig,
    pub io: BackendServerTlsConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendServerTlsConfig {
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
    pub client_ca_file: PathBuf,
    pub allowed_client_uri_sans: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,
    #[serde(default)]
    pub prometheus_enabled: bool,
    #[serde(default)]
    pub otlp_http_endpoint: Option<Url>,
    #[serde(default)]
    pub otlp_custom_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub otlp_header_files: std::collections::BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub trace_sample_ratio: Option<f64>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_format: LogFormat::Text,
            prometheus_enabled: false,
            otlp_http_endpoint: None,
            otlp_custom_ca_file: None,
            otlp_header_files: std::collections::BTreeMap::new(),
            trace_sample_ratio: None,
        }
    }
}

impl TelemetryConfig {
    #[must_use]
    pub fn effective_trace_sample_ratio(&self) -> f64 {
        self.trace_sample_ratio
            .unwrap_or(if self.otlp_http_endpoint.is_some() {
                0.1
            } else {
                0.0
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub root: PathBuf,
    pub backend_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub capability_private_key_file: PathBuf,
    pub capability_public_key_file: PathBuf,
    pub digest_key_file: PathBuf,
    #[serde(default = "default_key_generation")]
    pub current_generation: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    #[serde(default = "default_api_listener")]
    pub api: SocketAddr,
    #[serde(default = "default_io_listener")]
    pub io: SocketAddr,
    #[serde(default = "default_operations_listener")]
    pub operations: SocketAddr,
    /// Permit an unspecified bind address inside an explicitly isolated
    /// container network.
    #[serde(default)]
    pub allow_container_wildcard: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            api: default_api_listener(),
            io: default_io_listener(),
            operations: default_operations_listener(),
            allow_container_wildcard: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    #[serde(default = "default_whole_threshold")]
    pub whole_threshold_bytes: u64,
    #[serde(default = "default_chunk_size")]
    pub chunk_size_bytes: u64,
    #[serde(default = "default_max_parts")]
    pub max_parts: u32,
    #[serde(default = "default_max_file")]
    pub max_file_bytes: u64,
    #[serde(default = "default_upload_ttl")]
    pub upload_ttl_seconds: u64,
    #[serde(default = "default_generation_recheck")]
    pub generation_recheck_seconds: u64,
    #[serde(default = "default_orphan_grace")]
    pub orphan_grace_seconds: u64,
    #[serde(default = "default_expired_part_grace")]
    pub expired_part_grace_seconds: u64,
    #[serde(default = "default_private_quota")]
    pub private_drive_quota_bytes: u64,
    #[serde(default = "default_shared_quota")]
    pub shared_drive_quota_bytes: u64,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            whole_threshold_bytes: default_whole_threshold(),
            chunk_size_bytes: default_chunk_size(),
            max_parts: default_max_parts(),
            max_file_bytes: default_max_file(),
            upload_ttl_seconds: default_upload_ttl(),
            generation_recheck_seconds: default_generation_recheck(),
            orphan_grace_seconds: default_orphan_grace(),
            expired_part_grace_seconds: default_expired_part_grace(),
            private_drive_quota_bytes: default_private_quota(),
            shared_drive_quota_bytes: default_shared_quota(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IggyConfig {
    pub endpoint: String,
    #[serde(default = "default_iggy_stream")]
    pub stream: String,
    #[serde(default = "default_iggy_partitions")]
    pub partitions: u32,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("configuration is invalid: {0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let source = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&source)?;
        config.apply_environment()?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(invalid("unsupported config version"));
        }
        if self.public_origin.scheme() != "https"
            || self.public_origin.path() != "/"
            || self.public_origin.query().is_some()
            || self.public_origin.fragment().is_some()
        {
            return Err(invalid("public_origin must be a bare https origin"));
        }
        if self.tenant.slug.is_empty()
            || self.tenant.slug.len() > 63
            || !self
                .tenant
                .slug
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(invalid("tenant slug must be lowercase ASCII"));
        }
        if self.tenant.administrator.is_empty() {
            return Err(invalid(
                "at least one exact administrator subject is required",
            ));
        }
        if self.oidc.issuer.scheme() != "https" && !self.oidc.development_allow_insecure {
            return Err(invalid("OIDC issuer must use https"));
        }
        if let Some(proxy) = &self.oidc.egress_proxy_url
            && (!matches!(proxy.scheme(), "http" | "https")
                || proxy.host_str().is_none()
                || proxy.port().is_none()
                || !proxy.username().is_empty()
                || proxy.password().is_some()
                || proxy.path() != "/"
                || proxy.query().is_some()
                || proxy.fragment().is_some())
        {
            return Err(invalid(
                "OIDC egress proxy must be a credential-free HTTP(S) origin with a port",
            ));
        }
        if self.oidc.callback_path != "/api/v1/auth/callback" {
            return Err(invalid("OIDC callback path is not allowlisted"));
        }
        if !self.database.url_file.is_absolute()
            || !self.oidc.client_secret_file.is_absolute()
            || !self.storage.root.is_absolute()
            || !self.keys.capability_private_key_file.is_absolute()
            || !self.keys.capability_public_key_file.is_absolute()
            || !self.keys.digest_key_file.is_absolute()
            || self
                .oidc
                .custom_ca_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || self
                .telemetry
                .otlp_custom_ca_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || self
                .telemetry
                .otlp_header_files
                .values()
                .any(|path| !path.is_absolute())
        {
            return Err(invalid("secret and storage paths must be absolute"));
        }
        if !self.listeners.allow_container_wildcard
            && (self.listeners.api.ip().is_unspecified()
                || self.listeners.io.ip().is_unspecified()
                || self.listeners.operations.ip().is_unspecified())
        {
            return Err(invalid(
                "backend wildcard listeners require allow_container_wildcard",
            ));
        }
        if let Some(tls) = &self.backend_tls {
            validate_backend_tls(&tls.api)?;
            validate_backend_tls(&tls.io)?;
            let api_identities = tls
                .api
                .allowed_client_uri_sans
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            if tls
                .io
                .allowed_client_uri_sans
                .iter()
                .any(|identity| api_identities.contains(identity))
            {
                return Err(invalid(
                    "API and I/O backend TLS client identities must not overlap",
                ));
            }
        }
        let sample_ratio = self.telemetry.effective_trace_sample_ratio();
        if !sample_ratio.is_finite() || !(0.0..=1.0).contains(&sample_ratio) {
            return Err(invalid("trace sample ratio must be from 0 through 1"));
        }
        if let Some(endpoint) = &self.telemetry.otlp_http_endpoint
            && (!matches!(endpoint.scheme(), "http" | "https")
                || endpoint.host_str().is_none()
                || endpoint.path() != "/v1/traces"
                || endpoint.query().is_some()
                || endpoint.fragment().is_some())
        {
            return Err(invalid("OTLP endpoint must be an HTTP(S) /v1/traces URL"));
        }
        for header in self.telemetry.otlp_header_files.keys() {
            if header.is_empty()
                || !header
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid("OTLP header name is invalid"));
            }
        }
        if self.deployment.mode == DeploymentMode::Kubernetes
            && (self.oidc.development_allow_insecure
                || self.oidc.issuer.scheme() != "https"
                || self.oidc.egress_proxy_url.is_none()
                || self.backend_tls.is_none()
                || self.telemetry.log_format != LogFormat::Json
                || !self.telemetry.prometheus_enabled)
        {
            return Err(invalid(
                "Kubernetes mode requires HTTPS OIDC through an egress proxy, backend mTLS, JSON logs, and Prometheus metrics",
            ));
        }
        let limits = &self.limits;
        if limits.whole_threshold_bytes > 1_073_741_824 {
            return Err(invalid("whole threshold exceeds 1 GiB"));
        }
        if !(1_048_576..=268_435_456).contains(&limits.chunk_size_bytes)
            || !limits.chunk_size_bytes.is_power_of_two()
        {
            return Err(invalid(
                "chunk size must be a power of two from 1 to 256 MiB",
            ));
        }
        if !(1..=1_048_576).contains(&limits.max_parts) {
            return Err(invalid("part count is outside the accepted envelope"));
        }
        if !(1_048_576..=70_368_744_177_664).contains(&limits.max_file_bytes) {
            return Err(invalid("maximum file is outside 1 MiB to 64 TiB"));
        }
        if limits
            .chunk_size_bytes
            .checked_mul(u64::from(limits.max_parts))
            .is_none_or(|capacity| capacity < limits.max_file_bytes)
        {
            return Err(invalid(
                "chunk size and part count cannot represent maximum file",
            ));
        }
        if !(300..=2_592_000).contains(&limits.upload_ttl_seconds) {
            return Err(invalid("upload lifetime is outside 5 minutes to 30 days"));
        }
        if !(1..=60).contains(&limits.generation_recheck_seconds) {
            return Err(invalid("generation recheck must be 1 to 60 seconds"));
        }
        if !(3_600..=2_592_000).contains(&limits.orphan_grace_seconds)
            || limits.expired_part_grace_seconds > 604_800
        {
            return Err(invalid(
                "storage grace period is outside the accepted envelope",
            ));
        }
        if !(1_073_741_824..=1_125_899_906_842_624).contains(&limits.private_drive_quota_bytes)
            || !(1_073_741_824..=1_125_899_906_842_624).contains(&limits.shared_drive_quota_bytes)
        {
            return Err(invalid("drive quota is outside 1 GiB to 1 PiB"));
        }
        if self.keys.current_generation == 0 {
            return Err(invalid("key generation must be positive"));
        }
        if let Some(iggy) = &self.iggy
            && (iggy.stream != "filebelt" || iggy.partitions != 16)
        {
            return Err(invalid(
                "Phase 2 Iggy topology is one filebelt stream with 16 partitions",
            ));
        }
        Ok(())
    }

    fn apply_environment(&mut self) -> Result<(), ConfigError> {
        if let Ok(value) = std::env::var("FILEBELT_PUBLIC_ORIGIN") {
            self.public_origin =
                Url::parse(&value).map_err(|_| invalid("FILEBELT_PUBLIC_ORIGIN is invalid"))?;
        }
        if let Ok(value) = std::env::var("FILEBELT_DATABASE_URL_FILE") {
            self.database.url_file = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("FILEBELT_STORAGE_ROOT") {
            self.storage.root = PathBuf::from(value);
        }
        Ok(())
    }
}

fn validate_backend_tls(tls: &BackendServerTlsConfig) -> Result<(), ConfigError> {
    if !tls.certificate_chain_file.is_absolute()
        || !tls.private_key_file.is_absolute()
        || !tls.client_ca_file.is_absolute()
    {
        return Err(invalid("backend TLS paths must be absolute"));
    }
    if !(1..=2).contains(&tls.allowed_client_uri_sans.len()) {
        return Err(invalid(
            "backend TLS requires one or two allowed client URI SANs",
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for identity in &tls.allowed_client_uri_sans {
        let uri = Url::parse(identity).map_err(|_| invalid("client URI SAN is invalid"))?;
        if uri.scheme() != "spiffe"
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.port().is_some()
            || uri.path() == "/"
            || uri.query().is_some()
            || uri.fragment().is_some()
            || !unique.insert(identity)
        {
            return Err(invalid(
                "client URI SAN must be a unique absolute spiffe URI",
            ));
        }
    }
    Ok(())
}

pub fn read_secret(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = fs::read(path)?;
    while bytes.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(invalid("secret file is empty"));
    }
    Ok(bytes)
}
pub fn read_secret_string(path: &Path) -> Result<String, ConfigError> {
    String::from_utf8(read_secret(path)?).map_err(|_| invalid("secret file is not UTF-8"))
}
fn invalid(message: &str) -> ConfigError {
    ConfigError::Invalid(message.into())
}
const fn default_database_connections() -> u32 {
    16
}
fn default_callback_path() -> String {
    "/api/v1/auth/callback".into()
}
const fn default_log_format() -> LogFormat {
    LogFormat::Text
}
const fn default_key_generation() -> u32 {
    1
}
fn default_api_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}
fn default_io_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8081))
}
fn default_operations_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9090))
}
const fn default_whole_threshold() -> u64 {
    33_554_432
}
const fn default_chunk_size() -> u64 {
    16_777_216
}
const fn default_max_parts() -> u32 {
    65_536
}
const fn default_max_file() -> u64 {
    1_099_511_627_776
}
const fn default_upload_ttl() -> u64 {
    604_800
}
const fn default_generation_recheck() -> u64 {
    60
}
const fn default_orphan_grace() -> u64 {
    86_400
}
const fn default_expired_part_grace() -> u64 {
    86_400
}
const fn default_private_quota() -> u64 {
    1_099_511_627_776
}
const fn default_shared_quota() -> u64 {
    10_995_116_277_760
}
fn default_iggy_stream() -> String {
    "filebelt".into()
}
const fn default_iggy_partitions() -> u32 {
    16
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            version: CONFIG_VERSION,
            deployment: DeploymentConfig {
                mode: DeploymentMode::Development,
            },
            public_origin: Url::parse("https://files.example.test/").unwrap(),
            tenant: TenantConfig {
                slug: "example".into(),
                administrator: vec![ExternalSubject {
                    issuer: Url::parse("https://id.example.test/").unwrap(),
                    subject: "admin".into(),
                }],
            },
            database: DatabaseConfig {
                url_file: "/run/secrets/database-url".into(),
                max_connections: 16,
            },
            oidc: OidcConfig {
                issuer: Url::parse("https://id.example.test/").unwrap(),
                client_id: "filebelt".into(),
                client_secret_file: "/run/secrets/oidc-secret".into(),
                callback_path: default_callback_path(),
                required_acr: None,
                custom_ca_file: None,
                egress_proxy_url: None,
                development_allow_insecure: false,
            },
            storage: StorageConfig {
                root: "/var/lib/filebelt".into(),
                backend_id: Uuid::new_v4(),
            },
            keys: KeyConfig {
                capability_private_key_file: "/run/secrets/capability.pk8".into(),
                capability_public_key_file: "/run/secrets/capability.pub".into(),
                digest_key_file: "/run/secrets/digest-key".into(),
                current_generation: 1,
            },
            backend_tls: None,
            telemetry: TelemetryConfig::default(),
            listeners: ListenerConfig::default(),
            limits: LimitConfig::default(),
            iggy: None,
        }
    }
    #[test]
    fn defaults_validate() {
        config().validate().unwrap();
    }
    #[test]
    fn unsafe_listener_fails() {
        let mut candidate = config();
        candidate.listeners.api = SocketAddr::from(([0, 0, 0, 0], 8080));
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn explicit_container_listener_validates() {
        let mut candidate = config();
        candidate.listeners.api = SocketAddr::from(([0, 0, 0, 0], 8080));
        candidate.listeners.allow_container_wildcard = true;
        candidate.validate().unwrap();
    }
    #[test]
    fn inconsistent_chunk_capacity_fails() {
        let mut candidate = config();
        candidate.limits.max_parts = 1;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn version_one_is_rejected() {
        let mut candidate = config();
        candidate.version = 1;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn kubernetes_mode_fails_without_security_contract() {
        let mut candidate = config();
        candidate.deployment.mode = DeploymentMode::Kubernetes;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn kubernetes_security_contract_validates() {
        let mut candidate = config();
        candidate.deployment.mode = DeploymentMode::Kubernetes;
        candidate.oidc.egress_proxy_url = Some(Url::parse("http://oidc-egress:3128/").unwrap());
        candidate.telemetry.log_format = LogFormat::Json;
        candidate.telemetry.prometheus_enabled = true;
        let api_tls = BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: vec!["spiffe://filebelt.test/web-api".into()],
        };
        candidate.backend_tls = Some(BackendTlsConfig {
            api: api_tls,
            io: BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/tls.crt".into(),
                private_key_file: "/run/secrets/tls.key".into(),
                client_ca_file: "/run/secrets/client-ca.crt".into(),
                allowed_client_uri_sans: vec!["spiffe://filebelt.test/web-io".into()],
            },
        });
        candidate.validate().unwrap();
    }
    #[test]
    fn backend_tls_rejects_identity_overlap_between_api_and_io() {
        let mut candidate = config();
        let shared = BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: vec!["spiffe://filebelt.test/web".into()],
        };
        candidate.backend_tls = Some(BackendTlsConfig {
            api: shared.clone(),
            io: shared,
        });
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn backend_tls_rejects_duplicate_rotation_identity() {
        let tls = BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: vec![
                "spiffe://filebelt.test/web".into(),
                "spiffe://filebelt.test/web".into(),
            ],
        };
        assert!(validate_backend_tls(&tls).is_err());
    }
    #[test]
    fn telemetry_defaults_are_bounded() {
        let mut telemetry = TelemetryConfig::default();
        assert_eq!(telemetry.effective_trace_sample_ratio(), 0.0);
        telemetry.otlp_http_endpoint = Some(Url::parse("http://collector:4318/v1/traces").unwrap());
        assert_eq!(telemetry.effective_trace_sample_ratio(), 0.1);
        telemetry.trace_sample_ratio = Some(1.1);
        let mut candidate = config();
        candidate.telemetry = telemetry;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn helm_default_embeds_valid_kubernetes_configuration() {
        let values = include_str!("../../../../deploy/helm/filebelt/values.yaml");
        let mut in_filebelt = false;
        let mut source = String::new();
        for line in values.lines() {
            if line == "  filebelt: |" {
                in_filebelt = true;
                continue;
            }
            if in_filebelt && line.starts_with("  oxibelt:") {
                break;
            }
            if in_filebelt {
                source.push_str(line.strip_prefix("    ").unwrap_or(line));
                source.push('\n');
            }
        }
        assert!(!source.is_empty(), "Helm FileBelt config block is absent");
        let configuration: Config = toml::from_str(&source).unwrap();
        configuration.validate().unwrap();
        assert_eq!(configuration.deployment.mode, DeploymentMode::Kubernetes);
    }
}

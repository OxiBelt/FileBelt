// SPDX-License-Identifier: Apache-2.0

//! Versioned, typed FileBelt runtime configuration.

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const CONFIG_VERSION: u32 = 5;

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
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub collaboration: CollaborationConfig,
    #[serde(default)]
    pub mounts: MountConfig,
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
    #[serde(default)]
    pub mcp_broker: Option<BackendServerTlsConfig>,
    #[serde(default)]
    pub controller: Option<BackendServerTlsConfig>,
    #[serde(default)]
    pub collaboration: Option<BackendServerTlsConfig>,
    #[serde(default)]
    pub vfs: Option<BackendServerTlsConfig>,
    #[serde(default)]
    pub vfs_management: Option<BackendServerTlsConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendServerTlsConfig {
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
    pub client_ca_file: PathBuf,
    pub allowed_client_uri_sans: Vec<String>,
    #[serde(default)]
    pub allowed_client_trust_domains: Vec<String>,
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
    #[serde(default = "default_mcp_broker_listener")]
    pub mcp_broker: SocketAddr,
    #[serde(default = "default_mcp_runner_relay_listener")]
    pub mcp_runner_relay: SocketAddr,
    #[serde(default = "default_controller_listener")]
    pub controller: SocketAddr,
    #[serde(default = "default_collaboration_ws_listener")]
    pub collaboration_ws: SocketAddr,
    #[serde(default = "default_collaboration_webtransport_listener")]
    pub collaboration_webtransport: SocketAddr,
    #[serde(default = "default_vfs_listener")]
    pub vfs: SocketAddr,
    #[serde(default = "default_vfs_management_listener")]
    pub vfs_management: SocketAddr,
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
            mcp_broker: default_mcp_broker_listener(),
            mcp_runner_relay: default_mcp_runner_relay_listener(),
            controller: default_controller_listener(),
            collaboration_ws: default_collaboration_ws_listener(),
            collaboration_webtransport: default_collaboration_webtransport_listener(),
            vfs: default_vfs_listener(),
            vfs_management: default_vfs_management_listener(),
            allow_container_wildcard: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    #[serde(default)]
    pub vault_keyring_file: Option<PathBuf>,
    #[serde(default = "default_key_generation")]
    pub vault_key_generation: u32,
    #[serde(default)]
    pub capability_private_key_file: Option<PathBuf>,
    #[serde(default = "default_mount_capability_key_generation")]
    pub capability_key_generation: u32,
    #[serde(default)]
    pub io_url: Option<Url>,
    #[serde(default)]
    pub io_client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub io_client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub io_server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub management_url: Option<Url>,
    #[serde(default)]
    pub management_client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub management_client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub management_server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub headscale: HeadscaleSyncConfig,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url_file: None,
            vault_keyring_file: None,
            vault_key_generation: default_key_generation(),
            capability_private_key_file: None,
            capability_key_generation: default_mount_capability_key_generation(),
            io_url: None,
            io_client_certificate_chain_file: None,
            io_client_private_key_file: None,
            io_server_ca_file: None,
            management_url: None,
            management_client_certificate_chain_file: None,
            management_client_private_key_file: None,
            management_server_ca_file: None,
            headscale: HeadscaleSyncConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadscaleSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub api_url: Option<Url>,
    #[serde(default)]
    pub api_token_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub oidc_issuer: Option<Url>,
    #[serde(default = "default_headscale_sync_seconds")]
    pub sync_seconds: u64,
}

impl Default for HeadscaleSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: None,
            api_token_file: None,
            server_ca_file: None,
            oidc_issuer: None,
            sync_seconds: default_headscale_sync_seconds(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollaborationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    #[serde(default)]
    pub capability_private_key_file: Option<PathBuf>,
    #[serde(default = "default_collaboration_capability_key_generation")]
    pub capability_key_generation: u32,
    #[serde(default)]
    pub io_url: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub webtransport_enabled: bool,
    #[serde(default)]
    pub limits: CollaborationLimitConfig,
}

impl Default for CollaborationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url_file: None,
            capability_private_key_file: None,
            capability_key_generation: default_collaboration_capability_key_generation(),
            io_url: None,
            client_certificate_chain_file: None,
            client_private_key_file: None,
            server_ca_file: None,
            webtransport_enabled: false,
            limits: CollaborationLimitConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollaborationLimitConfig {
    #[serde(default = "default_collaboration_participants")]
    pub max_participants: u32,
    #[serde(default = "default_collaboration_update_bytes")]
    pub max_update_bytes: u64,
    #[serde(default = "default_collaboration_group_bytes")]
    pub max_operation_group_bytes: u64,
    #[serde(default = "default_collaboration_client_updates")]
    pub client_updates_per_second: u32,
    #[serde(default = "default_collaboration_client_bytes")]
    pub client_bytes_per_second: u64,
    #[serde(default = "default_collaboration_room_updates")]
    pub room_updates_per_second: u32,
    #[serde(default = "default_collaboration_room_bytes")]
    pub room_bytes_per_second: u64,
    #[serde(default = "default_collaboration_awareness_bytes")]
    pub max_awareness_bytes: u64,
    #[serde(default = "default_collaboration_client_awareness")]
    pub client_awareness_per_second: u32,
    #[serde(default = "default_collaboration_room_awareness")]
    pub room_awareness_per_second: u32,
    #[serde(default = "default_collaboration_state_bytes")]
    pub max_state_bytes: u64,
    #[serde(default = "default_collaboration_retained_bytes")]
    pub max_retained_room_bytes: u64,
    #[serde(default = "default_collaboration_recheck_seconds")]
    pub generation_recheck_seconds: u64,
    #[serde(default = "default_collaboration_dirty_retention_seconds")]
    pub dirty_retention_seconds: u64,
    #[serde(default = "default_collaboration_warning_seconds")]
    pub expiry_warning_seconds: u64,
}

impl Default for CollaborationLimitConfig {
    fn default() -> Self {
        Self {
            max_participants: default_collaboration_participants(),
            max_update_bytes: default_collaboration_update_bytes(),
            max_operation_group_bytes: default_collaboration_group_bytes(),
            client_updates_per_second: default_collaboration_client_updates(),
            client_bytes_per_second: default_collaboration_client_bytes(),
            room_updates_per_second: default_collaboration_room_updates(),
            room_bytes_per_second: default_collaboration_room_bytes(),
            max_awareness_bytes: default_collaboration_awareness_bytes(),
            client_awareness_per_second: default_collaboration_client_awareness(),
            room_awareness_per_second: default_collaboration_room_awareness(),
            max_state_bytes: default_collaboration_state_bytes(),
            max_retained_room_bytes: default_collaboration_retained_bytes(),
            generation_recheck_seconds: default_collaboration_recheck_seconds(),
            dirty_retention_seconds: default_collaboration_dirty_retention_seconds(),
            expiry_warning_seconds: default_collaboration_warning_seconds(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    #[serde(default = "default_mcp_callback_path")]
    pub callback_path: String,
    #[serde(default)]
    pub broker: McpBrokerClientConfig,
    #[serde(default)]
    pub vault: McpVaultConfig,
    #[serde(default)]
    pub egress: McpEgressConfig,
    #[serde(default)]
    pub attachments: McpAttachmentConfig,
    #[serde(default)]
    pub trust_profiles: BTreeMap<String, McpTrustProfile>,
    #[serde(default)]
    pub oauth_clients: BTreeMap<String, McpOauthClient>,
    #[serde(default)]
    pub service_trust_domains: Vec<String>,
    #[serde(default)]
    pub limits: McpLimitConfig,
    #[serde(default)]
    pub runners: McpRunnerConfig,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url_file: None,
            callback_path: default_mcp_callback_path(),
            broker: McpBrokerClientConfig::default(),
            vault: McpVaultConfig::default(),
            egress: McpEgressConfig::default(),
            attachments: McpAttachmentConfig::default(),
            trust_profiles: BTreeMap::new(),
            oauth_clients: BTreeMap::new(),
            service_trust_domains: Vec::new(),
            limits: McpLimitConfig::default(),
            runners: McpRunnerConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpBrokerClientConfig {
    #[serde(default)]
    pub url: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpVaultConfig {
    #[serde(default)]
    pub keyring_file: Option<PathBuf>,
    #[serde(default = "default_key_generation")]
    pub current_generation: u32,
}

impl Default for McpVaultConfig {
    fn default() -> Self {
        Self {
            keyring_file: None,
            current_generation: default_key_generation(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEgressConfig {
    #[serde(default)]
    pub gateway_url: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAttachmentConfig {
    #[serde(default)]
    pub io_url: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTrustProfile {
    #[serde(default)]
    pub public_webpki: bool,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default = "default_https_ports")]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub custom_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub allow_dynamic_client_registration: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpOauthClient {
    pub issuer: Url,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpLimitConfig {
    #[serde(default = "default_mcp_connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_mcp_discovery_timeout")]
    pub discovery_timeout_seconds: u64,
    #[serde(default = "default_mcp_progress_idle_timeout")]
    pub progress_idle_timeout_seconds: u64,
    #[serde(default = "default_mcp_operation_timeout")]
    pub operation_timeout_seconds: u64,
    #[serde(default = "default_mcp_absolute_timeout")]
    pub absolute_timeout_seconds: u64,
    #[serde(default = "default_mcp_message_bytes")]
    pub message_bytes: u64,
    #[serde(default = "default_mcp_result_bytes")]
    pub result_bytes: u64,
    #[serde(default = "default_mcp_attachment_bytes")]
    pub attachment_bytes: u64,
    #[serde(default = "default_mcp_attachment_hard_bytes")]
    pub attachment_hard_bytes: u64,
    #[serde(default = "default_mcp_encoded_wire_bytes")]
    pub encoded_wire_bytes: u64,
    #[serde(default = "default_mcp_principal_concurrency")]
    pub principal_concurrency: u32,
    #[serde(default = "default_mcp_registration_concurrency")]
    pub registration_concurrency: u32,
    #[serde(default = "default_mcp_replica_concurrency")]
    pub replica_concurrency: u32,
    #[serde(default = "default_mcp_queue_depth")]
    pub queue_depth: u32,
}

impl Default for McpLimitConfig {
    fn default() -> Self {
        Self {
            connect_timeout_seconds: default_mcp_connect_timeout(),
            discovery_timeout_seconds: default_mcp_discovery_timeout(),
            progress_idle_timeout_seconds: default_mcp_progress_idle_timeout(),
            operation_timeout_seconds: default_mcp_operation_timeout(),
            absolute_timeout_seconds: default_mcp_absolute_timeout(),
            message_bytes: default_mcp_message_bytes(),
            result_bytes: default_mcp_result_bytes(),
            attachment_bytes: default_mcp_attachment_bytes(),
            attachment_hard_bytes: default_mcp_attachment_hard_bytes(),
            encoded_wire_bytes: default_mcp_encoded_wire_bytes(),
            principal_concurrency: default_mcp_principal_concurrency(),
            registration_concurrency: default_mcp_registration_concurrency(),
            replica_concurrency: default_mcp_replica_concurrency(),
            queue_depth: default_mcp_queue_depth(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRunnerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mcp_runner_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub catalog_file: Option<PathBuf>,
    #[serde(default)]
    pub trusted_root_file: Option<PathBuf>,
    #[serde(default)]
    pub bundle_directory: Option<PathBuf>,
    #[serde(default)]
    pub runner_image: Option<String>,
    #[serde(default)]
    pub controller_url: Option<Url>,
    #[serde(default)]
    pub controller_client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub controller_client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub controller_server_ca_file: Option<PathBuf>,
    #[serde(default = "default_mcp_runner_per_principal")]
    pub max_per_principal: u32,
    #[serde(default = "default_mcp_runner_per_tenant")]
    pub max_per_tenant: u32,
}

impl Default for McpRunnerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            namespace: default_mcp_runner_namespace(),
            catalog_file: None,
            trusted_root_file: None,
            bundle_directory: None,
            runner_image: None,
            controller_url: None,
            controller_client_certificate_chain_file: None,
            controller_client_private_key_file: None,
            controller_server_ca_file: None,
            max_per_principal: default_mcp_runner_per_principal(),
            max_per_tenant: default_mcp_runner_per_tenant(),
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
                || self.listeners.operations.ip().is_unspecified()
                || (self.mcp.enabled && self.listeners.mcp_broker.ip().is_unspecified())
                || (self.mcp.runners.enabled
                    && self.listeners.mcp_runner_relay.ip().is_unspecified())
                || (self.mcp.runners.enabled && self.listeners.controller.ip().is_unspecified())
                || (self.collaboration.enabled
                    && self.listeners.collaboration_ws.ip().is_unspecified())
                || (self.collaboration.enabled
                    && self.collaboration.webtransport_enabled
                    && self
                        .listeners
                        .collaboration_webtransport
                        .ip()
                        .is_unspecified())
                || (self.mounts.enabled && self.listeners.vfs.ip().is_unspecified())
                || (self.mounts.enabled && self.listeners.vfs_management.ip().is_unspecified()))
        {
            return Err(invalid(
                "backend wildcard listeners require allow_container_wildcard",
            ));
        }
        if let Some(tls) = &self.backend_tls {
            validate_backend_tls(&tls.api)?;
            validate_backend_tls(&tls.io)?;
            if backend_tls_identity_policies_overlap(&tls.api, &tls.io) {
                return Err(invalid(
                    "API and I/O backend TLS client identities and trust domains must not overlap",
                ));
            }
            if let Some(broker) = &tls.mcp_broker {
                validate_backend_tls(broker)?;
            }
            if let Some(controller) = &tls.controller {
                validate_backend_tls(controller)?;
            }
            if let Some(collaboration) = &tls.collaboration {
                validate_backend_tls(collaboration)?;
            }
            if let Some(vfs) = &tls.vfs {
                validate_backend_tls(vfs)?;
            }
            if let Some(vfs_management) = &tls.vfs_management {
                validate_backend_tls(vfs_management)?;
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
        self.validate_mcp()?;
        self.validate_collaboration()?;
        self.validate_mounts()?;
        Ok(())
    }

    fn validate_mounts(&self) -> Result<(), ConfigError> {
        let mounts = &self.mounts;
        if !mounts.enabled {
            if mounts.headscale.enabled {
                return Err(invalid(
                    "Headscale synchronization requires mounts.enabled=true",
                ));
            }
            return Ok(());
        }
        if mounts.vault_key_generation == 0
            || mounts.capability_key_generation == 0
            || mounts.capability_key_generation == self.keys.current_generation
            || (self.collaboration.enabled
                && mounts.capability_key_generation == self.collaboration.capability_key_generation)
            || [
                mounts.database_url_file.as_ref(),
                mounts.vault_keyring_file.as_ref(),
                mounts.capability_private_key_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled mounts require absolute database, vault, and capability-key paths plus a distinct positive capability generation",
            ));
        }
        let expected_scheme = if self.deployment.mode == DeploymentMode::Kubernetes {
            "https"
        } else {
            "http"
        };
        let io_url = mounts
            .io_url
            .as_ref()
            .ok_or_else(|| invalid("enabled mounts require an internal I/O URL"))?;
        if io_url.scheme() != expected_scheme
            || io_url.host_str().is_none()
            || io_url.port().is_none()
            || io_url.path() != "/"
            || !io_url.username().is_empty()
            || io_url.password().is_some()
            || io_url.query().is_some()
            || io_url.fragment().is_some()
        {
            return Err(invalid("VFS I/O URL is invalid"));
        }
        let management = mounts
            .management_url
            .as_ref()
            .ok_or_else(|| invalid("enabled mounts require an internal VFS management URL"))?;
        if management.scheme() != expected_scheme
            || management.host_str().is_none()
            || management.port().is_none()
            || management.path() != "/"
            || !management.username().is_empty()
            || management.password().is_some()
            || management.query().is_some()
            || management.fragment().is_some()
        {
            return Err(invalid("VFS management URL is invalid"));
        }
        if self.deployment.mode == DeploymentMode::Kubernetes
            && (self
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.vfs.as_ref())
                .is_none()
                || self
                    .backend_tls
                    .as_ref()
                    .and_then(|tls| tls.vfs_management.as_ref())
                    .is_none()
                || [
                    mounts.io_client_certificate_chain_file.as_ref(),
                    mounts.io_client_private_key_file.as_ref(),
                    mounts.io_server_ca_file.as_ref(),
                    mounts.management_client_certificate_chain_file.as_ref(),
                    mounts.management_client_private_key_file.as_ref(),
                    mounts.management_server_ca_file.as_ref(),
                ]
                .into_iter()
                .any(|path| path.is_none_or(|path| !path.is_absolute())))
        {
            return Err(invalid(
                "Kubernetes mounts require separate VFS I/O and management mTLS identities",
            ));
        }
        let headscale = &mounts.headscale;
        if !headscale.enabled {
            return Ok(());
        }
        if !(5..=300).contains(&headscale.sync_seconds)
            || [
                headscale.api_token_file.as_ref(),
                headscale.server_ca_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "Headscale sync requires absolute token and CA paths and a 5 to 300 second interval",
            ));
        }
        let api = headscale
            .api_url
            .as_ref()
            .ok_or_else(|| invalid("Headscale sync requires an API URL"))?;
        if api.scheme() != "https"
            || api.host_str().is_none()
            || api.path() != "/"
            || !api.username().is_empty()
            || api.password().is_some()
            || api.query().is_some()
            || api.fragment().is_some()
        {
            return Err(invalid("Headscale API URL must be a bare HTTPS origin"));
        }
        let issuer = headscale
            .oidc_issuer
            .as_ref()
            .ok_or_else(|| invalid("Headscale sync requires the exact OIDC issuer"))?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err(invalid("Headscale OIDC issuer must use HTTPS"));
        }
        Ok(())
    }

    fn validate_collaboration(&self) -> Result<(), ConfigError> {
        let collaboration = &self.collaboration;
        validate_collaboration_limits(&collaboration.limits)?;
        if collaboration.webtransport_enabled {
            return Err(invalid(
                "WebTransport is reserved until the collaboration runtime listener is implemented",
            ));
        }
        if !collaboration.enabled {
            return Ok(());
        }
        if [
            collaboration.database_url_file.as_ref(),
            collaboration.capability_private_key_file.as_ref(),
        ]
        .into_iter()
        .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled collaboration requires absolute database and capability key paths",
            ));
        }
        if collaboration.capability_key_generation == 0
            || collaboration.capability_key_generation == self.keys.current_generation
        {
            return Err(invalid(
                "collaboration capability key generation must be positive and distinct from the API generation",
            ));
        }
        let io_url = collaboration
            .io_url
            .as_ref()
            .ok_or_else(|| invalid("enabled collaboration requires an internal I/O URL"))?;
        let expected_scheme = if self.deployment.mode == DeploymentMode::Kubernetes {
            "https"
        } else {
            "http"
        };
        if io_url.scheme() != expected_scheme
            || io_url.host_str().is_none()
            || io_url.port().is_none()
            || io_url.path() != "/"
            || io_url.query().is_some()
            || io_url.fragment().is_some()
            || !io_url.username().is_empty()
            || io_url.password().is_some()
        {
            return Err(invalid("collaboration internal I/O URL is invalid"));
        }
        if self.listeners.collaboration_ws == self.listeners.collaboration_webtransport {
            return Err(invalid(
                "collaboration WebSocket and WebTransport listeners must be distinct",
            ));
        }
        if self.deployment.mode == DeploymentMode::Kubernetes {
            if [
                collaboration.client_certificate_chain_file.as_ref(),
                collaboration.client_private_key_file.as_ref(),
                collaboration.server_ca_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
            {
                return Err(invalid(
                    "Kubernetes collaboration requires absolute I/O client TLS paths",
                ));
            }
            if self
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.collaboration.as_ref())
                .is_none()
            {
                return Err(invalid(
                    "Kubernetes collaboration requires backend mTLS configuration",
                ));
            }
        }
        Ok(())
    }

    fn validate_mcp(&self) -> Result<(), ConfigError> {
        let mcp = &self.mcp;
        if mcp.callback_path != "/api/v1/mcp/oauth/callback" {
            return Err(invalid("MCP OAuth callback path is not allowlisted"));
        }
        if !mcp.enabled {
            if mcp.runners.enabled {
                return Err(invalid("MCP runners require the MCP broker"));
            }
            return Ok(());
        }
        let required_paths = [
            mcp.database_url_file.as_ref(),
            mcp.vault.keyring_file.as_ref(),
            mcp.egress.client_certificate_chain_file.as_ref(),
            mcp.egress.client_private_key_file.as_ref(),
            mcp.egress.server_ca_file.as_ref(),
        ];
        if required_paths
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled MCP requires absolute database, vault, and gateway TLS paths",
            ));
        }
        let broker = mcp
            .broker
            .url
            .as_ref()
            .ok_or_else(|| invalid("enabled MCP requires an internal broker URL"))?;
        let expected_broker_scheme = if self.deployment.mode == DeploymentMode::Kubernetes {
            "https"
        } else {
            "http"
        };
        if broker.scheme() != expected_broker_scheme
            || broker.host_str().is_none()
            || broker.port().is_none()
            || !broker.username().is_empty()
            || broker.password().is_some()
            || broker.path() != "/"
            || broker.query().is_some()
            || broker.fragment().is_some()
        {
            return Err(invalid("MCP internal broker URL is invalid"));
        }
        if self.deployment.mode == DeploymentMode::Kubernetes
            && [
                mcp.broker.client_certificate_chain_file.as_ref(),
                mcp.broker.client_private_key_file.as_ref(),
                mcp.broker.server_ca_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "Kubernetes MCP requires absolute broker client TLS paths",
            ));
        }
        let io_url = mcp
            .attachments
            .io_url
            .as_ref()
            .ok_or_else(|| invalid("enabled MCP requires an internal I/O URL"))?;
        let expected_io_scheme = if self.deployment.mode == DeploymentMode::Kubernetes {
            "https"
        } else {
            "http"
        };
        if io_url.scheme() != expected_io_scheme
            || io_url.host_str().is_none()
            || io_url.port().is_none()
            || !io_url.username().is_empty()
            || io_url.password().is_some()
            || io_url.path() != "/"
            || io_url.query().is_some()
            || io_url.fragment().is_some()
        {
            return Err(invalid("MCP internal I/O URL is invalid"));
        }
        if self.deployment.mode == DeploymentMode::Kubernetes
            && [
                mcp.attachments.client_certificate_chain_file.as_ref(),
                mcp.attachments.client_private_key_file.as_ref(),
                mcp.attachments.server_ca_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "Kubernetes MCP attachment mediation requires absolute I/O client TLS paths",
            ));
        }
        let gateway = mcp
            .egress
            .gateway_url
            .as_ref()
            .ok_or_else(|| invalid("enabled MCP requires an egress gateway"))?;
        if gateway.scheme() != "https"
            || gateway.host_str().is_none()
            || gateway.port().is_none()
            || !gateway.username().is_empty()
            || gateway.password().is_some()
            || gateway.path() != "/"
            || gateway.query().is_some()
            || gateway.fragment().is_some()
        {
            return Err(invalid(
                "MCP egress gateway must be a credential-free HTTPS origin with a port",
            ));
        }
        if mcp.vault.current_generation == 0 {
            return Err(invalid("MCP vault key generation must be positive"));
        }
        if mcp.trust_profiles.is_empty() {
            return Err(invalid("enabled MCP requires at least one trust profile"));
        }
        for (name, profile) in &mcp.trust_profiles {
            validate_policy_name(name, "MCP trust profile")?;
            if profile.ports.is_empty() || profile.ports.contains(&0) {
                return Err(invalid("MCP trust profile ports must be non-zero"));
            }
            if profile
                .hosts
                .iter()
                .any(|host| !valid_dns_policy_name(host))
            {
                return Err(invalid("MCP trust profile host is invalid"));
            }
            if profile.cidrs.iter().any(|cidr| !valid_cidr(cidr)) {
                return Err(invalid("MCP trust profile CIDR is invalid"));
            }
            if profile
                .custom_ca_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            {
                return Err(invalid("MCP trust profile CA path must be absolute"));
            }
            if !profile.public_webpki && profile.hosts.is_empty() && profile.cidrs.is_empty() {
                return Err(invalid("private MCP trust profile requires hosts or CIDRs"));
            }
        }
        for (name, client) in &mcp.oauth_clients {
            validate_policy_name(name, "MCP OAuth client")?;
            if client.issuer.scheme() != "https"
                || client.issuer.query().is_some()
                || client.issuer.fragment().is_some()
                || client.client_id.is_empty()
                || client.client_id.len() > 512
                || client
                    .client_secret_file
                    .as_ref()
                    .is_some_and(|path| !path.is_absolute())
            {
                return Err(invalid("MCP OAuth client is invalid"));
            }
        }
        let mut trust_domains = std::collections::BTreeSet::new();
        for domain in &mcp.service_trust_domains {
            if !valid_dns_policy_name(domain) || !trust_domains.insert(domain) {
                return Err(invalid(
                    "MCP service trust domains must be unique DNS names",
                ));
            }
        }
        validate_mcp_limits(&mcp.limits)?;
        if self.deployment.mode == DeploymentMode::Kubernetes
            && self
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.mcp_broker.as_ref())
                .is_none()
        {
            return Err(invalid(
                "Kubernetes MCP requires broker backend mTLS configuration",
            ));
        }
        if mcp.runners.enabled {
            if self.listeners.mcp_runner_relay == self.listeners.mcp_broker
                || self.listeners.mcp_runner_relay == self.listeners.controller
            {
                return Err(invalid("MCP runner relay listener must be distinct"));
            }
            if mcp.runners.namespace.is_empty()
                || mcp.runners.namespace.len() > 63
                || !valid_dns_policy_name(&mcp.runners.namespace)
                || mcp
                    .runners
                    .catalog_file
                    .as_ref()
                    .is_none_or(|path| !path.is_absolute())
                || mcp
                    .runners
                    .trusted_root_file
                    .as_ref()
                    .is_none_or(|path| !path.is_absolute())
                || mcp
                    .runners
                    .bundle_directory
                    .as_ref()
                    .is_none_or(|path| !path.is_absolute())
                || mcp
                    .runners
                    .runner_image
                    .as_deref()
                    .is_none_or(|image| !valid_digest_reference(image))
                || mcp.runners.controller_url.as_ref().is_none_or(|url| {
                    url.scheme() != "https"
                        || url.host_str().is_none()
                        || url.port().is_none()
                        || url.path() != "/"
                        || url.query().is_some()
                        || url.fragment().is_some()
                        || !url.username().is_empty()
                        || url.password().is_some()
                })
                || [
                    mcp.runners
                        .controller_client_certificate_chain_file
                        .as_ref(),
                    mcp.runners.controller_client_private_key_file.as_ref(),
                    mcp.runners.controller_server_ca_file.as_ref(),
                ]
                .into_iter()
                .any(|path| path.is_none_or(|path| !path.is_absolute()))
                || mcp.runners.max_per_principal == 0
                || mcp.runners.max_per_tenant < mcp.runners.max_per_principal
            {
                return Err(invalid("MCP runner configuration is invalid"));
            }
            if self.deployment.mode != DeploymentMode::Kubernetes {
                return Err(invalid("MCP runners require Kubernetes deployment mode"));
            }
            if self
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.controller.as_ref())
                .is_none()
            {
                return Err(invalid("MCP runners require controller backend mTLS"));
            }
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
    if tls.allowed_client_uri_sans.is_empty() && tls.allowed_client_trust_domains.is_empty() {
        return Err(invalid(
            "backend TLS requires an exact client URI SAN or trust domain",
        ));
    }
    if tls.allowed_client_uri_sans.len() > 8 || tls.allowed_client_trust_domains.len() > 8 {
        return Err(invalid("backend TLS client identity policy is too large"));
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
    for domain in &tls.allowed_client_trust_domains {
        if !valid_dns_policy_name(domain) {
            return Err(invalid("backend TLS trust domain is invalid"));
        }
    }
    Ok(())
}

fn backend_tls_identity_policies_overlap(
    api: &BackendServerTlsConfig,
    io: &BackendServerTlsConfig,
) -> bool {
    let api_identities = api
        .allowed_client_uri_sans
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let io_identities = io
        .allowed_client_uri_sans
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let api_domains = api
        .allowed_client_trust_domains
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let io_domains = io
        .allowed_client_trust_domains
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();

    !api_identities.is_disjoint(&io_identities)
        || !api_domains.is_disjoint(&io_domains)
        || api_identities
            .iter()
            .any(|identity| spiffe_identity_uses_domain(identity, &io_domains))
        || io_identities
            .iter()
            .any(|identity| spiffe_identity_uses_domain(identity, &api_domains))
}

fn spiffe_identity_uses_domain(identity: &str, domains: &std::collections::BTreeSet<&str>) -> bool {
    Url::parse(identity)
        .ok()
        .and_then(|uri| uri.host_str().map(|domain| domains.contains(domain)))
        .unwrap_or(false)
}

fn validate_mcp_limits(limits: &McpLimitConfig) -> Result<(), ConfigError> {
    if !(1..=30).contains(&limits.connect_timeout_seconds)
        || !(1..=60).contains(&limits.discovery_timeout_seconds)
        || !(1..=60).contains(&limits.progress_idle_timeout_seconds)
        || !(1..=120).contains(&limits.operation_timeout_seconds)
        || limits.absolute_timeout_seconds < limits.operation_timeout_seconds
        || limits.absolute_timeout_seconds > 300
        || !(65_536..=1_048_576).contains(&limits.message_bytes)
        || limits.result_bytes < limits.message_bytes
        || limits.result_bytes > 4_194_304
        || !(1_048_576..=16_777_216).contains(&limits.attachment_bytes)
        || limits.attachment_hard_bytes != 16_777_216
        || limits.encoded_wire_bytes != 25_165_824
        || limits.principal_concurrency == 0
        || limits.registration_concurrency == 0
        || limits.registration_concurrency > limits.principal_concurrency
        || limits.principal_concurrency > limits.replica_concurrency
        || limits.replica_concurrency > 256
        || !(1..=64).contains(&limits.queue_depth)
    {
        return Err(invalid("MCP limits are outside the accepted envelope"));
    }
    Ok(())
}

fn validate_collaboration_limits(limits: &CollaborationLimitConfig) -> Result<(), ConfigError> {
    if !(1..=32).contains(&limits.max_participants)
        || !(16_384..=262_144).contains(&limits.max_update_bytes)
        || limits.max_operation_group_bytes < limits.max_update_bytes
        || limits.max_operation_group_bytes > 2_097_152
        || !(1..=50).contains(&limits.client_updates_per_second)
        || !(262_144..=2_097_152).contains(&limits.client_bytes_per_second)
        || limits.room_updates_per_second < limits.client_updates_per_second
        || limits.room_updates_per_second > 500
        || limits.room_bytes_per_second < limits.client_bytes_per_second
        || limits.room_bytes_per_second > 16_777_216
        || !(1_024..=8_192).contains(&limits.max_awareness_bytes)
        || !(1..=10).contains(&limits.client_awareness_per_second)
        || limits.room_awareness_per_second < limits.client_awareness_per_second
        || limits.room_awareness_per_second > 100
        || !(2_097_152..=67_108_864).contains(&limits.max_state_bytes)
        || limits.max_retained_room_bytes < limits.max_state_bytes
        || limits.max_retained_room_bytes > 268_435_456
        || !(1..=60).contains(&limits.generation_recheck_seconds)
        || limits.dirty_retention_seconds != 2_592_000
        || limits.expiry_warning_seconds != 1_987_200
        || limits.expiry_warning_seconds >= limits.dirty_retention_seconds
    {
        return Err(invalid(
            "collaboration limits are outside the accepted Large profile",
        ));
    }
    Ok(())
}

fn validate_policy_name(name: &str, kind: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid(&format!("{kind} name is invalid")));
    }
    Ok(())
}

fn valid_dns_policy_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn valid_digest_reference(value: &str) -> bool {
    let Some((name, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !value.chars().any(char::is_whitespace)
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
fn default_mcp_broker_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8082))
}
fn default_mcp_runner_relay_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8084))
}
fn default_controller_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8083))
}
fn default_collaboration_ws_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8085))
}
fn default_collaboration_webtransport_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8086))
}
fn default_vfs_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8087))
}
fn default_vfs_management_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8088))
}
const fn default_headscale_sync_seconds() -> u64 {
    15
}
const fn default_collaboration_participants() -> u32 {
    32
}
const fn default_collaboration_capability_key_generation() -> u32 {
    2
}
const fn default_mount_capability_key_generation() -> u32 {
    3
}
const fn default_collaboration_update_bytes() -> u64 {
    262_144
}
const fn default_collaboration_group_bytes() -> u64 {
    2_097_152
}
const fn default_collaboration_client_updates() -> u32 {
    50
}
const fn default_collaboration_client_bytes() -> u64 {
    2_097_152
}
const fn default_collaboration_room_updates() -> u32 {
    500
}
const fn default_collaboration_room_bytes() -> u64 {
    16_777_216
}
const fn default_collaboration_awareness_bytes() -> u64 {
    8_192
}
const fn default_collaboration_client_awareness() -> u32 {
    10
}
const fn default_collaboration_room_awareness() -> u32 {
    100
}
const fn default_collaboration_state_bytes() -> u64 {
    67_108_864
}
const fn default_collaboration_retained_bytes() -> u64 {
    268_435_456
}
const fn default_collaboration_recheck_seconds() -> u64 {
    60
}
const fn default_collaboration_dirty_retention_seconds() -> u64 {
    2_592_000
}
const fn default_collaboration_warning_seconds() -> u64 {
    1_987_200
}
fn default_mcp_callback_path() -> String {
    "/api/v1/mcp/oauth/callback".into()
}
fn default_https_ports() -> Vec<u16> {
    vec![443]
}
const fn default_mcp_connect_timeout() -> u64 {
    5
}
const fn default_mcp_discovery_timeout() -> u64 {
    15
}
const fn default_mcp_progress_idle_timeout() -> u64 {
    15
}
const fn default_mcp_operation_timeout() -> u64 {
    60
}
const fn default_mcp_absolute_timeout() -> u64 {
    120
}
const fn default_mcp_message_bytes() -> u64 {
    1_048_576
}
const fn default_mcp_result_bytes() -> u64 {
    4_194_304
}
const fn default_mcp_attachment_bytes() -> u64 {
    4_194_304
}
const fn default_mcp_attachment_hard_bytes() -> u64 {
    16_777_216
}
const fn default_mcp_encoded_wire_bytes() -> u64 {
    25_165_824
}
const fn default_mcp_principal_concurrency() -> u32 {
    4
}
const fn default_mcp_registration_concurrency() -> u32 {
    2
}
const fn default_mcp_replica_concurrency() -> u32 {
    64
}
const fn default_mcp_queue_depth() -> u32 {
    16
}
fn default_mcp_runner_namespace() -> String {
    "filebelt-mcp-runners".into()
}
const fn default_mcp_runner_per_principal() -> u32 {
    1
}
const fn default_mcp_runner_per_tenant() -> u32 {
    8
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
            mcp: McpConfig::default(),
            collaboration: CollaborationConfig::default(),
            mounts: MountConfig::default(),
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
    fn unsupported_configuration_version_is_rejected() {
        let mut candidate = config();
        candidate.version = 0;
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
            allowed_client_trust_domains: Vec::new(),
        };
        candidate.backend_tls = Some(BackendTlsConfig {
            api: api_tls,
            io: BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/tls.crt".into(),
                private_key_file: "/run/secrets/tls.key".into(),
                client_ca_file: "/run/secrets/client-ca.crt".into(),
                allowed_client_uri_sans: vec!["spiffe://filebelt.test/web-io".into()],
                allowed_client_trust_domains: Vec::new(),
            },
            mcp_broker: None,
            controller: None,
            collaboration: None,
            vfs: None,
            vfs_management: None,
        });
        candidate.validate().unwrap();
    }
    #[test]
    fn enabled_mcp_requires_vault_gateway_and_policy() {
        let mut candidate = config();
        candidate.mcp.enabled = true;
        assert!(candidate.validate().is_err());

        candidate.mcp.database_url_file = Some("/run/secrets/mcp-database-url".into());
        candidate.mcp.broker.url = Some(Url::parse("http://127.0.0.1:8082/").unwrap());
        candidate.mcp.attachments.io_url = Some(Url::parse("http://127.0.0.1:8081/").unwrap());
        candidate.mcp.vault.keyring_file = Some("/run/secrets/mcp-keyring".into());
        candidate.mcp.egress.gateway_url =
            Some(Url::parse("https://mcp-egress.example.test:8443/").unwrap());
        candidate.mcp.egress.client_certificate_chain_file =
            Some("/run/secrets/mcp-egress.crt".into());
        candidate.mcp.egress.client_private_key_file = Some("/run/secrets/mcp-egress.key".into());
        candidate.mcp.egress.server_ca_file = Some("/run/secrets/mcp-egress-ca.crt".into());
        candidate.mcp.trust_profiles.insert(
            "public".into(),
            McpTrustProfile {
                public_webpki: true,
                hosts: Vec::new(),
                cidrs: Vec::new(),
                ports: vec![443],
                custom_ca_file: None,
                allow_dynamic_client_registration: false,
            },
        );
        candidate.validate().unwrap();
    }
    #[test]
    fn mcp_runners_are_separately_opt_in() {
        let mut candidate = config();
        candidate.mcp.runners.enabled = true;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn headscale_sync_requires_exact_https_issuer() {
        let mut candidate = config();
        candidate.mounts.enabled = true;
        candidate.mounts.database_url_file = Some("/run/secrets/mount-database-url".into());
        candidate.mounts.vault_keyring_file = Some("/run/secrets/mount-vault-keyring".into());
        candidate.mounts.capability_private_key_file =
            Some("/run/secrets/mount-capability.pk8".into());
        candidate.mounts.io_url = Some(Url::parse("http://127.0.0.1:8081/").unwrap());
        candidate.mounts.management_url = Some(Url::parse("http://127.0.0.1:8091/").unwrap());
        candidate.mounts.headscale.enabled = true;
        candidate.mounts.headscale.api_url =
            Some(Url::parse("https://headscale.example.test/").unwrap());
        candidate.mounts.headscale.api_token_file = Some("/run/secrets/headscale-api-token".into());
        candidate.mounts.headscale.server_ca_file = Some("/run/secrets/headscale-ca.crt".into());
        candidate.mounts.headscale.oidc_issuer =
            Some(Url::parse("https://issuer.example.test/tenant").unwrap());
        candidate.validate().unwrap();

        candidate.mounts.headscale.oidc_issuer =
            Some(Url::parse("https://issuer.example.test/tenant?client=filebelt").unwrap());
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn backend_tls_rejects_role_identity_overlap() {
        let mut candidate = config();
        let shared = BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: vec!["spiffe://filebelt.test/web".into()],
            allowed_client_trust_domains: Vec::new(),
        };
        candidate.backend_tls = Some(BackendTlsConfig {
            api: shared.clone(),
            io: shared,
            mcp_broker: None,
            controller: None,
            collaboration: None,
            vfs: None,
            vfs_management: None,
        });
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn backend_tls_rejects_role_trust_domain_overlap() {
        let mut candidate = config();
        let api = BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: vec!["spiffe://filebelt.test/web-api".into()],
            allowed_client_trust_domains: Vec::new(),
        };
        candidate.backend_tls = Some(BackendTlsConfig {
            api,
            io: BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/tls.crt".into(),
                private_key_file: "/run/secrets/tls.key".into(),
                client_ca_file: "/run/secrets/client-ca.crt".into(),
                allowed_client_uri_sans: Vec::new(),
                allowed_client_trust_domains: vec!["filebelt.test".into()],
            },
            mcp_broker: None,
            controller: None,
            collaboration: None,
            vfs: None,
            vfs_management: None,
        });
        assert!(candidate.validate().is_err());

        let mut candidate = config();
        let shared_domain = BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: Vec::new(),
            allowed_client_trust_domains: vec!["filebelt.test".into()],
        };
        candidate.backend_tls = Some(BackendTlsConfig {
            api: shared_domain.clone(),
            io: shared_domain,
            mcp_broker: None,
            controller: None,
            collaboration: None,
            vfs: None,
            vfs_management: None,
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
            allowed_client_trust_domains: Vec::new(),
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

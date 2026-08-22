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

pub const CONFIG_VERSION: u32 = 9;
pub const SMB_GATEWAY_URI_SAN: &str = "spiffe://filebelt/smb-gateway/vfs";
pub const FTP_FTPS_GATEWAY_URI_SAN: &str = "spiffe://filebelt/ftp-ftps-gateway/vfs";
pub const NFS_GATEWAY_URI_SAN: &str = "spiffe://filebelt/nfs-gateway/vfs";

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
    pub documents: DocumentConfig,
    #[serde(default)]
    pub revisions: RevisionConfig,
    pub media: MediaConfig,
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
    pub document: Option<BackendServerTlsConfig>,
    #[serde(default)]
    pub document_adapter: Option<BackendServerTlsConfig>,
    #[serde(default)]
    pub revision: Option<BackendServerTlsConfig>,
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
    pub digest_key_file: PathBuf,
    pub digest_key_generation: u32,
    pub api_storage: SigningKeyConfig,
    #[serde(default)]
    pub api_collaboration_grant: Option<SigningKeyConfig>,
    #[serde(default)]
    pub api_mcp_delegation: Option<SigningKeyConfig>,
}

/// One purpose-scoped Ed25519 signing authority and its admitted public keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    pub private_key_file: PathBuf,
    pub public_keyset_file: PathBuf,
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
    #[serde(default = "default_document_listener")]
    pub document: SocketAddr,
    #[serde(default = "default_document_adapter_listener")]
    pub document_adapter: SocketAddr,
    #[serde(default = "default_revision_listener")]
    pub revision: SocketAddr,
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
            document: default_document_listener(),
            document_adapter: default_document_adapter_listener(),
            revision: default_revision_listener(),
            allow_container_wildcard: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_document_provider_id")]
    pub provider_id: String,
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    #[serde(default)]
    pub url: Option<Url>,
    /// Fixed public form action for submitting a one-use provider handoff.
    /// It is operator configuration, never browser or API request input.
    #[serde(default)]
    pub launch_action: Option<Url>,
    /// Exact external document-provider HTTPS origin disclosed before launch.
    /// It is non-secret operator configuration, never browser or API request input.
    #[serde(default)]
    pub provider_origin: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub capability_signing: Option<SigningKeyConfig>,
    #[serde(default = "default_document_max_active_tabs")]
    pub max_active_tabs: u32,
    #[serde(default = "default_document_max_bytes")]
    pub max_document_bytes: u64,
    #[serde(default = "default_document_generation_recheck_seconds")]
    pub generation_recheck_seconds: u64,
}

impl Default for DocumentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider_id: default_document_provider_id(),
            database_url_file: None,
            url: None,
            launch_action: None,
            provider_origin: None,
            client_certificate_chain_file: None,
            client_private_key_file: None,
            server_ca_file: None,
            capability_signing: None,
            max_active_tabs: default_document_max_active_tabs(),
            max_document_bytes: default_document_max_bytes(),
            generation_recheck_seconds: default_document_generation_recheck_seconds(),
        }
    }
}

/// Canonical revision coordinator and its purpose-scoped byte-plane clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    #[serde(default)]
    pub url: Option<Url>,
    #[serde(default)]
    pub adapter_url: Option<Url>,
    #[serde(default)]
    pub io_url: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub adapter_client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub adapter_client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub adapter_server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub io_client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub io_client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub io_server_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub capability_signing: Option<SigningKeyConfig>,
    #[serde(default = "default_revision_chunk_bytes")]
    pub chunk_size_bytes: u64,
    #[serde(default = "default_revision_text_bytes")]
    pub max_text_bytes: u64,
    #[serde(default = "default_revision_object_format")]
    pub git_object_format: String,
    #[serde(default)]
    pub limits: RevisionLimitConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionLimitConfig {
    #[serde(default = "default_revision_global_comparisons")]
    pub global_comparisons: u32,
    #[serde(default = "default_revision_user_comparisons")]
    pub per_user_comparisons: u32,
}

impl Default for RevisionLimitConfig {
    fn default() -> Self {
        Self {
            global_comparisons: default_revision_global_comparisons(),
            per_user_comparisons: default_revision_user_comparisons(),
        }
    }
}

impl Default for RevisionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url_file: None,
            url: None,
            adapter_url: None,
            io_url: None,
            client_certificate_chain_file: None,
            client_private_key_file: None,
            server_ca_file: None,
            adapter_client_certificate_chain_file: None,
            adapter_client_private_key_file: None,
            adapter_server_ca_file: None,
            io_client_certificate_chain_file: None,
            io_client_private_key_file: None,
            io_server_ca_file: None,
            capability_signing: None,
            chunk_size_bytes: default_revision_chunk_bytes(),
            max_text_bytes: default_revision_text_bytes(),
            git_object_format: default_revision_object_format(),
            limits: RevisionLimitConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    pub capability_signing: SigningKeyConfig,
    #[serde(default)]
    pub job_namespace: Option<String>,
    #[serde(default)]
    pub transcoder_image: Option<String>,
    #[serde(default)]
    pub cache_claim: Option<String>,
    #[serde(default = "default_media_generation_recheck_seconds")]
    pub generation_recheck_seconds: u64,
    #[serde(default = "default_media_cache_quota_percent")]
    pub cache_quota_percent: u8,
    #[serde(default = "default_media_cache_high_watermark_percent")]
    pub cache_high_watermark_percent: u8,
    #[serde(default = "default_media_cache_low_watermark_percent")]
    pub cache_low_watermark_percent: u8,
    #[serde(default)]
    pub experimental_vaapi: bool,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url_file: None,
            capability_signing: default_media_capability_signing(),
            job_namespace: None,
            transcoder_image: None,
            cache_claim: None,
            generation_recheck_seconds: default_media_generation_recheck_seconds(),
            cache_quota_percent: default_media_cache_quota_percent(),
            cache_high_watermark_percent: default_media_cache_high_watermark_percent(),
            cache_low_watermark_percent: default_media_cache_low_watermark_percent(),
            experimental_vaapi: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    #[serde(default)]
    pub database_url_file: Option<PathBuf>,
    #[serde(default)]
    pub vault_keyring_file: Option<PathBuf>,
    #[serde(default = "default_key_generation")]
    pub vault_key_generation: u32,
    #[serde(default)]
    pub capability_signing: Option<SigningKeyConfig>,
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
    #[serde(default)]
    pub smb: SmbMountConfig,
    #[serde(default)]
    pub ftp_ftps: FtpFtpsMountConfig,
    #[serde(default)]
    pub nfs: NfsMountConfig,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            database_url_file: None,
            vault_keyring_file: None,
            vault_key_generation: default_key_generation(),
            capability_signing: None,
            io_url: None,
            io_client_certificate_chain_file: None,
            io_client_private_key_file: None,
            io_server_ca_file: None,
            management_url: None,
            management_client_certificate_chain_file: None,
            management_client_private_key_file: None,
            management_server_ca_file: None,
            headscale: HeadscaleSyncConfig::default(),
            smb: SmbMountConfig::default(),
            ftp_ftps: FtpFtpsMountConfig::default(),
            nfs: NfsMountConfig::default(),
        }
    }
}

impl MountConfig {
    #[must_use]
    pub fn any_protocol_enabled(&self) -> bool {
        self.smb.enabled || self.ftp_ftps.enabled || self.nfs.enabled
    }

    #[must_use]
    pub fn headscale_required(&self) -> bool {
        self.headscale.enabled && (self.smb.enabled || self.ftp_ftps.enabled)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmbMountConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_smb_gateway_uri_san")]
    pub gateway_uri_san: String,
    #[serde(default)]
    pub previous_gateway_uri_san: Option<String>,
}

impl Default for SmbMountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_uri_san: default_smb_gateway_uri_san(),
            previous_gateway_uri_san: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FtpFtpsMountConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ftp_ftps_gateway_uri_san")]
    pub gateway_uri_san: String,
    #[serde(default)]
    pub previous_gateway_uri_san: Option<String>,
}

impl Default for FtpFtpsMountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_uri_san: default_ftp_ftps_gateway_uri_san(),
            previous_gateway_uri_san: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfsMountConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nfs_gateway_uri_san")]
    pub gateway_uri_san: String,
    #[serde(default)]
    pub previous_gateway_uri_san: Option<String>,
    #[serde(default)]
    pub realm: Option<String>,
    #[serde(default)]
    pub idmap_domain: Option<String>,
    #[serde(default)]
    pub handle_keyring_file: Option<PathBuf>,
    #[serde(default = "default_key_generation")]
    pub handle_key_generation: u32,
    #[serde(default = "default_nfs_grace_seconds")]
    pub grace_seconds: u64,
}

impl Default for NfsMountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_uri_san: default_nfs_gateway_uri_san(),
            previous_gateway_uri_san: None,
            realm: None,
            idmap_domain: None,
            handle_keyring_file: None,
            handle_key_generation: default_key_generation(),
            grace_seconds: default_nfs_grace_seconds(),
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
    pub capability_signing: Option<SigningKeyConfig>,
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
    pub webtransport_endpoint: Option<Url>,
    #[serde(default = "default_webtransport_idle_seconds")]
    pub webtransport_idle_seconds: u64,
    #[serde(default = "default_webtransport_drain_seconds")]
    pub webtransport_drain_seconds: u64,
    #[serde(default)]
    pub limits: CollaborationLimitConfig,
}

impl Default for CollaborationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url_file: None,
            capability_signing: None,
            io_url: None,
            client_certificate_chain_file: None,
            client_private_key_file: None,
            server_ca_file: None,
            webtransport_enabled: false,
            webtransport_endpoint: None,
            webtransport_idle_seconds: default_webtransport_idle_seconds(),
            webtransport_drain_seconds: default_webtransport_drain_seconds(),
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
    /// Named outbound gateways selected by an MCP trust profile. The legacy
    /// `egress` entry remains the default for profiles without a selector.
    #[serde(default)]
    pub gateways: BTreeMap<String, McpEgressConfig>,
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
            gateways: BTreeMap::new(),
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
    pub kind: McpGatewayKind,
    #[serde(default)]
    pub gateway_url: Option<Url>,
    #[serde(default)]
    pub client_certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub client_private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub server_ca_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpGatewayKind {
    #[default]
    Public,
    PrivateTunnel,
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
    /// Optional named outbound gateway. Profiles without a selector retain the
    /// legacy `mcp.egress` gateway.
    #[serde(default)]
    pub gateway: Option<String>,
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
            || self.public_origin.host_str().is_none()
            || self
                .public_origin
                .host_str()
                .is_some_and(|host| host.ends_with('.'))
            || self.public_origin.username() != ""
            || self.public_origin.password().is_some()
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
                || (self.documents.enabled && self.listeners.document.ip().is_unspecified())
                || (self.documents.enabled
                    && self.listeners.document_adapter.ip().is_unspecified())
                || (self.revisions.enabled && self.listeners.revision.ip().is_unspecified())
                || (self.mounts.any_protocol_enabled() && self.listeners.vfs.ip().is_unspecified())
                || (self.mounts.any_protocol_enabled()
                    && self.listeners.vfs_management.ip().is_unspecified()))
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
            if let Some(document) = &tls.document {
                validate_backend_tls(document)?;
                for (role, other) in [
                    ("API", Some(&tls.api)),
                    ("I/O", Some(&tls.io)),
                    ("MCP broker", tls.mcp_broker.as_ref()),
                    ("controller", tls.controller.as_ref()),
                    ("collaboration", tls.collaboration.as_ref()),
                    ("VFS", tls.vfs.as_ref()),
                    ("VFS management", tls.vfs_management.as_ref()),
                ] {
                    if other
                        .is_some_and(|other| backend_tls_identity_policies_overlap(document, other))
                    {
                        return Err(invalid(&format!(
                            "document and {role} backend TLS client identities and trust domains must not overlap"
                        )));
                    }
                }
            }
            if let Some(document_adapter) = &tls.document_adapter {
                validate_backend_tls(document_adapter)?;
                for (role, other) in [
                    ("API", Some(&tls.api)),
                    ("I/O", Some(&tls.io)),
                    ("MCP broker", tls.mcp_broker.as_ref()),
                    ("controller", tls.controller.as_ref()),
                    ("collaboration", tls.collaboration.as_ref()),
                    ("document API", tls.document.as_ref()),
                    ("VFS", tls.vfs.as_ref()),
                    ("VFS management", tls.vfs_management.as_ref()),
                ] {
                    if other.is_some_and(|other| {
                        backend_tls_identity_policies_overlap(document_adapter, other)
                    }) {
                        return Err(invalid(&format!(
                            "document adapter and {role} backend TLS client identities and trust domains must not overlap"
                        )));
                    }
                }
            }
            if let Some(revision) = &tls.revision {
                validate_backend_tls(revision)?;
                for (role, other) in [
                    ("API", Some(&tls.api)),
                    ("I/O", Some(&tls.io)),
                    ("MCP broker", tls.mcp_broker.as_ref()),
                    ("controller", tls.controller.as_ref()),
                    ("collaboration", tls.collaboration.as_ref()),
                    ("document API", tls.document.as_ref()),
                    ("document adapter", tls.document_adapter.as_ref()),
                    ("VFS", tls.vfs.as_ref()),
                    ("VFS management", tls.vfs_management.as_ref()),
                ] {
                    if other
                        .is_some_and(|other| backend_tls_identity_policies_overlap(revision, other))
                    {
                        return Err(invalid(&format!(
                            "revision and {role} backend TLS client identities and trust domains must not overlap"
                        )));
                    }
                }
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
        validate_signing_key(&self.keys.api_storage, "API storage")?;
        if self.keys.digest_key_generation == 0 {
            return Err(invalid("digest key generation must be positive"));
        }
        match (
            &self.keys.api_collaboration_grant,
            self.collaboration.enabled,
        ) {
            (Some(key), true) => validate_signing_key(key, "API collaboration grant")?,
            (None, true) | (Some(_), false) => {
                return Err(invalid(
                    "API collaboration-grant signing must be present exactly when collaboration is enabled",
                ));
            }
            (None, false) => {}
        }
        match (&self.keys.api_mcp_delegation, self.mcp.enabled) {
            (Some(key), true) => validate_signing_key(key, "API MCP delegation")?,
            (None, true) | (Some(_), false) => {
                return Err(invalid(
                    "API MCP-delegation signing must be present exactly when MCP is enabled",
                ));
            }
            (None, false) => {}
        }
        self.validate_signing_key_topology()?;
        if let Some(iggy) = &self.iggy
            && (iggy.stream != "filebelt" || iggy.partitions != 16)
        {
            return Err(invalid(
                "Phase 2 Iggy topology is one filebelt stream with 16 partitions",
            ));
        }
        self.validate_mcp()?;
        self.validate_collaboration()?;
        self.validate_documents()?;
        self.validate_revisions()?;
        self.validate_media()?;
        self.validate_mounts()?;
        Ok(())
    }

    fn validate_signing_key_topology(&self) -> Result<(), ConfigError> {
        let mut configured = vec![&self.keys.api_storage, &self.media.capability_signing];
        if let Some(key) = &self.keys.api_collaboration_grant {
            configured.push(key);
        }
        if let Some(key) = &self.keys.api_mcp_delegation {
            configured.push(key);
        }
        if let Some(key) = &self.collaboration.capability_signing {
            configured.push(key);
        }
        if let Some(key) = &self.documents.capability_signing {
            configured.push(key);
        }
        if let Some(key) = &self.revisions.capability_signing {
            configured.push(key);
        }
        if let Some(key) = &self.mounts.capability_signing {
            configured.push(key);
        }
        let mut paths = Vec::with_capacity(configured.len() * 2);
        for key in configured {
            if key.private_key_file == key.public_keyset_file {
                return Err(invalid(
                    "signing private and public-keyset paths must differ",
                ));
            }
            paths.push(&key.private_key_file);
            paths.push(&key.public_keyset_file);
        }
        paths.sort_unstable();
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid(
                "configured signing private and public-keyset paths must be purpose-distinct",
            ));
        }
        Ok(())
    }

    fn validate_documents(&self) -> Result<(), ConfigError> {
        let documents = &self.documents;
        validate_document_limits(documents)?;
        if !documents.enabled {
            if documents.database_url_file.is_some()
                || documents.url.is_some()
                || documents.launch_action.is_some()
                || documents.provider_origin.is_some()
                || documents.client_certificate_chain_file.is_some()
                || documents.client_private_key_file.is_some()
                || documents.server_ca_file.is_some()
                || documents.capability_signing.is_some()
                || self
                    .backend_tls
                    .as_ref()
                    .is_some_and(|tls| tls.document.is_some() || tls.document_adapter.is_some())
            {
                return Err(invalid(
                    "disabled documents must not configure database, service, capability, or TLS authority",
                ));
            }
            return Ok(());
        }

        if documents.provider_id.is_empty()
            || documents.provider_id.len() > 128
            || !documents.provider_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            || [documents.database_url_file.as_ref()]
                .into_iter()
                .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled documents require a provider ID and an absolute database path",
            ));
        }
        let signing = documents
            .capability_signing
            .as_ref()
            .ok_or_else(|| invalid("enabled documents require capability signing"))?;
        validate_signing_key(signing, "document storage")?;
        validate_internal_service_url(
            documents.url.as_ref(),
            self.deployment.mode,
            "document service",
        )?;
        validate_document_provider_origin(documents.provider_origin.as_ref(), &self.public_origin)?;
        validate_document_launch_action(
            documents.launch_action.as_ref(),
            &self.public_origin,
            documents.provider_origin.as_ref(),
        )?;
        if self.listeners.document == self.listeners.api
            || self.listeners.document == self.listeners.io
            || self.listeners.document == self.listeners.operations
            || self.listeners.document == self.listeners.mcp_broker
            || self.listeners.document == self.listeners.mcp_runner_relay
            || self.listeners.document == self.listeners.controller
            || self.listeners.document == self.listeners.collaboration_ws
            || self.listeners.document == self.listeners.collaboration_webtransport
            || self.listeners.document == self.listeners.vfs
            || self.listeners.document == self.listeners.vfs_management
            || self.listeners.document == self.listeners.document_adapter
            || self.listeners.document_adapter == self.listeners.api
            || self.listeners.document_adapter == self.listeners.io
            || self.listeners.document_adapter == self.listeners.operations
            || self.listeners.document_adapter == self.listeners.mcp_broker
            || self.listeners.document_adapter == self.listeners.mcp_runner_relay
            || self.listeners.document_adapter == self.listeners.controller
            || self.listeners.document_adapter == self.listeners.collaboration_ws
            || self.listeners.document_adapter == self.listeners.collaboration_webtransport
            || self.listeners.document_adapter == self.listeners.vfs
            || self.listeners.document_adapter == self.listeners.vfs_management
        {
            return Err(invalid(
                "document API and adapter listeners must be distinct from every other listener",
            ));
        }
        if self.deployment.mode == DeploymentMode::Kubernetes {
            if [
                documents.client_certificate_chain_file.as_ref(),
                documents.client_private_key_file.as_ref(),
                documents.server_ca_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
            {
                return Err(invalid(
                    "Kubernetes documents require absolute API-to-document TLS paths",
                ));
            }
            if self
                .backend_tls
                .as_ref()
                .is_none_or(|tls| tls.document.is_none() || tls.document_adapter.is_none())
            {
                return Err(invalid(
                    "Kubernetes documents require distinct API and adapter backend mTLS configurations",
                ));
            }
        } else if [
            documents.client_certificate_chain_file.as_ref(),
            documents.client_private_key_file.as_ref(),
            documents.server_ca_file.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|path| !path.is_absolute())
        {
            return Err(invalid(
                "document TLS paths must be absolute when configured",
            ));
        }
        Ok(())
    }

    fn validate_revisions(&self) -> Result<(), ConfigError> {
        let revisions = &self.revisions;
        if revisions.chunk_size_bytes != default_revision_chunk_bytes()
            || revisions.max_text_bytes != default_revision_text_bytes()
            || revisions.git_object_format != "sha256"
        {
            return Err(invalid(
                "revision storage requires 16 MiB fixed chunks, a 100 MiB text cap, and SHA-256 Git objects",
            ));
        }
        if !(1..=32).contains(&revisions.limits.global_comparisons)
            || !(1..=8).contains(&revisions.limits.per_user_comparisons)
            || revisions.limits.per_user_comparisons > revisions.limits.global_comparisons
        {
            return Err(invalid(
                "revision comparison concurrency is outside the accepted envelope",
            ));
        }
        let authority_paths = [
            revisions.database_url_file.as_ref(),
            revisions.client_certificate_chain_file.as_ref(),
            revisions.client_private_key_file.as_ref(),
            revisions.server_ca_file.as_ref(),
            revisions.adapter_client_certificate_chain_file.as_ref(),
            revisions.adapter_client_private_key_file.as_ref(),
            revisions.adapter_server_ca_file.as_ref(),
            revisions.io_client_certificate_chain_file.as_ref(),
            revisions.io_client_private_key_file.as_ref(),
            revisions.io_server_ca_file.as_ref(),
        ];
        if !revisions.enabled {
            if authority_paths.into_iter().any(|path| path.is_some())
                || revisions.url.is_some()
                || revisions.adapter_url.is_some()
                || revisions.io_url.is_some()
                || revisions.capability_signing.is_some()
                || self
                    .backend_tls
                    .as_ref()
                    .is_some_and(|tls| tls.revision.is_some())
            {
                return Err(invalid(
                    "disabled revisions must not configure database, service, capability, or TLS authority",
                ));
            }
            return Ok(());
        }
        if authority_paths
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled revisions require absolute database and mTLS paths",
            ));
        }
        let signing = revisions
            .capability_signing
            .as_ref()
            .ok_or_else(|| invalid("enabled revisions require capability signing"))?;
        validate_signing_key(signing, "revision storage")?;
        for (url, label) in [
            (revisions.url.as_ref(), "revision service"),
            (revisions.adapter_url.as_ref(), "revision adapter"),
            (revisions.io_url.as_ref(), "revision I/O"),
        ] {
            validate_internal_service_url(url, self.deployment.mode, label)?;
        }
        if [
            self.listeners.api,
            self.listeners.io,
            self.listeners.operations,
            self.listeners.mcp_broker,
            self.listeners.mcp_runner_relay,
            self.listeners.controller,
            self.listeners.collaboration_ws,
            self.listeners.collaboration_webtransport,
            self.listeners.vfs,
            self.listeners.vfs_management,
            self.listeners.document,
            self.listeners.document_adapter,
        ]
        .contains(&self.listeners.revision)
        {
            return Err(invalid(
                "revision listener must be distinct from every other listener",
            ));
        }
        if self.deployment.mode == DeploymentMode::Kubernetes
            && self
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.revision.as_ref())
                .is_none()
        {
            return Err(invalid(
                "Kubernetes revisions require a dedicated backend mTLS configuration",
            ));
        }
        if let Some(tls) = self
            .backend_tls
            .as_ref()
            .and_then(|backend| backend.revision.as_ref())
        {
            validate_backend_tls(tls)?;
        }
        Ok(())
    }

    fn validate_media(&self) -> Result<(), ConfigError> {
        let media = &self.media;
        // Media is deliberately not a runtime capability consumer yet, but its
        // configured public keyset is recovery evidence and must be valid.
        validate_signing_key(&media.capability_signing, "media storage")?;
        if !media.enabled {
            if media.database_url_file.is_some()
                || media.job_namespace.is_some()
                || media.transcoder_image.is_some()
                || media.cache_claim.is_some()
                || media.experimental_vaapi
            {
                return Err(invalid(
                    "disabled media must not configure database, Job, cache, image, or VAAPI authority",
                ));
            }
            return Ok(());
        }
        if [media.database_url_file.as_ref()]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid("enabled media requires an absolute database path"));
        }
        let namespace = media
            .job_namespace
            .as_deref()
            .ok_or_else(|| invalid("enabled media requires a Job namespace"))?;
        let claim = media
            .cache_claim
            .as_deref()
            .ok_or_else(|| invalid("enabled media requires a cache claim"))?;
        if !is_dns_label(namespace) || !is_dns_label(claim) {
            return Err(invalid(
                "media Job namespace and cache claim must be lowercase DNS labels",
            ));
        }
        let image = media
            .transcoder_image
            .as_deref()
            .ok_or_else(|| invalid("enabled media requires a digest-pinned transcoder image"))?;
        if !is_digest_pinned_image(image) {
            return Err(invalid(
                "media transcoder image must use an immutable lowercase sha256 digest",
            ));
        }
        if !(1..=60).contains(&media.generation_recheck_seconds)
            || !(1..=50).contains(&media.cache_quota_percent)
            || !(50..=95).contains(&media.cache_high_watermark_percent)
            || media.cache_low_watermark_percent >= media.cache_high_watermark_percent
        {
            return Err(invalid("media limits are outside the accepted envelope"));
        }
        Ok(())
    }

    fn validate_mounts(&self) -> Result<(), ConfigError> {
        let mounts = &self.mounts;
        validate_mount_gateway_identity(
            "SMB",
            mounts.smb.enabled,
            &mounts.smb.gateway_uri_san,
            SMB_GATEWAY_URI_SAN,
            mounts.smb.previous_gateway_uri_san.as_deref(),
        )?;
        validate_mount_gateway_identity(
            "FTP/FTPS",
            mounts.ftp_ftps.enabled,
            &mounts.ftp_ftps.gateway_uri_san,
            FTP_FTPS_GATEWAY_URI_SAN,
            mounts.ftp_ftps.previous_gateway_uri_san.as_deref(),
        )?;
        validate_mount_gateway_identity(
            "NFS",
            mounts.nfs.enabled,
            &mounts.nfs.gateway_uri_san,
            NFS_GATEWAY_URI_SAN,
            mounts.nfs.previous_gateway_uri_san.as_deref(),
        )?;
        validate_disjoint_mount_gateway_identities(mounts)?;
        self.validate_nfs()?;
        if mounts.headscale.enabled != (mounts.smb.enabled || mounts.ftp_ftps.enabled) {
            return Err(invalid(
                "Headscale synchronization must be enabled exactly when SMB or FTP/FTPS is enabled",
            ));
        }
        if !mounts.any_protocol_enabled() {
            return Ok(());
        }
        if mounts.vault_key_generation == 0
            || [
                mounts.database_url_file.as_ref(),
                mounts.vault_keyring_file.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "an enabled mount protocol requires absolute database and vault paths plus a positive vault generation",
            ));
        }
        let signing = mounts
            .capability_signing
            .as_ref()
            .ok_or_else(|| invalid("an enabled mount protocol requires capability signing"))?;
        validate_signing_key(signing, "mount storage")?;
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
                "Kubernetes mount protocols require separate VFS I/O and management mTLS identities",
            ));
        }
        if let Some(vfs_tls) = self
            .backend_tls
            .as_ref()
            .and_then(|backend_tls| backend_tls.vfs.as_ref())
        {
            validate_vfs_mount_gateway_identities(mounts, vfs_tls)?;
        }
        let headscale = &mounts.headscale;
        if !mounts.headscale_required() {
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

    fn validate_nfs(&self) -> Result<(), ConfigError> {
        let nfs = &self.mounts.nfs;
        if !nfs.enabled {
            if nfs.realm.is_some()
                || nfs.idmap_domain.is_some()
                || nfs.handle_keyring_file.is_some()
                || nfs.handle_key_generation != default_key_generation()
            {
                return Err(invalid(
                    "disabled NFS must not configure realm, idmap, or handle-key authority",
                ));
            }
            return Ok(());
        }
        if self.deployment.mode != DeploymentMode::Kubernetes {
            return Err(invalid(
                "NFS requires Kubernetes deployment with verified gateway mTLS",
            ));
        }
        let realm = nfs
            .realm
            .as_deref()
            .ok_or_else(|| invalid("enabled NFS requires an external Kerberos realm"))?;
        let idmap_domain = nfs
            .idmap_domain
            .as_deref()
            .ok_or_else(|| invalid("enabled NFS requires an NFSv4 idmap domain"))?;
        if realm.is_empty()
            || realm.len() > 255
            || !realm.bytes().all(|byte| {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
            || !valid_dns_policy_name(idmap_domain)
        {
            return Err(invalid("NFS Kerberos realm or idmap domain is invalid"));
        }
        if nfs
            .handle_keyring_file
            .as_ref()
            .is_none_or(|path| !path.is_absolute())
            || !(30..=300).contains(&nfs.grace_seconds)
            || nfs.handle_key_generation == 0
        {
            return Err(invalid(
                "NFS requires an absolute handle-key path, a 30 to 300 second grace period, and a positive handle-key generation",
            ));
        }
        Ok(())
    }

    fn validate_collaboration(&self) -> Result<(), ConfigError> {
        let collaboration = &self.collaboration;
        validate_collaboration_limits(&collaboration.limits)?;
        if !collaboration.enabled {
            if collaboration.webtransport_enabled
                || collaboration.webtransport_endpoint.is_some()
                || collaboration.capability_signing.is_some()
            {
                return Err(invalid("WebTransport requires collaboration.enabled=true"));
            }
            return Ok(());
        }
        if [collaboration.database_url_file.as_ref()]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled collaboration requires an absolute database path",
            ));
        }
        let signing = collaboration
            .capability_signing
            .as_ref()
            .ok_or_else(|| invalid("enabled collaboration requires capability signing"))?;
        validate_signing_key(signing, "collaboration storage")?;
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
        if collaboration.webtransport_enabled {
            let endpoint = collaboration
                .webtransport_endpoint
                .as_ref()
                .ok_or_else(|| invalid("enabled WebTransport requires a public endpoint"))?;
            if endpoint.scheme() != "https"
                || endpoint.origin() != self.public_origin.origin()
                || endpoint.path() != "/collaboration/v1/wt"
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || collaboration.webtransport_idle_seconds != 75
                || collaboration.webtransport_drain_seconds != 300
            {
                return Err(invalid(
                    "WebTransport requires the same-origin /collaboration/v1/wt endpoint with qualified idle and drain limits",
                ));
            }
        } else if collaboration.webtransport_endpoint.is_some() {
            return Err(invalid(
                "disabled WebTransport must not advertise an endpoint",
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
        ];
        if required_paths
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            return Err(invalid(
                "enabled MCP requires absolute database and vault paths",
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
        if mcp.vault.current_generation == 0 {
            return Err(invalid("MCP vault key generation must be positive"));
        }
        if mcp.trust_profiles.is_empty() {
            return Err(invalid("enabled MCP requires at least one trust profile"));
        }
        let legacy_gateway_required = mcp
            .trust_profiles
            .values()
            .any(|profile| profile.gateway.is_none());
        validate_mcp_gateway(&mcp.egress, legacy_gateway_required, "legacy")?;
        for (name, gateway) in &mcp.gateways {
            validate_policy_name(name, "MCP gateway")?;
            validate_mcp_gateway(gateway, true, "named")?;
        }
        for (name, profile) in &mcp.trust_profiles {
            validate_policy_name(name, "MCP trust profile")?;
            let gateway = match profile.gateway.as_deref() {
                Some(gateway) => mcp
                    .gateways
                    .get(gateway)
                    .ok_or_else(|| invalid("MCP trust profile selects an unknown gateway"))?,
                None => &mcp.egress,
            };
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
            if gateway.kind == McpGatewayKind::PrivateTunnel
                && profile.allow_dynamic_client_registration
            {
                return Err(invalid(
                    "private-tunnel MCP gateways forbid dynamic client registration",
                ));
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
        if !valid_exact_spiffe_uri_san(identity) || !unique.insert(identity) {
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

fn valid_exact_spiffe_uri_san(identity: &str) -> bool {
    Url::parse(identity).is_ok_and(|uri| {
        uri.scheme() == "spiffe"
            && uri.host_str().is_some()
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri.port().is_none()
            && !matches!(uri.path(), "" | "/")
            && uri.query().is_none()
            && uri.fragment().is_none()
    })
}

fn validate_mount_gateway_identity(
    protocol: &str,
    enabled: bool,
    current: &str,
    expected_current: &str,
    previous: Option<&str>,
) -> Result<(), ConfigError> {
    if current != expected_current || !valid_exact_spiffe_uri_san(current) {
        return Err(invalid(&format!(
            "{protocol} current gateway URI SAN must match the fixed deployment identity"
        )));
    }
    if !enabled && previous.is_some() {
        return Err(invalid(&format!(
            "disabled {protocol} must not configure a previous gateway URI SAN"
        )));
    }
    if previous.is_some_and(|identity| !valid_exact_spiffe_uri_san(identity)) {
        return Err(invalid(&format!(
            "{protocol} previous gateway URI SAN must be an exact spiffe URI"
        )));
    }
    Ok(())
}

fn validate_disjoint_mount_gateway_identities(mounts: &MountConfig) -> Result<(), ConfigError> {
    let mut identities = std::collections::BTreeSet::new();
    for identity in [
        Some(mounts.smb.gateway_uri_san.as_str()),
        mounts.smb.previous_gateway_uri_san.as_deref(),
        Some(mounts.ftp_ftps.gateway_uri_san.as_str()),
        mounts.ftp_ftps.previous_gateway_uri_san.as_deref(),
        Some(mounts.nfs.gateway_uri_san.as_str()),
        mounts.nfs.previous_gateway_uri_san.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !identities.insert(identity) {
            return Err(invalid(
                "mount gateway current and previous URI SANs must be disjoint",
            ));
        }
    }
    Ok(())
}

fn validate_vfs_mount_gateway_identities(
    mounts: &MountConfig,
    tls: &BackendServerTlsConfig,
) -> Result<(), ConfigError> {
    if !tls.allowed_client_trust_domains.is_empty() {
        return Err(invalid(
            "VFS backend TLS must authorize mount gateways by exact URI SAN only",
        ));
    }
    let mut expected = std::collections::BTreeSet::new();
    if mounts.smb.enabled {
        expected.insert(mounts.smb.gateway_uri_san.as_str());
        expected.extend(mounts.smb.previous_gateway_uri_san.as_deref());
    }
    if mounts.ftp_ftps.enabled {
        expected.insert(mounts.ftp_ftps.gateway_uri_san.as_str());
        expected.extend(mounts.ftp_ftps.previous_gateway_uri_san.as_deref());
    }
    if mounts.nfs.enabled {
        expected.insert(mounts.nfs.gateway_uri_san.as_str());
        expected.extend(mounts.nfs.previous_gateway_uri_san.as_deref());
    }
    let configured = tls
        .allowed_client_uri_sans
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if configured != expected {
        return Err(invalid(
            "VFS backend TLS exact URI SAN allowlist must match enabled mount gateways",
        ));
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

fn validate_mcp_gateway(
    gateway_config: &McpEgressConfig,
    required: bool,
    gateway_scope: &str,
) -> Result<(), ConfigError> {
    let fields_present = [
        gateway_config.gateway_url.is_some(),
        gateway_config.client_certificate_chain_file.is_some(),
        gateway_config.client_private_key_file.is_some(),
        gateway_config.server_ca_file.is_some(),
    ];
    if !fields_present.into_iter().any(|present| present) {
        if required {
            return Err(invalid("enabled MCP requires an egress gateway"));
        }
        return Ok(());
    }
    if fields_present.into_iter().any(|present| !present) {
        return Err(invalid(&format!(
            "MCP {gateway_scope} gateway requires a URL and absolute TLS paths"
        )));
    }
    let gateway = gateway_config
        .gateway_url
        .as_ref()
        .expect("gateway URL is present");
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
    if [
        gateway_config.client_certificate_chain_file.as_ref(),
        gateway_config.client_private_key_file.as_ref(),
        gateway_config.server_ca_file.as_ref(),
    ]
    .into_iter()
    .any(|path| path.is_none_or(|path| !path.is_absolute()))
    {
        return Err(invalid(&format!(
            "MCP {gateway_scope} gateway requires a URL and absolute TLS paths"
        )));
    }
    Ok(())
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

fn validate_document_limits(documents: &DocumentConfig) -> Result<(), ConfigError> {
    if !(1..=20).contains(&documents.max_active_tabs)
        || !(1..=104_857_600).contains(&documents.max_document_bytes)
        || documents.generation_recheck_seconds != 60
    {
        return Err(invalid(
            "document limits exceed the accepted tab, byte, or generation-recheck caps",
        ));
    }
    Ok(())
}

fn validate_document_launch_action(
    url: Option<&Url>,
    public_origin: &Url,
    provider_origin: Option<&Url>,
) -> Result<(), ConfigError> {
    let url = url.ok_or_else(|| {
        invalid("enabled documents require an exact isolated HTTPS launch action URL")
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.host_str().is_some_and(|host| host.ends_with('.'))
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/onlyoffice/launch"
        || url.host_str() == public_origin.host_str()
        || provider_origin
            .is_some_and(|provider_origin| url.host_str() == provider_origin.host_str())
    {
        return Err(invalid(
            "document launch action must be an exact isolated HTTPS /onlyoffice/launch URL without credentials, query, or fragment",
        ));
    }
    Ok(())
}

fn validate_document_provider_origin(
    url: Option<&Url>,
    public_origin: &Url,
) -> Result<(), ConfigError> {
    let url =
        url.ok_or_else(|| invalid("enabled documents require an exact provider HTTPS origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.host_str().is_some_and(|host| host.ends_with('.'))
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str() == public_origin.host_str()
    {
        return Err(invalid(
            "document provider origin must be an exact HTTPS origin without credentials, path, query, or fragment",
        ));
    }
    Ok(())
}

fn validate_internal_service_url(
    url: Option<&Url>,
    mode: DeploymentMode,
    service: &str,
) -> Result<(), ConfigError> {
    let url = url.ok_or_else(|| {
        invalid(&format!(
            "enabled feature requires an internal {service} URL"
        ))
    })?;
    let loopback_http = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    let expected_scheme = if mode == DeploymentMode::Kubernetes {
        "https"
    } else if url.scheme() == "http" && loopback_http {
        "http"
    } else {
        "https"
    };
    if url.scheme() != expected_scheme
        || url.host_str().is_none()
        || url.port().is_none()
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(&format!("internal {service} URL is invalid")));
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

fn is_dns_label(name: &str) -> bool {
    !name.contains('.') && valid_dns_policy_name(name)
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

fn is_digest_pinned_image(value: &str) -> bool {
    let Some((name, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

fn validate_signing_key(key: &SigningKeyConfig, purpose: &str) -> Result<(), ConfigError> {
    if !key.private_key_file.is_absolute()
        || !key.public_keyset_file.is_absolute()
        || key.current_generation == 0
    {
        return Err(invalid(&format!(
            "{purpose} signing requires absolute private and public-keyset paths and a positive current generation"
        )));
    }
    Ok(())
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
fn default_document_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8089))
}

fn default_document_adapter_listener() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8090))
}

fn default_revision_listener() -> SocketAddr {
    "127.0.0.1:8091".parse().expect("valid default listener")
}

const fn default_revision_chunk_bytes() -> u64 {
    16 * 1024 * 1024
}

const fn default_revision_text_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_revision_object_format() -> String {
    "sha256".to_owned()
}
const fn default_revision_global_comparisons() -> u32 {
    2
}
const fn default_revision_user_comparisons() -> u32 {
    1
}
const fn default_headscale_sync_seconds() -> u64 {
    15
}
const fn default_collaboration_participants() -> u32 {
    32
}
fn default_document_provider_id() -> String {
    "onlyoffice-community-9-4".into()
}
const fn default_document_max_active_tabs() -> u32 {
    20
}
const fn default_document_max_bytes() -> u64 {
    104_857_600
}
const fn default_document_generation_recheck_seconds() -> u64 {
    60
}
fn default_media_capability_signing() -> SigningKeyConfig {
    SigningKeyConfig {
        private_key_file: "/run/secrets/media-storage-capability-private-key".into(),
        public_keyset_file: "/run/secrets/media-storage-capability-public-keyset".into(),
        current_generation: 1,
    }
}
const fn default_media_generation_recheck_seconds() -> u64 {
    60
}
const fn default_media_cache_quota_percent() -> u8 {
    10
}
const fn default_media_cache_high_watermark_percent() -> u8 {
    80
}
const fn default_media_cache_low_watermark_percent() -> u8 {
    70
}
fn default_smb_gateway_uri_san() -> String {
    SMB_GATEWAY_URI_SAN.into()
}
fn default_ftp_ftps_gateway_uri_san() -> String {
    FTP_FTPS_GATEWAY_URI_SAN.into()
}
fn default_nfs_gateway_uri_san() -> String {
    NFS_GATEWAY_URI_SAN.into()
}
const fn default_nfs_grace_seconds() -> u64 {
    90
}
const fn default_webtransport_idle_seconds() -> u64 {
    75
}
const fn default_webtransport_drain_seconds() -> u64 {
    300
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
    fn signing(private: &str, public: &str, generation: u32) -> SigningKeyConfig {
        SigningKeyConfig {
            private_key_file: private.into(),
            public_keyset_file: public.into(),
            current_generation: generation,
        }
    }

    fn configure_mount_authority(candidate: &mut Config) {
        candidate.mounts.database_url_file = Some("/run/secrets/mount-database-url".into());
        candidate.mounts.vault_keyring_file = Some("/run/secrets/mount-vault-keyring".into());
        candidate.mounts.capability_signing = Some(signing(
            "/run/secrets/mount-capability.pk8",
            "/run/secrets/mount-capability.pub",
            1,
        ));
        candidate.mounts.io_url = Some(Url::parse("http://127.0.0.1:8081/").unwrap());
        candidate.mounts.management_url = Some(Url::parse("http://127.0.0.1:8088/").unwrap());
    }

    fn backend_server_tls(identity: &str) -> BackendServerTlsConfig {
        BackendServerTlsConfig {
            certificate_chain_file: "/run/secrets/tls.crt".into(),
            private_key_file: "/run/secrets/tls.key".into(),
            client_ca_file: "/run/secrets/client-ca.crt".into(),
            allowed_client_uri_sans: vec![identity.into()],
            allowed_client_trust_domains: Vec::new(),
        }
    }

    fn configure_nfs_authority(candidate: &mut Config) {
        candidate.mounts.nfs.enabled = true;
        candidate.mounts.nfs.realm = Some("EXAMPLE.TEST".into());
        candidate.mounts.nfs.idmap_domain = Some("example.test".into());
        candidate.mounts.nfs.handle_keyring_file = Some("/run/secrets/nfs/handles.json".into());
    }

    fn configure_kubernetes_nfs(candidate: &mut Config) {
        candidate.deployment.mode = DeploymentMode::Kubernetes;
        candidate.oidc.egress_proxy_url = Some(Url::parse("http://oidc-egress:3128/").unwrap());
        candidate.telemetry.log_format = LogFormat::Json;
        candidate.telemetry.prometheus_enabled = true;
        configure_mount_authority(candidate);
        candidate.mounts.io_url = Some(Url::parse("https://filebelt-worker-io:8081/").unwrap());
        candidate.mounts.management_url =
            Some(Url::parse("https://filebelt-vfs-management:8088/").unwrap());
        candidate.mounts.io_client_certificate_chain_file =
            Some("/run/secrets/vfs-io-client/tls.crt".into());
        candidate.mounts.io_client_private_key_file =
            Some("/run/secrets/vfs-io-client/tls.key".into());
        candidate.mounts.io_server_ca_file = Some("/run/secrets/vfs-io-client/ca.crt".into());
        candidate.mounts.management_client_certificate_chain_file =
            Some("/run/secrets/vfs-management-client/tls.crt".into());
        candidate.mounts.management_client_private_key_file =
            Some("/run/secrets/vfs-management-client/tls.key".into());
        candidate.mounts.management_server_ca_file =
            Some("/run/secrets/vfs-management-client/ca.crt".into());
        configure_nfs_authority(candidate);
        candidate.backend_tls = Some(BackendTlsConfig {
            api: backend_server_tls("spiffe://filebelt.test/web-api"),
            io: backend_server_tls("spiffe://filebelt.test/web-io"),
            mcp_broker: None,
            controller: None,
            collaboration: None,
            document: None,
            document_adapter: None,
            revision: None,
            vfs: Some(backend_server_tls(NFS_GATEWAY_URI_SAN)),
            vfs_management: Some(backend_server_tls(
                "spiffe://filebelt.test/api-vfs-management",
            )),
        });
    }

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
                digest_key_file: "/run/secrets/digest-key".into(),
                digest_key_generation: 1,
                api_storage: signing(
                    "/run/secrets/api-storage.pk8",
                    "/run/secrets/api-storage.pub",
                    1,
                ),
                api_collaboration_grant: None,
                api_mcp_delegation: None,
            },
            backend_tls: None,
            telemetry: TelemetryConfig::default(),
            listeners: ListenerConfig::default(),
            limits: LimitConfig::default(),
            iggy: None,
            mcp: McpConfig::default(),
            collaboration: CollaborationConfig::default(),
            documents: DocumentConfig::default(),
            revisions: RevisionConfig::default(),
            media: MediaConfig::default(),
            mounts: MountConfig::default(),
        }
    }
    #[test]
    fn defaults_validate() {
        config().validate().unwrap();
    }
    #[test]
    fn revision_comparison_limits_are_finite_and_ordered() {
        let mut candidate = config();
        candidate.revisions.limits.global_comparisons = 0;
        assert!(candidate.validate().is_err());
        candidate.revisions.limits.global_comparisons = 33;
        assert!(candidate.validate().is_err());
        candidate.revisions.limits.global_comparisons = 2;
        candidate.revisions.limits.per_user_comparisons = 0;
        assert!(candidate.validate().is_err());
        candidate.revisions.limits.per_user_comparisons = 9;
        assert!(candidate.validate().is_err());
        candidate.revisions.limits.per_user_comparisons = 3;
        assert!(candidate.validate().is_err());
        candidate.revisions.limits.per_user_comparisons = 1;
        candidate.validate().unwrap();
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
        assert_eq!(CONFIG_VERSION, 9);
        candidate.version = 7;
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn legacy_aggregate_mount_enabled_field_is_rejected_while_parsing() {
        let source =
            toml::to_string(&config())
                .unwrap()
                .replacen("[mounts]", "[mounts]\nenabled = true", 1);
        let error = toml::from_str::<Config>(&source).unwrap_err();
        assert!(error.to_string().contains("unknown field `enabled`"));
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
            document: None,
            document_adapter: None,
            revision: None,
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
        candidate.keys.api_mcp_delegation = Some(signing(
            "/run/secrets/api-mcp-delegation.pk8",
            "/run/secrets/api-mcp-delegation.pub",
            1,
        ));
        candidate.mcp.trust_profiles.insert(
            "public".into(),
            McpTrustProfile {
                gateway: None,
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
    fn enabled_mcp_allows_a_named_public_gateway_without_legacy_egress() {
        let mut candidate = config();
        candidate.mcp.enabled = true;
        candidate.mcp.database_url_file = Some("/run/secrets/mcp-database-url".into());
        candidate.mcp.broker.url = Some(Url::parse("http://127.0.0.1:8082/").unwrap());
        candidate.mcp.attachments.io_url = Some(Url::parse("http://127.0.0.1:8081/").unwrap());
        candidate.mcp.vault.keyring_file = Some("/run/secrets/mcp-keyring".into());
        candidate.keys.api_mcp_delegation = Some(signing(
            "/run/secrets/api-mcp-delegation.pk8",
            "/run/secrets/api-mcp-delegation.pub",
            1,
        ));
        candidate.mcp.gateways.insert(
            "public".into(),
            McpEgressConfig {
                kind: McpGatewayKind::Public,
                gateway_url: Some(Url::parse("https://mcp-egress.example.test:8443/").unwrap()),
                client_certificate_chain_file: Some("/run/secrets/mcp-egress.crt".into()),
                client_private_key_file: Some("/run/secrets/mcp-egress.key".into()),
                server_ca_file: Some("/run/secrets/mcp-egress-ca.crt".into()),
            },
        );
        candidate.mcp.trust_profiles.insert(
            "public".into(),
            McpTrustProfile {
                gateway: Some("public".into()),
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
    fn enabled_mcp_rejects_unknown_or_dynamic_private_gateway_selection() {
        let mut candidate = config();
        candidate.mcp.enabled = true;
        candidate.mcp.database_url_file = Some("/run/secrets/mcp-database-url".into());
        candidate.mcp.broker.url = Some(Url::parse("http://127.0.0.1:8082/").unwrap());
        candidate.mcp.attachments.io_url = Some(Url::parse("http://127.0.0.1:8081/").unwrap());
        candidate.mcp.vault.keyring_file = Some("/run/secrets/mcp-keyring".into());
        candidate.keys.api_mcp_delegation = Some(signing(
            "/run/secrets/api-mcp-delegation.pk8",
            "/run/secrets/api-mcp-delegation.pub",
            1,
        ));
        candidate.mcp.gateways.insert(
            "private".into(),
            McpEgressConfig {
                kind: McpGatewayKind::PrivateTunnel,
                gateway_url: Some(Url::parse("https://mcp-egress.example.test:8443/").unwrap()),
                client_certificate_chain_file: Some("/run/secrets/mcp-egress.crt".into()),
                client_private_key_file: Some("/run/secrets/mcp-egress.key".into()),
                server_ca_file: Some("/run/secrets/mcp-egress-ca.crt".into()),
            },
        );
        candidate.mcp.trust_profiles.insert(
            "private".into(),
            McpTrustProfile {
                gateway: Some("missing".into()),
                public_webpki: true,
                hosts: Vec::new(),
                cidrs: Vec::new(),
                ports: vec![443],
                custom_ca_file: None,
                allow_dynamic_client_registration: false,
            },
        );
        assert!(candidate.validate().is_err());

        candidate
            .mcp
            .trust_profiles
            .get_mut("private")
            .unwrap()
            .gateway = Some("private".into());
        candidate.validate().unwrap();
        candidate
            .mcp
            .trust_profiles
            .get_mut("private")
            .unwrap()
            .allow_dynamic_client_registration = true;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn mcp_runners_are_separately_opt_in() {
        let mut candidate = config();
        candidate.mcp.runners.enabled = true;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn document_defaults_are_disabled_and_bounded() {
        let documents = DocumentConfig::default();
        assert!(!documents.enabled);
        assert_eq!(documents.provider_id, "onlyoffice-community-9-4");
        assert!(documents.capability_signing.is_none());
        assert_eq!(documents.max_active_tabs, 20);
        assert_eq!(documents.max_document_bytes, 104_857_600);
        assert_eq!(documents.generation_recheck_seconds, 60);
        assert_eq!(documents.provider_origin, None);
    }
    #[test]
    fn phase8_defaults_are_disabled_and_bounded() {
        let media = MediaConfig::default();
        assert!(!media.enabled);
        assert_eq!(media.capability_signing.current_generation, 1);
        assert_eq!(media.generation_recheck_seconds, 60);
        assert_eq!(media.cache_quota_percent, 10);
        assert_eq!(media.cache_high_watermark_percent, 80);
        assert_eq!(media.cache_low_watermark_percent, 70);

        let mounts = MountConfig::default();
        assert!(!mounts.any_protocol_enabled());
        assert!(!mounts.headscale_required());
        assert_eq!(mounts.smb.gateway_uri_san, SMB_GATEWAY_URI_SAN);
        assert_eq!(mounts.ftp_ftps.gateway_uri_san, FTP_FTPS_GATEWAY_URI_SAN);

        let nfs = mounts.nfs;
        assert!(!nfs.enabled);
        assert_eq!(nfs.gateway_uri_san, NFS_GATEWAY_URI_SAN);
        assert!(nfs.previous_gateway_uri_san.is_none());
        assert_eq!(nfs.grace_seconds, 90);

        let collaboration = CollaborationConfig::default();
        assert!(!collaboration.webtransport_enabled);
        assert_eq!(collaboration.webtransport_idle_seconds, 75);
        assert_eq!(collaboration.webtransport_drain_seconds, 300);
    }
    #[test]
    fn enabled_media_requires_digest_pinned_isolated_job_inputs() {
        let mut candidate = config();
        candidate.media.enabled = true;
        candidate.media.database_url_file = Some("/run/secrets/media-database-url".into());
        candidate.media.job_namespace = Some("filebelt-media-jobs".into());
        candidate.media.transcoder_image = Some(format!(
            "ghcr.io/oxibelt/filebelt-transcoder@sha256:{}",
            "a".repeat(64)
        ));
        candidate.media.cache_claim = Some("filebelt-media-cache".into());
        candidate.validate().unwrap();

        candidate.media.transcoder_image =
            Some("ghcr.io/oxibelt/filebelt-transcoder:latest".into());
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn independently_enabled_nfs_does_not_require_headscale() {
        let mut development = config();
        configure_mount_authority(&mut development);
        configure_nfs_authority(&mut development);
        assert!(development.validate().is_err());

        let mut candidate = config();
        configure_kubernetes_nfs(&mut candidate);
        candidate.mounts.nfs.handle_key_generation = 6;
        assert!(candidate.mounts.any_protocol_enabled());
        assert!(!candidate.mounts.headscale_required());
        candidate.validate().unwrap();

        candidate.mounts.nfs.realm = Some("example.test".into());
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn disabled_protocol_rejects_rotation_and_nfs_authority() {
        let mut candidate = config();
        candidate.mounts.smb.previous_gateway_uri_san =
            Some("spiffe://filebelt/smb-gateway/vfs-previous".into());
        assert!(candidate.validate().is_err());

        let mut candidate = config();
        candidate.mounts.nfs.handle_keyring_file = Some("/run/secrets/nfs/handles.json".into());
        assert!(candidate.validate().is_err());

        let mut candidate = config();
        candidate.mounts.nfs.handle_key_generation = 2;
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn mount_gateway_uri_sans_must_be_disjoint_across_protocols() {
        let mut candidate = config();
        configure_kubernetes_nfs(&mut candidate);
        candidate.mounts.nfs.previous_gateway_uri_san = Some(SMB_GATEWAY_URI_SAN.into());
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn vfs_tls_allowlist_must_exactly_match_enabled_gateway_identities() {
        const PREVIOUS_NFS_GATEWAY_URI_SAN: &str = "spiffe://filebelt/nfs-gateway-previous/vfs";
        let mut candidate = config();
        configure_kubernetes_nfs(&mut candidate);
        candidate.mounts.nfs.previous_gateway_uri_san = Some(PREVIOUS_NFS_GATEWAY_URI_SAN.into());
        candidate
            .backend_tls
            .as_mut()
            .unwrap()
            .vfs
            .as_mut()
            .unwrap()
            .allowed_client_uri_sans
            .push(PREVIOUS_NFS_GATEWAY_URI_SAN.into());
        candidate.validate().unwrap();

        candidate
            .backend_tls
            .as_mut()
            .unwrap()
            .vfs
            .as_mut()
            .unwrap()
            .allowed_client_uri_sans
            .pop();
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn webtransport_is_same_origin_and_separately_opt_in() {
        let mut candidate = config();
        candidate.collaboration.enabled = true;
        candidate.collaboration.database_url_file =
            Some("/run/secrets/collaboration-database-url".into());
        candidate.collaboration.capability_signing = Some(signing(
            "/run/secrets/collaboration-capability.pk8",
            "/run/secrets/collaboration-capability.pub",
            1,
        ));
        candidate.keys.api_collaboration_grant = Some(signing(
            "/run/secrets/api-collaboration-grant.pk8",
            "/run/secrets/api-collaboration-grant.pub",
            1,
        ));
        candidate.collaboration.io_url = Some(Url::parse("http://127.0.0.1:8081/").unwrap());
        candidate.collaboration.webtransport_enabled = true;
        candidate.collaboration.webtransport_endpoint =
            Some(Url::parse("https://files.example.test/collaboration/v1/wt").unwrap());
        candidate.validate().unwrap();

        candidate.collaboration.webtransport_endpoint =
            Some(Url::parse("https://other.example.test/collaboration/v1/wt").unwrap());
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn disabled_documents_reject_authority_configuration() {
        let mut candidate = config();
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/").unwrap());
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn enabled_documents_validate_with_development_loopback() {
        let mut candidate = config();
        candidate.documents.enabled = true;
        candidate.documents.database_url_file = Some("/run/secrets/document-database-url".into());
        candidate.documents.capability_signing = Some(signing(
            "/run/secrets/document-capability.pk8",
            "/run/secrets/document-capability.pub",
            1,
        ));
        candidate.documents.url = Some(Url::parse("http://127.0.0.1:8089/").unwrap());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test/onlyoffice/launch").unwrap());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/").unwrap());
        candidate.validate().unwrap();
    }
    #[test]
    fn documents_reject_unisolated_launch_actions_and_limit_changes() {
        let mut candidate = config();
        candidate.documents.enabled = true;
        candidate.documents.database_url_file = Some("/run/secrets/document-database-url".into());
        candidate.documents.capability_signing = Some(signing(
            "/run/secrets/document-capability.pk8",
            "/run/secrets/document-capability.pub",
            1,
        ));
        candidate.documents.url = Some(Url::parse("http://document:8089/").unwrap());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test/onlyoffice/launch").unwrap());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/").unwrap());
        assert!(candidate.validate().is_err());

        candidate.documents.url = Some(Url::parse("http://127.0.0.1:8089/").unwrap());
        candidate.documents.launch_action =
            Some(Url::parse("http://editor.example.test/onlyoffice/launch").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test/integrations/launch").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test:8443/onlyoffice/launch").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test./onlyoffice/launch").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://files.example.test:8443/onlyoffice/launch").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://documentserver.example.test:8443/onlyoffice/launch").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test/onlyoffice/launch?grant=leak").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test/onlyoffice/launch").unwrap());
        candidate.documents.provider_origin = None;
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("http://documentserver.example.test/").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/editor").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/?tenant=example").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/#consent").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://operator@documentserver.example.test/").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test:8443/").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test./").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://files.example.test:8443/").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://files.example.test/").unwrap());
        assert!(candidate.validate().is_err());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/").unwrap());
        candidate.documents.max_active_tabs = 21;
        assert!(candidate.validate().is_err());
        candidate.documents.max_active_tabs = 20;
        candidate.documents.max_document_bytes = 104_857_601;
        assert!(candidate.validate().is_err());
        candidate.documents.max_document_bytes = 104_857_600;
        candidate.documents.generation_recheck_seconds = 59;
        assert!(candidate.validate().is_err());
        candidate.documents.generation_recheck_seconds = 60;
        candidate
            .documents
            .capability_signing
            .as_mut()
            .unwrap()
            .current_generation = 0;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn kubernetes_documents_require_distinct_mtls_listeners() {
        let mut candidate = config();
        candidate.deployment.mode = DeploymentMode::Kubernetes;
        candidate.oidc.egress_proxy_url = Some(Url::parse("http://oidc-egress:3128/").unwrap());
        candidate.telemetry.log_format = LogFormat::Json;
        candidate.telemetry.prometheus_enabled = true;
        candidate.documents.enabled = true;
        candidate.documents.database_url_file = Some("/run/secrets/document-database-url".into());
        candidate.documents.capability_signing = Some(signing(
            "/run/secrets/document-capability.pk8",
            "/run/secrets/document-capability.pub",
            1,
        ));
        candidate.documents.url = Some(Url::parse("https://document:8089/").unwrap());
        candidate.documents.launch_action =
            Some(Url::parse("https://editor.example.test/onlyoffice/launch").unwrap());
        candidate.documents.provider_origin =
            Some(Url::parse("https://documentserver.example.test/").unwrap());
        candidate.documents.client_certificate_chain_file =
            Some("/run/secrets/api-document.crt".into());
        candidate.documents.client_private_key_file = Some("/run/secrets/api-document.key".into());
        candidate.documents.server_ca_file = Some("/run/secrets/document-ca.crt".into());
        candidate.backend_tls = Some(BackendTlsConfig {
            api: BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/api.crt".into(),
                private_key_file: "/run/secrets/api.key".into(),
                client_ca_file: "/run/secrets/api-ca.crt".into(),
                allowed_client_uri_sans: vec!["spiffe://filebelt.test/web-api".into()],
                allowed_client_trust_domains: Vec::new(),
            },
            io: BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/io.crt".into(),
                private_key_file: "/run/secrets/io.key".into(),
                client_ca_file: "/run/secrets/io-ca.crt".into(),
                allowed_client_uri_sans: vec!["spiffe://filebelt.test/web-io".into()],
                allowed_client_trust_domains: Vec::new(),
            },
            mcp_broker: None,
            controller: None,
            collaboration: None,
            document: Some(BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/document.crt".into(),
                private_key_file: "/run/secrets/document.key".into(),
                client_ca_file: "/run/secrets/document-client-ca.crt".into(),
                allowed_client_uri_sans: vec!["spiffe://filebelt.test/api-document".into()],
                allowed_client_trust_domains: Vec::new(),
            }),
            document_adapter: Some(BackendServerTlsConfig {
                certificate_chain_file: "/run/secrets/document-adapter.crt".into(),
                private_key_file: "/run/secrets/document-adapter.key".into(),
                client_ca_file: "/run/secrets/document-adapter-client-ca.crt".into(),
                allowed_client_uri_sans: vec!["spiffe://filebelt.test/onlyoffice-document".into()],
                allowed_client_trust_domains: Vec::new(),
            }),
            revision: None,
            vfs: None,
            vfs_management: None,
        });
        candidate.validate().unwrap();

        candidate.listeners.document = candidate.listeners.io;
        assert!(candidate.validate().is_err());
        candidate.listeners.document = default_document_listener();
        candidate
            .backend_tls
            .as_mut()
            .unwrap()
            .document
            .as_mut()
            .unwrap()
            .allowed_client_uri_sans = vec!["spiffe://filebelt.test/web-api".into()];
        assert!(candidate.validate().is_err());
        candidate
            .backend_tls
            .as_mut()
            .unwrap()
            .document
            .as_mut()
            .unwrap()
            .allowed_client_uri_sans = vec!["spiffe://filebelt.test/api-document".into()];
        candidate.listeners.document_adapter = candidate.listeners.document;
        assert!(candidate.validate().is_err());
    }
    #[test]
    fn headscale_sync_requires_exact_https_issuer() {
        let mut candidate = config();
        configure_mount_authority(&mut candidate);
        candidate.mounts.smb.enabled = true;
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
    fn smb_and_ftp_ftps_require_headscale_while_nfs_does_not() {
        let mut candidate = config();
        configure_mount_authority(&mut candidate);
        candidate.mounts.smb.enabled = true;
        assert!(candidate.validate().is_err());

        let mut candidate = config();
        configure_mount_authority(&mut candidate);
        candidate.mounts.ftp_ftps.enabled = true;
        assert!(candidate.validate().is_err());

        let mut candidate = config();
        configure_kubernetes_nfs(&mut candidate);
        candidate.validate().unwrap();
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
            document: None,
            document_adapter: None,
            revision: None,
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
            document: None,
            document_adapter: None,
            revision: None,
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
            document: None,
            document_adapter: None,
            revision: None,
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
        let source = source
            .replace("{{ .Values.capabilityGenerations.apiStorage }}", "1")
            .replace("{{ .Values.capabilityGenerations.mediaStorage }}", "2");
        let configuration: Config = toml::from_str(&source).unwrap();
        configuration.validate().unwrap();
        assert_eq!(configuration.deployment.mode, DeploymentMode::Kubernetes);
        assert_eq!(configuration.keys.api_storage.current_generation, 1);
        assert_eq!(configuration.media.capability_signing.current_generation, 2);
    }
}

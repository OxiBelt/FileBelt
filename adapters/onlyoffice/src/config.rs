// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub const DOCUMENT_SERVER_VERSION: &str = "9.4.0";
pub const JWT_RETIREMENT_OVERLAP: Duration = Duration::from_secs(30 * 60);
pub const MAX_OUTPUT_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_ACTIVE_TABS: usize = 20;

/// This is the sole provider selected by the approved slice. Adding a value
/// requires a new provider-specific review; it is not a user setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    OnlyOfficeDocumentServer940,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Origin(String);

impl Origin {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidOrigin)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(ConfigError::InvalidOrigin);
        }
        Ok(Self(value.trim_end_matches('/').to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accept an absolute HTTPS URL only when its origin is exactly the
    /// configured DocumentServer origin. Prefix checks are not URL checks:
    /// they would admit `office.example.test.evil.invalid` and userinfo.
    pub fn exact_url(&self, value: &str) -> bool {
        let Ok(url) = Url::parse(value) else {
            return false;
        };
        url.origin().ascii_serialization() == self.0
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtlsClientConfig {
    pub url: Url,
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
    pub server_ca_file: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerTlsConfig {
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
    pub client_ca_file: PathBuf,
    pub allowed_client_uri_san: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterConfig {
    pub provider: Provider,
    pub document_server_version: String,
    pub public_origin: Origin,
    pub document_server_origin: Origin,
    pub document_server_api_js: String,
    /// Signs the browser initialization configuration. This key is not
    /// accepted at inbound provider endpoints.
    pub browser_jwt_file: PathBuf,
    /// Verifies DocumentServer outbox tokens. Rotation accepts the current key
    /// and a strictly time-bounded retiring key.
    pub outbox_jwt_current_file: PathBuf,
    pub outbox_jwt_retiring_file: Option<PathBuf>,
    pub outbox_jwt_retiring_until: Option<SystemTime>,
    pub tenant_id: String,
    pub core: MtlsClientConfig,
    pub io: MtlsClientConfig,
    pub egress_gateway: MtlsClientConfig,
    pub server_tls: ServerTlsConfig,
}

impl AdapterConfig {
    pub fn validate(&self, now: SystemTime) -> Result<(), ConfigError> {
        if self.provider != Provider::OnlyOfficeDocumentServer940
            || self.document_server_version != DOCUMENT_SERVER_VERSION
        {
            return Err(ConfigError::UnsupportedProviderVersion);
        }
        let expected_api = format!(
            "{}/web-apps/apps/api/documents/api.js",
            self.document_server_origin.as_str()
        );
        if self.document_server_api_js != expected_api {
            return Err(ConfigError::UnexpectedProviderApi);
        }
        if self.tenant_id.is_empty()
            || !self
                .tenant_id
                .chars()
                .all(|value| value.is_ascii_hexdigit() || value == '-')
        {
            return Err(ConfigError::InvalidCallbackClaims);
        }
        for endpoint in [&self.core, &self.io, &self.egress_gateway] {
            if endpoint.url.scheme() != "https"
                || endpoint.url.host_str().is_none()
                || !endpoint.url.username().is_empty()
                || endpoint.url.password().is_some()
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
                || endpoint.url.path() != "/"
            {
                return Err(ConfigError::InvalidMtlsEndpoint);
            }
        }
        if !self
            .server_tls
            .allowed_client_uri_san
            .starts_with("spiffe://")
            || self.server_tls.allowed_client_uri_san.len() > 2048
            || self
                .server_tls
                .allowed_client_uri_san
                .chars()
                .any(char::is_whitespace)
        {
            return Err(ConfigError::InvalidServerTls);
        }
        match (
            &self.outbox_jwt_retiring_file,
            self.outbox_jwt_retiring_until,
        ) {
            (None, None) => {}
            (Some(_), Some(until))
                if until > now
                    && until.duration_since(now).unwrap_or_default() <= JWT_RETIREMENT_OVERLAP => {}
            _ => return Err(ConfigError::InvalidRetiringKey),
        }
        Ok(())
    }

    pub fn load_browser_key(&self, now: SystemTime) -> Result<Vec<u8>, ConfigError> {
        self.validate(now)?;
        read_secret(&self.browser_jwt_file)
    }

    pub fn load_outbox_keys(&self, now: SystemTime) -> Result<JwtKeySet, ConfigError> {
        self.validate(now)?;
        let current = read_secret(&self.outbox_jwt_current_file)?;
        let retiring = match (
            &self.outbox_jwt_retiring_file,
            self.outbox_jwt_retiring_until,
        ) {
            (Some(path), Some(until)) if until > now => Some(read_secret(path)?),
            _ => None,
        };
        Ok(JwtKeySet { current, retiring })
    }

    pub fn load(path: &Path, now: SystemTime) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|_| ConfigError::ConfigUnreadable)?;
        let wire: WireConfig = toml::from_str(&text).map_err(|_| ConfigError::InvalidConfig)?;
        let retiring_until = wire
            .outbox_jwt_retiring_until_unix_seconds
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds));
        let config = Self {
            provider: match wire.provider.as_str() {
                "onlyoffice_document_server_9_4_0" => Provider::OnlyOfficeDocumentServer940,
                _ => return Err(ConfigError::UnsupportedProviderVersion),
            },
            document_server_version: wire.document_server_version,
            public_origin: Origin::parse(&wire.public_origin)?,
            document_server_origin: Origin::parse(&wire.document_server_origin)?,
            document_server_api_js: wire.document_server_api_js,
            browser_jwt_file: wire.browser_jwt_file.into(),
            outbox_jwt_current_file: wire.outbox_jwt_current_file.into(),
            outbox_jwt_retiring_file: wire.outbox_jwt_retiring_file.map(Into::into),
            outbox_jwt_retiring_until: retiring_until,
            tenant_id: wire.tenant_id,
            core: wire.core.try_into()?,
            io: wire.io.try_into()?,
            egress_gateway: wire.egress_gateway.try_into()?,
            server_tls: wire.server_tls.into(),
        };
        config.validate(now)?;
        Ok(config)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfig {
    provider: String,
    document_server_version: String,
    public_origin: String,
    document_server_origin: String,
    document_server_api_js: String,
    browser_jwt_file: String,
    outbox_jwt_current_file: String,
    #[serde(default)]
    outbox_jwt_retiring_file: Option<String>,
    #[serde(default)]
    outbox_jwt_retiring_until_unix_seconds: Option<u64>,
    tenant_id: String,
    core: WireMtlsClientConfig,
    io: WireMtlsClientConfig,
    egress_gateway: WireMtlsClientConfig,
    server_tls: WireServerTlsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMtlsClientConfig {
    url: String,
    certificate_chain_file: String,
    private_key_file: String,
    server_ca_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireServerTlsConfig {
    certificate_chain_file: String,
    private_key_file: String,
    client_ca_file: String,
    allowed_client_uri_san: String,
}

impl From<WireServerTlsConfig> for ServerTlsConfig {
    fn from(value: WireServerTlsConfig) -> Self {
        Self {
            certificate_chain_file: value.certificate_chain_file.into(),
            private_key_file: value.private_key_file.into(),
            client_ca_file: value.client_ca_file.into(),
            allowed_client_uri_san: value.allowed_client_uri_san,
        }
    }
}

impl TryFrom<WireMtlsClientConfig> for MtlsClientConfig {
    type Error = ConfigError;

    fn try_from(value: WireMtlsClientConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            url: Url::parse(&value.url).map_err(|_| ConfigError::InvalidMtlsEndpoint)?,
            certificate_chain_file: value.certificate_chain_file.into(),
            private_key_file: value.private_key_file.into(),
            server_ca_file: value.server_ca_file.into(),
        })
    }
}

fn read_secret(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let value = fs::read(path).map_err(|_| ConfigError::SecretUnreadable)?;
    let value = value.strip_suffix(b"\n").unwrap_or(&value).to_vec();
    if !(32..=4096).contains(&value.len()) || value.iter().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ConfigError::InvalidSecret);
    }
    Ok(value)
}

#[derive(Debug, Eq, PartialEq)]
pub struct JwtKeySet {
    pub current: Vec<u8>,
    pub retiring: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    ConfigUnreadable,
    InvalidConfig,
    InvalidOrigin,
    UnsupportedProviderVersion,
    UnexpectedProviderApi,
    InvalidCallbackClaims,
    InvalidMtlsEndpoint,
    InvalidServerTls,
    InvalidRetiringKey,
    SecretUnreadable,
    InvalidSecret,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn mtls(url: &str) -> MtlsClientConfig {
        MtlsClientConfig {
            url: Url::parse(url).unwrap(),
            certificate_chain_file: "certificate".into(),
            private_key_file: "key".into(),
            server_ca_file: "ca".into(),
        }
    }

    fn config() -> AdapterConfig {
        AdapterConfig {
            provider: Provider::OnlyOfficeDocumentServer940,
            document_server_version: DOCUMENT_SERVER_VERSION.into(),
            public_origin: Origin::parse("https://files.example.test").unwrap(),
            document_server_origin: Origin::parse("https://office.example.test").unwrap(),
            document_server_api_js:
                "https://office.example.test/web-apps/apps/api/documents/api.js".into(),
            browser_jwt_file: "browser".into(),
            outbox_jwt_current_file: "outbox-current".into(),
            outbox_jwt_retiring_file: None,
            outbox_jwt_retiring_until: None,
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            core: mtls("https://document.example.test"),
            io: mtls("https://io.example.test"),
            egress_gateway: mtls("https://egress.example.test"),
            server_tls: ServerTlsConfig {
                certificate_chain_file: "server-certificate".into(),
                private_key_file: "server-key".into(),
                client_ca_file: "client-ca".into(),
                allowed_client_uri_san: "spiffe://filebelt/oxibelt/onlyoffice".into(),
            },
        }
    }

    #[test]
    fn locks_the_provider_and_api_path() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        assert_eq!(config().validate(now), Ok(()));
        let mut bad = config();
        bad.document_server_version = "9.4.1".into();
        assert_eq!(
            bad.validate(now),
            Err(ConfigError::UnsupportedProviderVersion)
        );
        let mut bad = config();
        bad.document_server_api_js = "https://office.example.test/evil.js".into();
        assert_eq!(bad.validate(now), Err(ConfigError::UnexpectedProviderApi));
    }

    #[test]
    fn origin_matching_rejects_prefix_userinfo_and_fragments() {
        let origin = Origin::parse("https://office.example.test").unwrap();
        assert!(origin.exact_url("https://office.example.test/cache/output"));
        assert!(!origin.exact_url("https://office.example.test.evil.invalid/cache"));
        assert!(!origin.exact_url("https://office.example.test@evil.invalid/cache"));
        assert!(!origin.exact_url("https://office.example.test/cache#fragment"));
    }

    #[test]
    fn limits_retiring_key_overlap() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        let mut checked = config();
        checked.outbox_jwt_retiring_file = Some("retiring".into());
        checked.outbox_jwt_retiring_until = Some(now + JWT_RETIREMENT_OVERLAP);
        assert_eq!(checked.validate(now), Ok(()));
        checked.outbox_jwt_retiring_until =
            Some(now + JWT_RETIREMENT_OVERLAP + Duration::from_secs(1));
        assert_eq!(checked.validate(now), Err(ConfigError::InvalidRetiringKey));
    }

    #[test]
    fn requires_one_exact_spiffe_client_identity_for_inbound_tls() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        let mut checked = config();
        checked.server_tls.allowed_client_uri_san = "filebelt/oxibelt".into();
        assert_eq!(checked.validate(now), Err(ConfigError::InvalidServerTls));
        checked.server_tls.allowed_client_uri_san = "spiffe://filebelt/oxibelt one".into();
        assert_eq!(checked.validate(now), Err(ConfigError::InvalidServerTls));
    }
}

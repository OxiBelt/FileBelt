// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::Database;
use filebelt_runtime::{
    MtlsListener, OperationsState, certificate_not_after_unix_seconds, observe_request,
    operations_router, trace_request, wait_for_shutdown,
};
use openidconnect::core::{CoreClient, CoreClientAuthMethod, CoreProviderMetadata};
use openidconnect::{AuthType, ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::auth::OidcClient;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) database: Database,
    pub(crate) tenant_id: Uuid,
    oidc: Arc<tokio::sync::RwLock<OidcClient>>,
    oidc_refreshed_at: Arc<AtomicI64>,
    pub(crate) oidc_http: reqwest::Client,
    pub(crate) capability_signer: Arc<Ed25519KeyPair>,
    pub(crate) public_origin: String,
    digest_key: [u8; 32],
}

impl AppState {
    pub(crate) fn digest(&self, domain: &[u8], secret: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.digest_key);
        hasher.update(domain);
        hasher.update(secret);
        *hasher.finalize().as_bytes()
    }

    pub(crate) async fn oidc_client(&self) -> Result<OidcClient, crate::error::ApiError> {
        let refreshed_at = self.oidc_refreshed_at.load(Ordering::Acquire);
        let now = unix_time().map_err(|_| crate::error::ApiError::internal())?;
        if refreshed_at <= 0 || now.saturating_sub(refreshed_at) > 48 * 60 * 60 {
            return Err(crate::error::ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "oidc.metadata_stale",
                "OIDC provider metadata is too stale",
            ));
        }
        Ok(self.oidc.read().await.clone())
    }
}

pub(crate) async fn serve(config: Config) -> Result<()> {
    let config = Arc::new(config);
    let database_url = read_secret_string(&config.database.url_file)
        .context("cannot read the database URL secret")?;
    let database = Database::connect(&database_url, config.database.max_connections)
        .await
        .context("cannot connect to PostgreSQL")?;
    database
        .health()
        .await
        .context("PostgreSQL is unavailable")?;
    let tenant_id = database
        .tenant_by_slug(&config.tenant.slug)
        .await
        .context("configured tenant is not bootstrapped")?;

    let oidc_http = oidc_http_client(&config)?;
    let oidc = discover_oidc(&config, &oidc_http).await?;

    let private_key = std::fs::read(&config.keys.capability_private_key_file)
        .context("cannot read the capability private key")?;
    let capability_signer = Arc::new(
        Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| anyhow!("capability private key is not valid Ed25519 PKCS#8"))?,
    );
    validate_public_key(&config, &capability_signer)?;
    let digest_key_bytes =
        std::fs::read(&config.keys.digest_key_file).context("cannot read the digest key")?;
    let digest_key: [u8; 32] = digest_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("digest key must contain exactly 32 bytes"))?;
    let public_origin = config.public_origin.origin().ascii_serialization();
    let listener = config.listeners.api;
    let state = AppState {
        config: config.clone(),
        database,
        tenant_id,
        oidc: Arc::new(tokio::sync::RwLock::new(oidc)),
        oidc_refreshed_at: Arc::new(AtomicI64::new(unix_time()?)),
        oidc_http,
        capability_signer,
        public_origin,
        digest_key,
    };
    tokio::spawn(refresh_oidc(state.clone()));
    let ready_database = state.database.clone();
    let operations = OperationsState::new(
        "filebelt-api",
        state.config.telemetry.prometheus_enabled,
        move || {
            let database = ready_database.clone();
            async move { database.health().await.is_ok() }
        },
    );
    let database_ready = operations.register_gauge(
        "database_ready",
        "Whether PostgreSQL is available to this role.",
    );
    database_ready.set(1);
    let observed_database = state.database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            database_ready.set(i64::from(observed_database.health().await.is_ok()));
        }
    });
    let oidc_age = operations.register_gauge(
        "oidc_metadata_age_seconds",
        "Age of the active OIDC provider metadata.",
    );
    let refreshed_at = state.oidc_refreshed_at.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            let now = unix_time().unwrap_or_default();
            let age = now.saturating_sub(refreshed_at.load(Ordering::Acquire));
            oidc_age.set(age.max(0));
        }
    });
    if let Some(tls) = state.config.backend_tls.as_ref() {
        let expiry = certificate_not_after_unix_seconds(&tls.api).map_err(anyhow::Error::msg)?;
        operations
            .register_gauge(
                "tls_certificate_not_after_seconds",
                "Unix timestamp when the backend server certificate expires.",
            )
            .set(expiry);
    }
    let application = router(state, operations.clone());
    let operations_listener = tokio::net::TcpListener::bind(config.listeners.operations)
        .await
        .with_context(|| {
            format!(
                "cannot bind operations listener {}",
                config.listeners.operations
            )
        })?;
    let (operations_stop, operations_stopped) = tokio::sync::oneshot::channel();
    let operations_state = operations.clone();
    let operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations_state))
            .with_graceful_shutdown(async move {
                let _ = operations_stopped.await;
            })
            .await
            .map_err(|error| error.to_string())
    });
    let (application_stop, application_stopped) = tokio::sync::oneshot::channel();
    let mut application_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let tcp = tokio::net::TcpListener::bind(listener)
                .await
                .with_context(|| format!("cannot bind API listener {listener}"))?;
            tokio::spawn(async move {
                axum::serve(tcp, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .ok_or_else(|| anyhow!("Kubernetes backend TLS configuration is absent"))?;
            let listener = MtlsListener::bind(listener, &tls.api)
                .await
                .map_err(anyhow::Error::msg)?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
    };
    tracing::info!(address = %listener, "FileBelt API is ready");
    tokio::select! {
        result = &mut application_server => {
            let _ = operations_stop.send(());
            result.context("API server task failed")?.map_err(anyhow::Error::msg)?;
        }
        () = wait_for_shutdown() => {
            operations.begin_draining();
            let _ = application_stop.send(());
            if tokio::time::timeout(Duration::from_secs(45), &mut application_server).await.is_err() {
                application_server.abort();
            }
            let _ = operations_stop.send(());
        }
    }
    operations_server
        .await
        .context("operations server task failed")?
        .map_err(anyhow::Error::msg)?;
    Ok(())
}

fn router(state: AppState, operations: OperationsState) -> Router {
    Router::new()
        .nest(
            "/api/v1",
            Router::new()
                .merge(crate::auth::router())
                .merge(crate::resources::router()),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(trace_request))
        .layer(middleware::from_fn_with_state(operations, observe_request))
        .with_state(state)
}

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

fn oidc_http_client(config: &Config) -> Result<reqwest::Client> {
    let mut builder = reqwest::ClientBuilder::new()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    if !config.oidc.development_allow_insecure {
        builder = builder.https_only(true);
    }
    if let Some(path) = &config.oidc.custom_ca_file {
        let pem = std::fs::read(path).context("cannot read the OIDC custom CA bundle")?;
        let certificates = reqwest::tls::Certificate::from_pem_bundle(&pem)
            .context("OIDC custom CA bundle is not valid PEM")?;
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    if let Some(proxy) = &config.oidc.egress_proxy_url {
        builder = builder.proxy(
            reqwest::Proxy::all(proxy.as_str()).context("OIDC egress proxy URL is invalid")?,
        );
    }
    builder
        .build()
        .context("cannot initialize OIDC HTTP client")
}

async fn discover_oidc(config: &Config, http: &reqwest::Client) -> Result<OidcClient> {
    let issuer = IssuerUrl::new(config.oidc.issuer.as_str().to_owned())
        .context("configured OIDC issuer is invalid")?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, http)
        .await
        .context("OIDC discovery failed")?;
    let auth_type = select_oidc_auth_type(
        provider_metadata
            .token_endpoint_auth_methods_supported()
            .map(Vec::as_slice),
    )?;
    let redirect_url = config
        .public_origin
        .join(config.oidc.callback_path.trim_start_matches('/'))
        .context("OIDC callback URL is invalid")?;
    Ok(CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oidc.client_id.clone()),
        Some(ClientSecret::new(
            read_secret_string(&config.oidc.client_secret_file)
                .context("cannot read the OIDC client secret")?,
        )),
    )
    .set_auth_type(auth_type)
    .set_redirect_uri(
        RedirectUrl::new(redirect_url.to_string()).context("OIDC callback URL is invalid")?,
    ))
}

fn select_oidc_auth_type(methods: Option<&[CoreClientAuthMethod]>) -> Result<AuthType> {
    let Some(methods) = methods else {
        return Ok(AuthType::BasicAuth);
    };
    if methods.contains(&CoreClientAuthMethod::ClientSecretBasic) {
        return Ok(AuthType::BasicAuth);
    }
    if methods.contains(&CoreClientAuthMethod::ClientSecretPost) {
        return Ok(AuthType::RequestBody);
    }
    bail!("OIDC provider does not advertise a supported client-secret authentication method")
}

async fn refresh_oidc(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    interval.tick().await;
    loop {
        interval.tick().await;
        match discover_oidc(&state.config, &state.oidc_http).await {
            Ok(client) => {
                *state.oidc.write().await = client;
                if let Ok(now) = unix_time() {
                    state.oidc_refreshed_at.store(now, Ordering::Release);
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "OIDC metadata refresh failed");
            }
        }
    }
}

fn validate_public_key(config: &Config, signer: &Ed25519KeyPair) -> Result<()> {
    let bytes = std::fs::read(&config.keys.capability_public_key_file)
        .context("cannot read the capability public keyset")?;
    let expected = if bytes.len() == 32 {
        bytes
    } else {
        let text = std::str::from_utf8(&bytes).context("capability public keyset is not UTF-8")?;
        let mut lines = text.lines();
        if lines.next() != Some("filebelt-capability-keyset-v1") {
            bail!("capability public keyset header is invalid");
        }
        let generation = config.keys.current_generation.to_string();
        let encoded = lines
            .filter_map(|line| line.split_once(':'))
            .find_map(|(candidate, encoded)| (candidate == generation).then_some(encoded))
            .ok_or_else(|| anyhow!("current capability key generation is absent"))?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .context("current capability public key is not base64url")?
    };
    if expected.len() != 32 || !bool::from(expected.as_slice().ct_eq(signer.public_key().as_ref()))
    {
        bail!("capability private key does not match the current public key generation");
    }
    Ok(())
}

fn unix_time() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system time exceeds the supported range")
}

#[cfg(test)]
mod tests {
    use super::{select_oidc_auth_type, validate_public_key};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    use base64::Engine as _;
    use filebelt_control_protocol::{
        Config, DatabaseConfig, DeploymentConfig, DeploymentMode, ExternalSubject, KeyConfig,
        LimitConfig, ListenerConfig, OidcConfig, StorageConfig, TelemetryConfig, TenantConfig,
    };
    use openidconnect::AuthType;
    use openidconnect::core::CoreClientAuthMethod;
    use std::fs;
    use url::Url;
    use uuid::Uuid;

    #[test]
    fn oidc_client_authentication_follows_provider_metadata() {
        assert!(matches!(
            select_oidc_auth_type(None).unwrap(),
            AuthType::BasicAuth
        ));
        assert!(matches!(
            select_oidc_auth_type(Some(&[CoreClientAuthMethod::ClientSecretPost])).unwrap(),
            AuthType::RequestBody
        ));
        assert!(matches!(
            select_oidc_auth_type(Some(&[
                CoreClientAuthMethod::ClientSecretPost,
                CoreClientAuthMethod::ClientSecretBasic,
            ]))
            .unwrap(),
            AuthType::BasicAuth
        ));
        assert!(select_oidc_auth_type(Some(&[CoreClientAuthMethod::PrivateKeyJwt])).is_err());
    }

    #[test]
    fn keyset_validation_selects_configured_generation() {
        let directory = tempfile::tempdir().unwrap();
        let private = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(private.as_ref()).unwrap();
        let keyset_path = directory.path().join("capability.pub");
        fs::write(
            &keyset_path,
            format!(
                "filebelt-capability-keyset-v1\n7:{}\n",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signer.public_key())
            ),
        )
        .unwrap();
        let config = Config {
            version: 2,
            deployment: DeploymentConfig {
                mode: DeploymentMode::Development,
            },
            public_origin: Url::parse("https://files.example.test/").unwrap(),
            tenant: TenantConfig {
                slug: "test".into(),
                administrator: vec![ExternalSubject {
                    issuer: Url::parse("https://id.example.test/").unwrap(),
                    subject: "admin".into(),
                }],
            },
            database: DatabaseConfig {
                url_file: "/run/secrets/database-url".into(),
                max_connections: 1,
            },
            oidc: OidcConfig {
                issuer: Url::parse("https://id.example.test/").unwrap(),
                client_id: "test".into(),
                client_secret_file: "/run/secrets/oidc-secret".into(),
                callback_path: "/api/v1/auth/callback".into(),
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
                capability_public_key_file: keyset_path,
                digest_key_file: "/run/secrets/digest-key".into(),
                current_generation: 7,
            },
            backend_tls: None,
            telemetry: TelemetryConfig::default(),
            listeners: ListenerConfig::default(),
            limits: LimitConfig::default(),
            iggy: None,
        };
        validate_public_key(&config, &signer).unwrap();
    }
}

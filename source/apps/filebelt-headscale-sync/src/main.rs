// SPDX-License-Identifier: Apache-2.0

//! Narrow Headscale node-ownership projection into FileBelt mount state.

#![deny(unsafe_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use filebelt_control_protocol::{Config, read_secret_string};
use filebelt_database::Database;
use filebelt_database::mount::MountDeviceObservation;
use filebelt_runtime::{
    OperationsState, init_telemetry, install_crypto_provider, operations_router, wait_for_shutdown,
};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tracing::{error, info, warn};

const ROLE: &str = "filebelt-headscale-sync";
const HEADSCALE_VERSION: &str = "0.29.3";
const MAX_VERSION_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_NODE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "filebelt-headscale-sync", disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionDocument {
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeList {
    nodes: Vec<HeadscaleNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct HeadscaleNode {
    id: serde_json::Value,
    #[serde(default)]
    machine_key: String,
    #[serde(default)]
    node_key: String,
    #[serde(default)]
    disco_key: String,
    name: String,
    #[serde(default)]
    ip_addresses: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    expiry: Option<String>,
    #[serde(default)]
    pre_auth_key: Option<serde_json::Value>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    register_method: String,
    #[serde(default)]
    given_name: String,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    approved_routes: Vec<String>,
    #[serde(default)]
    available_routes: Vec<String>,
    #[serde(default)]
    subnet_routes: Vec<String>,
    user: Option<HeadscaleUser>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct HeadscaleUser {
    id: serde_json::Value,
    name: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    profile_pic_url: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--version" | "--build-info=json")
    ) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "Headscale sync stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    install_crypto_provider().map_err(|message| anyhow!(message))?;
    let Arguments {
        command: Command::Serve { config },
    } = Arguments::parse();
    let config = Config::load(&config)?;
    if !config.mounts.enabled || !config.mounts.headscale.enabled {
        bail!("Headscale synchronization is disabled");
    }
    let _telemetry = init_telemetry(&config.telemetry, ROLE).map_err(|message| anyhow!(message))?;
    let database_url = read_secret_string(
        config
            .mounts
            .database_url_file
            .as_ref()
            .ok_or_else(|| anyhow!("mount database URL file is absent"))?,
    )?;
    let database = Database::connect(&database_url, config.database.max_connections).await?;
    database.health().await?;
    let tenant_id = database.tenant_by_slug(&config.tenant.slug).await?;
    let headscale = &config.mounts.headscale;
    let api_url = headscale
        .api_url
        .clone()
        .ok_or_else(|| anyhow!("Headscale API URL is absent"))?;
    let issuer = headscale
        .oidc_issuer
        .as_ref()
        .ok_or_else(|| anyhow!("Headscale OIDC issuer is absent"))?
        .as_str()
        .trim_end_matches('/')
        .to_owned();
    let token = read_secret_string(
        headscale
            .api_token_file
            .as_ref()
            .ok_or_else(|| anyhow!("Headscale API token is absent"))?,
    )?;
    let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .context("Headscale API token is not a valid header value")?;
    let ca = std::fs::read(
        headscale
            .server_ca_file
            .as_ref()
            .ok_or_else(|| anyhow!("Headscale server CA is absent"))?,
    )
    .context("cannot read Headscale server CA")?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .build()?;

    let ready = Arc::new(AtomicBool::new(false));
    let ready_check = Arc::clone(&ready);
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, move || {
        let ready = Arc::clone(&ready_check);
        async move { ready.load(Ordering::Acquire) }
    });
    let observed = operations.register_gauge(
        "headscale_observed_devices",
        "Number of active user-owned Headscale nodes projected in the last complete sync.",
    );
    let failures = operations.register_counter(
        "headscale_sync_failures",
        "Number of Headscale synchronization attempts that failed closed.",
    );
    let operations_listener = tokio::net::TcpListener::bind(config.listeners.operations).await?;
    let operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations))
            .await
            .map_err(anyhow::Error::from)
    });
    let sync_seconds = headscale.sync_seconds;
    let sync_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(sync_seconds));
        loop {
            interval.tick().await;
            match synchronize(
                &client,
                &api_url,
                &authorization,
                &database,
                tenant_id,
                &issuer,
            )
            .await
            {
                Ok(count) => {
                    ready.store(true, Ordering::Release);
                    observed.set(i64::try_from(count).unwrap_or(i64::MAX));
                    info!(count, "Headscale node projection synchronized");
                }
                Err(error) => {
                    failures.inc();
                    ready.store(false, Ordering::Release);
                    warn!(%error, "Headscale synchronization failed closed");
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });
    tokio::select! {
        result = operations_server => result??,
        result = sync_task => result??,
        () = wait_for_shutdown() => {},
    }
    Ok(())
}

async fn synchronize(
    client: &reqwest::Client,
    api_url: &url::Url,
    authorization: &HeaderValue,
    database: &Database,
    tenant_id: uuid::Uuid,
    issuer: &str,
) -> Result<usize> {
    let version_url = api_url.join("version")?;
    let version: VersionDocument = get_bounded_json(
        client,
        version_url,
        authorization,
        MAX_VERSION_RESPONSE_BYTES,
    )
    .await?;
    if version.version.trim_start_matches('v') != HEADSCALE_VERSION {
        bail!(
            "Headscale version mismatch: expected {HEADSCALE_VERSION}, received {}",
            version.version
        );
    }
    let nodes_url = api_url.join("api/v1/node")?;
    let nodes: NodeList =
        get_bounded_json(client, nodes_url, authorization, MAX_NODE_RESPONSE_BYTES).await?;
    if nodes.nodes.len() > 10_000 {
        bail!("Headscale node list exceeds the configured safety envelope");
    }
    let mut observations = Vec::new();
    let mut node_ids = HashSet::new();
    for node in nodes.nodes {
        let node_id = scalar_id(&node.id)?;
        if !node_ids.insert(node_id.clone()) {
            bail!("Headscale returned a duplicate node ID");
        }
        if let Some(expiry) = node.expiry.as_deref() {
            let expiry = expiry
                .parse::<jiff::Timestamp>()
                .context("Headscale node expiry is invalid")?;
            if expiry <= jiff::Timestamp::now() {
                continue;
            }
        }
        if !node.tags.is_empty() {
            // Tagged/service nodes are not user devices and must never satisfy
            // an optional credential-to-user-device binding.
            continue;
        }
        let Some(user) = node.user else {
            continue;
        };
        let Some(subject) = user.provider_id else {
            continue;
        };
        if user.provider != "oidc" {
            continue;
        }
        let addresses = node
            .ip_addresses
            .into_iter()
            .map(|address| {
                address
                    .parse::<IpAddr>()
                    .map(|parsed| parsed.to_string())
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<Vec<_>>>()?;
        if addresses.is_empty() || addresses.len() > 16 {
            bail!("Headscale node {node_id} has an invalid address set");
        }
        let Some(principal_id) = database
            .mount_principal_for_external_identity(tenant_id, issuer, &subject)
            .await?
        else {
            continue;
        };
        observations.push(MountDeviceObservation {
            principal_id,
            headscale_node_id: node_id,
            issuer: issuer.to_owned(),
            subject,
            display_name: if node.name.is_empty() {
                user.name
            } else {
                node.name
            },
            addresses,
            tags: node.tags,
            capability_version: HEADSCALE_VERSION.to_owned(),
        });
    }
    database
        .replace_mount_devices(tenant_id, &observations)
        .await?;
    Ok(observations.len())
}

async fn get_bounded_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: url::Url,
    authorization: &HeaderValue,
    maximum_bytes: usize,
) -> Result<T> {
    let mut response = client
        .get(url)
        .header(AUTHORIZATION, authorization.clone())
        .send()
        .await?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        bail!("Headscale response exceeds the configured safety envelope");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("Headscale response size overflow"))?;
        if next > maximum_bytes {
            bail!("Headscale response exceeds the configured safety envelope");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("Headscale response is invalid JSON")
}

fn scalar_id(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::String(value) if !value.is_empty() && value.len() <= 255 => {
            Ok(value.clone())
        }
        serde_json::Value::Number(value) => Ok(value.to_string()),
        _ => bail!("Headscale node ID is not a bounded scalar"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_identifiers_accept_only_bounded_scalars() {
        assert_eq!(scalar_id(&serde_json::json!(42)).unwrap(), "42");
        assert_eq!(scalar_id(&serde_json::json!("node-1")).unwrap(), "node-1");
        assert!(scalar_id(&serde_json::json!({"id": 1})).is_err());
    }

    #[test]
    fn schema_rejects_unreviewed_headscale_fields() {
        let document = serde_json::json!({
            "nodes": [{
                "id": "1",
                "name": "workstation",
                "ip_addresses": ["100.64.0.2"],
                "tags": [],
                "user": {"id": "7", "name": "alice", "provider_id": "subject", "provider": "oidc"},
                "unexpected": true
            }]
        });
        assert!(serde_json::from_value::<NodeList>(document).is_err());
    }
}

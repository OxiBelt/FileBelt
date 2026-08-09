// SPDX-License-Identifier: Apache-2.0

//! Dedicated, capability-limited Markdown collaboration service.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use clap::{Parser, Subcommand};
use filebelt_collaboration::io_client::CollaborationIoClient;
use filebelt_collaboration::server::{CollaborationServerState, router};
use filebelt_collaboration::webtransport;
use filebelt_collaboration_protocol::VerificationKey as CollaborationVerificationKey;
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::Database;
use filebelt_runtime::{
    MtlsListener, OperationsState, certificate_not_after_unix_seconds, init_telemetry,
    install_crypto_provider, operations_router, trace_request, wait_for_shutdown,
};
use filebelt_storage_protocol::{VerificationKey, parse_verification_keyset};
use reqwest::{Certificate, Client, Identity};
use tracing::{error, info};

const ROLE: &str = "filebelt-collaboration";

#[derive(Debug, Parser)]
#[command(name = "filebelt-collaboration", disable_version_flag = true)]
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

#[tokio::main]
async fn main() -> ExitCode {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    let raw_refs = raw.iter().map(String::as_str).collect::<Vec<_>>();
    if matches!(raw_refs.as_slice(), ["--version"] | ["--build-info=json"]) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            let _ = error.print();
            return ExitCode::FAILURE;
        }
    };
    let result = match arguments.command {
        Command::Serve { config } => match Config::load(&config) {
            Ok(config) => match install_crypto_provider()
                .and_then(|()| init_telemetry(&config.telemetry, ROLE))
            {
                Ok(_guard) => serve(config).await,
                Err(error) => Err(anyhow!(error)),
            },
            Err(error) => Err(anyhow!(error)),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "collaboration service stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<()> {
    if !config.collaboration.enabled {
        bail!("collaboration service is disabled");
    }
    let config = Arc::new(config);
    let database_path = config
        .collaboration
        .database_url_file
        .as_ref()
        .ok_or_else(|| anyhow!("collaboration database URL is absent"))?;
    let database_url =
        read_secret_string(database_path).context("cannot read collaboration database URL")?;
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
        .context("configured tenant is unavailable")?;

    let key_path = config
        .collaboration
        .capability_private_key_file
        .as_ref()
        .ok_or_else(|| anyhow!("collaboration capability private key is absent"))?;
    let private_key =
        std::fs::read(key_path).context("cannot read collaboration capability private key")?;
    let signer = Arc::new(
        Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| anyhow!("collaboration capability key is not Ed25519 PKCS#8"))?,
    );
    let keyset_source = std::fs::read_to_string(&config.keys.capability_public_key_file)
        .context("cannot read capability verification keyset")?;
    let verification_keys = Arc::new(
        parse_verification_keyset(
            &keyset_source,
            config.collaboration.capability_key_generation,
        )
        .map_err(|_| anyhow!("capability verification keyset is invalid"))?,
    );
    validate_signer(
        &verification_keys,
        config.collaboration.capability_key_generation,
        &signer,
    )?;
    let grant_keys = Arc::new(grant_verification_keys(
        &verification_keys,
        config.keys.current_generation,
    )?);
    let http = io_http_client(&config)?;
    let io = CollaborationIoClient::new(
        http,
        config
            .collaboration
            .io_url
            .clone()
            .ok_or_else(|| anyhow!("collaboration I/O URL is absent"))?,
        signer,
        config.collaboration.capability_key_generation,
        verification_keys,
    );
    let state = CollaborationServerState::new(
        database.clone(),
        tenant_id,
        config.public_origin.origin().ascii_serialization(),
        grant_keys,
        io,
        config.collaboration.limits.clone(),
    );
    let (webtransport_stop, webtransport_stopped) = tokio::sync::watch::channel(false);
    let mut webtransport_server = config.collaboration.webtransport_enabled.then(|| {
        let server_config = Arc::clone(&config);
        let server_state = state.clone();
        tokio::spawn(async move {
            webtransport::serve(server_config, server_state, webtransport_stopped).await
        })
    });
    let application = router(state).layer(axum::middleware::from_fn(trace_request));
    let ready_database = database.clone();
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, move || {
        let database = ready_database.clone();
        async move { database.health().await.is_ok() }
    });
    let database_ready = operations.register_gauge(
        "database_ready",
        "Whether PostgreSQL is available to this role.",
    );
    database_ready.set(1);
    let observed_database = database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            database_ready.set(i64::from(observed_database.health().await.is_ok()));
        }
    });
    if let Some(tls) = config
        .backend_tls
        .as_ref()
        .and_then(|backend| backend.collaboration.as_ref())
    {
        operations
            .register_gauge(
                "tls_certificate_not_after_seconds",
                "Unix timestamp when the backend server certificate expires.",
            )
            .set(certificate_not_after_unix_seconds(tls).map_err(|message| anyhow!(message))?);
    }
    let operations_listener = tokio::net::TcpListener::bind(config.listeners.operations)
        .await
        .context("cannot bind operations listener")?;
    let (operations_stop, operations_stopped) = tokio::sync::oneshot::channel();
    let operations_state = operations.clone();
    let operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations_state))
            .with_graceful_shutdown(async move {
                let _ = operations_stopped.await;
            })
            .await
            .map_err(anyhow::Error::from)
    });
    let (application_stop, application_stopped) = tokio::sync::oneshot::channel();
    let listener = config.listeners.collaboration_ws;
    let mut application_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(listener)
                .await
                .context("cannot bind collaboration listener")?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|backend| backend.collaboration.as_ref())
                .ok_or_else(|| anyhow!("collaboration backend TLS is absent"))?;
            let listener = MtlsListener::bind(listener, tls)
                .await
                .map_err(|message| anyhow!(message))?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
    };
    info!(%listener, "collaboration service ready");
    let webtransport_failure = async {
        match webtransport_server.as_mut() {
            Some(server) => Some(server.await),
            None => std::future::pending().await,
        }
    };
    tokio::pin!(webtransport_failure);
    let result = tokio::select! {
        result = &mut application_server => result.context("collaboration server task failed")?,
        result = &mut webtransport_failure => {
            let result = result.expect("disabled WebTransport future cannot complete");
            result.context("WebTransport server task failed")??;
            Err(anyhow!("WebTransport server stopped before shutdown"))
        }
        () = wait_for_shutdown() => {
            operations.begin_draining();
            let _ = application_stop.send(());
            let _ = webtransport_stop.send(true);
            if tokio::time::timeout(Duration::from_secs(75), &mut application_server).await.is_err() {
                application_server.abort();
            }
            if let Some(server) = webtransport_server.as_mut()
                && tokio::time::timeout(
                    Duration::from_secs(config.collaboration.webtransport_drain_seconds),
                    &mut *server,
                )
                .await
                .is_err()
            {
                server.abort();
            }
            Ok(())
        }
    };
    let _ = operations_stop.send(());
    operations_server
        .await
        .context("operations server task failed")??;
    result
}

fn validate_signer(
    keys: &[VerificationKey],
    generation: u32,
    signer: &Ed25519KeyPair,
) -> Result<()> {
    let expected = keys
        .iter()
        .find(|key| key.generation == generation)
        .ok_or_else(|| anyhow!("collaboration capability generation is absent"))?;
    if expected.public_key.as_slice() != signer.public_key().as_ref() {
        bail!("collaboration capability private key does not match the keyset");
    }
    Ok(())
}

fn grant_verification_keys(
    keys: &[VerificationKey],
    api_generation: u32,
) -> Result<Vec<CollaborationVerificationKey>> {
    let keys = keys
        .iter()
        .filter(|key| key.generation == api_generation)
        .map(|key| CollaborationVerificationKey {
            generation: key.generation,
            public_key: key.public_key.clone(),
        })
        .collect::<Vec<_>>();
    if keys.len() != 1 {
        bail!("exactly one API grant verification key is required");
    }
    Ok(keys)
}

fn io_http_client(config: &Config) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(75));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let collaboration = &config.collaboration;
        let mut identity_pem = std::fs::read(
            collaboration
                .client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("collaboration I/O client certificate is absent"))?,
        )?;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&std::fs::read(
            collaboration
                .client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("collaboration I/O client key is absent"))?,
        )?);
        let identity =
            Identity::from_pem(&identity_pem).context("I/O client identity is invalid")?;
        let roots = Certificate::from_pem_bundle(&std::fs::read(
            collaboration
                .server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("collaboration I/O CA is absent"))?,
        )?)
        .context("collaboration I/O CA is invalid")?;
        builder = builder.https_only(true).identity(identity);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    builder
        .build()
        .context("cannot initialize collaboration I/O client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_verification_excludes_collaboration_signing_generation() {
        let keys = vec![
            VerificationKey {
                generation: 1,
                public_key: vec![1; 32],
            },
            VerificationKey {
                generation: 2,
                public_key: vec![2; 32],
            },
        ];
        let grants = grant_verification_keys(&keys, 1).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].generation, 1);
        assert_eq!(grants[0].public_key, vec![1; 32]);
    }

    #[test]
    fn grant_verification_requires_exact_api_generation() {
        let keys = vec![VerificationKey {
            generation: 2,
            public_key: vec![2; 32],
        }];
        assert!(grant_verification_keys(&keys, 1).is_err());
    }
}

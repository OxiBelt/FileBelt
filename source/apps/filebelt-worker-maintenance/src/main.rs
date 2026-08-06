// SPDX-License-Identifier: Apache-2.0

//! FileBelt durable maintenance worker.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use clap::{Parser, Subcommand};
use filebelt_control_protocol::{Config, IggyConfig, read_secret_string};
use filebelt_database::Database;
use filebelt_storage::StorageLayout;
use filebelt_worker_maintenance::{IggyPublisher, Maintenance};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const ROLE: &str = "filebelt-worker-maintenance";

#[derive(Debug, Parser)]
#[command(disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8082")]
        health_listener: SocketAddr,
    },
}

#[derive(Clone)]
struct HealthState {
    database: Database,
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    let raw_refs = raw.iter().map(String::as_str).collect::<Vec<_>>();
    if matches!(raw_refs.as_slice(), ["--version"] | ["--build-info=json"]) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    init_tracing();
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            let _ = error.print();
            return ExitCode::FAILURE;
        }
    };
    let result = match arguments.command {
        Command::Serve {
            config,
            health_listener,
        } => serve(&config, health_listener).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!(error = %message, "maintenance worker stopped");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

async fn serve(config_path: &Path, health_listener: SocketAddr) -> Result<(), String> {
    if health_listener.ip().is_unspecified() {
        return Err("maintenance health listener must not bind an unspecified address".into());
    }
    let config = Config::load(config_path).map_err(|error| error.to_string())?;
    let database_url =
        read_secret_string(&config.database.url_file).map_err(|error| error.to_string())?;
    let database = Database::connect(&database_url, config.database.max_connections)
        .await
        .map_err(|error| error.to_string())?;
    database.health().await.map_err(|error| error.to_string())?;
    let tenant_id = database
        .tenant_by_slug(&config.tenant.slug)
        .await
        .map_err(|error| format!("configured tenant is unavailable: {error}"))?;
    let storage = StorageLayout::new(config.storage.root.clone());
    storage.probe().await.map_err(|error| error.to_string())?;
    let maintenance = Maintenance::new(
        database.clone(),
        storage,
        tenant_id,
        config.storage.backend_id,
        i64::try_from(config.limits.orphan_grace_seconds)
            .map_err(|_| "orphan grace overflows".to_owned())?,
        i64::try_from(config.limits.expired_part_grace_seconds)
            .map_err(|_| "expired part grace overflows".to_owned())?,
    );
    let listener = tokio::net::TcpListener::bind(health_listener)
        .await
        .map_err(|error| error.to_string())?;
    let (stop_health, mut health_stopped) = watch::channel(false);
    let application = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(HealthState {
            database: database.clone(),
        });
    let health_server = tokio::spawn(async move {
        axum::serve(listener, application)
            .with_graceful_shutdown(async move {
                while !*health_stopped.borrow() {
                    if health_stopped.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
    });
    info!(listener = %health_listener, "maintenance worker ready");
    let result = run_loop(maintenance, database, tenant_id, config.iggy).await;
    let _ = stop_health.send(true);
    health_server
        .await
        .map_err(|_| "maintenance health server task failed".to_owned())?
        .map_err(|error| error.to_string())?;
    result
}

async fn run_loop(
    maintenance: Maintenance,
    database: Database,
    tenant_id: uuid::Uuid,
    iggy: Option<IggyConfig>,
) -> Result<(), String> {
    let report = maintenance
        .reconcile()
        .await
        .map_err(|error| error.to_string())?;
    info!(
        reopened_finalizations = report.reopened_finalizations,
        expired_uploads = report.expired_uploads,
        orphan_jobs = report.orphan_jobs_created,
        finalized_staging_sets_removed = report.finalized_staging_sets_removed,
        writing_temporaries_removed = report.writing_temporaries_removed,
        finalizing_temporaries_removed = report.finalizing_temporaries_removed,
        scrub_jobs_created = report.scrub_jobs_created,
        expired_capability_nonces_removed = report.expired_capability_nonces_removed,
        retained_consumer_deduplications_removed = report.retained_consumer_deduplications_removed,
        retained_outbox_events_removed = report.retained_outbox_events_removed,
        "startup reconciliation complete"
    );
    let mut job_tick = tokio::time::interval(Duration::from_secs(5));
    let mut reconcile_tick = tokio::time::interval(Duration::from_secs(60));
    let mut outbox_tick = tokio::time::interval(Duration::from_secs(5));
    for interval in [&mut job_tick, &mut reconcile_tick, &mut outbox_tick] {
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;
    }
    let mut publisher = None;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            _ = job_tick.tick() => {
                for _ in 0..32 {
                    match maintenance.run_one_job().await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => warn!(code = "job_cycle_failed", %error),
                    }
                }
            }
            _ = reconcile_tick.tick() => match maintenance.reconcile().await {
                Ok(report) => info!(reopened_finalizations = report.reopened_finalizations, expired_uploads = report.expired_uploads, orphan_jobs = report.orphan_jobs_created, finalized_staging_sets_removed = report.finalized_staging_sets_removed, writing_temporaries_removed = report.writing_temporaries_removed, finalizing_temporaries_removed = report.finalizing_temporaries_removed, scrub_jobs_created = report.scrub_jobs_created, expired_capability_nonces_removed = report.expired_capability_nonces_removed, retained_consumer_deduplications_removed = report.retained_consumer_deduplications_removed, retained_outbox_events_removed = report.retained_outbox_events_removed, "periodic reconciliation complete"),
                Err(error) => warn!(code = "reconciliation_failed", %error),
            },
            _ = outbox_tick.tick(), if iggy.is_some() => {
                let settings = iggy.as_ref().expect("guarded by is_some");
                if publisher.is_none() {
                    publisher = IggyPublisher::connect(database.clone(), tenant_id, &settings.endpoint, settings.stream.clone(), settings.partitions).await.ok();
                }
                if let Some(active) = &publisher
                    && let Err(error) = active.publish_pending(100).await
                {
                    warn!(code = "outbox_publish_failed", %error);
                    publisher = None;
                }
            }
        }
    }
}

async fn live() -> &'static str {
    "live\n"
}

async fn ready(State(state): State<HealthState>) -> Result<&'static str, StatusCode> {
    state
        .database
        .health()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok("ready\n")
}

async fn shutdown_signal() {
    let control_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            warn!("failed to install Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => warn!(%error, "failed to install termination handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = control_c => {}, () = terminate => {} }
}

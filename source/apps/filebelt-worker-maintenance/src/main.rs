// SPDX-License-Identifier: Apache-2.0

//! FileBelt durable maintenance worker.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use filebelt_control_protocol::{Config, IggyConfig, read_secret_string};
use filebelt_database::Database;
use filebelt_runtime::{
    OperationsState, init_telemetry, install_crypto_provider, operations_router, wait_for_shutdown,
};
use filebelt_storage::StorageLayout;
use filebelt_worker_maintenance::{IggyPublisher, Maintenance};
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

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
    },
}

#[derive(Clone)]
struct MaintenanceMetrics {
    reconciliations: prometheus_client::metrics::counter::Counter,
    reconciliation_failures: prometheus_client::metrics::counter::Counter,
    scrub_jobs_created: prometheus_client::metrics::counter::Counter,
    outbox_publish_failures: prometheus_client::metrics::counter::Counter,
    job_cycle_failures: prometheus_client::metrics::counter::Counter,
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
                Err(error) => Err(error),
            },
            Err(error) => Err(error.to_string()),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!(error = %message, "maintenance worker stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
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
    let metrics = MaintenanceMetrics {
        reconciliations: operations.register_counter(
            "maintenance_reconciliations",
            "Completed maintenance reconciliation passes.",
        ),
        reconciliation_failures: operations.register_counter(
            "maintenance_reconciliation_failures",
            "Failed maintenance reconciliation passes.",
        ),
        scrub_jobs_created: operations.register_counter(
            "maintenance_scrub_jobs_created",
            "Payload scrub jobs created by reconciliation.",
        ),
        outbox_publish_failures: operations.register_counter(
            "maintenance_outbox_publish_failures",
            "Failed optional Iggy publication batches.",
        ),
        job_cycle_failures: operations.register_counter(
            "maintenance_job_cycle_failures",
            "Failed durable job executions.",
        ),
    };
    let listener = tokio::net::TcpListener::bind(config.listeners.operations)
        .await
        .map_err(|error| error.to_string())?;
    let (stop_operations, operations_stopped) = tokio::sync::oneshot::channel();
    let operations_state = operations.clone();
    let operations_server = tokio::spawn(async move {
        axum::serve(listener, operations_router(operations_state))
            .with_graceful_shutdown(async move {
                let _ = operations_stopped.await;
            })
            .await
    });
    info!(listener = %config.listeners.operations, "maintenance worker ready");
    let (stop_loop, loop_stopped) = tokio::sync::oneshot::channel();
    let mut loop_task = tokio::spawn(run_loop(
        maintenance,
        database,
        tenant_id,
        config.iggy,
        metrics,
        loop_stopped,
    ));
    let result = tokio::select! {
        result = &mut loop_task => result
            .map_err(|_| "maintenance loop task failed".to_owned())?,
        () = wait_for_shutdown() => {
            operations.begin_draining();
            let _ = stop_loop.send(());
            if tokio::time::timeout(Duration::from_secs(90), &mut loop_task).await.is_err() {
                loop_task.abort();
            }
            Ok(())
        }
    };
    operations.begin_draining();
    let _ = stop_operations.send(());
    operations_server
        .await
        .map_err(|_| "maintenance operations server task failed".to_owned())?
        .map_err(|error| error.to_string())?;
    result
}

async fn run_loop(
    maintenance: Maintenance,
    database: Database,
    tenant_id: uuid::Uuid,
    iggy: Option<IggyConfig>,
    metrics: MaintenanceMetrics,
    stopped: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    let report = maintenance
        .reconcile()
        .await
        .map_err(|error| error.to_string())?;
    metrics.reconciliations.inc();
    metrics.scrub_jobs_created.inc_by(report.scrub_jobs_created);
    info!(
        reopened_finalizations = report.reopened_finalizations,
        expired_uploads = report.expired_uploads,
        orphan_jobs = report.orphan_jobs_created,
        finalized_staging_sets_removed = report.finalized_staging_sets_removed,
        mount_staging_sets_removed = report.mount_staging_sets_removed,
        writing_temporaries_removed = report.writing_temporaries_removed,
        finalizing_temporaries_removed = report.finalizing_temporaries_removed,
        scrub_jobs_created = report.scrub_jobs_created,
        expired_capability_nonces_removed = report.expired_capability_nonces_removed,
        retained_consumer_deduplications_removed = report.retained_consumer_deduplications_removed,
        retained_outbox_events_removed = report.retained_outbox_events_removed,
        collaboration_warnings_emitted = report.collaboration_warnings_emitted,
        collaboration_epochs_expired = report.collaboration_epochs_expired,
        collaboration_payload_deletions_enqueued = report.collaboration_payload_deletions_enqueued,
        collaboration_objects_abandoned = report.collaboration_objects_abandoned,
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
    let shutdown = async move {
        let _ = stopped.await;
    };
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            _ = job_tick.tick() => {
                for _ in 0..32 {
                    match maintenance.run_one_job().await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            metrics.job_cycle_failures.inc();
                            warn!(code = "job_cycle_failed", %error);
                        }
                    }
                }
            }
            _ = reconcile_tick.tick() => match maintenance.reconcile().await {
                Ok(report) => {
                    metrics.reconciliations.inc();
                    metrics.scrub_jobs_created.inc_by(report.scrub_jobs_created);
                    info!(reopened_finalizations = report.reopened_finalizations, expired_uploads = report.expired_uploads, orphan_jobs = report.orphan_jobs_created, finalized_staging_sets_removed = report.finalized_staging_sets_removed, mount_staging_sets_removed = report.mount_staging_sets_removed, writing_temporaries_removed = report.writing_temporaries_removed, finalizing_temporaries_removed = report.finalizing_temporaries_removed, scrub_jobs_created = report.scrub_jobs_created, expired_capability_nonces_removed = report.expired_capability_nonces_removed, retained_consumer_deduplications_removed = report.retained_consumer_deduplications_removed, retained_outbox_events_removed = report.retained_outbox_events_removed, collaboration_warnings_emitted = report.collaboration_warnings_emitted, collaboration_epochs_expired = report.collaboration_epochs_expired, collaboration_payload_deletions_enqueued = report.collaboration_payload_deletions_enqueued, collaboration_objects_abandoned = report.collaboration_objects_abandoned, "periodic reconciliation complete");
                }
                Err(error) => {
                    metrics.reconciliation_failures.inc();
                    warn!(code = "reconciliation_failed", %error);
                }
            },
            _ = outbox_tick.tick(), if iggy.is_some() => {
                let settings = iggy.as_ref().expect("guarded by is_some");
                if publisher.is_none() {
                    publisher = IggyPublisher::connect(database.clone(), tenant_id, &settings.endpoint, settings.stream.clone(), settings.partitions).await.ok();
                }
                if let Some(active) = &publisher
                    && let Err(error) = active.publish_pending(100).await
                {
                    metrics.outbox_publish_failures.inc();
                    warn!(code = "outbox_publish_failed", %error);
                    publisher = None;
                }
            }
        }
    }
}

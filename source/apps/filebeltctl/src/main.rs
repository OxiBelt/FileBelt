// SPDX-License-Identifier: Apache-2.0

//! FileBelt administrative and recovery CLI.

#![deny(unsafe_code)]

mod audit;
mod grants;
mod nfs;
mod phase8;
mod recovery;
mod scrub;
mod security;

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use clap::{Parser, Subcommand, ValueEnum};
use filebelt_capability_keyset::{
    ApiCollaborationGrantKeyset, ApiMcpDelegationKeyset, ApiStorageKeyset,
    CollaborationStorageKeyset, DocumentStorageKeyset, KeyPurpose as CoreKeyPurpose,
    MediaStorageKeyset, MountStorageKeyset, encode_keyset,
};
use filebelt_control_protocol::{Config, read_secret_string};
use filebelt_database::Database;
use filebelt_storage::StorageLayout;
use filebelt_worker_maintenance::Maintenance;
use sqlx::Row as _;
use uuid::Uuid;

const ROLE: &str = "filebelt-tools";

#[derive(Debug, Parser)]
#[command(name = "filebeltctl", disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Database {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    Jobs {
        #[command(subcommand)]
        command: JobCommand,
    },
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    Phase8 {
        #[command(subcommand)]
        command: Phase8Command,
    },
    Nfs {
        #[command(subcommand)]
        command: nfs::Command,
    },
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SecurityCommand {
    DescendantShares {
        #[command(subcommand)]
        command: DescendantShareCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DescendantShareCommand {
    Status {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        operation_id: Uuid,
    },
    Repair {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        operation_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u32).range(1..=1_000))]
        batch_size: u32,
    },
    Verify {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        operation_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        actor_principal_id: Uuid,
    },
    Activate {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        operation_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        actor_principal_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum Phase8Command {
    Advertise {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        role: String,
        #[arg(long)]
        instance_id: Uuid,
        #[arg(long)]
        source_revision: String,
        #[arg(long, default_value_t = false)]
        incompatible: bool,
    },
    Status {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
    Activate {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
    },
    Deactivate {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    Export {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        limit: u32,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DatabaseCommand {
    Migrate {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
    VerifyGrants {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TenantCommand {
    Bootstrap {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    Generate {
        #[arg(long, value_enum)]
        purpose: KeyPurposeArg,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_keyset: PathBuf,
        #[arg(long, default_value_t = 1)]
        generation: u32,
        #[arg(long)]
        force: bool,
    },
    Rotate {
        #[arg(long, value_enum)]
        purpose: KeyPurposeArg,
        #[arg(long)]
        previous_public_keyset: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_keyset: PathBuf,
        #[arg(long)]
        generation: u32,
    },
    Verify {
        #[arg(long, value_enum)]
        purpose: KeyPurposeArg,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_keyset: PathBuf,
        #[arg(long)]
        generation: u32,
    },
    Audit {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KeyPurposeArg {
    ApiStorage,
    ApiCollaborationGrant,
    ApiMcpDelegation,
    CollaborationStorage,
    DocumentStorage,
    MountStorage,
    MediaStorage,
}

impl From<KeyPurposeArg> for CoreKeyPurpose {
    fn from(value: KeyPurposeArg) -> Self {
        match value {
            KeyPurposeArg::ApiStorage => Self::ApiStorage,
            KeyPurposeArg::ApiCollaborationGrant => Self::ApiCollaborationGrant,
            KeyPurposeArg::ApiMcpDelegation => Self::ApiMcpDelegation,
            KeyPurposeArg::CollaborationStorage => Self::CollaborationStorage,
            KeyPurposeArg::DocumentStorage => Self::DocumentStorage,
            KeyPurposeArg::MountStorage => Self::MountStorage,
            KeyPurposeArg::MediaStorage => Self::MediaStorage,
        }
    }
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    Probe {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
    Reconcile {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = 32)]
        max_jobs: u32,
    },
    Scrub {
        #[command(subcommand)]
        command: ScrubCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ScrubCommand {
    Start {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        run_id: Uuid,
        #[arg(long)]
        payload_id: Option<Uuid>,
        #[arg(long)]
        confirm_tenant: Option<String>,
        #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        batch_size: u32,
    },
    Status {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        run_id: Uuid,
        #[arg(long)]
        payload_id: Option<Uuid>,
    },
    Verify {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        run_id: Uuid,
        #[arg(long)]
        payload_id: Option<Uuid>,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    Checkpoint {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        /// Permit offline comparison of legacy v2 evidence. This never proves
        /// purpose-bound key admission and cannot authorize restored traffic.
        #[arg(long)]
        legacy_v2_offline: bool,
    },
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    RunOne {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
    List {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long, default_value = "terminal")]
        state: String,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=200))]
        limit: u32,
    },
    Retry {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
        #[arg(long)]
        tenant_id: Uuid,
        #[arg(long)]
        job_id: Uuid,
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
    match execute(arguments.command).await {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("filebeltctl: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(command: Command) -> Result<String, String> {
    match command {
        Command::Audit {
            command:
                AuditCommand::Export {
                    config,
                    after,
                    limit,
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            audit::export(
                &database,
                &configuration.tenant.slug,
                after.as_deref(),
                limit,
            )
            .await
        }
        Command::Config {
            command: ConfigCommand::Validate { config },
        } => {
            Config::load(&config).map_err(|error| error.to_string())?;
            Ok("configuration is valid".into())
        }
        Command::Database {
            command: DatabaseCommand::Migrate { config },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            database
                .migrate()
                .await
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "database schema is current for tenant {}",
                configuration.tenant.slug
            ))
        }
        Command::Database {
            command: DatabaseCommand::VerifyGrants { config },
        } => {
            let (_, database) = configured_database(&config).await?;
            grants::verify(&database).await
        }
        Command::Tenant {
            command: TenantCommand::Bootstrap { config },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            let administrators = configuration
                .tenant
                .administrator
                .iter()
                .map(|administrator| {
                    (
                        administrator.issuer.as_str().to_owned(),
                        administrator.subject.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let tenant_id = database
                .bootstrap_tenant(
                    &configuration.tenant.slug,
                    configuration.storage.backend_id,
                    &administrators,
                )
                .await
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "tenant {} bootstrapped as {tenant_id}",
                configuration.tenant.slug
            ))
        }
        Command::Keys {
            command:
                KeyCommand::Generate {
                    purpose,
                    private_key,
                    public_keyset,
                    generation,
                    force,
                },
        } => generate_keys(
            purpose.into(),
            &private_key,
            &public_keyset,
            generation,
            force,
        ),
        Command::Keys {
            command:
                KeyCommand::Rotate {
                    purpose,
                    previous_public_keyset,
                    private_key,
                    public_keyset,
                    generation,
                },
        } => rotate_keys(
            purpose.into(),
            &previous_public_keyset,
            &private_key,
            &public_keyset,
            generation,
        ),
        Command::Keys {
            command:
                KeyCommand::Verify {
                    purpose,
                    private_key,
                    public_keyset,
                    generation,
                },
        } => verify_key_pair(purpose.into(), &private_key, &public_keyset, generation),
        Command::Keys {
            command: KeyCommand::Audit { config },
        } => {
            let configuration = Config::load(&config).map_err(|error| error.to_string())?;
            audit_keysets(&configuration)?;
            Ok("configured capability keysets are purpose-isolated".into())
        }
        Command::Storage {
            command: StorageCommand::Probe { config },
        } => {
            let configuration = Config::load(&config).map_err(|error| error.to_string())?;
            StorageLayout::new(configuration.storage.root)
                .probe()
                .await
                .map_err(|error| error.to_string())?;
            Ok("storage semantics are supported".into())
        }
        Command::Storage {
            command: StorageCommand::Reconcile { config, max_jobs },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            StorageLayout::new(configuration.storage.root.clone())
                .probe()
                .await
                .map_err(|error| error.to_string())?;
            let maintenance = configured_maintenance(&configuration, database).await?;
            let report = maintenance
                .reconcile()
                .await
                .map_err(|error| error.to_string())?;
            let mut jobs = 0_u32;
            while jobs < max_jobs
                && maintenance
                    .run_one_job()
                    .await
                    .map_err(|error| error.to_string())?
            {
                jobs += 1;
            }
            Ok(format!(
                "reconciliation complete: expired_uploads={}, orphan_jobs={}, finalized_staging_sets_removed={}, jobs_run={jobs}",
                report.expired_uploads,
                report.orphan_jobs_created,
                report.finalized_staging_sets_removed,
            ))
        }
        Command::Storage {
            command:
                StorageCommand::Scrub {
                    command:
                        ScrubCommand::Start {
                            config,
                            run_id,
                            payload_id,
                            confirm_tenant,
                            batch_size,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            scrub::start(
                &database,
                &configuration.tenant.slug,
                configuration.storage.backend_id,
                run_id,
                payload_id,
                confirm_tenant.as_deref(),
                batch_size,
            )
            .await
        }
        Command::Storage {
            command:
                StorageCommand::Scrub {
                    command:
                        ScrubCommand::Status {
                            config,
                            run_id,
                            payload_id,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            scrub::status(
                &database,
                &configuration.tenant.slug,
                configuration.storage.backend_id,
                run_id,
                payload_id,
            )
            .await
        }
        Command::Storage {
            command:
                StorageCommand::Scrub {
                    command:
                        ScrubCommand::Verify {
                            config,
                            run_id,
                            payload_id,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            scrub::verify(
                &database,
                &configuration.tenant.slug,
                configuration.storage.backend_id,
                run_id,
                payload_id,
            )
            .await
        }
        Command::Jobs {
            command: JobCommand::RunOne { config },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            StorageLayout::new(configuration.storage.root.clone())
                .probe()
                .await
                .map_err(|error| error.to_string())?;
            let maintenance = configured_maintenance(&configuration, database).await?;
            let ran = maintenance
                .run_one_job()
                .await
                .map_err(|error| error.to_string())?;
            Ok(if ran {
                "one job processed"
            } else {
                "no job was ready"
            }
            .into())
        }
        Command::Jobs {
            command:
                JobCommand::List {
                    config,
                    state,
                    limit,
                },
        } => {
            if !matches!(
                state.as_str(),
                "queued" | "running" | "retry_wait" | "terminal" | "operator_blocked" | "complete"
            ) {
                return Err("job state is invalid".into());
            }
            let (_, database) = configured_database(&config).await?;
            let rows = sqlx::query("SELECT tenant_id,id,kind,state,attempt_count,fencing_token,last_error_code,available_at::text AS available_at,lease_expires_at::text AS lease_expires_at FROM jobs WHERE state=$1 ORDER BY updated_at DESC,id LIMIT $2")
                .bind(&state)
                .bind(i64::from(limit))
                .fetch_all(database.pool())
                .await
                .map_err(|error| error.to_string())?;
            let jobs = rows
                .into_iter()
                .map(|row| {
                    serde_json::json!({
                        "tenant_id": row.get::<Uuid, _>("tenant_id"),
                        "job_id": row.get::<Uuid, _>("id"),
                        "kind": row.get::<String, _>("kind"),
                        "state": row.get::<String, _>("state"),
                        "attempt_count": row.get::<i32, _>("attempt_count"),
                        "fencing_token": row.get::<i64, _>("fencing_token"),
                        "last_error_code": row.get::<Option<String>, _>("last_error_code"),
                        "available_at": row.get::<String, _>("available_at"),
                        "lease_expires_at": row.get::<Option<String>, _>("lease_expires_at"),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::to_string_pretty(&jobs).map_err(|error| error.to_string())
        }
        Command::Jobs {
            command:
                JobCommand::Retry {
                    config,
                    tenant_id,
                    job_id,
                },
        } => {
            let (_, database) = configured_database(&config).await?;
            let mut transaction = database
                .pool()
                .begin()
                .await
                .map_err(|error| error.to_string())?;
            let row = sqlx::query("SELECT kind,aggregate_id,payload FROM jobs WHERE tenant_id=$1 AND id=$2 AND state IN ('terminal','operator_blocked') FOR UPDATE")
                .bind(tenant_id)
                .bind(job_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "terminal job was not found".to_owned())?;
            let retry_id = Uuid::new_v4();
            sqlx::query("INSERT INTO jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) VALUES ($1,$2,$3,'queued',50,$4,$5,$6)")
                .bind(tenant_id)
                .bind(retry_id)
                .bind(row.get::<String, _>("kind"))
                .bind(row.get::<Option<Uuid>, _>("aggregate_id"))
                .bind(format!("operator-retry:{job_id}:{retry_id}"))
                .bind(row.get::<serde_json::Value, _>("payload"))
                .execute(&mut *transaction)
                .await
                .map_err(|error| error.to_string())?;
            sqlx::query("INSERT INTO audit_events (tenant_id,id,action,outcome,reason_code,privacy_visible,details) VALUES ($1,$2,'job.retry','allowed','operator_retry',false,$3)")
                .bind(tenant_id)
                .bind(Uuid::new_v4())
                .bind(serde_json::json!({"terminal_job_id": job_id, "retry_job_id": retry_id}))
                .execute(&mut *transaction)
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .commit()
                .await
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "retry job {retry_id} queued for terminal job {job_id}"
            ))
        }
        Command::Recovery {
            command: RecoveryCommand::Checkpoint { config },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            recovery::checkpoint(&database, &configuration).await
        }
        Command::Recovery {
            command:
                RecoveryCommand::Verify {
                    config,
                    checkpoint,
                    legacy_v2_offline,
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            recovery::verify(&database, &configuration, &checkpoint, legacy_v2_offline).await
        }
        Command::Phase8 {
            command:
                Phase8Command::Advertise {
                    config,
                    role,
                    instance_id,
                    source_revision,
                    incompatible,
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            phase8::advertise(
                &database,
                &configuration.tenant.slug,
                &role,
                instance_id,
                &source_revision,
                !incompatible,
            )
            .await
        }
        Command::Phase8 {
            command: Phase8Command::Status { config },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            phase8::status(&database, &configuration.tenant.slug).await
        }
        Command::Phase8 {
            command:
                Phase8Command::Activate {
                    config,
                    actor_principal_id,
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            phase8::activate(&database, &configuration.tenant.slug, actor_principal_id).await
        }
        Command::Phase8 {
            command:
                Phase8Command::Deactivate {
                    config,
                    actor_principal_id,
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            phase8::deactivate(&database, &configuration.tenant.slug, actor_principal_id).await
        }
        Command::Nfs { command } => nfs::execute(command).await,
        Command::Security {
            command:
                SecurityCommand::DescendantShares {
                    command:
                        DescendantShareCommand::Status {
                            config,
                            operation_id,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            security::descendant_shares_status(&database, &configuration.tenant.slug, operation_id)
                .await
        }
        Command::Security {
            command:
                SecurityCommand::DescendantShares {
                    command:
                        DescendantShareCommand::Repair {
                            config,
                            operation_id,
                            confirm_tenant,
                            actor_principal_id,
                            batch_size,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            security::repair_descendant_shares(
                &database,
                &configuration.tenant.slug,
                operation_id,
                &confirm_tenant,
                actor_principal_id,
                batch_size,
            )
            .await
        }
        Command::Security {
            command:
                SecurityCommand::DescendantShares {
                    command:
                        DescendantShareCommand::Verify {
                            config,
                            operation_id,
                            confirm_tenant,
                            actor_principal_id,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            security::verify_descendant_shares(
                &database,
                &configuration.tenant.slug,
                operation_id,
                &confirm_tenant,
                actor_principal_id,
            )
            .await
        }
        Command::Security {
            command:
                SecurityCommand::DescendantShares {
                    command:
                        DescendantShareCommand::Activate {
                            config,
                            operation_id,
                            confirm_tenant,
                            actor_principal_id,
                        },
                },
        } => {
            let (configuration, database) = configured_database(&config).await?;
            security::activate_descendant_shares(
                &database,
                &configuration.tenant.slug,
                operation_id,
                &confirm_tenant,
                actor_principal_id,
            )
            .await
        }
    }
}

async fn configured_database(path: &Path) -> Result<(Config, Database), String> {
    let configuration = Config::load(path).map_err(|error| error.to_string())?;
    let database_url =
        read_secret_string(&configuration.database.url_file).map_err(|error| error.to_string())?;
    let database = Database::connect(&database_url, configuration.database.max_connections)
        .await
        .map_err(|error| error.to_string())?;
    Ok((configuration, database))
}

async fn configured_maintenance(
    configuration: &Config,
    database: Database,
) -> Result<Maintenance, String> {
    let tenant_id = database
        .tenant_by_slug(&configuration.tenant.slug)
        .await
        .map_err(|error| error.to_string())?;
    Ok(Maintenance::new(
        database,
        StorageLayout::new(configuration.storage.root.clone()),
        tenant_id,
        configuration.storage.backend_id,
        i64::try_from(configuration.limits.orphan_grace_seconds)
            .map_err(|_| "orphan grace overflows".to_owned())?,
        i64::try_from(configuration.limits.expired_part_grace_seconds)
            .map_err(|_| "expired part grace overflows".to_owned())?,
    ))
}

fn generate_keys(
    purpose: CoreKeyPurpose,
    private_key_path: &Path,
    public_keyset_path: &Path,
    generation: u32,
    force: bool,
) -> Result<String, String> {
    if generation == 0 {
        return Err("key generation must be positive".into());
    }
    if private_key_path == public_keyset_path {
        return Err("private key and public keyset paths must differ".into());
    }
    let private_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "failed to generate Ed25519 key".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(private_key.as_ref())
        .map_err(|_| "generated Ed25519 key is invalid".to_owned())?;
    let public_keyset = encode_keyset(
        purpose,
        &[(
            generation,
            pair.public_key()
                .as_ref()
                .try_into()
                .expect("Ed25519 public key length"),
        )],
    )
    .map_err(|_| "capability keyset is invalid".to_owned())?;
    verify_pair(&public_keyset, purpose, generation, &pair)?;
    write_key_file(private_key_path, private_key.as_ref(), 0o600, force)?;
    if let Err(error) = write_key_file(public_keyset_path, public_keyset.as_bytes(), 0o644, force) {
        if !force {
            let _ = fs::remove_file(private_key_path);
        }
        return Err(error);
    }
    Ok(format!(
        "{} capability key generation {generation} created",
        purpose
    ))
}

fn rotate_keys(
    purpose: CoreKeyPurpose,
    previous_public_keyset_path: &Path,
    private_key_path: &Path,
    public_keyset_path: &Path,
    generation: u32,
) -> Result<String, String> {
    if generation == 0
        || private_key_path == public_keyset_path
        || private_key_path == previous_public_keyset_path
        || public_keyset_path == previous_public_keyset_path
    {
        return Err("rotation key paths and generation are invalid".into());
    }
    let existing =
        fs::read_to_string(previous_public_keyset_path).map_err(|error| error.to_string())?;
    let records = read_keyset(&existing, purpose)?;
    if records.len() != 1 || records.iter().any(|(known, _)| *known == generation) {
        return Err(
            "rotation requires exactly one previous generation and a new generation".into(),
        );
    }
    let private_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "failed to generate Ed25519 key".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(private_key.as_ref())
        .map_err(|_| "generated Ed25519 key is invalid".to_owned())?;
    let public = pair
        .public_key()
        .as_ref()
        .try_into()
        .expect("Ed25519 public key length");
    let public_keyset = encode_keyset(
        purpose,
        &[(records[0].0, records[0].1), (generation, public)],
    )
    .map_err(|_| "capability keyset is invalid".to_owned())?;
    verify_pair(&public_keyset, purpose, generation, &pair)?;
    // A private rotation target is always created; it is never overwritten.
    write_key_file(private_key_path, private_key.as_ref(), 0o600, false)?;
    if let Err(error) = write_key_file(public_keyset_path, public_keyset.as_bytes(), 0o644, false) {
        let _ = fs::remove_file(private_key_path);
        return Err(error);
    }
    Ok(format!(
        "{} capability key rotated to generation {generation}",
        purpose
    ))
}

fn verify_pair(
    keyset: &str,
    purpose: CoreKeyPurpose,
    generation: u32,
    pair: &Ed25519KeyPair,
) -> Result<(), String> {
    let records = read_keyset(keyset, purpose)?;
    if records
        .iter()
        .find(|(candidate, _)| *candidate == generation)
        .is_none_or(|(_, public)| public.as_slice() != pair.public_key().as_ref())
    {
        return Err("generated capability private key does not match public keyset".into());
    }
    Ok(())
}

pub(crate) fn read_keyset(
    source: &str,
    purpose: CoreKeyPurpose,
) -> Result<Vec<(u32, [u8; 32])>, String> {
    macro_rules! entries {
        ($keyset:ty) => {{
            <$keyset>::parse(source)
                .map_err(|_| "capability keyset is invalid".to_owned())?
                .entries()
                .map(|(generation, public)| (generation, *public))
                .collect()
        }};
    }
    Ok(match purpose {
        CoreKeyPurpose::ApiStorage => entries!(ApiStorageKeyset),
        CoreKeyPurpose::ApiCollaborationGrant => entries!(ApiCollaborationGrantKeyset),
        CoreKeyPurpose::ApiMcpDelegation => entries!(ApiMcpDelegationKeyset),
        CoreKeyPurpose::CollaborationStorage => entries!(CollaborationStorageKeyset),
        CoreKeyPurpose::DocumentStorage => entries!(DocumentStorageKeyset),
        CoreKeyPurpose::MountStorage => entries!(MountStorageKeyset),
        CoreKeyPurpose::MediaStorage => entries!(MediaStorageKeyset),
    })
}

fn verify_key_pair(
    purpose: CoreKeyPurpose,
    private_key_path: &Path,
    public_keyset_path: &Path,
    generation: u32,
) -> Result<String, String> {
    let private =
        fs::read(private_key_path).map_err(|_| "capability private key is invalid".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(&private)
        .map_err(|_| "capability private key is invalid".to_owned())?;
    let keyset = fs::read_to_string(public_keyset_path)
        .map_err(|_| "capability public keyset is invalid".to_owned())?;
    verify_pair(&keyset, purpose, generation, &pair)?;
    Ok(format!(
        "{} capability key generation {generation} verified",
        purpose
    ))
}

fn audit_keysets(configuration: &Config) -> Result<(), String> {
    let mut configured = vec![
        (CoreKeyPurpose::ApiStorage, &configuration.keys.api_storage),
        (
            CoreKeyPurpose::MediaStorage,
            &configuration.media.capability_signing,
        ),
    ];
    if let Some(key) = &configuration.keys.api_collaboration_grant {
        configured.push((CoreKeyPurpose::ApiCollaborationGrant, key));
    }
    if let Some(key) = &configuration.keys.api_mcp_delegation {
        configured.push((CoreKeyPurpose::ApiMcpDelegation, key));
    }
    if let Some(key) = &configuration.collaboration.capability_signing {
        configured.push((CoreKeyPurpose::CollaborationStorage, key));
    }
    if let Some(key) = &configuration.documents.capability_signing {
        configured.push((CoreKeyPurpose::DocumentStorage, key));
    }
    if let Some(key) = &configuration.mounts.capability_signing {
        configured.push((CoreKeyPurpose::MountStorage, key));
    }
    let mut observed = Vec::<[u8; 32]>::new();
    for (purpose, key) in configured {
        let source = fs::read_to_string(&key.public_keyset_file)
            .map_err(|_| "capability public keyset is invalid".to_owned())?;
        let records = read_keyset(&source, purpose)
            .map_err(|_| "capability public keyset is invalid".to_owned())?;
        if !records
            .iter()
            .any(|(generation, _)| *generation == key.current_generation)
        {
            return Err("capability current generation is absent".into());
        }
        for (_, public) in records {
            if observed.contains(&public) {
                return Err("capability public key material is reused across purposes".into());
            }
            observed.push(public);
        }
    }
    Ok(())
}

fn write_key_file(path: &Path, bytes: &[u8], mode: u32, force: bool) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("key paths must be absolute".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "key path has no parent".to_owned())?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err("key parent directory is unsafe".into());
    }
    let temporary = parent.join(format!(".filebelt-key-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    let publish = if force {
        fs::rename(&temporary, path)
    } else {
        fs::hard_link(&temporary, path).and_then(|()| fs::remove_file(&temporary))
    };
    if let Err(error) = publish {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_pair_has_secure_private_mode_and_versioned_public_set() {
        let temporary = tempfile::tempdir().expect("temporary key directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
        let private = temporary.path().join("capability.pk8");
        let public = temporary.path().join("capability.pub");
        generate_keys(CoreKeyPurpose::ApiStorage, &private, &public, 7, false)
            .expect("generate key pair");
        let private_metadata = fs::metadata(&private).expect("private key metadata");
        assert_eq!(private_metadata.permissions().mode() & 0o777, 0o600);
        let public_text = fs::read_to_string(public).expect("public keyset");
        assert!(public_text.starts_with("filebelt-capability-keyset-v2\npurpose=api-storage\n7:"));
        assert!(
            generate_keys(
                CoreKeyPurpose::ApiStorage,
                &private,
                &temporary.path().join("second.pub"),
                8,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn rotation_preserves_only_current_and_one_retiring_generation() {
        let temporary = tempfile::tempdir().expect("temporary key directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
        let first_private = temporary.path().join("first.pk8");
        let public = temporary.path().join("keys.pub");
        generate_keys(
            CoreKeyPurpose::ApiStorage,
            &first_private,
            &public,
            4,
            false,
        )
        .expect("initial key");
        let second_private = temporary.path().join("second.pk8");
        let rotated = temporary.path().join("rotated.pub");
        rotate_keys(
            CoreKeyPurpose::ApiStorage,
            &public,
            &second_private,
            &rotated,
            5,
        )
        .expect("rotation");
        let records = read_keyset(
            &fs::read_to_string(&rotated).expect("keyset"),
            CoreKeyPurpose::ApiStorage,
        )
        .expect("valid keyset");
        assert_eq!(
            records
                .iter()
                .map(|(generation, _)| *generation)
                .collect::<Vec<_>>(),
            [4, 5]
        );
        assert!(
            rotate_keys(
                CoreKeyPurpose::ApiStorage,
                &public,
                &second_private,
                &rotated,
                6
            )
            .is_err()
        );
    }
}

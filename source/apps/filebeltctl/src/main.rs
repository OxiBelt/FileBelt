// SPDX-License-Identifier: Apache-2.0

//! FileBelt administrative and recovery CLI.

#![deny(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand};
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
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_keyset: PathBuf,
        #[arg(long, default_value_t = 1)]
        generation: u32,
        #[arg(long)]
        force: bool,
    },
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
                    private_key,
                    public_keyset,
                    generation,
                    force,
                },
        } => generate_keys(&private_key, &public_keyset, generation, force),
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
    let public_keyset = format!(
        "filebelt-capability-keyset-v1\n{generation}:{}\n",
        URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
    );
    write_key_file(private_key_path, private_key.as_ref(), 0o600, force)?;
    if let Err(error) = write_key_file(public_keyset_path, public_keyset.as_bytes(), 0o644, force) {
        if !force {
            let _ = fs::remove_file(private_key_path);
        }
        return Err(error);
    }
    Ok(format!("capability key generation {generation} created"))
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
        generate_keys(&private, &public, 7, false).expect("generate key pair");
        let private_metadata = fs::metadata(&private).expect("private key metadata");
        assert_eq!(private_metadata.permissions().mode() & 0o777, 0o600);
        let public_text = fs::read_to_string(public).expect("public keyset");
        assert!(public_text.starts_with("filebelt-capability-keyset-v1\n7:"));
        assert!(generate_keys(&private, &temporary.path().join("second.pub"), 8, false).is_err());
    }
}

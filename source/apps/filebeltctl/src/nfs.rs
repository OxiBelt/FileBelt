// SPDX-License-Identifier: Apache-2.0

//! Tenant-scoped NFS administration for privileged operators.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use filebelt_control_protocol::{Config, read_secret_string};
use filebelt_database::Database;
use filebelt_database::mount::{
    NfsExportRecord, NfsExportState, NfsFeatureState, NfsFeatureStateRecord, NfsPosixGroupRecord,
    NfsPrincipalMapping,
};
use serde_json::{Value, json};
use uuid::Uuid;

const DEFAULT_CONFIG: &str = "/etc/filebelt/filebelt.toml";
#[cfg(test)]
const MAX_PROJECTED_ID: i64 = 4_294_967_294;
#[cfg(test)]
const NOBODY_PROJECTED_ID: i64 = 65_534;

#[derive(Debug, Subcommand)]
pub enum Command {
    Status {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    Feature {
        #[command(subcommand)]
        command: FeatureCommand,
    },
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    PosixGroup {
        #[command(subcommand)]
        command: PosixGroupCommand,
    },
    Mapping {
        #[command(subcommand)]
        command: MappingCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum FeatureCommand {
    Transition {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        expected_generation: i64,
        #[arg(long, value_parser = ["disabled", "preflight", "active", "draining"])]
        target_state: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    Register {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        drive_id: Uuid,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        export_id: i64,
    },
    Transition {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        drive_id: Uuid,
        #[arg(long)]
        expected_generation: i64,
        #[arg(long, value_parser = ["disabled", "active", "draining"])]
        target_state: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PosixGroupCommand {
    Register {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        group_id: Uuid,
        #[arg(long)]
        posix_name: String,
        #[arg(long)]
        projected_gid: i64,
    },
}

#[derive(Debug, Subcommand)]
pub enum MappingCommand {
    Upsert {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        principal_id: Uuid,
        #[arg(long)]
        kerberos_principal: String,
        #[arg(long)]
        projected_uid: i64,
        #[arg(long)]
        projected_gid: i64,
        #[arg(long, required = true)]
        allowed_drive_id: Vec<Uuid>,
        #[arg(long)]
        expected_generation: Option<i64>,
    },
    Revoke {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        actor_principal_id: Uuid,
        #[arg(long)]
        confirm_tenant: String,
        #[arg(long)]
        credential_id: Uuid,
        #[arg(long)]
        expected_generation: i64,
    },
}

pub async fn execute(command: Command) -> Result<String, String> {
    match command {
        Command::Status { config } => status(&config).await,
        Command::Feature {
            command:
                FeatureCommand::Transition {
                    config,
                    actor_principal_id,
                    confirm_tenant,
                    expected_generation,
                    target_state,
                },
        } => {
            let (configuration, database, tenant_id, _) =
                mutation_context(&config, actor_principal_id, &confirm_tenant).await?;
            let target = parse_feature_state(&target_state)?;
            let record = database
                .transition_nfs_feature_state(
                    tenant_id,
                    actor_principal_id,
                    expected_generation,
                    target,
                )
                .await
                .map_err(|error| error.to_string())?;
            pretty(json!({
                "schema": "filebelt.nfs.feature.v1",
                "tenant_slug": configuration.tenant.slug,
                "feature": feature_json(&record),
            }))
        }
        Command::Export {
            command:
                ExportCommand::Register {
                    config,
                    actor_principal_id,
                    confirm_tenant,
                    drive_id,
                    export_id,
                },
        } => {
            let (configuration, database, tenant_id, _) =
                mutation_context(&config, actor_principal_id, &confirm_tenant).await?;
            require_accessible_drives(&database, tenant_id, actor_principal_id, &[drive_id])
                .await?;
            let record = database
                .register_nfs_export(tenant_id, actor_principal_id, drive_id, export_id)
                .await
                .map_err(|error| error.to_string())?;
            pretty(json!({
                "schema": "filebelt.nfs.export.v1",
                "tenant_slug": configuration.tenant.slug,
                "export": export_json(&record, None),
            }))
        }
        Command::Export {
            command:
                ExportCommand::Transition {
                    config,
                    actor_principal_id,
                    confirm_tenant,
                    drive_id,
                    expected_generation,
                    target_state,
                },
        } => {
            let (configuration, database, tenant_id, _) =
                mutation_context(&config, actor_principal_id, &confirm_tenant).await?;
            let target = parse_export_state(&target_state)?;
            require_accessible_drives(&database, tenant_id, actor_principal_id, &[drive_id])
                .await?;
            let record = database
                .stage_nfs_export(
                    tenant_id,
                    actor_principal_id,
                    drive_id,
                    expected_generation,
                    target,
                )
                .await
                .map_err(|error| error.to_string())?;
            let feature = database
                .nfs_feature_state(tenant_id)
                .await
                .map_err(|error| error.to_string())?;
            pretty(json!({
                "schema": "filebelt.nfs.export.v1",
                "tenant_slug": configuration.tenant.slug,
                "export": export_json(&record, Some(feature.state)),
            }))
        }
        Command::PosixGroup {
            command:
                PosixGroupCommand::Register {
                    config,
                    actor_principal_id,
                    confirm_tenant,
                    group_id,
                    posix_name,
                    projected_gid,
                },
        } => {
            let (configuration, database, tenant_id, _) =
                mutation_context(&config, actor_principal_id, &confirm_tenant).await?;
            let record = database
                .register_nfs_posix_group(
                    tenant_id,
                    actor_principal_id,
                    group_id,
                    &posix_name,
                    projected_gid,
                )
                .await
                .map_err(|error| error.to_string())?;
            pretty(json!({
                "schema": "filebelt.nfs.posix_group.v1",
                "tenant_slug": configuration.tenant.slug,
                "posix_group": posix_group_json(&record),
            }))
        }
        Command::Mapping {
            command:
                MappingCommand::Upsert {
                    config,
                    actor_principal_id,
                    confirm_tenant,
                    ..
                },
        } => {
            mutation_context(&config, actor_principal_id, &confirm_tenant).await?;
            Err("mount.nfs.target_approval_required: create the mapping proposal through the authenticated NFS administration API so the target user can approve it".into())
        }
        Command::Mapping {
            command:
                MappingCommand::Revoke {
                    config,
                    actor_principal_id,
                    confirm_tenant,
                    credential_id,
                    expected_generation,
                },
        } => {
            let (configuration, database, tenant_id, realm) =
                mutation_context(&config, actor_principal_id, &confirm_tenant).await?;
            require_positive_generation(expected_generation)?;
            database
                .revoke_nfs_principal_mapping(
                    tenant_id,
                    actor_principal_id,
                    credential_id,
                    expected_generation,
                )
                .await
                .map_err(|error| error.to_string())?;
            pretty(json!({
                "schema": "filebelt.nfs.mapping_revoke.v1",
                "tenant_slug": configuration.tenant.slug,
                "realm": realm,
                "credential_id": credential_id,
                "revoked_generation": expected_generation,
            }))
        }
    }
}

async fn status(path: &Path) -> Result<String, String> {
    let (configuration, database) = configured_database(path).await?;
    let tenant_id = database
        .tenant_by_slug(&configuration.tenant.slug)
        .await
        .map_err(|error| error.to_string())?;
    let realm = configured_realm(&configuration)?.to_owned();
    let (feature, exports, posix_groups, mappings) = tokio::try_join!(
        database.nfs_feature_state(tenant_id),
        database.list_nfs_exports(tenant_id),
        database.list_nfs_posix_groups(tenant_id),
        database.list_nfs_principal_mappings(tenant_id),
    )
    .map_err(|error| error.to_string())?;
    let manifest_applied = feature.applied_manifest_generation > 0
        && feature.applied_manifest_generation == feature.manifest_generation;
    pretty(json!({
        "schema": "filebelt.nfs.admin.v1",
        "tenant_id": tenant_id,
        "tenant_slug": configuration.tenant.slug,
        "configured_enabled": configuration.mounts.nfs.enabled,
        "realm": realm,
        "feature": feature_json(&feature),
        "manifest_applied": manifest_applied,
        "exports": exports.iter().map(|record| export_json(record, Some(feature.state))).collect::<Vec<_>>(),
        "posix_groups": posix_groups.iter().map(posix_group_json).collect::<Vec<_>>(),
        "mappings": mappings.iter().map(mapping_json).collect::<Vec<_>>(),
    }))
}

async fn mutation_context(
    path: &Path,
    actor_principal_id: Uuid,
    confirm_tenant: &str,
) -> Result<(Config, Database, Uuid, String), String> {
    let (configuration, database) = configured_database(path).await?;
    require_tenant_confirmation(&configuration.tenant.slug, confirm_tenant)?;
    if !configuration.mounts.nfs.enabled {
        return Err("NFS administration is disabled in the configured deployment".into());
    }
    let realm = configured_realm(&configuration)?.to_owned();
    let tenant_id = database
        .tenant_by_slug(&configuration.tenant.slug)
        .await
        .map_err(|error| error.to_string())?;
    require_tenant_admin(&database, tenant_id, actor_principal_id).await?;
    Ok((configuration, database, tenant_id, realm))
}

fn require_tenant_confirmation(tenant_slug: &str, confirm_tenant: &str) -> Result<(), String> {
    if tenant_slug == confirm_tenant {
        Ok(())
    } else {
        Err("--confirm-tenant must exactly match the configured tenant slug".into())
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

async fn require_tenant_admin(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
) -> Result<(), String> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users u JOIN external_identities e \
         ON e.tenant_id=u.tenant_id AND e.user_id=u.id AND e.disabled_at IS NULL \
         JOIN tenant_admin_bindings b ON b.tenant_id=e.tenant_id \
         AND b.issuer=e.issuer AND b.subject=e.subject WHERE u.tenant_id=$1 \
         AND u.principal_id=$2 AND u.status='active')",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .fetch_one(database.pool())
    .await
    .map_err(|error| error.to_string())?;
    if !authorized {
        return Err("actor is not an active tenant administrator".into());
    }
    Ok(())
}

async fn require_accessible_drives(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    selected: &[Uuid],
) -> Result<(), String> {
    let accessible = database
        .list_drives(tenant_id, actor_principal_id)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|drive| drive.id)
        .collect::<HashSet<_>>();
    if selected
        .iter()
        .all(|drive_id| accessible.contains(drive_id))
    {
        Ok(())
    } else {
        Err("NFS drive selection contains a drive inaccessible to the actor".into())
    }
}

fn configured_realm(configuration: &Config) -> Result<&str, String> {
    configuration
        .mounts
        .nfs
        .realm
        .as_deref()
        .filter(|realm| !realm.is_empty())
        .ok_or_else(|| "NFS Kerberos realm is absent from configuration".to_owned())
}

#[cfg(test)]
fn validate_kerberos_principal(principal: &str, realm: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "Kerberos principal must be an unescaped non-root POSIX user in the exact realm {realm}"
        )
    };
    if principal.is_empty()
        || principal.len() > 512
        || principal
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '/' | '\\'))
    {
        return Err(invalid());
    }
    let Some((user, actual_realm)) = principal.split_once('@') else {
        return Err(invalid());
    };
    if user.is_empty()
        || user.eq_ignore_ascii_case("root")
        || actual_realm != realm
        || actual_realm.contains('@')
        || !valid_posix_name(&user.to_ascii_lowercase())
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
fn valid_posix_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'_'))
        && value.len() <= 255
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

#[cfg(test)]
fn valid_projected_id(value: i64) -> bool {
    (1..=MAX_PROJECTED_ID).contains(&value) && value != NOBODY_PROJECTED_ID
}

fn require_positive_generation(generation: i64) -> Result<(), String> {
    if generation <= 0 {
        Err("expected generation must be positive".into())
    } else {
        Ok(())
    }
}

fn parse_feature_state(value: &str) -> Result<NfsFeatureState, String> {
    match value {
        "disabled" => Ok(NfsFeatureState::Disabled),
        "preflight" => Ok(NfsFeatureState::Preflight),
        "active" => Ok(NfsFeatureState::Active),
        "draining" => Ok(NfsFeatureState::Draining),
        _ => Err("NFS feature state is invalid".into()),
    }
}

fn parse_export_state(value: &str) -> Result<NfsExportState, String> {
    match value {
        "disabled" => Ok(NfsExportState::Disabled),
        "active" => Ok(NfsExportState::Active),
        "draining" => Ok(NfsExportState::Draining),
        _ => Err("NFS export state is invalid".into()),
    }
}

fn feature_json(record: &NfsFeatureStateRecord) -> Value {
    json!({
        "state": record.state.as_str(),
        "generation": record.generation,
        "desired_manifest_generation": record.manifest_generation,
        "applied_manifest_generation": record.applied_manifest_generation,
        "applied_gateway_id": record.applied_gateway_id,
        "applied_gateway_epoch": record.applied_gateway_epoch,
        "restore_generation": record.restore_generation,
        "allowed_transitions": feature_transitions(record.state),
    })
}

fn feature_transitions(state: NfsFeatureState) -> &'static [&'static str] {
    match state {
        NfsFeatureState::Disabled => &["preflight"],
        NfsFeatureState::Preflight => &["disabled", "active"],
        NfsFeatureState::Active => &["draining"],
        NfsFeatureState::Draining => &["disabled"],
    }
}

fn export_json(record: &NfsExportRecord, feature_state: Option<NfsFeatureState>) -> Value {
    let in_sync = record.desired_state == record.applied_state
        && record.desired_generation == record.applied_generation;
    json!({
        "drive_id": record.drive_id,
        "export_id": record.export_id,
        "export_path": record.export_path,
        "desired_state": record.desired_state.as_str(),
        "applied_state": record.applied_state.as_str(),
        "desired_generation": record.desired_generation,
        "applied_generation": record.applied_generation,
        "in_sync": in_sync,
        "allowed_transitions": export_transitions(record, feature_state),
    })
}

fn export_transitions(
    record: &NfsExportRecord,
    feature_state: Option<NfsFeatureState>,
) -> Vec<&'static str> {
    if !matches!(
        feature_state,
        Some(NfsFeatureState::Preflight | NfsFeatureState::Draining)
    ) {
        return Vec::new();
    }
    match record.desired_state {
        NfsExportState::Disabled => vec!["active"],
        NfsExportState::Active => vec!["draining"],
        NfsExportState::Draining => {
            let mut transitions = vec!["active"];
            if record.applied_state == NfsExportState::Draining
                && record.applied_generation == record.desired_generation
            {
                transitions.push("disabled");
            }
            transitions
        }
    }
}

fn posix_group_json(record: &NfsPosixGroupRecord) -> Value {
    json!({
        "group_id": record.group_id,
        "posix_name": record.posix_name,
        "projected_gid": record.projected_gid,
    })
}

fn mapping_json(record: &NfsPrincipalMapping) -> Value {
    json!({
        "kerberos_principal": record.kerberos_principal,
        "principal_id": record.principal_id,
        "credential_id": record.credential_id,
        "projected_uid": record.projected_uid,
        "projected_gid": record.projected_gid,
        "allowed_drive_ids": record.allowed_drive_ids,
        "generation": record.generation,
    })
}

fn pretty(value: Value) -> Result<String, String> {
    serde_json::to_string_pretty(&value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_principal_requires_the_exact_realm() {
        assert!(validate_kerberos_principal("alice@EXAMPLE.TEST", "EXAMPLE.TEST").is_ok());
        assert!(
            validate_kerberos_principal("alice.platform-1@EXAMPLE.TEST", "EXAMPLE.TEST").is_ok()
        );
        assert!(validate_kerberos_principal("alice@example.test", "EXAMPLE.TEST").is_err());
        assert!(validate_kerberos_principal("root@EXAMPLE.TEST", "EXAMPLE.TEST").is_err());
        assert!(validate_kerberos_principal("alice/admin@EXAMPLE.TEST", "EXAMPLE.TEST").is_err());
    }

    #[test]
    fn projected_ids_reject_nobody_and_out_of_range_values() {
        assert!(valid_projected_id(1));
        assert!(!valid_projected_id(NOBODY_PROJECTED_ID));
        assert!(!valid_projected_id(MAX_PROJECTED_ID + 1));
    }

    #[test]
    fn tenant_confirmation_is_exact() {
        assert!(require_tenant_confirmation("acme", "acme").is_ok());
        assert!(require_tenant_confirmation("acme", "ACME").is_err());
        assert!(require_tenant_confirmation("acme", " acme").is_err());
    }

    #[test]
    fn export_disable_waits_for_an_applied_drain() {
        let mut record = NfsExportRecord {
            drive_id: Uuid::nil(),
            export_id: 7,
            export_path: "/filebelt/00000000-0000-0000-0000-000000000000".into(),
            desired_state: NfsExportState::Draining,
            applied_state: NfsExportState::Active,
            desired_generation: 3,
            applied_generation: 2,
        };
        assert_eq!(
            export_transitions(&record, Some(NfsFeatureState::Draining)),
            vec!["active"]
        );
        record.applied_state = NfsExportState::Draining;
        record.applied_generation = 3;
        assert_eq!(
            export_transitions(&record, Some(NfsFeatureState::Draining)),
            vec!["active", "disabled"]
        );
    }
}

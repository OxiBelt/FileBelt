// SPDX-License-Identifier: Apache-2.0

//! Deterministic, bounded recovery checkpoints and restored-state verification.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;

use aws_lc_rs::digest::{Context, SHA256};
use filebelt_capability_keyset::{KeyPurpose, encode_keyset};
use filebelt_control_protocol::{Config, SigningKeyConfig};
use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::grants::{encode_hex, migration_manifest_in};
use crate::read_keyset;

const CHECKPOINT_SCHEMA: &str = "filebelt.recovery.checkpoint.v3";
const VERIFICATION_SCHEMA: &str = "filebelt.recovery.verification.v3";
const LEGACY_CHECKPOINT_SCHEMA: &str = "filebelt.recovery.checkpoint.v2";
const MAX_CHECKPOINT_BYTES: u64 = 1_048_576;
const PAYLOAD_BATCH_SIZE: i64 = 1_000;
const CHECKPOINT_FIELDS: &[&str] = &[
    "schema",
    "tenant",
    "storage_backend_id",
    "digest_key_generation",
    "capability_keysets",
    "database_key_generations",
    "migrations",
    "audit_watermark",
    "inventory",
];

pub async fn checkpoint(database: &Database, configuration: &Config) -> Result<String, String> {
    let checkpoint = checkpoint_value(database, configuration).await?;
    serde_json::to_string_pretty(&checkpoint).map_err(|error| error.to_string())
}

pub async fn verify(
    database: &Database,
    configuration: &Config,
    checkpoint_path: &Path,
    legacy_v2_offline: bool,
) -> Result<String, String> {
    let expected = read_checkpoint(checkpoint_path)?;
    let actual = checkpoint_value(database, configuration).await?;
    if expected.get("schema").and_then(Value::as_str) == Some(LEGACY_CHECKPOINT_SCHEMA) {
        if !legacy_v2_offline {
            return Err("legacy recovery checkpoint requires --legacy-v2-offline".into());
        }
        validate_legacy_v2_checkpoint(&expected)?;
        let legacy_actual = legacy_v2_value(actual.clone(), configuration);
        let fields = [
            "schema",
            "tenant",
            "storage_backend_id",
            "capability_key_generation",
            "database_key_generations",
            "migrations",
            "audit_watermark",
            "inventory",
        ];
        let differences = fields
            .iter()
            .filter(|field| expected.get(**field) != legacy_actual.get(**field))
            .copied()
            .collect::<Vec<_>>();
        let document = json!({
            "schema": VERIFICATION_SCHEMA,
            "status": if differences.is_empty() { "legacy_offline_verified" } else { "mismatch" },
            "checkpoint_schema": LEGACY_CHECKPOINT_SCHEMA,
            "differences": differences,
            "admission_verified": false,
            "key_purpose_proven": false,
            "traffic_admission": false,
            "required_next_step": "create and verify a v3 recovery checkpoint before admitting traffic",
        });
        if !differences.is_empty() {
            return Err(serde_json::to_string(&document).map_err(|error| error.to_string())?);
        }
        return serde_json::to_string_pretty(&document).map_err(|error| error.to_string());
    }
    validate_checkpoint(&expected)?;
    let differences = CHECKPOINT_FIELDS
        .iter()
        .filter(|field| expected.get(**field) != actual.get(**field))
        .copied()
        .collect::<Vec<_>>();
    let document = json!({
        "schema": VERIFICATION_SCHEMA,
        "status": if differences.is_empty() { "verified" } else { "mismatch" },
        "checkpoint_schema": CHECKPOINT_SCHEMA,
        "differences": differences,
        "tenant_id": actual.pointer("/tenant/id"),
        "payload_manifest_sha256": actual.pointer("/inventory/payload_manifest_sha256"),
    });
    if !differences.is_empty() {
        return Err(serde_json::to_string(&document).map_err(|error| error.to_string())?);
    }
    serde_json::to_string_pretty(&document).map_err(|error| error.to_string())
}

fn legacy_v2_value(mut actual: Value, configuration: &Config) -> Value {
    let object = actual.as_object_mut().expect("checkpoint object");
    object.insert(
        "schema".into(),
        Value::String(LEGACY_CHECKPOINT_SCHEMA.into()),
    );
    object.remove("digest_key_generation");
    object.remove("capability_keysets");
    object.insert(
        "capability_key_generation".into(),
        json!(configuration.keys.api_storage.current_generation),
    );
    actual
}

async fn checkpoint_value(database: &Database, configuration: &Config) -> Result<Value, String> {
    let mut transaction = database
        .pool()
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let migrations = migration_manifest_in(&mut transaction).await?;
    let tenant = sqlx::query("SELECT id,slug FROM tenants WHERE slug=$1")
        .bind(&configuration.tenant.slug)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "configured tenant was not found".to_owned())?;
    let tenant_id: Uuid = tenant.get("id");
    let backend_exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT id FROM storage_backends WHERE tenant_id=$1 AND id=$2 AND kind='posix')")
        .bind(tenant_id)
        .bind(configuration.storage.backend_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    if !backend_exists {
        return Err("configured POSIX storage backend was not found".into());
    }
    let session_generations = distinct_generations(
        &mut transaction,
        "SELECT DISTINCT token_key_generation FROM api_sessions WHERE tenant_id=$1 ORDER BY token_key_generation",
        tenant_id,
    )
    .await?;
    let share_generations = distinct_generations(
        &mut transaction,
        "SELECT DISTINCT token_key_generation FROM share_links WHERE tenant_id=$1 ORDER BY token_key_generation",
        tenant_id,
    )
    .await?;
    let mcp_vault_generations = distinct_generations(
        &mut transaction,
        "SELECT DISTINCT kek_generation AS token_key_generation FROM (SELECT tenant_id,kek_generation FROM filebelt_mcp_vault.secret_envelopes UNION ALL SELECT tenant_id,kek_generation FROM filebelt_mcp_vault.oauth_attempt_secrets) vault_keys WHERE tenant_id=$1 ORDER BY token_key_generation",
        tenant_id,
    )
    .await?;
    let audit_watermark = sqlx::query("SELECT occurred_at::text AS occurred_at,id FROM audit_events WHERE tenant_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 1")
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?
        .map(|row| {
            json!({
                "occurred_at": row.get::<String, _>("occurred_at"),
                "id": row.get::<Uuid, _>("id"),
            })
        });
    let descendant_share_security: Value =
        sqlx::query_scalar("SELECT filebelt_security.descendant_shares_status($1,$2)")
            .bind(tenant_id)
            .bind(Uuid::nil())
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| error.to_string())?;
    let counts = sqlx::query("SELECT (SELECT count(id) FROM principals WHERE tenant_id=$1) AS principals,(SELECT count(id) FROM users WHERE tenant_id=$1) AS users,(SELECT count(id) FROM groups WHERE tenant_id=$1) AS groups,(SELECT count(id) FROM drives WHERE tenant_id=$1) AS drives,(SELECT count(id) FROM nodes WHERE tenant_id=$1) AS nodes,(SELECT count(id) FROM file_versions WHERE tenant_id=$1) AS file_versions,(SELECT count(id) FROM payload_objects WHERE tenant_id=$1) AS payload_objects,(SELECT count(id) FROM jobs WHERE tenant_id=$1) AS jobs,(SELECT count(id) FROM audit_events WHERE tenant_id=$1) AS audit_events,(SELECT count(id) FROM outbox_events WHERE tenant_id=$1 AND published_at IS NULL) AS pending_outbox,(SELECT count(id) FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND deleted_at IS NULL) AS mcp_registrations,(SELECT count(id) FROM filebelt_mcp.deletion_tombstones WHERE tenant_id=$1) AS mcp_deletion_tombstones,(SELECT count(invocation_id) FROM filebelt_mcp.runner_slot_reservations WHERE tenant_id=$1 AND released_at IS NULL) AS mcp_runner_slot_reservations,(SELECT count(registration_id) FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND deleted_at IS NULL) AS mcp_secret_envelopes,(SELECT count(attempt_id) FROM filebelt_mcp_vault.oauth_attempt_secrets WHERE tenant_id=$1) AS mcp_oauth_attempt_secrets,(SELECT count(id) FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('referenced','finalized','quarantining','quarantined')) AS expected_payloads,(SELECT count(id) FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('quarantining','quarantined')) AS quarantined_payloads,(SELECT COALESCE(sum(size_bytes),0)::bigint FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('referenced','finalized','quarantining','quarantined')) AS total_payload_bytes")
        .bind(tenant_id)
        .bind(configuration.storage.backend_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    let nfs = sqlx::query(
        "SELECT feature.state,feature.generation,feature.manifest_generation,\
                feature.applied_manifest_generation,feature.applied_manifest_digest,\
                feature.applied_gateway_id,feature.applied_gateway_epoch,\
                feature.restore_generation,\
                (SELECT count(*) FROM filebelt_mount.nfs_exports AS export \
                  WHERE export.tenant_id=feature.tenant_id) AS exports,\
                (SELECT count(*) FROM filebelt_mount.nfs_principal_mappings AS mapping \
                  WHERE mapping.tenant_id=feature.tenant_id AND mapping.revoked_at IS NULL) AS active_mappings,\
                (SELECT count(*) FROM filebelt_mount.nfs_posix_groups AS posix_group \
                  WHERE posix_group.tenant_id=feature.tenant_id) AS posix_groups,\
                (SELECT count(*) FROM filebelt_mount.nfs_posix_users AS posix_user \
                  WHERE posix_user.tenant_id=feature.tenant_id) AS posix_users,\
                (SELECT count(*) FROM public.nodes AS node \
                  WHERE node.tenant_id=feature.tenant_id AND node.kind='symlink') AS symlinks,\
                (SELECT count(*) FROM public.node_xattrs AS xattr \
                  WHERE xattr.tenant_id=feature.tenant_id) AS xattrs,\
                (SELECT count(*) FROM public.acl_entries AS acl \
                  WHERE acl.tenant_id=feature.tenant_id AND acl.source='nfs') AS nfs_acl_entries,\
                (SELECT count(*) FROM filebelt_mount.nfs_replay_receipts AS receipt \
                  WHERE receipt.tenant_id=feature.tenant_id \
                    AND receipt.expires_at>statement_timestamp()) AS live_replay_receipts,\
                (SELECT count(*) FROM filebelt_mount.write_sessions AS write_session \
                  JOIN filebelt_mount.sessions AS session \
                    ON session.tenant_id=write_session.tenant_id \
                   AND session.id=write_session.mount_session_id \
                  WHERE write_session.tenant_id=feature.tenant_id AND session.protocol='nfs' \
                    AND write_session.state IN ('open','flushing','committing','aborting')) AS unfinished_writes,\
                (SELECT count(*) FROM filebelt_mount.nfs_write_conflicts AS conflict \
                  WHERE conflict.tenant_id=feature.tenant_id \
                    AND conflict.state='retained') AS retained_conflicts \
         FROM filebelt_mount.nfs_feature_state AS feature WHERE feature.tenant_id=$1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| error.to_string())?;
    let replay_slots = nfs_replay_slot_inventory(&mut transaction, tenant_id).await?;
    let io_recovery = nfs_io_recovery_inventory(&mut transaction, tenant_id).await?;
    let nfs_inventory = nfs.map_or_else(
        || json!({"configured":false}),
        |row| {
            let manifest_digest = row
                .get::<Option<Vec<u8>>, _>("applied_manifest_digest")
                .map(|digest| encode_hex(&digest));
            json!({
                "configured": true,
                "state": row.get::<String, _>("state"),
                "generation": row.get::<i64, _>("generation"),
                "manifest_generation": row.get::<i64, _>("manifest_generation"),
                "applied_manifest_generation": row.get::<i64, _>("applied_manifest_generation"),
                "applied_manifest_digest": manifest_digest,
                "applied_gateway_id": row.get::<Option<String>, _>("applied_gateway_id"),
                "applied_gateway_epoch": row.get::<Option<i64>, _>("applied_gateway_epoch"),
                "restore_generation": row.get::<i64, _>("restore_generation"),
                "exports": row.get::<i64, _>("exports"),
                "active_mappings": row.get::<i64, _>("active_mappings"),
                "posix_groups": row.get::<i64, _>("posix_groups"),
                "posix_users": row.get::<i64, _>("posix_users"),
                "symlinks": row.get::<i64, _>("symlinks"),
                "xattrs": row.get::<i64, _>("xattrs"),
                "nfs_acl_entries": row.get::<i64, _>("nfs_acl_entries"),
                "live_replay_receipts": row.get::<i64, _>("live_replay_receipts"),
                "replay_slots": replay_slots.get("count"),
                "replay_slot_max_sequence": replay_slots.get("max_sequence"),
                "replay_slot_manifest_sha256": replay_slots.get("manifest_sha256"),
                "pending_protocol_operations": io_recovery.get("pending_protocol_operations"),
                "live_io_admissions": io_recovery.get("live_io_admissions"),
                "io_receipts": io_recovery.get("io_receipts"),
                "pending_io_receipts": io_recovery.get("pending_io_receipts"),
                "staging_cleanup_jobs": io_recovery.get("staging_cleanup_jobs"),
                "active_staging_cleanup_jobs": io_recovery.get("active_staging_cleanup_jobs"),
                "lock_cleanup_jobs": io_recovery.get("lock_cleanup_jobs"),
                "active_lock_cleanup_jobs": io_recovery.get("active_lock_cleanup_jobs"),
                "io_recovery_manifest_sha256": io_recovery.get("manifest_sha256"),
                "unfinished_writes": row.get::<i64, _>("unfinished_writes"),
                "retained_conflicts": row.get::<i64, _>("retained_conflicts"),
            })
        },
    );
    let payload_manifest_sha256 = payload_manifest(
        &mut transaction,
        tenant_id,
        configuration.storage.backend_id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema": CHECKPOINT_SCHEMA,
        "tenant": {
            "id": tenant_id,
            "slug": tenant.get::<String, _>("slug"),
        },
        "storage_backend_id": configuration.storage.backend_id,
        "digest_key_generation": configuration.keys.digest_key_generation,
        "capability_keysets": capability_keysets(configuration)?,
        "database_key_generations": {
            "sessions": session_generations,
            "share_links": share_generations,
            "mcp_vault": mcp_vault_generations,
        },
        "migrations": migrations,
        "audit_watermark": audit_watermark,
        "inventory": {
            "principals": counts.get::<i64, _>("principals"),
            "users": counts.get::<i64, _>("users"),
            "groups": counts.get::<i64, _>("groups"),
            "drives": counts.get::<i64, _>("drives"),
            "nodes": counts.get::<i64, _>("nodes"),
            "file_versions": counts.get::<i64, _>("file_versions"),
            "payload_objects": counts.get::<i64, _>("payload_objects"),
            "jobs": counts.get::<i64, _>("jobs"),
            "audit_events": counts.get::<i64, _>("audit_events"),
            "pending_outbox": counts.get::<i64, _>("pending_outbox"),
            "mcp_registrations": counts.get::<i64, _>("mcp_registrations"),
            "mcp_deletion_tombstones": counts.get::<i64, _>("mcp_deletion_tombstones"),
            "mcp_runner_slot_reservations": counts.get::<i64, _>("mcp_runner_slot_reservations"),
            "mcp_secret_envelopes": counts.get::<i64, _>("mcp_secret_envelopes"),
            "mcp_oauth_attempt_secrets": counts.get::<i64, _>("mcp_oauth_attempt_secrets"),
            "expected_payloads": counts.get::<i64, _>("expected_payloads"),
            "quarantined_payloads": counts.get::<i64, _>("quarantined_payloads"),
            "total_payload_bytes": counts.get::<i64, _>("total_payload_bytes"),
            "payload_manifest_sha256": payload_manifest_sha256,
            "descendant_share_security": descendant_share_security,
            "nfs": nfs_inventory,
        },
    }))
}

fn capability_keysets(configuration: &Config) -> Result<Value, String> {
    let mut configured: Vec<(&str, KeyPurpose, &SigningKeyConfig)> = vec![
        (
            "api_storage",
            KeyPurpose::ApiStorage,
            &configuration.keys.api_storage,
        ),
        (
            "media_storage",
            KeyPurpose::MediaStorage,
            &configuration.media.capability_signing,
        ),
    ];
    if let Some(key) = &configuration.keys.api_collaboration_grant {
        configured.push((
            "api_collaboration_grant",
            KeyPurpose::ApiCollaborationGrant,
            key,
        ));
    }
    if let Some(key) = &configuration.keys.api_mcp_delegation {
        configured.push(("api_mcp_delegation", KeyPurpose::ApiMcpDelegation, key));
    }
    if let Some(key) = &configuration.collaboration.capability_signing {
        configured.push((
            "collaboration_storage",
            KeyPurpose::CollaborationStorage,
            key,
        ));
    }
    if let Some(key) = &configuration.documents.capability_signing {
        configured.push(("document_storage", KeyPurpose::DocumentStorage, key));
    }
    if let Some(key) = &configuration.mounts.capability_signing {
        configured.push(("mount_storage", KeyPurpose::MountStorage, key));
    }
    let mut result = serde_json::Map::new();
    let mut observed = Vec::<[u8; 32]>::new();
    for (name, purpose, key) in configured {
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
        for (_, public) in &records {
            if observed.contains(public) {
                return Err("capability public key material is reused across purposes".into());
            }
            observed.push(*public);
        }
        let canonical_records = records
            .iter()
            .map(|(generation, public)| (*generation, *public))
            .collect::<Vec<_>>();
        let canonical = encode_keyset(purpose, &canonical_records)
            .map_err(|_| "capability public keyset is invalid".to_owned())?;
        let mut digest = Context::new(&SHA256);
        digest.update(canonical.as_bytes());
        result.insert(
            name.into(),
            json!({
                "purpose": purpose.as_str(),
                "current_generation": key.current_generation,
                "admitted_generations": records.iter().map(|(generation, _)| *generation).collect::<Vec<_>>(),
                "canonical_sha256": encode_hex(digest.finish().as_ref()),
            }),
        );
    }
    Ok(Value::Object(result))
}

async fn distinct_generations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    query: &'static str,
    tenant_id: Uuid,
) -> Result<Vec<i32>, String> {
    sqlx::query(query)
        .bind(tenant_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| error.to_string())
        .map(|rows| {
            rows.into_iter()
                .map(|row| row.get("token_key_generation"))
                .collect()
        })
}

async fn payload_manifest(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    backend_id: Uuid,
) -> Result<String, String> {
    let mut context = Context::new(&SHA256);
    let mut last_id = None;
    loop {
        let rows = sqlx::query("SELECT id,drive_id,backend_id,locator,layout,state,size_bytes,encode(blake3,'hex') AS blake3 FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('referenced','finalized','quarantining','quarantined') AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4")
            .bind(tenant_id)
            .bind(backend_id)
            .bind(last_id)
            .bind(PAYLOAD_BATCH_SIZE)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let id: Uuid = row.get("id");
            let canonical = json!([
                id,
                row.get::<Uuid, _>("drive_id"),
                row.get::<Uuid, _>("backend_id"),
                row.get::<Uuid, _>("locator"),
                row.get::<String, _>("layout"),
                row.get::<String, _>("state"),
                row.get::<i64, _>("size_bytes"),
                row.get::<Option<String>, _>("blake3"),
            ]);
            let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
            context.update(&encoded);
            context.update(b"\n");
            last_id = Some(id);
        }
        if rows.len() < usize::try_from(PAYLOAD_BATCH_SIZE).expect("positive batch size") {
            break;
        }
    }
    Ok(encode_hex(context.finish().as_ref()))
}

async fn nfs_replay_slot_inventory(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
) -> Result<Value, String> {
    let mut context = Context::new(&SHA256);
    let mut offset = 0_i64;
    let mut count = 0_i64;
    let mut max_sequence = 0_i64;
    loop {
        let rows = sqlx::query(
            "SELECT slot.mount_session_id,slot.nfs_session_id,slot.slot_id,slot.client_id,\
                    slot.current_sequence_id,slot.max_operation_index,slot.gateway_epoch,\
                    (SELECT count(*)::bigint FROM filebelt_mount.nfs_replay_receipts AS receipt \
                      WHERE receipt.tenant_id=slot.tenant_id \
                        AND receipt.mount_session_id=slot.mount_session_id \
                        AND receipt.nfs_session_id=slot.nfs_session_id \
                        AND receipt.slot_id=slot.slot_id) AS receipt_count,\
                    (SELECT max(receipt.operation_index) \
                      FROM filebelt_mount.nfs_replay_receipts AS receipt \
                      WHERE receipt.tenant_id=slot.tenant_id \
                        AND receipt.mount_session_id=slot.mount_session_id \
                        AND receipt.nfs_session_id=slot.nfs_session_id \
                        AND receipt.slot_id=slot.slot_id) AS receipt_max_operation_index,\
                    (SELECT count(*)::bigint FROM filebelt_mount.nfs_replay_receipts AS receipt \
                      WHERE receipt.tenant_id=slot.tenant_id \
                        AND receipt.mount_session_id=slot.mount_session_id \
                        AND receipt.nfs_session_id=slot.nfs_session_id \
                        AND receipt.slot_id=slot.slot_id AND (\
                          receipt.sequence_id<>slot.current_sequence_id \
                          OR receipt.operation_index>slot.max_operation_index \
                          OR receipt.client_id<>slot.client_id \
                          OR receipt.gateway_epoch<>slot.gateway_epoch)) AS invalid_receipts,\
                    (SELECT count(*)::bigint \
                      FROM filebelt_mount.nfs_pending_protocol_operations AS pending \
                      WHERE pending.tenant_id=slot.tenant_id \
                        AND pending.mount_session_id=slot.mount_session_id \
                        AND pending.nfs_session_id=slot.nfs_session_id \
                        AND pending.slot_id=slot.slot_id) AS pending_count,\
                    (SELECT max(pending.operation_index) \
                      FROM filebelt_mount.nfs_pending_protocol_operations AS pending \
                      WHERE pending.tenant_id=slot.tenant_id \
                        AND pending.mount_session_id=slot.mount_session_id \
                        AND pending.nfs_session_id=slot.nfs_session_id \
                        AND pending.slot_id=slot.slot_id) AS pending_operation_index,\
                    (SELECT count(*)::bigint \
                      FROM filebelt_mount.nfs_pending_protocol_operations AS pending \
                      WHERE pending.tenant_id=slot.tenant_id \
                        AND pending.mount_session_id=slot.mount_session_id \
                        AND pending.nfs_session_id=slot.nfs_session_id \
                        AND pending.slot_id=slot.slot_id AND (\
                          pending.sequence_id<>slot.current_sequence_id \
                          OR pending.operation_index<>slot.max_operation_index \
                          OR pending.client_id<>slot.client_id \
                          OR pending.gateway_epoch<>slot.gateway_epoch \
                          OR EXISTS (SELECT 1 \
                            FROM filebelt_mount.nfs_replay_receipts AS receipt \
                            WHERE receipt.tenant_id=pending.tenant_id \
                              AND receipt.mount_session_id=pending.mount_session_id \
                              AND receipt.nfs_session_id=pending.nfs_session_id \
                              AND receipt.slot_id=pending.slot_id \
                              AND receipt.sequence_id=pending.sequence_id \
                              AND receipt.operation_index=pending.operation_index))) \
                      AS invalid_pending \
             FROM filebelt_mount.nfs_replay_slots AS slot \
             WHERE slot.tenant_id=$1 \
             ORDER BY slot.mount_session_id,slot.nfs_session_id,slot.slot_id \
             OFFSET $2 LIMIT $3",
        )
        .bind(tenant_id)
        .bind(offset)
        .bind(PAYLOAD_BATCH_SIZE)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let receipt_count = row.get::<i64, _>("receipt_count");
            let max_operation_index = row.get::<i32, _>("max_operation_index");
            let receipt_max = row.get::<Option<i32>, _>("receipt_max_operation_index");
            let pending_count = row.get::<i64, _>("pending_count");
            let pending_operation_index = row.get::<Option<i32>, _>("pending_operation_index");
            let terminal_receipt_set =
                pending_count == 0 && receipt_count > 0 && receipt_max == Some(max_operation_index);
            let in_flight_set = pending_count == 1
                && pending_operation_index == Some(max_operation_index)
                && receipt_max.is_none_or(|index| index < max_operation_index);
            if (!terminal_receipt_set && !in_flight_set)
                || row.get::<i64, _>("invalid_receipts") != 0
                || row.get::<i64, _>("invalid_pending") != 0
            {
                return Err(
                    "NFS replay slot high-water has neither a coherent receipt set nor an explicit in-flight operation".into(),
                );
            }
            let sequence = row.get::<i64, _>("current_sequence_id");
            max_sequence = max_sequence.max(sequence);
            count += 1;
            let canonical = json!([
                row.get::<Uuid, _>("mount_session_id"),
                row.get::<String, _>("nfs_session_id"),
                row.get::<i32, _>("slot_id"),
                row.get::<String, _>("client_id"),
                sequence,
                max_operation_index,
                row.get::<i64, _>("gateway_epoch"),
                receipt_count,
                pending_count,
                pending_operation_index,
            ]);
            let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
            context.update(&encoded);
            context.update(b"\n");
        }
        offset += i64::try_from(rows.len()).map_err(|error| error.to_string())?;
        if rows.len() < usize::try_from(PAYLOAD_BATCH_SIZE).expect("positive batch size") {
            break;
        }
    }
    Ok(json!({
        "count": count,
        "max_sequence": max_sequence,
        "manifest_sha256": encode_hex(context.finish().as_ref()),
    }))
}

async fn nfs_io_recovery_inventory(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
) -> Result<Value, String> {
    let mut context = Context::new(&SHA256);
    let mut offset = 0_i64;
    let mut pending_protocol_operations = 0_i64;
    let mut live_io_admissions = 0_i64;
    loop {
        let rows = sqlx::query(
            "SELECT pending.mount_session_id,pending.client_id,pending.nfs_session_id,\
                    pending.slot_id,pending.sequence_id,pending.operation_index,\
                    pending.protocol_operation,pending.request_digest,pending.gateway_epoch,\
                    pending.protocol_operation_id,pending.write_session_id,\
                    pending.capability_id,pending.nonce_digest,pending.claims_digest,\
                    pending.io_operation,pending.operation_id,pending.content_blake3,\
                    pending.range_start,pending.range_end,pending.fencing_token,\
                    pending.capability_expires_at::text AS capability_expires_at,\
                    pending.expires_at::text AS expires_at,\
                    admission.capability_id AS admission_capability_id,\
                    receipt.capability_id AS receipt_capability_id,\
                    receipt.state AS receipt_state,receipt.outcome AS receipt_outcome \
             FROM filebelt_mount.nfs_pending_protocol_operations AS pending \
             LEFT JOIN filebelt_mount.nfs_io_admissions AS admission \
               ON admission.tenant_id=pending.tenant_id \
              AND admission.capability_id=pending.capability_id \
              AND admission.nonce_digest=pending.nonce_digest \
              AND admission.write_session_id=pending.write_session_id \
              AND admission.operation_id IS NOT DISTINCT FROM pending.operation_id \
              AND admission.operation=pending.io_operation \
              AND admission.claims_digest=pending.claims_digest \
              AND admission.content_blake3 IS NOT DISTINCT FROM pending.content_blake3 \
             LEFT JOIN filebelt_mount.nfs_io_receipts AS receipt \
               ON receipt.tenant_id=pending.tenant_id \
              AND receipt.capability_id=pending.capability_id \
              AND receipt.nonce_digest=pending.nonce_digest \
              AND receipt.write_session_id=pending.write_session_id \
              AND receipt.operation_id IS NOT DISTINCT FROM pending.operation_id \
              AND receipt.operation=pending.io_operation \
              AND receipt.claims_digest=pending.claims_digest \
              AND receipt.content_blake3 IS NOT DISTINCT FROM pending.content_blake3 \
             WHERE pending.tenant_id=$1 \
             ORDER BY pending.mount_session_id,pending.nfs_session_id,pending.slot_id,\
                      pending.sequence_id,pending.operation_index \
             OFFSET $2 LIMIT $3",
        )
        .bind(tenant_id)
        .bind(offset)
        .bind(PAYLOAD_BATCH_SIZE)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let has_admission = row
                .get::<Option<Uuid>, _>("admission_capability_id")
                .is_some();
            let has_receipt = row
                .get::<Option<Uuid>, _>("receipt_capability_id")
                .is_some();
            if has_admission == has_receipt {
                return Err(
                    "NFS pending protocol operation must have exactly one admission or worker receipt"
                        .into(),
                );
            }
            pending_protocol_operations += 1;
            if has_admission {
                live_io_admissions += 1;
            }
            let canonical = json!([
                row.get::<Uuid, _>("mount_session_id"),
                row.get::<String, _>("client_id"),
                row.get::<String, _>("nfs_session_id"),
                row.get::<i32, _>("slot_id"),
                row.get::<i64, _>("sequence_id"),
                row.get::<i32, _>("operation_index"),
                row.get::<String, _>("protocol_operation"),
                encode_hex(&row.get::<Vec<u8>, _>("request_digest")),
                row.get::<i64, _>("gateway_epoch"),
                row.get::<Uuid, _>("protocol_operation_id"),
                row.get::<Uuid, _>("write_session_id"),
                row.get::<Uuid, _>("capability_id"),
                encode_hex(&row.get::<Vec<u8>, _>("nonce_digest")),
                encode_hex(&row.get::<Vec<u8>, _>("claims_digest")),
                row.get::<String, _>("io_operation"),
                row.get::<Option<Uuid>, _>("operation_id"),
                row.get::<Option<Vec<u8>>, _>("content_blake3")
                    .map(|digest| encode_hex(&digest)),
                row.get::<Option<i64>, _>("range_start"),
                row.get::<Option<i64>, _>("range_end"),
                row.get::<i64, _>("fencing_token"),
                row.get::<String, _>("capability_expires_at"),
                row.get::<String, _>("expires_at"),
                if has_admission {
                    "admission"
                } else {
                    "receipt"
                },
                row.get::<Option<String>, _>("receipt_state"),
                row.get::<Option<Value>, _>("receipt_outcome"),
            ]);
            let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
            context.update(b"pending-protocol\0");
            context.update(&encoded);
            context.update(b"\n");
        }
        offset += i64::try_from(rows.len()).map_err(|error| error.to_string())?;
        if rows.len() < usize::try_from(PAYLOAD_BATCH_SIZE).expect("positive batch size") {
            break;
        }
    }
    let orphan_admissions: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM filebelt_mount.nfs_io_admissions AS admission \
         LEFT JOIN filebelt_mount.nfs_pending_protocol_operations AS pending \
           ON pending.tenant_id=admission.tenant_id \
          AND pending.capability_id=admission.capability_id \
          AND pending.nonce_digest=admission.nonce_digest \
         WHERE admission.tenant_id=$1 AND pending.capability_id IS NULL",
    )
    .bind(tenant_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| error.to_string())?;
    if orphan_admissions != 0 {
        return Err("NFS I/O admission has no durable pending protocol identity".into());
    }

    offset = 0;
    let mut io_receipts = 0_i64;
    let mut pending_io_receipts = 0_i64;
    loop {
        let rows = sqlx::query(
            "SELECT receipt.nonce_digest,receipt.write_session_id,receipt.operation_id,\
                    receipt.operation,receipt.operation_ordinal,receipt.claims_digest,\
                    receipt.content_blake3,receipt.state,receipt.outcome,\
                    receipt.created_at::text AS created_at,\
                    receipt.expires_at::text AS expires_at,\
                    writer.state AS writer_state,\
                    writer.expires_at>statement_timestamp() AS writer_live,\
                    operation.state AS range_operation_state,\
                    cleanup.state AS cleanup_state,\
                    cleanup.source_nonce_digest AS cleanup_source_nonce_digest,\
                    cleanup.completion_kind AS cleanup_completion_kind \
             FROM filebelt_mount.nfs_io_receipts AS receipt \
             JOIN filebelt_mount.write_sessions AS writer \
               ON writer.tenant_id=receipt.tenant_id \
              AND writer.id=receipt.write_session_id \
             LEFT JOIN filebelt_mount.nfs_write_operations AS operation \
               ON operation.tenant_id=receipt.tenant_id \
              AND operation.write_session_id=receipt.write_session_id \
              AND operation.operation_id=receipt.operation_id \
             LEFT JOIN filebelt_mount.nfs_staging_cleanup_jobs AS cleanup \
               ON cleanup.tenant_id=receipt.tenant_id \
              AND cleanup.write_session_id=receipt.write_session_id \
             WHERE receipt.tenant_id=$1 \
             ORDER BY receipt.nonce_digest OFFSET $2 LIMIT $3",
        )
        .bind(tenant_id)
        .bind(offset)
        .bind(PAYLOAD_BATCH_SIZE)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let receipt_state = row.get::<String, _>("state");
            let operation_id = row.get::<Option<Uuid>, _>("operation_id");
            let range_state = row.get::<Option<String>, _>("range_operation_state");
            let nonce_digest = row.get::<Vec<u8>, _>("nonce_digest");
            let cleanup_state = row.get::<Option<String>, _>("cleanup_state");
            let cleanup_source_nonce = row.get::<Option<Vec<u8>>, _>("cleanup_source_nonce_digest");
            let exact_cleanup = cleanup_source_nonce.as_deref() == Some(nonce_digest.as_slice())
                && matches!(
                    cleanup_state.as_deref(),
                    Some("pending" | "leased" | "physical_deleted")
                );
            if operation_id.is_some() {
                let coherent = if receipt_state == "pending" {
                    if exact_cleanup {
                        if cleanup_state.as_deref() == Some("physical_deleted") {
                            range_state.as_deref() == Some("cancelled")
                        } else {
                            matches!(
                                range_state.as_deref(),
                                Some("planned" | "executing" | "io_completed" | "cancelled")
                            )
                        }
                    } else {
                        range_state.as_deref() == Some("executing")
                    }
                } else {
                    matches!(
                        range_state.as_deref(),
                        Some("io_completed" | "applied" | "cancelled")
                    )
                };
                if !coherent {
                    return Err(
                        "NFS byte-plane receipt has an incoherent range-operation state".into(),
                    );
                }
            }
            if receipt_state == "pending" {
                pending_io_receipts += 1;
                if !row.get::<bool, _>("writer_live") && !exact_cleanup {
                    return Err(
                        "expired pending NFS byte-plane receipt has no cleanup authority".into(),
                    );
                }
            } else if row.get::<Option<Value>, _>("outcome").is_none() {
                return Err("completed NFS byte-plane receipt has no durable outcome".into());
            }
            io_receipts += 1;
            let canonical = json!([
                encode_hex(&nonce_digest),
                row.get::<Uuid, _>("write_session_id"),
                operation_id,
                row.get::<String, _>("operation"),
                row.get::<i64, _>("operation_ordinal"),
                encode_hex(&row.get::<Vec<u8>, _>("claims_digest")),
                row.get::<Option<Vec<u8>>, _>("content_blake3")
                    .map(|digest| encode_hex(&digest)),
                receipt_state,
                row.get::<Option<Value>, _>("outcome"),
                row.get::<String, _>("created_at"),
                row.get::<String, _>("expires_at"),
                row.get::<String, _>("writer_state"),
                range_state,
                cleanup_state,
                cleanup_source_nonce.map(|digest| encode_hex(&digest)),
                row.get::<Option<String>, _>("cleanup_completion_kind"),
            ]);
            let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
            context.update(b"receipt\0");
            context.update(&encoded);
            context.update(b"\n");
        }
        offset += i64::try_from(rows.len()).map_err(|error| error.to_string())?;
        if rows.len() < usize::try_from(PAYLOAD_BATCH_SIZE).expect("positive batch size") {
            break;
        }
    }

    offset = 0;
    let mut staging_cleanup_jobs = 0_i64;
    let mut active_staging_cleanup_jobs = 0_i64;
    loop {
        let rows = sqlx::query(
            "SELECT write_session_id,backend_id,payload_id,source_nonce_digest,reason,\
                    completion_kind,state,\
                    fencing_token,lease_owner,lease_expires_at::text AS lease_expires_at,\
                    attempts,created_at::text AS created_at,completed_by,\
                    completed_fencing_token,completed_at::text AS completed_at \
             FROM filebelt_mount.nfs_staging_cleanup_jobs WHERE tenant_id=$1 \
             ORDER BY write_session_id OFFSET $2 LIMIT $3",
        )
        .bind(tenant_id)
        .bind(offset)
        .bind(PAYLOAD_BATCH_SIZE)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            staging_cleanup_jobs += 1;
            let state = row.get::<String, _>("state");
            if state != "completed" {
                active_staging_cleanup_jobs += 1;
            }
            let canonical = json!([
                row.get::<Uuid, _>("write_session_id"),
                row.get::<Uuid, _>("backend_id"),
                row.get::<Uuid, _>("payload_id"),
                row.get::<Option<Vec<u8>>, _>("source_nonce_digest")
                    .map(|digest| encode_hex(&digest)),
                row.get::<String, _>("reason"),
                row.get::<String, _>("completion_kind"),
                state,
                row.get::<i64, _>("fencing_token"),
                row.get::<Option<Uuid>, _>("lease_owner"),
                row.get::<Option<String>, _>("lease_expires_at"),
                row.get::<i64, _>("attempts"),
                row.get::<String, _>("created_at"),
                row.get::<Option<Uuid>, _>("completed_by"),
                row.get::<Option<i64>, _>("completed_fencing_token"),
                row.get::<Option<String>, _>("completed_at"),
            ]);
            let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
            context.update(b"cleanup\0");
            context.update(&encoded);
            context.update(b"\n");
        }
        offset += i64::try_from(rows.len()).map_err(|error| error.to_string())?;
        if rows.len() < usize::try_from(PAYLOAD_BATCH_SIZE).expect("positive batch size") {
            break;
        }
    }

    offset = 0;
    let mut lock_cleanup_jobs = 0_i64;
    let mut active_lock_cleanup_jobs = 0_i64;
    loop {
        let rows = sqlx::query(
            "SELECT write_session_id,backend_id,staging_payload_id,state,fencing_token,\
                    lease_owner,lease_expires_at::text AS lease_expires_at,attempts,\
                    created_at::text AS created_at,completed_by,completed_fencing_token,\
                    completed_at::text AS completed_at \
             FROM filebelt_mount.nfs_write_lock_cleanup_jobs WHERE tenant_id=$1 \
             ORDER BY write_session_id OFFSET $2 LIMIT $3",
        )
        .bind(tenant_id)
        .bind(offset)
        .bind(PAYLOAD_BATCH_SIZE)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            lock_cleanup_jobs += 1;
            let state = row.get::<String, _>("state");
            if state != "completed" {
                active_lock_cleanup_jobs += 1;
            }
            let canonical = json!([
                row.get::<Uuid, _>("write_session_id"),
                row.get::<Uuid, _>("backend_id"),
                row.get::<Uuid, _>("staging_payload_id"),
                state,
                row.get::<i64, _>("fencing_token"),
                row.get::<Option<Uuid>, _>("lease_owner"),
                row.get::<Option<String>, _>("lease_expires_at"),
                row.get::<i64, _>("attempts"),
                row.get::<String, _>("created_at"),
                row.get::<Option<Uuid>, _>("completed_by"),
                row.get::<Option<i64>, _>("completed_fencing_token"),
                row.get::<Option<String>, _>("completed_at"),
            ]);
            let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
            context.update(b"lock-cleanup\0");
            context.update(&encoded);
            context.update(b"\n");
        }
        offset += i64::try_from(rows.len()).map_err(|error| error.to_string())?;
        if rows.len() < usize::try_from(PAYLOAD_BATCH_SIZE).expect("positive batch size") {
            break;
        }
    }
    Ok(json!({
        "pending_protocol_operations": pending_protocol_operations,
        "live_io_admissions": live_io_admissions,
        "io_receipts": io_receipts,
        "pending_io_receipts": pending_io_receipts,
        "staging_cleanup_jobs": staging_cleanup_jobs,
        "active_staging_cleanup_jobs": active_staging_cleanup_jobs,
        "lock_cleanup_jobs": lock_cleanup_jobs,
        "active_lock_cleanup_jobs": active_lock_cleanup_jobs,
        "manifest_sha256": encode_hex(context.finish().as_ref()),
    }))
}

fn read_checkpoint(path: &Path) -> Result<Value, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_CHECKPOINT_BYTES {
        return Err("recovery checkpoint must be a regular file no larger than 1 MiB".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err("recovery checkpoint exceeds 1 MiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "recovery checkpoint JSON is invalid".to_owned())
}

fn validate_checkpoint(checkpoint: &Value) -> Result<(), String> {
    let object = checkpoint
        .as_object()
        .ok_or_else(|| "recovery checkpoint must be a JSON object".to_owned())?;
    if checkpoint.get("schema").and_then(Value::as_str) != Some(CHECKPOINT_SCHEMA) {
        return Err("recovery checkpoint schema is unsupported".into());
    }
    let actual_fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    if actual_fields.len() != CHECKPOINT_FIELDS.len()
        || CHECKPOINT_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err("recovery checkpoint fields are invalid".into());
    }
    for field in ["tenant", "database_key_generations", "inventory"] {
        if !matches!(checkpoint.get(field), Some(Value::Object(_))) {
            return Err(format!("recovery checkpoint field {field} is invalid"));
        }
    }
    if !matches!(checkpoint.get("migrations"), Some(Value::Array(_))) {
        return Err("recovery checkpoint migrations are invalid".into());
    }
    Ok(())
}

fn validate_legacy_v2_checkpoint(checkpoint: &Value) -> Result<(), String> {
    let object = checkpoint
        .as_object()
        .ok_or_else(|| "recovery checkpoint must be a JSON object".to_owned())?;
    const FIELDS: &[&str] = &[
        "schema",
        "tenant",
        "storage_backend_id",
        "capability_key_generation",
        "database_key_generations",
        "migrations",
        "audit_watermark",
        "inventory",
    ];
    if checkpoint.get("schema").and_then(Value::as_str) != Some(LEGACY_CHECKPOINT_SCHEMA)
        || object.len() != FIELDS.len()
        || FIELDS.iter().any(|field| !object.contains_key(*field))
    {
        return Err("legacy recovery checkpoint fields are invalid".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    #[test]
    fn checkpoint_shape_is_closed_and_versioned() {
        let mut object = Map::new();
        for field in CHECKPOINT_FIELDS {
            object.insert(
                (*field).to_owned(),
                match *field {
                    "schema" => Value::String(CHECKPOINT_SCHEMA.into()),
                    "tenant" | "database_key_generations" | "inventory" => {
                        Value::Object(Map::new())
                    }
                    "migrations" => Value::Array(Vec::new()),
                    _ => Value::Null,
                },
            );
        }
        let checkpoint = Value::Object(object.clone());
        validate_checkpoint(&checkpoint).expect("valid checkpoint shape");
        object.insert("unreviewed".into(), Value::Bool(true));
        assert!(validate_checkpoint(&Value::Object(object)).is_err());
    }

    #[test]
    fn hexadecimal_encoding_is_stable() {
        assert_eq!(encode_hex(&[0x00, 0x7f, 0x80, 0xff]), "007f80ff");
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Deterministic, bounded recovery checkpoints and restored-state verification.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use aws_lc_rs::digest::{Context, SHA256};
use filebelt_control_protocol::Config;
use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::grants::{encode_hex, migration_manifest_in};

const CHECKPOINT_SCHEMA: &str = "filebelt.recovery.checkpoint.v2";
const VERIFICATION_SCHEMA: &str = "filebelt.recovery.verification.v2";
const MAX_CHECKPOINT_BYTES: u64 = 1_048_576;
const PAYLOAD_BATCH_SIZE: i64 = 1_000;
const CHECKPOINT_FIELDS: &[&str] = &[
    "schema",
    "tenant",
    "storage_backend_id",
    "capability_key_generation",
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
) -> Result<String, String> {
    let expected = read_checkpoint(checkpoint_path)?;
    validate_checkpoint(&expected)?;
    let actual = checkpoint_value(database, configuration).await?;
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
    let counts = sqlx::query("SELECT (SELECT count(id) FROM principals WHERE tenant_id=$1) AS principals,(SELECT count(id) FROM users WHERE tenant_id=$1) AS users,(SELECT count(id) FROM groups WHERE tenant_id=$1) AS groups,(SELECT count(id) FROM drives WHERE tenant_id=$1) AS drives,(SELECT count(id) FROM nodes WHERE tenant_id=$1) AS nodes,(SELECT count(id) FROM file_versions WHERE tenant_id=$1) AS file_versions,(SELECT count(id) FROM payload_objects WHERE tenant_id=$1) AS payload_objects,(SELECT count(id) FROM jobs WHERE tenant_id=$1) AS jobs,(SELECT count(id) FROM audit_events WHERE tenant_id=$1) AS audit_events,(SELECT count(id) FROM outbox_events WHERE tenant_id=$1 AND published_at IS NULL) AS pending_outbox,(SELECT count(id) FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND deleted_at IS NULL) AS mcp_registrations,(SELECT count(id) FROM filebelt_mcp.deletion_tombstones WHERE tenant_id=$1) AS mcp_deletion_tombstones,(SELECT count(invocation_id) FROM filebelt_mcp.runner_slot_reservations WHERE tenant_id=$1 AND released_at IS NULL) AS mcp_runner_slot_reservations,(SELECT count(registration_id) FROM filebelt_mcp_vault.secret_envelopes WHERE tenant_id=$1 AND deleted_at IS NULL) AS mcp_secret_envelopes,(SELECT count(attempt_id) FROM filebelt_mcp_vault.oauth_attempt_secrets WHERE tenant_id=$1) AS mcp_oauth_attempt_secrets,(SELECT count(id) FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('referenced','finalized','quarantining','quarantined')) AS expected_payloads,(SELECT count(id) FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('quarantining','quarantined')) AS quarantined_payloads,(SELECT COALESCE(sum(size_bytes),0)::bigint FROM payload_objects WHERE tenant_id=$1 AND backend_id=$2 AND state IN ('referenced','finalized','quarantining','quarantined')) AS total_payload_bytes")
        .bind(tenant_id)
        .bind(configuration.storage.backend_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
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
        "capability_key_generation": configuration.keys.current_generation,
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
        },
    }))
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

// SPDX-License-Identifier: Apache-2.0

//! Fail-closed verification of migrations and reviewed PostgreSQL grants.

use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/postgres");

const ROLES: &[&str] = &[
    "filebelt_migrator",
    "filebelt_api",
    "filebelt_io",
    "filebelt_maintenance",
    "filebelt_audit_exporter",
    "filebelt_recovery",
];
const TABLE_PRIVILEGES: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
];
const COLUMN_PRIVILEGES: &[&str] = &["SELECT", "INSERT", "UPDATE", "REFERENCES"];

pub async fn verify(database: &Database) -> Result<String, String> {
    let migrations = migration_manifest(database).await?;
    let mut failures = Vec::new();
    verify_role_properties(database, &mut failures).await?;
    if !failures.is_empty() {
        return Err(verification_failure(failures));
    }
    verify_schema_privileges(database, &mut failures).await?;
    let tables = public_tables(database).await?;
    verify_table_privileges(database, &tables, &mut failures).await?;
    verify_column_privileges(database, &tables, &mut failures).await?;
    if !failures.is_empty() {
        return Err(verification_failure(failures));
    }
    serde_json::to_string_pretty(&json!({
        "schema": "filebelt.database.grants.verification.v1",
        "status": "verified",
        "migrations": migrations,
        "roles": ROLES,
        "public_tables": tables.len(),
    }))
    .map_err(|error| error.to_string())
}

fn verification_failure(mut failures: Vec<String>) -> String {
    failures.sort();
    format!(
        "database grant verification failed:\n{}",
        failures.join("\n")
    )
}

pub async fn migration_manifest(database: &Database) -> Result<Value, String> {
    let rows = sqlx::query(
        "SELECT version,description,success,checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(database.pool())
    .await
    .map_err(|error| error.to_string())?;
    validate_migrations(rows)
}

pub async fn migration_manifest_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Value, String> {
    let rows = sqlx::query(
        "SELECT version,description,success,checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| error.to_string())?;
    validate_migrations(rows)
}

fn validate_migrations(rows: Vec<sqlx::postgres::PgRow>) -> Result<Value, String> {
    if rows.len() != MIGRATOR.iter().len() {
        return Err(format!(
            "migration count differs: database={}, binary={}",
            rows.len(),
            MIGRATOR.iter().len()
        ));
    }
    let mut manifest = Vec::with_capacity(rows.len());
    for (row, expected) in rows.into_iter().zip(MIGRATOR.iter()) {
        let version: i64 = row.get("version");
        let description: String = row.get("description");
        let success: bool = row.get("success");
        let checksum: Vec<u8> = row.get("checksum");
        if version != expected.version
            || !success
            || checksum.as_slice() != expected.checksum.as_ref()
        {
            return Err(format!(
                "migration {version} does not match the compiled successful migration"
            ));
        }
        manifest.push(json!({
            "version": version,
            "description": description,
            "checksum": encode_hex(&checksum),
        }));
    }
    Ok(Value::Array(manifest))
}

async fn verify_role_properties(
    database: &Database,
    failures: &mut Vec<String>,
) -> Result<(), String> {
    for role in ROLES {
        let row = sqlx::query("SELECT rolcanlogin,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=$1")
            .bind(role)
            .fetch_optional(database.pool())
            .await
            .map_err(|error| error.to_string())?;
        let Some(row) = row else {
            failures.push(format!("missing required NOLOGIN role {role}"));
            continue;
        };
        if row.get::<bool, _>("rolcanlogin")
            || row.get::<bool, _>("rolsuper")
            || row.get::<bool, _>("rolcreaterole")
            || row.get::<bool, _>("rolcreatedb")
            || row.get::<bool, _>("rolreplication")
            || row.get::<bool, _>("rolbypassrls")
        {
            failures.push(format!("role {role} has prohibited role attributes"));
        }
    }
    Ok(())
}

async fn verify_schema_privileges(
    database: &Database,
    failures: &mut Vec<String>,
) -> Result<(), String> {
    for role in ROLES {
        for privilege in ["USAGE", "CREATE"] {
            let actual: bool = sqlx::query_scalar("SELECT has_schema_privilege($1,'public',$2)")
                .bind(role)
                .bind(privilege)
                .fetch_one(database.pool())
                .await
                .map_err(|error| error.to_string())?;
            let expected = privilege == "USAGE" || *role == "filebelt_migrator";
            if actual != expected {
                failures.push(format!(
                    "role {role} schema privilege {privilege}: expected {expected}, found {actual}"
                ));
            }
        }
    }
    Ok(())
}

async fn public_tables(database: &Database) -> Result<Vec<String>, String> {
    sqlx::query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') ORDER BY c.relname")
        .fetch_all(database.pool())
        .await
        .map_err(|error| error.to_string())
        .map(|rows| rows.into_iter().map(|row| row.get("relname")).collect())
}

async fn verify_table_privileges(
    database: &Database,
    tables: &[String],
    failures: &mut Vec<String>,
) -> Result<(), String> {
    for role in &ROLES[1..] {
        for table in tables {
            for privilege in TABLE_PRIVILEGES {
                let actual: bool = sqlx::query_scalar(
                    "SELECT has_table_privilege($1,format('%I.%I','public',$2),$3)",
                )
                .bind(role)
                .bind(table)
                .bind(privilege)
                .fetch_one(database.pool())
                .await
                .map_err(|error| error.to_string())?;
                let expected = expected_table_privilege(role, table, privilege);
                if actual != expected {
                    failures.push(format!(
                        "role {role} table {table} privilege {privilege}: expected {expected}, found {actual}"
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn verify_column_privileges(
    database: &Database,
    tables: &[String],
    failures: &mut Vec<String>,
) -> Result<(), String> {
    for table in tables {
        let columns = sqlx::query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position")
            .bind(table)
            .fetch_all(database.pool())
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<String, _>("column_name"))
            .collect::<Vec<_>>();
        for role in &ROLES[1..] {
            for column in &columns {
                for privilege in COLUMN_PRIVILEGES {
                    let actual: bool = sqlx::query_scalar(
                        "SELECT has_column_privilege($1,format('%I.%I','public',$2),$3,$4)",
                    )
                    .bind(role)
                    .bind(table)
                    .bind(column)
                    .bind(privilege)
                    .fetch_one(database.pool())
                    .await
                    .map_err(|error| error.to_string())?;
                    let expected = expected_table_privilege(role, table, privilege)
                        || expected_column_privilege(role, table, column, privilege);
                    if actual != expected {
                        failures.push(format!(
                            "role {role} column {table}.{column} privilege {privilege}: expected {expected}, found {actual}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn expected_table_privilege(role: &str, table: &str, privilege: &str) -> bool {
    match role {
        "filebelt_api" => match privilege {
            "SELECT" | "INSERT" => true,
            "UPDATE" => table != "audit_events",
            "DELETE" => matches!(
                table,
                "authorization_generations" | "acl_entries" | "oidc_login_attempts"
            ),
            _ => false,
        },
        "filebelt_io" => matches!(
            (table, privilege),
            (
                "payload_objects" | "upload_sessions" | "upload_parts",
                "SELECT" | "UPDATE"
            ) | ("storage_backends" | "authorization_generations", "SELECT")
                | ("capability_nonces", "SELECT" | "INSERT")
        ),
        "filebelt_maintenance" => {
            matches!(
                table,
                "jobs"
                    | "job_attempts"
                    | "outbox_events"
                    | "consumer_deduplication"
                    | "payload_objects"
                    | "upload_sessions"
                    | "upload_parts"
                    | "quota_reservations"
                    | "capability_nonces"
            ) && matches!(privilege, "SELECT" | "INSERT" | "UPDATE" | "DELETE")
        }
        "filebelt_audit_exporter" | "filebelt_recovery" => false,
        _ => false,
    }
}

fn expected_column_privilege(role: &str, table: &str, column: &str, privilege: &str) -> bool {
    match role {
        "filebelt_io" => {
            (table == "tenants" && privilege == "SELECT" && matches!(column, "id" | "slug"))
                || (table == "storage_backends"
                    && privilege == "UPDATE"
                    && matches!(
                        column,
                        "capacity_total_bytes"
                            | "capacity_free_bytes"
                            | "capacity_checked_at"
                            | "storage_ready"
                    ))
        }
        "filebelt_maintenance" => {
            (table == "tenants" && privilege == "SELECT" && matches!(column, "id" | "slug"))
                || (table == "drives"
                    && privilege == "SELECT"
                    && matches!(column, "tenant_id" | "id" | "reserved_bytes"))
                || (table == "drives" && privilege == "UPDATE" && column == "reserved_bytes")
        }
        "filebelt_audit_exporter" => privilege == "SELECT" && audit_column(table, column),
        "filebelt_recovery" => privilege == "SELECT" && recovery_column(table, column),
        _ => false,
    }
}

fn audit_column(table: &str, column: &str) -> bool {
    (table == "tenants" && matches!(column, "id" | "slug"))
        || (table == "audit_events"
            && matches!(
                column,
                "tenant_id"
                    | "id"
                    | "actor_principal_id"
                    | "target_principal_id"
                    | "resource_id"
                    | "action"
                    | "outcome"
                    | "reason_code"
                    | "privacy_visible"
                    | "request_id"
                    | "details"
                    | "occurred_at"
            ))
}

fn recovery_column(table: &str, column: &str) -> bool {
    match table {
        "tenants" => matches!(column, "id" | "slug"),
        "principals" | "users" | "groups" | "nodes" => {
            matches!(column, "tenant_id" | "id")
        }
        "drives" => matches!(column, "tenant_id" | "id"),
        "storage_backends" => matches!(column, "tenant_id" | "id" | "kind"),
        "payload_objects" => matches!(
            column,
            "tenant_id"
                | "id"
                | "drive_id"
                | "backend_id"
                | "locator"
                | "layout"
                | "state"
                | "size_bytes"
                | "blake3"
        ),
        "file_versions" => matches!(
            column,
            "tenant_id" | "id" | "node_id" | "payload_id" | "size_bytes" | "blake3"
        ),
        "jobs" => matches!(column, "tenant_id" | "id" | "state"),
        "outbox_events" => matches!(column, "tenant_id" | "id" | "published_at"),
        "audit_events" => matches!(column, "tenant_id" | "id" | "occurred_at"),
        "api_sessions" | "share_links" => {
            matches!(column, "tenant_id" | "token_key_generation")
        }
        "_sqlx_migrations" => matches!(column, "version" | "description" | "success" | "checksum"),
        _ => false,
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_and_recovery_roles_are_read_only_and_column_scoped() {
        for role in ["filebelt_audit_exporter", "filebelt_recovery"] {
            assert!(!expected_table_privilege(role, "audit_events", "SELECT"));
            assert!(!expected_table_privilege(role, "audit_events", "UPDATE"));
        }
        assert!(audit_column("audit_events", "details"));
        assert!(!audit_column("users", "verified_email"));
        assert!(recovery_column("payload_objects", "blake3"));
        assert!(!recovery_column("payload_objects", "quarantine_reason"));
    }

    #[test]
    fn runtime_excess_privileges_are_not_accepted() {
        assert!(expected_table_privilege("filebelt_api", "users", "UPDATE"));
        assert!(!expected_table_privilege(
            "filebelt_api",
            "audit_events",
            "UPDATE"
        ));
        assert!(!expected_table_privilege(
            "filebelt_io",
            "payload_objects",
            "DELETE"
        ));
        assert!(!expected_column_privilege(
            "filebelt_maintenance",
            "drives",
            "quota_bytes",
            "UPDATE"
        ));
    }

    #[test]
    fn sql_role_allowlist_has_no_default_privileges() {
        let roles = include_str!("../../../migrations/postgres/roles.sql");
        let grants = include_str!("../../../migrations/postgres/grants.sql");
        for role in ["filebelt_audit_exporter", "filebelt_recovery"] {
            assert!(roles.contains(&format!("CREATE ROLE {role} NOLOGIN")));
            assert!(grants.contains(role));
        }
        assert!(!roles.contains("ALTER DEFAULT PRIVILEGES"));
        assert!(!grants.contains("ALTER DEFAULT PRIVILEGES"));
    }
}

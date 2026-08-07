// SPDX-License-Identifier: Apache-2.0

//! Fail-closed verification of migrations and reviewed PostgreSQL grants.

use filebelt_database::Database;
use serde_json::{Value, json};
use sqlx::Row as _;

mod acl;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/postgres");

const ROLES: &[&str] = &[
    "filebelt_migrator",
    "filebelt_api",
    "filebelt_io",
    "filebelt_maintenance",
    "filebelt_audit_exporter",
    "filebelt_recovery",
    "filebelt_mcp_broker",
];
const SCHEMAS: &[&str] = &["public", "filebelt_mcp", "filebelt_mcp_vault"];
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
    let tables = reviewed_tables(database).await?;
    verify_table_privileges(database, &tables, &mut failures).await?;
    verify_column_privileges(database, &tables, &mut failures).await?;
    verify_function_privileges(database, &mut failures).await?;
    acl::verify_unlisted_acl_grantees(database, &mut failures).await?;
    if !failures.is_empty() {
        return Err(verification_failure(failures));
    }
    serde_json::to_string_pretty(&json!({
        "schema": "filebelt.database.grants.verification.v1",
        "status": "verified",
        "migrations": migrations,
        "roles": ROLES,
        "reviewed_schemas": SCHEMAS,
        "reviewed_tables": tables.len(),
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
    for schema in SCHEMAS {
        for role in ROLES {
            for privilege in ["USAGE", "CREATE"] {
                let actual: bool = sqlx::query_scalar("SELECT has_schema_privilege($1,$2,$3)")
                    .bind(role)
                    .bind(schema)
                    .bind(privilege)
                    .fetch_one(database.pool())
                    .await
                    .map_err(|error| error.to_string())?;
                let expected = expected_schema_privilege(role, schema, privilege);
                if actual != expected {
                    failures.push(format!(
                        "role {role} schema {schema} privilege {privilege}: expected {expected}, found {actual}"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn expected_schema_privilege(role: &str, schema: &str, privilege: &str) -> bool {
    if role == "filebelt_migrator" {
        return matches!(privilege, "USAGE" | "CREATE");
    }
    if privilege != "USAGE" {
        return false;
    }
    match schema {
        "public" => true,
        "filebelt_mcp" => matches!(
            role,
            "filebelt_api" | "filebelt_recovery" | "filebelt_mcp_broker"
        ),
        "filebelt_mcp_vault" => matches!(role, "filebelt_recovery" | "filebelt_mcp_broker"),
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct ReviewedTable {
    schema: String,
    name: String,
}

async fn reviewed_tables(database: &Database) -> Result<Vec<ReviewedTable>, String> {
    sqlx::query("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','f') ORDER BY n.nspname,c.relname")
        .bind(SCHEMAS)
        .fetch_all(database.pool())
        .await
        .map_err(|error| error.to_string())
        .map(|rows| {
            rows.into_iter()
                .map(|row| ReviewedTable {
                    schema: row.get("nspname"),
                    name: row.get("relname"),
                })
                .collect()
        })
}

async fn verify_table_privileges(
    database: &Database,
    tables: &[ReviewedTable],
    failures: &mut Vec<String>,
) -> Result<(), String> {
    for role in &ROLES[1..] {
        for table in tables {
            for privilege in TABLE_PRIVILEGES {
                let actual: bool =
                    sqlx::query_scalar("SELECT has_table_privilege($1,format('%I.%I',$2,$3),$4)")
                        .bind(role)
                        .bind(&table.schema)
                        .bind(&table.name)
                        .bind(privilege)
                        .fetch_one(database.pool())
                        .await
                        .map_err(|error| error.to_string())?;
                let expected =
                    expected_table_privilege(role, &table.schema, &table.name, privilege);
                if actual != expected {
                    failures.push(format!(
                        "role {role} table {}.{} privilege {privilege}: expected {expected}, found {actual}",
                        table.schema, table.name
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn verify_column_privileges(
    database: &Database,
    tables: &[ReviewedTable],
    failures: &mut Vec<String>,
) -> Result<(), String> {
    for table in tables {
        let columns = sqlx::query("SELECT column_name FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 ORDER BY ordinal_position")
            .bind(&table.schema)
            .bind(&table.name)
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
                        "SELECT has_column_privilege($1,format('%I.%I',$2,$3),$4,$5)",
                    )
                    .bind(role)
                    .bind(&table.schema)
                    .bind(&table.name)
                    .bind(column)
                    .bind(privilege)
                    .fetch_one(database.pool())
                    .await
                    .map_err(|error| error.to_string())?;
                    let expected =
                        expected_table_privilege(role, &table.schema, &table.name, privilege)
                            || expected_column_privilege(
                                role,
                                &table.schema,
                                &table.name,
                                column,
                                privilege,
                            );
                    if actual != expected {
                        failures.push(format!(
                            "role {role} column {}.{}.{column} privilege {privilege}: expected {expected}, found {actual}",
                            table.schema, table.name
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn expected_table_privilege(role: &str, schema: &str, table: &str, privilege: &str) -> bool {
    if schema == "filebelt_mcp" {
        return expected_mcp_table_privilege(role, table, privilege);
    }
    if schema == "filebelt_mcp_vault" {
        return role == "filebelt_mcp_broker"
            && ((table == "secret_envelopes"
                && matches!(privilege, "SELECT" | "INSERT" | "UPDATE" | "DELETE"))
                || (table == "oauth_attempt_secrets"
                    && matches!(privilege, "SELECT" | "INSERT" | "DELETE")));
    }
    if schema != "public" {
        return false;
    }
    match role {
        "filebelt_api" => match privilege {
            "SELECT" | "INSERT" => table != "_sqlx_migrations",
            "UPDATE" => table != "audit_events" && table != "_sqlx_migrations",
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
        "filebelt_audit_exporter" | "filebelt_recovery" | "filebelt_mcp_broker" => false,
        _ => false,
    }
}

fn expected_mcp_table_privilege(role: &str, table: &str, privilege: &str) -> bool {
    const API_WRITE_TABLES: &[&str] = &[
        "service_principals",
        "service_identity_bindings",
        "managed_templates",
        "template_assignments",
        "admin_block_rules",
        "capability_reviews",
        "approval_rules",
        "data_grants",
        "service_invocation_grants",
        "service_grant_data_grants",
        "invocation_intents",
        "policy_generations",
    ];
    const API_READ_TABLES: &[&str] = &[
        "capability_snapshots",
        "capabilities",
        "oauth_attempts",
        "invocations",
        "invocation_attachments",
        "deletion_tombstones",
    ];
    const BROKER_READ_TABLES: &[&str] = &[
        "registrations",
        "capability_snapshots",
        "capabilities",
        "capability_reviews",
        "approval_rules",
        "data_grants",
        "service_invocation_grants",
        "service_grant_data_grants",
        "oauth_attempts",
        "invocation_intents",
        "invocations",
        "invocation_attachments",
        "rate_buckets",
        "runner_leases",
        "deletion_tombstones",
        "service_principals",
        "service_identity_bindings",
        "managed_templates",
        "template_assignments",
        "admin_block_rules",
        "policy_generations",
        "runner_slot_admission",
        "runner_slot_reservations",
    ];
    match role {
        "filebelt_api" => {
            (API_WRITE_TABLES.contains(&table)
                && matches!(privilege, "SELECT" | "INSERT" | "UPDATE"))
                || API_READ_TABLES.contains(&table) && privilege == "SELECT"
                || table == "deletion_tombstones" && privilege == "INSERT"
                || table == "registrations" && matches!(privilege, "SELECT" | "INSERT")
                || table == "invocations" && privilege == "INSERT"
        }
        "filebelt_mcp_broker" => {
            BROKER_READ_TABLES.contains(&table) && privilege == "SELECT"
                || matches!(
                    table,
                    "oauth_attempts" | "invocation_attachments" | "rate_buckets"
                ) && privilege == "INSERT"
                || matches!(table, "oauth_attempts" | "rate_buckets") && privilege == "DELETE"
                || table == "runner_slot_admission" && privilege == "INSERT"
                || table == "runner_slot_reservations" && matches!(privilege, "INSERT" | "UPDATE")
                || table == "policy_generations" && privilege == "INSERT"
        }
        _ => false,
    }
}

fn expected_column_privilege(
    role: &str,
    schema: &str,
    table: &str,
    column: &str,
    privilege: &str,
) -> bool {
    if schema == "filebelt_mcp_vault" {
        return role == "filebelt_recovery"
            && privilege == "SELECT"
            && ((table == "secret_envelopes"
                && matches!(
                    column,
                    "tenant_id" | "registration_id" | "kek_generation" | "deleted_at"
                ))
                || (table == "oauth_attempt_secrets"
                    && matches!(column, "tenant_id" | "attempt_id" | "kek_generation")));
    }
    if schema == "filebelt_mcp" {
        if role == "filebelt_api" && table == "registrations" && privilege == "UPDATE" {
            return matches!(
                column,
                "validation_state"
                    | "authentication_state"
                    | "capability_state"
                    | "quarantine_state"
                    | "enabled"
                    | "protocol_version"
                    | "revision"
                    | "revocation_generation"
                    | "credential_generation"
                    | "credential_kind"
                    | "revoked_at"
                    | "deleted_at"
                    | "updated_at"
            );
        }
        if role == "filebelt_api"
            && table == "capability_snapshots"
            && privilege == "UPDATE"
            && column == "superseded_at"
        {
            return true;
        }
        if role == "filebelt_api"
            && table == "invocations"
            && privilege == "UPDATE"
            && matches!(
                column,
                "state" | "response_bytes" | "reason_code" | "finished_at"
            )
        {
            return true;
        }
        if role == "filebelt_api" && table == "deletion_tombstones" && privilege == "INSERT" {
            return true;
        }
        if role == "filebelt_mcp_broker" && privilege == "UPDATE" {
            return match table {
                "registrations" => matches!(
                    column,
                    "validation_state"
                        | "authentication_state"
                        | "capability_state"
                        | "quarantine_state"
                        | "enabled"
                        | "protocol_version"
                        | "revision"
                        | "revocation_generation"
                        | "credential_generation"
                        | "credential_kind"
                        | "updated_at"
                ),
                "approval_rules" => matches!(column, "consumed_at" | "revoked_at"),
                "service_invocation_grants" => column == "revoked_at",
                "data_grants" | "capability_reviews" => column == "revoked_at",
                "capability_snapshots" => column == "superseded_at",
                "oauth_attempts" | "invocation_intents" => column == "consumed_at",
                "invocations" => matches!(
                    column,
                    "state" | "response_bytes" | "reason_code" | "finished_at"
                ),
                "rate_buckets" => matches!(column, "used" | "limit_value" | "expires_at"),
                "deletion_tombstones" => {
                    matches!(
                        column,
                        "remote_revocation_deadline" | "remote_revocation_outcome"
                    )
                }
                "runner_slot_reservations" => {
                    matches!(column, "lease_expires_at" | "updated_at" | "released_at")
                }
                _ => false,
            };
        }
        return role == "filebelt_recovery"
            && privilege == "SELECT"
            && ((table == "registrations" && matches!(column, "tenant_id" | "id" | "deleted_at"))
                || (table == "deletion_tombstones"
                    && matches!(
                        column,
                        "tenant_id"
                            | "id"
                            | "object_kind"
                            | "object_id"
                            | "revocation_generation"
                            | "deleted_at"
                    ))
                || (table == "runner_slot_reservations"
                    && matches!(
                        column,
                        "tenant_id"
                            | "invocation_id"
                            | "principal_id"
                            | "lease_expires_at"
                            | "released_at"
                    )));
    }
    if schema != "public" {
        return false;
    }
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
        "filebelt_mcp_broker" => {
            privilege == "SELECT"
                && ((table == "tenants" && matches!(column, "id" | "slug"))
                    || (table == "principals"
                        && matches!(
                            column,
                            "tenant_id" | "id" | "kind" | "generation" | "disabled_at"
                        ))
                    || (table == "nodes"
                        && matches!(
                            column,
                            "tenant_id"
                                | "id"
                                | "drive_id"
                                | "acl_generation"
                                | "namespace_generation"
                        ))
                    || (table == "file_versions"
                        && matches!(column, "tenant_id" | "id" | "node_id")))
        }
        _ => false,
    }
}

async fn verify_function_privileges(
    database: &Database,
    failures: &mut Vec<String>,
) -> Result<(), String> {
    let functions = sqlx::query(
        "SELECT p.oid::regprocedure::text AS function FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY($1) ORDER BY p.oid::regprocedure::text",
    )
    .bind(SCHEMAS)
    .fetch_all(database.pool())
    .await
    .map_err(|error| error.to_string())?
    .into_iter()
    .map(|row| row.get::<String, _>("function"))
    .collect::<Vec<_>>();
    for function in functions {
        for role in &ROLES[1..] {
            let actual: bool = sqlx::query_scalar("SELECT has_function_privilege($1,$2,'EXECUTE')")
                .bind(role)
                .bind(&function)
                .fetch_one(database.pool())
                .await
                .map_err(|error| error.to_string())?;
            let expected = function
                == "filebelt_mcp.replace_registration_configuration_and_erase(uuid,uuid,uuid,bigint,text,text,text,text,text,jsonb)"
                && *role == "filebelt_mcp_broker";
            if actual != expected {
                failures.push(format!(
                    "role {role} function {function} EXECUTE: expected {expected}, found {actual}"
                ));
            }
        }
    }
    Ok(())
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
            assert!(!expected_table_privilege(
                role,
                "public",
                "audit_events",
                "SELECT"
            ));
            assert!(!expected_table_privilege(
                role,
                "public",
                "audit_events",
                "UPDATE"
            ));
        }
        assert!(audit_column("audit_events", "details"));
        assert!(!audit_column("users", "verified_email"));
        assert!(recovery_column("payload_objects", "blake3"));
        assert!(!recovery_column("payload_objects", "quarantine_reason"));
    }

    #[test]
    fn runtime_excess_privileges_are_not_accepted() {
        assert!(expected_table_privilege(
            "filebelt_api",
            "public",
            "users",
            "UPDATE"
        ));
        assert!(!expected_table_privilege(
            "filebelt_api",
            "public",
            "audit_events",
            "UPDATE"
        ));
        assert!(!expected_table_privilege(
            "filebelt_io",
            "public",
            "payload_objects",
            "DELETE"
        ));
        assert!(!expected_column_privilege(
            "filebelt_maintenance",
            "public",
            "drives",
            "quota_bytes",
            "UPDATE"
        ));
        assert!(!expected_table_privilege(
            "filebelt_api",
            "filebelt_mcp_vault",
            "secret_envelopes",
            "SELECT"
        ));
        assert!(expected_table_privilege(
            "filebelt_mcp_broker",
            "filebelt_mcp_vault",
            "secret_envelopes",
            "UPDATE"
        ));
        assert!(!expected_table_privilege(
            "filebelt_mcp_broker",
            "filebelt_mcp",
            "registrations",
            "UPDATE"
        ));
        assert!(expected_column_privilege(
            "filebelt_mcp_broker",
            "filebelt_mcp",
            "registrations",
            "credential_generation",
            "UPDATE"
        ));
        assert!(!expected_column_privilege(
            "filebelt_mcp_broker",
            "filebelt_mcp",
            "registrations",
            "endpoint_uri",
            "UPDATE"
        ));
    }

    #[test]
    fn sql_role_allowlist_has_no_default_privileges() {
        let roles = include_str!("../../../migrations/postgres/roles.sql");
        let grants = include_str!("../../../migrations/postgres/grants.sql");
        for role in [
            "filebelt_audit_exporter",
            "filebelt_recovery",
            "filebelt_mcp_broker",
        ] {
            assert!(roles.contains(&format!("CREATE ROLE {role} NOLOGIN")));
            assert!(grants.contains(role));
        }
        assert!(!roles.contains("ALTER DEFAULT PRIVILEGES"));
        assert!(!grants.contains("ALTER DEFAULT PRIVILEGES"));
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in FILEBELT_MCP_TEST_DATABASE_URL"]
    async fn postgres_grants_match_the_complete_reviewed_allowlist() {
        let database_url = std::env::var("FILEBELT_MCP_TEST_DATABASE_URL")
            .expect("FILEBELT_MCP_TEST_DATABASE_URL is required");
        let database = Database::connect(&database_url, 1)
            .await
            .expect("connect test database");
        let document = verify(&database).await.expect("verified grants");
        assert!(document.contains("\"status\": \"verified\""));
        assert!(document.contains("filebelt_mcp_vault"));

        sqlx::query("CREATE ROLE filebelt_unreviewed_grantee NOLOGIN")
            .execute(database.pool())
            .await
            .expect("create unexpected grantee");
        sqlx::query("GRANT SELECT ON public.tenants TO filebelt_unreviewed_grantee")
            .execute(database.pool())
            .await
            .expect("inject unexpected ACL");
        let acl_error = verify(&database)
            .await
            .expect_err("unexpected ACL must fail");
        sqlx::query("REVOKE SELECT ON public.tenants FROM filebelt_unreviewed_grantee")
            .execute(database.pool())
            .await
            .expect("remove unexpected ACL");

        sqlx::query("GRANT filebelt_unreviewed_grantee TO filebelt_api")
            .execute(database.pool())
            .await
            .expect("inject reverse membership");
        let membership_error = verify(&database)
            .await
            .expect_err("reverse membership must fail");
        sqlx::query("REVOKE filebelt_unreviewed_grantee FROM filebelt_api")
            .execute(database.pool())
            .await
            .expect("remove reverse membership");

        sqlx::query("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO filebelt_api")
            .execute(database.pool())
            .await
            .expect("inject default ACL");
        let default_error = verify(&database)
            .await
            .expect_err("any default ACL must fail");
        sqlx::query("ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM filebelt_api")
            .execute(database.pool())
            .await
            .expect("remove default ACL");
        sqlx::query("DROP ROLE filebelt_unreviewed_grantee")
            .execute(database.pool())
            .await
            .expect("drop unexpected grantee");

        assert!(acl_error.contains("unreviewed ACL grantee"));
        assert!(membership_error.contains("inherits unreviewed role"));
        assert!(default_error.contains("prohibited default ACL"));
    }
}

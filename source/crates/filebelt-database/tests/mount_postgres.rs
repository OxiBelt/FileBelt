// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed mount schema and least-privilege contract checks.

use filebelt_database::Database;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_MOUNT_TEST_DATABASE_URL"]
async fn mount_schema_enforces_process_and_vault_boundaries() {
    let database_url = std::env::var("FILEBELT_MOUNT_TEST_DATABASE_URL")
        .expect("FILEBELT_MOUNT_TEST_DATABASE_URL is required");
    let database = Database::connect(&database_url, 2)
        .await
        .expect("connect test database");
    sqlx::raw_sql(include_str!("../../../migrations/postgres/roles.sql"))
        .execute(database.pool())
        .await
        .expect("apply roles");
    database.migrate().await.expect("apply migrations");
    sqlx::raw_sql(include_str!("../../../migrations/postgres/grants.sql"))
        .execute(database.pool())
        .await
        .expect("apply grants");

    assert!(schema_privilege(&database, "filebelt_vfs", "filebelt_mount", "USAGE").await);
    assert!(schema_privilege(&database, "filebelt_vfs", "filebelt_mount_vault", "USAGE").await);
    assert!(
        table_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount_vault.secret_envelopes",
            "SELECT"
        )
        .await
    );
    for role in ["filebelt_api", "filebelt_io", "filebelt_headscale_sync"] {
        assert!(
            !schema_privilege(&database, role, "filebelt_mount_vault", "USAGE").await,
            "{role} must not enter the mount vault"
        );
        assert!(
            !table_privilege(
                &database,
                role,
                "filebelt_mount_vault.secret_envelopes",
                "SELECT"
            )
            .await,
            "{role} must not read mount verifier envelopes"
        );
    }
    assert!(
        table_privilege(
            &database,
            "filebelt_headscale_sync",
            "filebelt_mount.headscale_devices",
            "UPDATE"
        )
        .await
    );
    assert!(
        !table_privilege(
            &database,
            "filebelt_headscale_sync",
            "filebelt_mount.credentials",
            "SELECT"
        )
        .await
    );
    assert!(table_privilege(&database, "filebelt_io", "filebelt_mount.handles", "SELECT").await);
    assert!(!table_privilege(&database, "filebelt_io", "filebelt_mount.handles", "INSERT").await);
    assert!(
        !column_privilege(
            &database,
            "filebelt_recovery",
            "filebelt_mount_vault.secret_envelopes",
            "ciphertext",
            "SELECT"
        )
        .await
    );
    assert!(
        column_privilege(
            &database,
            "filebelt_recovery",
            "filebelt_mount_vault.secret_envelopes",
            "kek_generation",
            "SELECT"
        )
        .await
    );

    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=5 AND success)",
    )
    .fetch_one(database.pool())
    .await
    .expect("query migration ledger");
    assert!(
        applied,
        "the completed mount-vault envelope migration is required"
    );

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'mount-test')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("insert throttle tenant");
    let principal_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user')")
        .bind(tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await
        .expect("insert mount test principal");
    assert!(
        sqlx::query(
            "INSERT INTO filebelt_mount.credentials \
             (tenant_id,id,principal_id,protocol,username,verifier_kind,expires_at) \
             VALUES ($1,$2,$3,'ftps','credential-user-1','hmac_sha256',clock_timestamp()+interval '8 days')",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(principal_id)
        .execute(database.pool())
        .await
        .is_err(),
        "PostgreSQL must reject credentials beyond the seven-day maximum lifetime"
    );
    let principal_key = [7_u8; 32];
    let source_key = [9_u8; 32];
    database
        .record_mount_authentication_failure(tenant_id, "ftps", &principal_key, &source_key)
        .await
        .expect("record first authentication failure");
    database
        .record_mount_authentication_failure(tenant_id, "ftps", &principal_key, &source_key)
        .await
        .expect("record exponential authentication delay");
    assert!(
        database
            .mount_authentication_throttled(tenant_id, "ftps", &principal_key, &source_key,)
            .await
            .expect("query authentication throttle")
    );
    database
        .clear_mount_authentication_failures(tenant_id, "ftps", &principal_key, &source_key)
        .await
        .expect("clear authentication throttle");
    assert!(
        !database
            .mount_authentication_throttled(tenant_id, "ftps", &principal_key, &source_key,)
            .await
            .expect("query cleared authentication throttle")
    );

    let nonce_digest = [11_u8; 32];
    database
        .consume_capability_nonce(tenant_id, &nonce_digest, "mount_read", 2_000_000_000)
        .await
        .expect("consume mount read nonce once");
    assert!(matches!(
        database
            .consume_capability_nonce(tenant_id, &nonce_digest, "mount_read", 2_000_000_000)
            .await,
        Err(filebelt_database::DatabaseError::Conflict)
    ));
}

async fn schema_privilege(database: &Database, role: &str, schema: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_schema_privilege($1,$2,$3)")
        .bind(role)
        .bind(schema)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("schema privilege query")
}

async fn table_privilege(database: &Database, role: &str, table: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1,$2,$3)")
        .bind(role)
        .bind(table)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("table privilege query")
}

async fn column_privilege(
    database: &Database,
    role: &str,
    table: &str,
    column: &str,
    privilege: &str,
) -> bool {
    sqlx::query_scalar("SELECT has_column_privilege($1,$2,$3,$4)")
        .bind(role)
        .bind(table)
        .bind(column)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("column privilege query")
}

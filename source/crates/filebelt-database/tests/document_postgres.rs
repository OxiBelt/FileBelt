// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed Phase 7 migration and least-privilege checks.

use filebelt_database::Database;

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_DOCUMENT_TEST_DATABASE_URL"]
async fn document_schema_migrates_and_exposes_only_narrow_role_authority() {
    let database_url = std::env::var("FILEBELT_DOCUMENT_TEST_DATABASE_URL")
        .expect("FILEBELT_DOCUMENT_TEST_DATABASE_URL is required");
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

    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=6 AND success)",
    )
    .fetch_one(database.pool())
    .await
    .expect("migration ledger");
    assert!(applied, "Phase 7 document migration must be applied");
    assert!(schema_privilege(&database, "filebelt_document", "filebelt_document", "USAGE").await);
    assert!(
        table_privilege(
            &database,
            "filebelt_document",
            "filebelt_document.revisions",
            "INSERT"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_document",
            "filebelt_document.create_session_principal(uuid,uuid)"
        )
        .await
    );
    for table in [
        "public.acl_entries",
        "public.direct_shares",
        "public.principals",
    ] {
        assert!(
            !table_privilege(&database, "filebelt_document", table, "INSERT").await,
            "document role must not insert {table}"
        );
    }
}

async fn schema_privilege(database: &Database, role: &str, schema: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_schema_privilege($1,$2,$3)")
        .bind(role)
        .bind(schema)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("schema privilege")
}
async fn table_privilege(database: &Database, role: &str, table: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1,$2,$3)")
        .bind(role)
        .bind(table)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("table privilege")
}
async fn function_privilege(database: &Database, role: &str, function: &str) -> bool {
    sqlx::query_scalar("SELECT has_function_privilege($1,$2,'EXECUTE')")
        .bind(role)
        .bind(function)
        .fetch_one(database.pool())
        .await
        .expect("function privilege")
}

// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed revision migration, compatibility, and authority checks.

use filebelt_database::{Database, DatabaseError};
use sqlx::Row as _;

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_REVISION_TEST_DATABASE_URL"]
async fn revision_schema_preserves_legacy_writers_and_narrows_role_authority() {
    let database_url = std::env::var("FILEBELT_REVISION_TEST_DATABASE_URL")
        .expect("FILEBELT_REVISION_TEST_DATABASE_URL is required");
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
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=16 AND success)",
    )
    .fetch_one(database.pool())
    .await
    .expect("migration ledger");
    assert!(applied, "revision migration must be applied");

    sqlx::raw_sql(
        r#"
        INSERT INTO tenants(id,slug)
        VALUES ('10000000-0000-4000-8000-000000000001','revision-test');
        INSERT INTO principals(tenant_id,id,kind)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000002','user');
        INSERT INTO users(tenant_id,id,principal_id,display_name)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000003',
                '10000000-0000-4000-8000-000000000002','Revision User');
        INSERT INTO user_preferences(tenant_id,user_id)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000003');
        INSERT INTO drives(tenant_id,id,owner_principal_id,kind,display_name,quota_bytes)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000004',
                '10000000-0000-4000-8000-000000000002','private','Revision',1073741824);
        INSERT INTO nodes(tenant_id,drive_id,id,kind,display_name,name_key,owner_principal_id)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000004',
                '10000000-0000-4000-8000-00000000000a','directory','','',
                '10000000-0000-4000-8000-000000000002');
        INSERT INTO nodes(tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000004',
                '10000000-0000-4000-8000-000000000005',
                '10000000-0000-4000-8000-00000000000a','file','note.txt','note.txt',
                '10000000-0000-4000-8000-000000000002');
        INSERT INTO storage_backends(tenant_id,id,kind)
        VALUES ('10000000-0000-4000-8000-000000000001',
                '10000000-0000-4000-8000-000000000006','posix');
        INSERT INTO payload_objects(
          tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3,finalized_at
        ) VALUES (
          '10000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000007',
          '10000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000006',
          '10000000-0000-4000-8000-000000000008','whole','referenced',4,
          decode(repeat('11',32),'hex'),clock_timestamp()
        );
        INSERT INTO file_versions(
          tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by
        ) VALUES (
          '10000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000005',
          '10000000-0000-4000-8000-000000000009',1,'10000000-0000-4000-8000-000000000007',
          4,decode(repeat('11',32),'hex'),'text/plain',
          '10000000-0000-4000-8000-000000000002'
        );
        "#,
    )
    .execute(database.pool())
    .await
    .expect("seed a post-migration legacy write");

    let row = sqlx::query(
        "SELECT v.content_id,c.backend,c.state,c.legacy_payload_id \
         FROM file_versions v JOIN filebelt_revision.contents c \
         ON c.tenant_id=v.tenant_id AND c.id=v.content_id \
         WHERE v.id='10000000-0000-4000-8000-000000000009'",
    )
    .fetch_one(database.pool())
    .await
    .expect("compatibility content projection");
    assert_eq!(row.get::<String, _>("backend"), "legacy_payload");
    assert_eq!(row.get::<String, _>("state"), "legacy");
    assert_eq!(
        row.get::<uuid::Uuid, _>("content_id"),
        uuid::Uuid::parse_str("10000000-0000-4000-8000-000000000009").unwrap()
    );

    sqlx::query(
        "UPDATE filebelt_revision.activation_state SET state='backfilling',source_revision='revision-test' WHERE tenant_id='10000000-0000-4000-8000-000000000001'",
    )
    .execute(database.pool())
    .await
    .expect("open revision backfill");
    let lease_owner = uuid::Uuid::new_v4();
    let lease = database
        .lease_revision_backfill(
            uuid::Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
            lease_owner,
            60,
        )
        .await
        .expect("lease query")
        .expect("legacy content lease");
    sqlx::query(
        "UPDATE filebelt_revision.backfill_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND content_id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .execute(database.pool())
    .await
    .expect("expire revision lease");
    assert!(matches!(
        database
            .hold_revision_backfill(
                lease.tenant_id,
                lease.content_id,
                lease.lease_owner,
                lease.fencing_token,
                "expired",
                "expired lease must not create a hold",
            )
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    assert!(matches!(
        database
            .reserve_revision_chunks(&lease, &[(vec![0x22; 32], 4)])
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    let holds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_revision.holds WHERE tenant_id=$1 AND content_id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .fetch_one(database.pool())
    .await
    .expect("hold count");
    assert_eq!(holds, 0);
    let chunks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_revision.chunk_objects WHERE tenant_id=$1",
    )
    .bind(lease.tenant_id)
    .fetch_one(database.pool())
    .await
    .expect("chunk count");
    assert_eq!(chunks, 0);
    sqlx::query(
        "UPDATE filebelt_revision.backfill_jobs SET lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE tenant_id=$1 AND content_id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .execute(database.pool())
    .await
    .expect("renew revision lease for positive control");
    let reserved = database
        .reserve_revision_chunks(&lease, &[(vec![0x22; 32], 4)])
        .await
        .expect("unexpired lease may reserve chunks");
    assert_eq!(reserved.len(), 1);
    database
        .hold_revision_backfill(
            lease.tenant_id,
            lease.content_id,
            lease.lease_owner,
            lease.fencing_token,
            "operator_review",
            "valid lease hold",
        )
        .await
        .expect("unexpired lease may create a hold");
    sqlx::query("DELETE FROM filebelt_revision.chunk_objects WHERE tenant_id=$1")
        .bind(lease.tenant_id)
        .execute(database.pool())
        .await
        .expect("remove positive-control staging chunk");
    sqlx::query("DELETE FROM filebelt_revision.holds WHERE tenant_id=$1 AND content_id=$2")
        .bind(lease.tenant_id)
        .bind(lease.content_id)
        .execute(database.pool())
        .await
        .expect("remove positive-control hold");
    sqlx::query(
        "UPDATE filebelt_revision.backfill_jobs SET state='pending',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND content_id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .execute(database.pool())
    .await
    .expect("restore pending backfill");

    sqlx::query(
        "UPDATE filebelt_revision.contents SET backend='git_sha256',observed_class='text',state='referenced',legacy_payload_id=NULL WHERE tenant_id=$1 AND id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .execute(database.pool())
    .await
    .expect("legacy to referenced remains valid");
    for prohibited_state in ["staging", "held"] {
        let error = sqlx::query(
            "UPDATE filebelt_revision.contents SET state=$3 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(lease.tenant_id)
        .bind(lease.content_id)
        .bind(prohibited_state)
        .execute(database.pool())
        .await
        .expect_err("referenced content cannot leave the terminal state set");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .as_deref(),
            Some("55000")
        );
    }
    sqlx::query(
        "UPDATE filebelt_revision.contents SET state='quarantined' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .execute(database.pool())
    .await
    .expect("referenced content may be quarantined");
    let error = sqlx::query(
        "UPDATE filebelt_revision.contents SET state='referenced' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(lease.tenant_id)
    .bind(lease.content_id)
    .execute(database.pool())
    .await
    .expect_err("quarantined content is terminal");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref(),
        Some("55000")
    );

    assert!(schema_privilege(&database, "filebelt_revision", "filebelt_revision", "USAGE").await);
    assert!(
        table_privilege(
            &database,
            "filebelt_revision",
            "filebelt_revision.chunk_objects",
            "INSERT"
        )
        .await
    );
    assert!(
        !table_privilege(
            &database,
            "filebelt_revision",
            "public.api_sessions",
            "UPDATE"
        )
        .await
    );
    assert!(!schema_privilege(&database, "filebelt_io", "filebelt_revision", "USAGE").await);
    for table in [
        "contents",
        "git_repositories",
        "git_revisions",
        "chunk_objects",
        "chunk_manifests",
        "chunk_members",
        "operations",
        "backfill_jobs",
        "holds",
        "activation_state",
    ] {
        for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            assert!(
                !table_privilege(
                    &database,
                    "filebelt_io",
                    &format!("filebelt_revision.{table}"),
                    privilege,
                )
                .await,
                "I/O unexpectedly has {privilege} on {table}"
            );
        }
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

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
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=10 AND success)",
    )
    .fetch_one(database.pool())
    .await
    .expect("migration ledger");
    assert!(
        applied,
        "document origin-isolation migration must be applied"
    );
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

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_DOCUMENT_CUTOVER_TEST_DATABASE_URL"]
async fn origin_isolation_cutover_revokes_exact_sessions_and_preserves_revisions() {
    let database_url = std::env::var("FILEBELT_DOCUMENT_CUTOVER_TEST_DATABASE_URL")
        .expect("FILEBELT_DOCUMENT_CUTOVER_TEST_DATABASE_URL is required");
    let database = Database::connect(&database_url, 2)
        .await
        .expect("connect cutover test database");
    sqlx::raw_sql(include_str!("../../../migrations/postgres/roles.sql"))
        .execute(database.pool())
        .await
        .expect("apply roles");
    database.migrate().await.expect("apply migrations");

    sqlx::raw_sql(
        r#"
        DELETE FROM filebelt_document.data_migrations
        WHERE name='onlyoffice_origin_isolation_v1';

        INSERT INTO tenants (id,slug)
        VALUES ('00000000-0000-4000-8000-000000000001','cutover-test');
        INSERT INTO principals (tenant_id,id,kind) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','user'),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000004','document_session'),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000005','document_session');
        INSERT INTO users (tenant_id,id,principal_id,display_name) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000003',
           '00000000-0000-4000-8000-000000000002','Cutover User');
        INSERT INTO drives (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000006',
           '00000000-0000-4000-8000-000000000002','private','Cutover',1073741824);
        INSERT INTO nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000006',
           '00000000-0000-4000-8000-000000000007',NULL,'directory','',''),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000006',
           '00000000-0000-4000-8000-000000000008','00000000-0000-4000-8000-000000000007',
           'file','document.docx','document.docx');
        INSERT INTO storage_backends (tenant_id,id,kind) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000009','posix');
        INSERT INTO payload_objects
          (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3,finalized_at)
        VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-00000000000a',
           '00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000009',
           '00000000-0000-4000-8000-00000000001a','whole','referenced',10,
           decode(repeat('01',32),'hex'),clock_timestamp());
        INSERT INTO file_versions
          (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by)
        VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000008',
           '00000000-0000-4000-8000-00000000000b',1,'00000000-0000-4000-8000-00000000000a',
           10,decode(repeat('01',32),'hex'),
           'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
           '00000000-0000-4000-8000-000000000002');
        UPDATE nodes SET head_version_id='00000000-0000-4000-8000-00000000000b'
        WHERE tenant_id='00000000-0000-4000-8000-000000000001'
          AND drive_id='00000000-0000-4000-8000-000000000006'
          AND id='00000000-0000-4000-8000-000000000008';

        INSERT INTO api_sessions
          (tenant_id,id,user_id,principal_id,token_key_generation,token_digest,csrf_digest,
           idle_expires_at,absolute_expires_at,revoked_at) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-00000000000c',
           '00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000002',
           1,decode('01','hex'),decode('11','hex'),clock_timestamp()+interval '1 hour',
           clock_timestamp()+interval '2 hours',NULL),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-00000000000d',
           '00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000002',
           1,decode('02','hex'),decode('12','hex'),clock_timestamp()+interval '1 hour',
           clock_timestamp()+interval '2 hours',NULL),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-00000000000e',
           '00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000002',
           1,decode('03','hex'),decode('13','hex'),clock_timestamp()-interval '2 hours',
           clock_timestamp()-interval '1 hour',NULL);

        INSERT INTO filebelt_document.sessions
          (tenant_id,id,session_principal_id,drive_id,node_id,provider_id,base_version_id,
           expected_head_version_id,state,created_by) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-00000000000f',
           '00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000006',
           '00000000-0000-4000-8000-000000000008','onlyoffice-community-9-4-secondary',
           '00000000-0000-4000-8000-00000000000b','00000000-0000-4000-8000-00000000000b',
           'active','00000000-0000-4000-8000-000000000002'),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000010',
           '00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000006',
           '00000000-0000-4000-8000-000000000008','onlyoffice-community-9-4',
           '00000000-0000-4000-8000-00000000000b','00000000-0000-4000-8000-00000000000b',
           'draining','00000000-0000-4000-8000-000000000002');
        INSERT INTO filebelt_document.participants
          (tenant_id,id,document_session_id,user_principal_id,api_session_id,mode,state,
           membership_generation,drive_acl_generation,namespace_generation,resource_acl_generation,
           closed_at,close_reason) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011',
           '00000000-0000-4000-8000-00000000000f','00000000-0000-4000-8000-000000000002',
           '00000000-0000-4000-8000-00000000000c','edit','closed',1,1,1,1,
           clock_timestamp(),'user_closed'),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000012',
           '00000000-0000-4000-8000-00000000000f','00000000-0000-4000-8000-000000000002',
           '00000000-0000-4000-8000-00000000000e','edit','active',1,1,1,1,NULL,NULL),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000013',
           '00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000002',
           '00000000-0000-4000-8000-00000000000e','view','active',1,1,1,1,NULL,NULL);
        INSERT INTO filebelt_document.launch_grants
          (tenant_id,id,participant_id,token_digest,expires_at) VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000014',
           '00000000-0000-4000-8000-000000000012',decode(repeat('21',32),'hex'),
           clock_timestamp()+interval '30 seconds'),
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000015',
           '00000000-0000-4000-8000-000000000013',decode(repeat('22',32),'hex'),
           clock_timestamp()+interval '30 seconds');
        INSERT INTO filebelt_document.revisions
          (tenant_id,id,document_session_id,actor_participant_id,provider_event_digest,kind,state,
           expected_head_version_id,payload_id,reserved_bytes,size_bytes,blake3,media_type,staged_at)
        VALUES
          ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000016',
           '00000000-0000-4000-8000-00000000000f','00000000-0000-4000-8000-000000000012',
           decode(repeat('31',32),'hex'),'checkpoint','staged',
           '00000000-0000-4000-8000-00000000000b','00000000-0000-4000-8000-00000000000a',
           0,10,decode(repeat('01',32),'hex'),
           'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
           clock_timestamp());
        INSERT INTO filebelt_document.reconciliation_jobs (tenant_id,revision_id)
        VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000016');
        "#,
    )
    .execute(database.pool())
    .await
    .expect("seed cutover state");

    sqlx::raw_sql(include_str!(
        "../../../migrations/postgres/000010_onlyoffice_origin_isolation.sql"
    ))
    .execute(database.pool())
    .await
    .expect("apply origin-isolation cutover");

    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM api_sessions WHERE id='00000000-0000-4000-8000-00000000000c'",
    )
    .fetch_one(database.pool())
    .await
    .expect("linked session state");
    let unrelated_revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM api_sessions WHERE id='00000000-0000-4000-8000-00000000000d'",
    )
    .fetch_one(database.pool())
    .await
    .expect("unrelated session state");
    let expired_revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM api_sessions WHERE id='00000000-0000-4000-8000-00000000000e'",
    )
    .fetch_one(database.pool())
    .await
    .expect("expired session state");
    assert!(revoked);
    assert!(!unrelated_revoked);
    assert!(!expired_revoked);

    let closed_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_document.sessions WHERE state='revoked' AND fencing_token=2 AND close_reason='onlyoffice_origin_isolation_cutover'",
    )
    .fetch_one(database.pool())
    .await
    .expect("closed document sessions");
    let closed_participants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_document.participants WHERE id IN ('00000000-0000-4000-8000-000000000012','00000000-0000-4000-8000-000000000013') AND state='closed' AND close_reason='onlyoffice_origin_isolation_cutover'",
    )
    .fetch_one(database.pool())
    .await
    .expect("closed participants");
    let consumed_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_document.launch_grants WHERE consumed_at IS NOT NULL",
    )
    .fetch_one(database.pool())
    .await
    .expect("consumed grants");
    assert_eq!(closed_sessions, 2);
    assert_eq!(closed_participants, 2);
    assert_eq!(consumed_grants, 2);

    let revision_state: String = sqlx::query_scalar(
        "SELECT state FROM filebelt_document.revisions WHERE id='00000000-0000-4000-8000-000000000016'",
    )
    .fetch_one(database.pool())
    .await
    .expect("preserved revision");
    let reconciliation_state: String = sqlx::query_scalar(
        "SELECT state FROM filebelt_document.reconciliation_jobs WHERE revision_id='00000000-0000-4000-8000-000000000016'",
    )
    .fetch_one(database.pool())
    .await
    .expect("preserved reconciliation job");
    assert_eq!(revision_state, "staged");
    assert_eq!(reconciliation_state, "queued");

    let receipt: i64 = sqlx::query_scalar(
        "SELECT affected_resources FROM filebelt_document.data_migrations WHERE name='onlyoffice_origin_isolation_v1'",
    )
    .fetch_one(database.pool())
    .await
    .expect("cutover receipt");
    let session_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action='session.revoke' AND reason_code='onlyoffice_origin_isolation_cutover'",
    )
    .fetch_one(database.pool())
    .await
    .expect("session revocation audit");
    let document_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action='document.session.force_close' AND reason_code='onlyoffice_origin_isolation_cutover'",
    )
    .fetch_one(database.pool())
    .await
    .expect("document close audit");
    assert_eq!(receipt, 2);
    assert_eq!(session_audits, 1);
    assert_eq!(document_audits, 2);
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

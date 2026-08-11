// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed descendant-share cutover contract checks.

use filebelt_database::Database;
use filebelt_events_protocol::EventEnvelope;
use prost::Message as _;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_DESCENDANT_SHARE_SECURITY_TEST_DATABASE_URL"]
async fn descendant_share_cutover_revokes_legacy_rows_and_opens_only_after_verification() {
    let database_url = std::env::var("FILEBELT_DESCENDANT_SHARE_SECURITY_TEST_DATABASE_URL")
        .expect("FILEBELT_DESCENDANT_SHARE_SECURITY_TEST_DATABASE_URL is required");
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

    let tenant_id = id(1);
    let actor_id = id(2);
    let target_id = id(3);
    let user_id = id(4);
    let identity_id = id(5);
    let drive_id = id(6);
    let root_id = id(7);
    let file_id = id(8);
    let backend_id = id(9);
    let payload_id = id(10);
    let version_id = id(11);
    let registration_id = id(12);
    let legacy_share_id = id(13);
    let legacy_acl_id = id(14);
    let legacy_grant_id = id(15);
    let operation_id = id(16);

    seed_fixture(
        &database,
        tenant_id,
        actor_id,
        target_id,
        user_id,
        identity_id,
        drive_id,
        root_id,
        file_id,
        backend_id,
        payload_id,
        version_id,
        registration_id,
    )
    .await;

    assert_admission_blocked_for_raw_inserts(
        &database,
        tenant_id,
        actor_id,
        target_id,
        drive_id,
        root_id,
        file_id,
        version_id,
        registration_id,
    )
    .await;

    // The fixture is deliberately opened only long enough to create rows that
    // predate the final fence. Production rows exist before the migration;
    // this makes the same chronology explicit without weakening the test.
    sqlx::query(
        "UPDATE filebelt_security.tenant_descendant_share_admission \
         SET state='open',opened_by=$2,opened_at=clock_timestamp() WHERE tenant_id=$1",
    )
    .bind(tenant_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect("temporarily open fixture admission");
    insert_direct_share(
        &database,
        tenant_id,
        legacy_share_id,
        legacy_acl_id,
        actor_id,
        target_id,
        drive_id,
        root_id,
    )
    .await;
    sqlx::query(
        "UPDATE public.direct_shares SET authorization_model_version=NULL \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(legacy_share_id)
    .execute(database.pool())
    .await
    .expect("mark fixture share as legacy");
    insert_data_grant(
        &database,
        tenant_id,
        legacy_grant_id,
        actor_id,
        registration_id,
        drive_id,
        file_id,
        version_id,
        1,
    )
    .await;
    sqlx::query(
        "UPDATE filebelt_security.tenant_descendant_share_admission \
         SET state='blocked',fence_at=clock_timestamp(),active_repair_run_id=NULL, \
             opened_at=NULL,opened_by=NULL,generation=generation+1 WHERE tenant_id=$1",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("restore fixture fence");

    let before: (i64, i64) = sqlx::query_as(
        "SELECT d.acl_generation,n.acl_generation FROM public.drives d \
         JOIN public.nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id \
         WHERE d.tenant_id=$1 AND d.id=$2 AND n.id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_id)
    .fetch_one(database.pool())
    .await
    .expect("pre-repair generations");

    let first = repair(&database, tenant_id, operation_id, actor_id, 1).await;
    assert_eq!(
        first.get("selected").and_then(serde_json::Value::as_i64),
        Some(1)
    );
    assert_eq!(
        first.get("remaining").and_then(serde_json::Value::as_i64),
        Some(1)
    );
    let second = repair(&database, tenant_id, operation_id, actor_id, 1).await;
    assert_eq!(
        second.get("selected").and_then(serde_json::Value::as_i64),
        Some(1)
    );
    assert_eq!(
        second.get("remaining").and_then(serde_json::Value::as_i64),
        Some(0)
    );

    let direct: (bool, Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT revoked_at IS NOT NULL,revocation_reason,repair_run_id \
         FROM public.direct_shares WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(legacy_share_id)
    .fetch_one(database.pool())
    .await
    .expect("repaired direct share");
    assert_eq!(
        direct,
        (
            true,
            Some("security.descendant_attenuation_v1".into()),
            Some(operation_id)
        )
    );
    let grant: (bool, Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT revoked_at IS NOT NULL,revocation_reason,repair_run_id \
         FROM filebelt_mcp.data_grants WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(legacy_grant_id)
    .fetch_one(database.pool())
    .await
    .expect("repaired data grant");
    assert_eq!(
        grant,
        (
            true,
            Some("security.pre_fence_mcp_data_grant".into()),
            Some(operation_id)
        )
    );
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_security.descendant_share_repair_receipts \
         WHERE tenant_id=$1 AND run_id=$2",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .fetch_one(database.pool())
    .await
    .expect("repair receipts");
    assert_eq!(receipts, 2);
    let acl_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.acl_entries WHERE tenant_id=$1 AND direct_share_id=$2",
    )
    .bind(tenant_id)
    .bind(legacy_share_id)
    .fetch_one(database.pool())
    .await
    .expect("deleted direct-share ACL rows");
    assert_eq!(acl_rows, 0);

    let after: (i64, i64) = sqlx::query_as(
        "SELECT d.acl_generation,n.acl_generation FROM public.drives d \
         JOIN public.nodes n ON n.tenant_id=d.tenant_id AND n.drive_id=d.id \
         WHERE d.tenant_id=$1 AND d.id=$2 AND n.id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_id)
    .fetch_one(database.pool())
    .await
    .expect("post-repair generations");
    assert!(after.0 > before.0 && after.1 > before.1);
    let payload: Vec<u8> = sqlx::query_scalar(
        "SELECT payload FROM public.outbox_events \
         WHERE tenant_id=$1 AND topic='filebelt.v1.acl.changed' AND aggregate_id=$2 \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(root_id)
    .fetch_one(database.pool())
    .await
    .expect("repair ACL outbox event");
    let envelope = EventEnvelope::decode(payload.as_slice()).expect("canonical EventEnvelope");
    assert_eq!(envelope.tenant_id, tenant_id.to_string());
    assert_eq!(envelope.aggregate_type, "node");
    assert_eq!(envelope.aggregate_id, root_id.to_string());
    assert_eq!(
        envelope.aggregate_generation,
        u64::try_from(after.1).expect("positive generation")
    );
    assert_eq!(envelope.event_type, "filebelt.v1.acl.changed");
    assert!(envelope.payload.is_empty());

    assert_source_revision_mismatch_rejected(&database, tenant_id, operation_id, actor_id).await;
    verify(&database, tenant_id, operation_id, actor_id).await;
    activate(&database, tenant_id, operation_id, actor_id).await;
    assert_snapshot_scopes_creator_facts(
        &database, tenant_id, actor_id, drive_id, root_id, file_id,
    )
    .await;

    let old_writer_error = sqlx::query(
        "INSERT INTO public.direct_shares \
         (tenant_id,id,drive_id,resource_id,target_principal_id,preset,inheritance,created_by) \
         VALUES ($1,$2,$3,$4,$5,'viewer','self_and_descendants',$6)",
    )
    .bind(tenant_id)
    .bind(id(103))
    .bind(drive_id)
    .bind(root_id)
    .bind(target_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect_err("old direct-share writer after activation");
    assert_fb001_message(
        old_writer_error,
        "filebelt descendant-share authorization model is incompatible",
    );

    insert_direct_share(
        &database,
        tenant_id,
        id(17),
        id(18),
        actor_id,
        target_id,
        drive_id,
        root_id,
    )
    .await;
    let current_drive_acl_generation: i64 =
        sqlx::query_scalar("SELECT acl_generation FROM public.drives WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(drive_id)
            .fetch_one(database.pool())
            .await
            .expect("current drive ACL generation after direct-share ACL");
    insert_data_grant(
        &database,
        tenant_id,
        id(19),
        actor_id,
        registration_id,
        drive_id,
        file_id,
        version_id,
        current_drive_acl_generation,
    )
    .await;
    let before_user_status_fanout: i64 =
        sqlx::query_scalar("SELECT acl_generation FROM public.drives WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(drive_id)
            .fetch_one(database.pool())
            .await
            .expect("generation before creator suspension");
    sqlx::query("UPDATE public.users SET status='suspended' WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(user_id)
        .execute(database.pool())
        .await
        .expect("suspend direct-share creator");
    let after_user_status_fanout: i64 =
        sqlx::query_scalar("SELECT acl_generation FROM public.drives WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(drive_id)
            .fetch_one(database.pool())
            .await
            .expect("generation after creator suspension");
    assert_eq!(after_user_status_fanout, before_user_status_fanout + 1);
}

#[allow(clippy::too_many_arguments)]
async fn seed_fixture(
    database: &Database,
    tenant_id: Uuid,
    actor_id: Uuid,
    target_id: Uuid,
    user_id: Uuid,
    identity_id: Uuid,
    drive_id: Uuid,
    root_id: Uuid,
    file_id: Uuid,
    backend_id: Uuid,
    payload_id: Uuid,
    version_id: Uuid,
    registration_id: Uuid,
) {
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'descendant-security-test')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("tenant");
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user'),($1,$3,'user')",
    )
    .bind(tenant_id)
    .bind(actor_id)
    .bind(target_id)
    .execute(database.pool())
    .await
    .expect("principals");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) VALUES ($1,$2,$3,'Operator')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect("operator user");
    sqlx::query(
        "INSERT INTO public.external_identities (tenant_id,id,user_id,issuer,subject) \
         VALUES ($1,$2,$3,'https://issuer.example.test','operator')",
    )
    .bind(tenant_id)
    .bind(identity_id)
    .bind(user_id)
    .execute(database.pool())
    .await
    .expect("operator identity");
    sqlx::query(
        "INSERT INTO public.tenant_admin_bindings (tenant_id,issuer,subject) \
         VALUES ($1,'https://issuer.example.test','operator')",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("live tenant administrator");
    sqlx::query(
        "INSERT INTO public.drives (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) \
         VALUES ($1,$2,$3,'private','Security test',1073741824)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect("drive");
    sqlx::query(
        "INSERT INTO public.nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES \
         ($1,$2,$3,NULL,'directory','',''),($1,$2,$4,$3,'file','source.txt','source.txt')",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_id)
    .bind(file_id)
    .execute(database.pool())
    .await
    .expect("nodes");
    sqlx::query(
        "INSERT INTO public.node_ancestry \
         (tenant_id,drive_id,ancestor_id,descendant_id,depth) VALUES \
         ($1,$2,$3,$3,0),($1,$2,$3,$4,1),($1,$2,$4,$4,0)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_id)
    .bind(file_id)
    .execute(database.pool())
    .await
    .expect("node ancestry");
    sqlx::query("INSERT INTO public.storage_backends (tenant_id,id) VALUES ($1,$2)")
        .bind(tenant_id)
        .bind(backend_id)
        .execute(database.pool())
        .await
        .expect("backend");
    sqlx::query(
        "INSERT INTO public.payload_objects \
         (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3) \
         VALUES ($1,$2,$3,$4,$5,'whole','referenced',3,$6)",
    )
    .bind(tenant_id)
    .bind(payload_id)
    .bind(drive_id)
    .bind(backend_id)
    .bind(id(20))
    .bind(vec![7_u8; 32])
    .execute(database.pool())
    .await
    .expect("payload");
    sqlx::query(
        "INSERT INTO public.file_versions \
         (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,created_by) \
         VALUES ($1,$2,$3,1,$4,3,$5,$6)",
    )
    .bind(tenant_id)
    .bind(file_id)
    .bind(version_id)
    .bind(payload_id)
    .bind(vec![7_u8; 32])
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect("version");
    sqlx::query(
        "UPDATE public.nodes SET head_version_id=$4 \
         WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(file_id)
    .bind(version_id)
    .execute(database.pool())
    .await
    .expect("head version");
    sqlx::query(
        "INSERT INTO filebelt_mcp.registrations \
         (tenant_id,id,owner_principal_id,owner_kind,source_kind,display_name,transport,endpoint_uri) \
         VALUES ($1,$2,$3,'user','personal','Security test MCP','streamable_http','https://mcp.example.test/rpc')",
    )
    .bind(tenant_id)
    .bind(registration_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect("MCP registration");
}

#[allow(clippy::too_many_arguments)]
async fn assert_admission_blocked_for_raw_inserts(
    database: &Database,
    tenant_id: Uuid,
    actor_id: Uuid,
    target_id: Uuid,
    drive_id: Uuid,
    root_id: Uuid,
    file_id: Uuid,
    version_id: Uuid,
    registration_id: Uuid,
) {
    let direct_error = sqlx::query(
        "INSERT INTO public.direct_shares \
         (tenant_id,id,drive_id,resource_id,target_principal_id,preset,inheritance,created_by,authorization_model_version) \
         VALUES ($1,$2,$3,$4,$5,'viewer','self_and_descendants',$6,1)",
    )
    .bind(tenant_id)
    .bind(id(101))
    .bind(drive_id)
    .bind(root_id)
    .bind(target_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect_err("blocked direct share insert");
    assert_fb001(direct_error);

    let grant_error = raw_data_grant_query(
        tenant_id,
        id(102),
        actor_id,
        registration_id,
        drive_id,
        file_id,
        version_id,
        1,
    )
    .execute(database.pool())
    .await
    .expect_err("blocked MCP data-grant insert");
    assert_fb001(grant_error);
}

#[allow(clippy::too_many_arguments)]
async fn insert_direct_share(
    database: &Database,
    tenant_id: Uuid,
    share_id: Uuid,
    acl_id: Uuid,
    actor_id: Uuid,
    target_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
) {
    sqlx::query(
        "INSERT INTO public.direct_shares \
         (tenant_id,id,drive_id,resource_id,target_principal_id,preset,inheritance,created_by,authorization_model_version) \
         VALUES ($1,$2,$3,$4,$5,'viewer','self_and_descendants',$6,1)",
    )
    .bind(tenant_id)
    .bind(share_id)
    .bind(drive_id)
    .bind(resource_id)
    .bind(target_id)
    .bind(actor_id)
    .execute(database.pool())
    .await
    .expect("direct share");
    sqlx::query(
        "INSERT INTO public.acl_entries \
         (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation,direct_share_id) \
         VALUES ($1,$2,$3,$4,$5,'READ_METADATA','allow','self_and_descendants',$6,1,$7)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(resource_id)
    .bind(acl_id)
    .bind(target_id)
    .bind(actor_id)
    .bind(share_id)
    .execute(database.pool())
    .await
    .expect("direct-share ACL row");
}

#[allow(clippy::too_many_arguments)]
async fn insert_data_grant(
    database: &Database,
    tenant_id: Uuid,
    grant_id: Uuid,
    actor_id: Uuid,
    registration_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    version_id: Uuid,
    drive_acl_generation: i64,
) {
    raw_data_grant_query(
        tenant_id,
        grant_id,
        actor_id,
        registration_id,
        drive_id,
        resource_id,
        version_id,
        drive_acl_generation,
    )
    .execute(database.pool())
    .await
    .expect("MCP data grant");
}

async fn assert_snapshot_scopes_creator_facts(
    database: &Database,
    tenant_id: Uuid,
    owner_id: Uuid,
    drive_id: Uuid,
    root_id: Uuid,
    child_id: Uuid,
) {
    let manager_id = id(30);
    let recipient_id = id(31);
    let manager_share_id = id(32);
    let recipient_share_id = id(33);
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) \
         VALUES ($1,$2,'user'),($1,$3,'user')",
    )
    .bind(tenant_id)
    .bind(manager_id)
    .bind(recipient_id)
    .execute(database.pool())
    .await
    .expect("snapshot principals");
    sqlx::query(
        "INSERT INTO public.direct_shares \
         (tenant_id,id,drive_id,resource_id,target_principal_id,preset,inheritance,created_by,authorization_model_version) \
         VALUES ($1,$2,$3,$4,$5,'manager','self',$6,1), \
                ($1,$7,$3,$4,$8,'viewer','self_and_descendants',$5,1)",
    )
    .bind(tenant_id)
    .bind(manager_share_id)
    .bind(drive_id)
    .bind(root_id)
    .bind(manager_id)
    .bind(owner_id)
    .bind(recipient_share_id)
    .bind(recipient_id)
    .execute(database.pool())
    .await
    .expect("snapshot direct shares");
    sqlx::query(
        "INSERT INTO public.acl_entries \
         (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation,direct_share_id) \
         VALUES ($1,$2,$3,$4,$5,'SHARE','allow','self',$6,1,$7), \
                ($1,$2,$3,$8,$5,'READ_METADATA','allow','self',$6,1,$7), \
                ($1,$2,$3,$9,$10,'READ_METADATA','allow','self_and_descendants',$5,1,$11)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_id)
    .bind(id(34))
    .bind(manager_id)
    .bind(owner_id)
    .bind(manager_share_id)
    .bind(id(35))
    .bind(id(36))
    .bind(recipient_id)
    .bind(recipient_share_id)
    .execute(database.pool())
    .await
    .expect("snapshot ACL rows");

    let root = database
        .authorization_snapshot(tenant_id, recipient_id, drive_id, root_id)
        .await
        .expect("root authorization snapshot");
    assert!(
        root.entries.iter().any(|entry| {
            entry.principal_id == recipient_id
                && entry.action == "READ_METADATA"
                && entry.direct
                && entry.direct_share_active
        }),
        "root snapshot: {root:#?}"
    );
    let root_manager = root
        .creator_facts
        .iter()
        .find(|facts| facts.principal_id == manager_id)
        .expect("manager facts at root");
    assert!(
        root_manager
            .entries
            .iter()
            .any(|entry| entry.action == "SHARE")
    );
    assert!(
        root_manager
            .entries
            .iter()
            .any(|entry| entry.action == "READ_METADATA")
    );

    let child = database
        .authorization_snapshot(tenant_id, recipient_id, drive_id, child_id)
        .await
        .expect("child authorization snapshot");
    assert!(
        child.entries.iter().any(|entry| {
            entry.principal_id == recipient_id
                && entry.action == "READ_METADATA"
                && !entry.direct
                && entry.direct_share_active
        }),
        "child snapshot: {child:#?}"
    );
    let child_manager = child
        .creator_facts
        .iter()
        .find(|facts| facts.principal_id == manager_id)
        .expect("manager facts at child");
    assert!(child_manager.entries.is_empty());
}

#[allow(clippy::too_many_arguments)]
fn raw_data_grant_query<'q>(
    tenant_id: Uuid,
    grant_id: Uuid,
    actor_id: Uuid,
    registration_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    version_id: Uuid,
    drive_acl_generation: i64,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "INSERT INTO filebelt_mcp.data_grants \
         (tenant_id,id,principal_id,registration_id,drive_id,resource_id,version_id,allow_metadata,allow_content, \
          drive_acl_generation,acl_generation,namespace_generation,registration_generation,created_by,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,true,true,$8,1,1,1,$3,clock_timestamp()+interval '5 minutes')",
    )
    .bind(tenant_id)
    .bind(grant_id)
    .bind(actor_id)
    .bind(registration_id)
    .bind(drive_id)
    .bind(resource_id)
    .bind(version_id)
    .bind(drive_acl_generation)
}

async fn repair(
    database: &Database,
    tenant_id: Uuid,
    operation_id: Uuid,
    actor_id: Uuid,
    limit: i32,
) -> serde_json::Value {
    let mut transaction = database.pool().begin().await.expect("repair transaction");
    bind_source_revision(&mut transaction).await;
    let value = sqlx::query_scalar(
        "SELECT filebelt_security.repair_descendant_shares($1,$2,'descendant-security-test',$3,$4)",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .bind(actor_id)
    .bind(limit)
    .fetch_one(&mut *transaction)
    .await
    .expect("repair batch");
    transaction.commit().await.expect("commit repair batch");
    value
}

async fn assert_source_revision_mismatch_rejected(
    database: &Database,
    tenant_id: Uuid,
    operation_id: Uuid,
    actor_id: Uuid,
) {
    let mut transaction = database
        .pool()
        .begin()
        .await
        .expect("revision-mismatch transaction");
    sqlx::query_scalar::<_, String>(
        "SELECT set_config('filebelt.source_revision','different-test-revision',true)",
    )
    .fetch_one(&mut *transaction)
    .await
    .expect("set mismatched source revision");
    let error = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT filebelt_security.verify_descendant_shares($1,$2,'descendant-security-test',$3)",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .bind(actor_id)
    .fetch_one(&mut *transaction)
    .await
    .expect_err("different source revision must not resume the operation");
    assert!(error.as_database_error().is_some());
    transaction
        .rollback()
        .await
        .expect("rollback revision mismatch");
}

async fn verify(database: &Database, tenant_id: Uuid, operation_id: Uuid, actor_id: Uuid) {
    let mut transaction = database.pool().begin().await.expect("verify transaction");
    bind_source_revision(&mut transaction).await;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT (filebelt_security.verify_descendant_shares($1,$2,'descendant-security-test',$3)->>'remaining')::bigint",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .bind(actor_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("verify cutover");
    assert_eq!(remaining, 0);
    transaction.commit().await.expect("commit verification");
}

async fn activate(database: &Database, tenant_id: Uuid, operation_id: Uuid, actor_id: Uuid) {
    let mut transaction = database.pool().begin().await.expect("activate transaction");
    bind_source_revision(&mut transaction).await;
    let opened: bool = sqlx::query_scalar(
        "SELECT (filebelt_security.activate_descendant_shares($1,$2,'descendant-security-test',$3)->>'admission_open')::boolean",
    )
    .bind(tenant_id)
    .bind(operation_id)
    .bind(actor_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("activate cutover");
    assert!(opened);
    transaction.commit().await.expect("commit activation");
}

async fn bind_source_revision(transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>) {
    sqlx::query_scalar::<_, String>(
        "SELECT set_config('filebelt.source_revision','test-revision',true)",
    )
    .fetch_one(&mut **transaction)
    .await
    .expect("set source revision");
}

fn assert_fb001(error: sqlx::Error) {
    assert_fb001_message(error, "filebelt descendant-share admission is blocked");
}

fn assert_fb001_message(error: sqlx::Error, expected_message: &str) {
    let database = error
        .as_database_error()
        .expect("PostgreSQL database error");
    assert_eq!(database.code().as_deref(), Some("FB001"));
    assert_eq!(database.message(), expected_message);
}

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

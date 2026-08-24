// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed first-room convergence checks for collaboration grants.

use std::sync::Arc;

use filebelt_database::collaboration::CollaborationJoinGrantInput;
use filebelt_database::{
    Database, DatabaseError, ResourceMutationIdempotency, ResourceMutationWrite,
};
use serde_json::json;
use tokio::sync::Barrier;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_COLLABORATION_TEST_DATABASE_URL"]
async fn concurrent_first_room_grants_converge_without_leaving_pending_receipts() {
    let database_url = std::env::var("FILEBELT_COLLABORATION_TEST_DATABASE_URL")
        .expect("FILEBELT_COLLABORATION_TEST_DATABASE_URL is required");
    let database = Database::connect(&database_url, 4)
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
    install_first_room_insert_barrier(&database).await;

    let tenant_id = Uuid::new_v4();
    let caller_one = Caller::new();
    let caller_two = Caller::new();
    let drive_id = Uuid::new_v4();
    let root_id = Uuid::new_v4();
    let node_id = Uuid::new_v4();
    let backend_id = Uuid::new_v4();
    let payload_id = Uuid::new_v4();
    let base_version_id = Uuid::new_v4();
    seed_collaboration_target(
        &database,
        tenant_id,
        &caller_one,
        &caller_two,
        drive_id,
        root_id,
        node_id,
        backend_id,
        payload_id,
        base_version_id,
    )
    .await;

    let barrier = Arc::new(Barrier::new(2));
    let (first, second) = tokio::join!(
        create_first_room_grant(
            &database,
            barrier.clone(),
            tenant_id,
            drive_id,
            node_id,
            base_version_id,
            caller_one,
            "concurrent-first-room-one",
            [0x11; 32],
        ),
        create_first_room_grant(
            &database,
            barrier,
            tenant_id,
            drive_id,
            node_id,
            base_version_id,
            caller_two,
            "concurrent-first-room-two",
            [0x22; 32],
        ),
    );
    let first = first.expect("first concurrent grant");
    let second = second.expect("second concurrent grant");

    let attempted_inserts: i64 =
        sqlx::query_scalar("SELECT last_value FROM public.collaboration_test_room_insert_sequence")
            .fetch_one(database.pool())
            .await
            .expect("both callers reached the room insert");
    assert_eq!(attempted_inserts, 2);

    assert_eq!(first.room_id, second.room_id);
    assert_eq!(first.epoch, second.epoch);
    assert_eq!(first.epoch, 1);
    assert_ne!(first.grant_id, second.grant_id);

    let (room_count, current_epoch, epoch_count, grant_count, completed_receipts, pending_receipts): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM filebelt_collaboration.rooms \
            WHERE tenant_id=$1 AND drive_id=$2 AND node_id=$3), \
           (SELECT current_epoch FROM filebelt_collaboration.rooms \
            WHERE tenant_id=$1 AND id=$4), \
           (SELECT count(*) FROM filebelt_collaboration.epochs \
            WHERE tenant_id=$1 AND room_id=$4 AND epoch=1 AND base_version_id=$5), \
           (SELECT count(*) FROM filebelt_collaboration.join_grants \
            WHERE tenant_id=$1 AND room_id=$4 AND epoch=1), \
           (SELECT count(*) FROM public.idempotency_records \
            WHERE tenant_id=$1 AND route=$6 AND key IN ($7,$8) AND response_status=201), \
           (SELECT count(*) FROM public.idempotency_records \
            WHERE tenant_id=$1 AND route=$6 AND key IN ($7,$8) AND response_status=102)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .bind(first.room_id)
    .bind(base_version_id)
    .bind("POST /api/v1/collaboration/rooms")
    .bind("concurrent-first-room-one")
    .bind("concurrent-first-room-two")
    .fetch_one(database.pool())
    .await
    .expect("converged room state");
    assert_eq!(room_count, 1);
    assert_eq!(current_epoch, 1);
    assert_eq!(epoch_count, 1);
    assert_eq!(grant_count, 2);
    assert_eq!(completed_receipts, 2);
    assert_eq!(pending_receipts, 0);

    verify_dirty_epoch_base_mismatch(
        &database,
        tenant_id,
        drive_id,
        node_id,
        base_version_id,
        first.room_id,
        payload_id,
        caller_one,
    )
    .await;
    remove_first_room_insert_barrier(&database).await;
}

#[derive(Clone, Copy)]
struct Caller {
    principal_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    client_id: Uuid,
}

impl Caller {
    fn new() -> Self {
        Self {
            principal_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
struct GrantResult {
    room_id: Uuid,
    epoch: i64,
    grant_id: Uuid,
}

#[allow(clippy::too_many_arguments)]
async fn create_first_room_grant(
    database: &Database,
    barrier: Arc<Barrier>,
    tenant_id: Uuid,
    drive_id: Uuid,
    node_id: Uuid,
    base_version_id: Uuid,
    caller: Caller,
    key: &str,
    request_fingerprint: [u8; 32],
) -> Result<GrantResult, DatabaseError> {
    barrier.wait().await;
    let token_digest = if request_fingerprint[0] == 0x11 {
        vec![0x31; 32]
    } else {
        vec![0x32; 32]
    };
    let idempotency = ResourceMutationIdempotency {
        principal_id: caller.principal_id,
        route: "POST /api/v1/collaboration/rooms",
        key,
        request_fingerprint: &request_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let write = database
        .collaboration_create_join_grant_idempotent(
            tenant_id,
            drive_id,
            node_id,
            base_version_id,
            caller.principal_id,
            &idempotency,
            |_room, _payload| {
                Ok((
                    CollaborationJoinGrantInput {
                        id: Uuid::new_v4(),
                        token_digest,
                        principal_id: caller.principal_id,
                        session_id: caller.session_id,
                        client_id: caller.client_id,
                        presence_mode: "pseudonym".to_owned(),
                        presence_label: "Concurrent caller".to_owned(),
                        resource_acl_generation: 1,
                        drive_acl_generation: 1,
                        membership_generation: 1,
                        namespace_generation: 1,
                        can_checkpoint: false,
                    },
                    (),
                ))
            },
            |room, grant, ()| {
                Ok(json!({
                    "room_id": room.room_id,
                    "epoch": room.epoch,
                    "grant_id": grant.id,
                }))
            },
        )
        .await?;
    let ResourceMutationWrite::Created(record) = write else {
        return Err(DatabaseError::InvalidPersistedValue);
    };
    Ok(GrantResult {
        room_id: serde_json::from_value(record.response_body["room_id"].clone())
            .map_err(|_| DatabaseError::InvalidPersistedValue)?,
        epoch: serde_json::from_value(record.response_body["epoch"].clone())
            .map_err(|_| DatabaseError::InvalidPersistedValue)?,
        grant_id: serde_json::from_value(record.response_body["grant_id"].clone())
            .map_err(|_| DatabaseError::InvalidPersistedValue)?,
    })
}

async fn install_first_room_insert_barrier(database: &Database) {
    sqlx::raw_sql(
        "CREATE SEQUENCE public.collaboration_test_room_insert_sequence CACHE 1;
         CREATE FUNCTION public.collaboration_test_wait_for_second_room_insert()
         RETURNS trigger
         LANGUAGE plpgsql
         AS $$
         DECLARE
           ordinal bigint;
           attempts integer := 0;
         BEGIN
           ordinal := nextval('public.collaboration_test_room_insert_sequence');
           IF ordinal = 1 THEN
             WHILE (SELECT last_value FROM public.collaboration_test_room_insert_sequence) < 2 LOOP
               IF attempts >= 500 THEN
                 RAISE EXCEPTION 'timed out waiting for second collaboration room insert';
               END IF;
               PERFORM pg_sleep(0.01);
               attempts := attempts + 1;
             END LOOP;
           END IF;
           RETURN NEW;
         END;
         $$;
         CREATE TRIGGER collaboration_test_wait_for_second_room_insert
         BEFORE INSERT ON filebelt_collaboration.rooms
         FOR EACH ROW
         EXECUTE FUNCTION public.collaboration_test_wait_for_second_room_insert();",
    )
    .execute(database.pool())
    .await
    .expect("install first-room insert barrier");
}

async fn remove_first_room_insert_barrier(database: &Database) {
    sqlx::raw_sql(
        "DROP TRIGGER collaboration_test_wait_for_second_room_insert
           ON filebelt_collaboration.rooms;
         DROP FUNCTION public.collaboration_test_wait_for_second_room_insert();
         DROP SEQUENCE public.collaboration_test_room_insert_sequence;",
    )
    .execute(database.pool())
    .await
    .expect("remove first-room insert barrier");
}

#[allow(clippy::too_many_arguments)]
async fn verify_dirty_epoch_base_mismatch(
    database: &Database,
    tenant_id: Uuid,
    drive_id: Uuid,
    node_id: Uuid,
    base_version_id: Uuid,
    room_id: Uuid,
    payload_id: Uuid,
    caller: Caller,
) {
    let replacement_base_version_id = Uuid::new_v4();
    sqlx::query("INSERT INTO file_versions (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by) VALUES ($1,$2,$3,2,$4,4,decode(repeat('33',32),'hex'),'text/markdown',$5)")
        .bind(tenant_id)
        .bind(node_id)
        .bind(replacement_base_version_id)
        .bind(payload_id)
        .bind(caller.principal_id)
        .execute(database.pool())
        .await
        .expect("replacement base version");
    sqlx::query("UPDATE nodes SET head_version_id=$4 WHERE tenant_id=$1 AND drive_id=$2 AND id=$3")
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(replacement_base_version_id)
        .execute(database.pool())
        .await
        .expect("advance external head");
    let marked_dirty = sqlx::query("UPDATE filebelt_collaboration.epochs SET dirty=true WHERE tenant_id=$1 AND room_id=$2 AND epoch=1 AND base_version_id=$3 AND state='active'")
        .bind(tenant_id)
        .bind(room_id)
        .bind(base_version_id)
        .execute(database.pool())
        .await
        .expect("mark active epoch dirty")
        .rows_affected();
    assert_eq!(marked_dirty, 1);

    let request_fingerprint = [0x44; 32];
    let idempotency = ResourceMutationIdempotency {
        principal_id: caller.principal_id,
        route: "POST /api/v1/collaboration/rooms",
        key: "dirty-base-mismatch",
        request_fingerprint: &request_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    assert!(matches!(
        database
            .collaboration_create_join_grant_idempotent(
                tenant_id,
                drive_id,
                node_id,
                replacement_base_version_id,
                caller.principal_id,
                &idempotency,
                |_, _| -> Result<(CollaborationJoinGrantInput, ()), DatabaseError> {
                    Err(DatabaseError::InvalidPersistedValue)
                },
                |_, _, _: ()| -> Result<serde_json::Value, DatabaseError> {
                    Err(DatabaseError::InvalidPersistedValue)
                },
            )
            .await,
        Err(DatabaseError::Conflict)
    ));

    let (state, dirty, freeze_reason, fencing_token): (String, bool, Option<String>, i64) =
        sqlx::query_as("SELECT state,dirty,freeze_reason,fencing_token FROM filebelt_collaboration.epochs WHERE tenant_id=$1 AND room_id=$2 AND epoch=1")
            .bind(tenant_id)
            .bind(room_id)
            .fetch_one(database.pool())
            .await
            .expect("frozen dirty epoch");
    assert_eq!(state, "frozen");
    assert!(dirty);
    assert_eq!(freeze_reason.as_deref(), Some("external_head"));
    assert_eq!(fencing_token, 2);
    let grant_count: i64 = sqlx::query_scalar("SELECT count(*) FROM filebelt_collaboration.join_grants WHERE tenant_id=$1 AND room_id=$2 AND epoch=1")
        .bind(tenant_id)
        .bind(room_id)
        .fetch_one(database.pool())
        .await
        .expect("unchanged join grants");
    assert_eq!(grant_count, 2);
    let receipt_count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4")
        .bind(tenant_id)
        .bind(caller.principal_id)
        .bind("POST /api/v1/collaboration/rooms")
        .bind("dirty-base-mismatch")
        .fetch_one(database.pool())
        .await
        .expect("base mismatch receipt cleanup");
    assert_eq!(receipt_count, 0);
}

#[allow(clippy::too_many_arguments)]
async fn seed_collaboration_target(
    database: &Database,
    tenant_id: Uuid,
    caller_one: &Caller,
    caller_two: &Caller,
    drive_id: Uuid,
    root_id: Uuid,
    node_id: Uuid,
    backend_id: Uuid,
    payload_id: Uuid,
    base_version_id: Uuid,
) {
    sqlx::query("INSERT INTO tenants(id,slug) VALUES ($1,'collaboration-test')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("tenant");
    sqlx::query("INSERT INTO principals(tenant_id,id,kind) VALUES ($1,$2,'user'),($1,$3,'user')")
        .bind(tenant_id)
        .bind(caller_one.principal_id)
        .bind(caller_two.principal_id)
        .execute(database.pool())
        .await
        .expect("principals");
    sqlx::query("INSERT INTO users(tenant_id,id,principal_id,display_name) VALUES ($1,$2,$3,'Caller One'),($1,$4,$5,'Caller Two')")
        .bind(tenant_id)
        .bind(caller_one.user_id)
        .bind(caller_one.principal_id)
        .bind(caller_two.user_id)
        .bind(caller_two.principal_id)
        .execute(database.pool())
        .await
        .expect("users");
    sqlx::query("INSERT INTO api_sessions(tenant_id,id,user_id,principal_id,token_key_generation,token_digest,csrf_digest,idle_expires_at,absolute_expires_at) VALUES ($1,$2,$3,$4,1,decode(repeat('11',32),'hex'),decode(repeat('21',32),'hex'),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours'),($1,$5,$6,$7,1,decode(repeat('12',32),'hex'),decode(repeat('22',32),'hex'),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')")
        .bind(tenant_id)
        .bind(caller_one.session_id)
        .bind(caller_one.user_id)
        .bind(caller_one.principal_id)
        .bind(caller_two.session_id)
        .bind(caller_two.user_id)
        .bind(caller_two.principal_id)
        .execute(database.pool())
        .await
        .expect("sessions");
    sqlx::query("INSERT INTO drives(tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES ($1,$2,$3,'private','Collaboration',1073741824)")
        .bind(tenant_id)
        .bind(drive_id)
        .bind(caller_one.principal_id)
        .execute(database.pool())
        .await
        .expect("drive");
    sqlx::query("INSERT INTO nodes(tenant_id,drive_id,id,kind,display_name,name_key,owner_principal_id) VALUES ($1,$2,$3,'directory','','',$4)")
        .bind(tenant_id)
        .bind(drive_id)
        .bind(root_id)
        .bind(caller_one.principal_id)
        .execute(database.pool())
        .await
        .expect("root node");
    sqlx::query("INSERT INTO nodes(tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) VALUES ($1,$2,$3,$4,'file','note.md','note.md',$5)")
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(root_id)
        .bind(caller_one.principal_id)
        .execute(database.pool())
        .await
        .expect("file node");
    sqlx::query("INSERT INTO storage_backends(tenant_id,id,kind) VALUES ($1,$2,'posix')")
        .bind(tenant_id)
        .bind(backend_id)
        .execute(database.pool())
        .await
        .expect("storage backend");
    sqlx::query("INSERT INTO payload_objects(tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3,finalized_at) VALUES ($1,$2,$3,$4,$5,'whole','referenced',4,decode(repeat('33',32),'hex'),clock_timestamp())")
        .bind(tenant_id)
        .bind(payload_id)
        .bind(drive_id)
        .bind(backend_id)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await
        .expect("payload object");
    sqlx::query("INSERT INTO file_versions(tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by) VALUES ($1,$2,$3,1,$4,4,decode(repeat('33',32),'hex'),'text/markdown',$5)")
        .bind(tenant_id)
        .bind(node_id)
        .bind(base_version_id)
        .bind(payload_id)
        .bind(caller_one.principal_id)
        .execute(database.pool())
        .await
        .expect("base version");
}

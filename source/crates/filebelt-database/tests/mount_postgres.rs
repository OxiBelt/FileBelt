// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed mount schema and least-privilege contract checks.

use filebelt_database::mount::{
    ApplyNfsWriteExtentInput, BeginMountIoOperationInput, CommitNfsWriteInput,
    CreateNfsMappingProposalInput, CreateNfsMountSessionInput, EndNfsSessionInput,
    ExtendNfsWriteChunksInput, FinalizeNfsInternalIoReplayInput, MountIoAdmission,
    MountIoCompletion, MountIoLookup, MountIoOperation, MountWriteCapabilityFence,
    MountWriteChunkPlan, MountWriteRangeOperation, NfsAdminIdempotency, NfsAdminIdempotentWrite,
    NfsExportState, NfsFeatureState, NfsMountSessionProjection, NfsMutationAuthorization,
    NfsPrincipalMapping, NfsReplayContext, OpenNfsHandleInput, PendingMountIoWorkerState,
    PreauthorizeMountIoOperationInput, ReconcileNfsExportManifestInput,
    RecordNfsReplayReceiptInput, ReissueMountIoOperationInput, SeekNfsWriteExtentInput,
    UpsertNfsPrincipalMappingInput,
};
use filebelt_database::{Database, DatabaseError, IdempotencyRecord};
use serde_json::{Value, json};
use sqlx::ConnectOptions as _;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn mount_capability_expiry() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock is after the Unix epoch")
            .as_secs(),
    )
    .expect("wall clock fits in i64")
        + 10
}

async fn insert_fresh_test_api_session(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
) -> Uuid {
    let session_id = Uuid::new_v4();
    let user_id: Uuid =
        sqlx::query_scalar("SELECT id FROM public.users WHERE tenant_id=$1 AND principal_id=$2")
            .bind(tenant_id)
            .bind(principal_id)
            .fetch_one(database.pool())
            .await
            .expect("resolve NFS approval test user");
    sqlx::query(
        "INSERT INTO public.api_sessions \
         (tenant_id,id,user_id,principal_id,token_key_generation,token_digest,csrf_digest,\
          idle_expires_at,absolute_expires_at,reauthenticated_at) \
         VALUES ($1,$2,$3,$4,1,$5,$6,clock_timestamp()+interval '15 minutes',\
                 clock_timestamp()+interval '1 hour',clock_timestamp())",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(user_id)
    .bind(principal_id)
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .execute(database.pool())
    .await
    .expect("insert fresh NFS approval test session");
    session_id
}

#[allow(clippy::too_many_arguments)]
async fn approve_test_nfs_mapping(
    database: &Database,
    tenant_id: Uuid,
    proposer_principal_id: Uuid,
    target_principal_id: Uuid,
    kerberos_principal: &str,
    projected_uid: i64,
    projected_gid: i64,
    allowed_drive_ids: &[Uuid],
) -> NfsPrincipalMapping {
    let proposer_user_id: Uuid =
        sqlx::query_scalar("SELECT id FROM public.users WHERE tenant_id=$1 AND principal_id=$2")
            .bind(tenant_id)
            .bind(proposer_principal_id)
            .fetch_one(database.pool())
            .await
            .expect("resolve NFS proposal administrator");
    let existing_identity: Option<(String, String)> = sqlx::query_as(
        "SELECT issuer,subject FROM public.external_identities \
         WHERE tenant_id=$1 AND user_id=$2 AND disabled_at IS NULL",
    )
    .bind(tenant_id)
    .bind(proposer_user_id)
    .fetch_optional(database.pool())
    .await
    .expect("read NFS proposal administrator identity");
    let (issuer, subject) = if let Some(identity) = existing_identity {
        identity
    } else {
        let issuer = "https://nfs-approval.test".to_owned();
        let subject = format!("nfs-admin-{proposer_principal_id}");
        sqlx::query(
            "INSERT INTO public.external_identities \
             (tenant_id,id,user_id,issuer,subject) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(proposer_user_id)
        .bind(&issuer)
        .bind(&subject)
        .execute(database.pool())
        .await
        .expect("insert NFS proposal administrator identity");
        (issuer, subject)
    };
    sqlx::query(
        "INSERT INTO public.tenant_admin_bindings (tenant_id,issuer,subject) \
         VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(&issuer)
    .bind(&subject)
    .execute(database.pool())
    .await
    .expect("bind NFS proposal test administrator");
    for drive_id in allowed_drive_ids {
        let root_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM public.nodes WHERE tenant_id=$1 AND drive_id=$2 AND parent_id IS NULL",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .fetch_one(database.pool())
        .await
        .expect("resolve NFS approval test drive root");
        sqlx::query(
            "INSERT INTO public.acl_entries \
             (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation) \
             VALUES ($1,$2,$3,$4,$5,'READ_METADATA','allow','self',$6,1) \
             ON CONFLICT (tenant_id,resource_id,principal_id,action,inheritance,source) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(root_id)
        .bind(Uuid::new_v4())
        .bind(target_principal_id)
        .bind(proposer_principal_id)
        .execute(database.pool())
        .await
        .expect("grant target READ_METADATA for NFS approval fixture");
    }
    let proposer_session_id =
        insert_fresh_test_api_session(database, tenant_id, proposer_principal_id).await;
    let target_session_id = if target_principal_id == proposer_principal_id {
        proposer_session_id
    } else {
        insert_fresh_test_api_session(database, tenant_id, target_principal_id).await
    };
    let server_fingerprint = [211_u8; 32];
    let request_fingerprint = [212_u8; 32];
    let proposal_key = format!("test-nfs-proposal-{}", Uuid::new_v4());
    let created_proposal = expect_idempotent_created(
        database
            .create_nfs_mapping_proposal_idempotent(
                &CreateNfsMappingProposalInput {
                    tenant_id,
                    proposer_principal_id,
                    proposer_api_session_id: proposer_session_id,
                    principal_id: target_principal_id,
                    kerberos_principal,
                    projected_uid,
                    projected_gid,
                    allowed_drive_ids,
                    server_fingerprint: &server_fingerprint,
                },
                &NfsAdminIdempotency {
                    principal_id: proposer_principal_id,
                    route: "POST /api/v1/admin/mounts/nfs/mapping-proposals",
                    key: &proposal_key,
                    request_fingerprint: &request_fingerprint,
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |record| serde_json::to_value(record),
            )
            .await
            .expect("create immutable NFS mapping proposal"),
    );
    let replayed_proposal = expect_idempotent_replayed(
        database
            .create_nfs_mapping_proposal_idempotent(
                &CreateNfsMappingProposalInput {
                    tenant_id,
                    proposer_principal_id,
                    proposer_api_session_id: proposer_session_id,
                    principal_id: target_principal_id,
                    kerberos_principal,
                    projected_uid,
                    projected_gid,
                    allowed_drive_ids,
                    server_fingerprint: &server_fingerprint,
                },
                &NfsAdminIdempotency {
                    principal_id: proposer_principal_id,
                    route: "POST /api/v1/admin/mounts/nfs/mapping-proposals",
                    key: &proposal_key,
                    request_fingerprint: &request_fingerprint,
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |_| panic!("an exact proposal retry must not rerender or mutate"),
            )
            .await
            .expect("replay immutable NFS mapping proposal"),
    );
    assert_eq!(
        replayed_proposal.response_body,
        created_proposal.response_body
    );
    let active_before_approval: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_approved_active_mappings \
         WHERE tenant_id=$1 AND kerberos_principal=$2",
    )
    .bind(tenant_id)
    .bind(kerberos_principal)
    .fetch_one(database.pool())
    .await
    .expect("count authority before target approval");
    assert_eq!(
        active_before_approval, 0,
        "a proposal confers no NFS authority"
    );
    let (proposal_id, proposal_generation): (Uuid, i64) = sqlx::query_as(
        "SELECT id,generation FROM filebelt_mount.nfs_mapping_proposals \
         WHERE tenant_id=$1 AND kerberos_principal=$2 AND state='pending'",
    )
    .bind(tenant_id)
    .bind(kerberos_principal)
    .fetch_one(database.pool())
    .await
    .expect("read pending NFS mapping proposal");
    let wrong_fingerprint_key = format!("test-nfs-wrong-config-{}", Uuid::new_v4());
    assert!(
        database
            .approve_nfs_mapping_proposal_idempotent(
                tenant_id,
                proposal_id,
                target_principal_id,
                target_session_id,
                proposal_generation,
                &[214_u8; 32],
                &NfsAdminIdempotency {
                    principal_id: target_principal_id,
                    route: "POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval",
                    key: &wrong_fingerprint_key,
                    request_fingerprint: &[215_u8; 32],
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |_| panic!("configuration drift must not render mapping authority"),
            )
            .await
            .is_err(),
        "approval must fail when the server configuration fingerprint changed"
    );
    if proposer_principal_id != target_principal_id {
        let wrong_target_key = format!("test-nfs-wrong-target-{}", Uuid::new_v4());
        assert!(
            database
                .approve_nfs_mapping_proposal_idempotent(
                    tenant_id,
                    proposal_id,
                    proposer_principal_id,
                    proposer_session_id,
                    proposal_generation,
                    &server_fingerprint,
                    &NfsAdminIdempotency {
                        principal_id: proposer_principal_id,
                        route: "POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval",
                        key: &wrong_target_key,
                        request_fingerprint: &[216_u8; 32],
                        legacy_request_fingerprint: None,
                        response_status: 201,
                    },
                    |_| panic!("a non-target must not render mapping authority"),
                )
                .await
                .is_err(),
            "only the exact proposal target may approve"
        );
    }
    let stale_session_key = format!("test-nfs-stale-session-{}", Uuid::new_v4());
    assert!(matches!(
        database
            .approve_nfs_mapping_proposal_idempotent(
                tenant_id,
                proposal_id,
                target_principal_id,
                Uuid::new_v4(),
                proposal_generation,
                &server_fingerprint,
                &NfsAdminIdempotency {
                    principal_id: target_principal_id,
                    route: "POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval",
                    key: &stale_session_key,
                    request_fingerprint: &[217_u8; 32],
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |_| panic!("a missing fresh session must not render mapping authority"),
            )
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    let mut authority_revocation = database
        .pool()
        .begin()
        .await
        .expect("begin concurrent NFS authority revocation");
    sqlx::query(
        "UPDATE public.drives SET acl_generation=acl_generation+1 \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(allowed_drive_ids[0])
    .execute(&mut *authority_revocation)
    .await
    .expect("hold the approval drive-generation fence");
    let racing_approval_key = format!("test-nfs-racing-approval-{}", Uuid::new_v4());
    assert!(matches!(
        database
            .approve_nfs_mapping_proposal_idempotent(
                tenant_id,
                proposal_id,
                target_principal_id,
                target_session_id,
                proposal_generation,
                &server_fingerprint,
                &NfsAdminIdempotency {
                    principal_id: target_principal_id,
                    route: "POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval",
                    key: &racing_approval_key,
                    request_fingerprint: &[218_u8; 32],
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |_| panic!("an in-flight authority revocation must not activate a mapping"),
            )
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    authority_revocation
        .rollback()
        .await
        .expect("release concurrent NFS authority revocation");
    let approval_key = format!("test-nfs-approval-{}", Uuid::new_v4());
    let approved = expect_idempotent_created(
        database
            .approve_nfs_mapping_proposal_idempotent(
                tenant_id,
                proposal_id,
                target_principal_id,
                target_session_id,
                proposal_generation,
                &server_fingerprint,
                &NfsAdminIdempotency {
                    principal_id: target_principal_id,
                    route: "POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval",
                    key: &approval_key,
                    request_fingerprint: &[213_u8; 32],
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |record| serde_json::to_value(record),
            )
            .await
            .expect("approve exact NFS mapping proposal"),
    );
    let replayed_approval = expect_idempotent_replayed(
        database
            .approve_nfs_mapping_proposal_idempotent(
                tenant_id,
                proposal_id,
                target_principal_id,
                target_session_id,
                proposal_generation,
                &server_fingerprint,
                &NfsAdminIdempotency {
                    principal_id: target_principal_id,
                    route: "POST /api/v1/mounts/nfs/mapping-proposals/{proposal_id}/approval",
                    key: &approval_key,
                    request_fingerprint: &[213_u8; 32],
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |_| panic!("an exact approval retry must not recreate authority"),
            )
            .await
            .expect("replay approved NFS mapping proposal"),
    );
    assert_eq!(replayed_approval.response_body, approved.response_body);
    serde_json::from_value(approved.response_body).expect("decode approved NFS mapping")
}

fn expect_idempotent_created(outcome: NfsAdminIdempotentWrite) -> IdempotencyRecord {
    match outcome {
        NfsAdminIdempotentWrite::Created(record) => record,
        NfsAdminIdempotentWrite::Replayed(_) => panic!("write unexpectedly replayed"),
        NfsAdminIdempotentWrite::KeyReused => panic!("idempotency key unexpectedly reused"),
    }
}

fn expect_idempotent_replayed(outcome: NfsAdminIdempotentWrite) -> IdempotencyRecord {
    match outcome {
        NfsAdminIdempotentWrite::Replayed(record) => record,
        NfsAdminIdempotentWrite::Created(_) => panic!("write unexpectedly created twice"),
        NfsAdminIdempotentWrite::KeyReused => panic!("idempotency key unexpectedly reused"),
    }
}

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_NFS_UPGRADE_TEST_DATABASE_URL"]
async fn nfs_alias_upgrade_is_deterministic_and_non_mutating_on_conflict() {
    let database_url = std::env::var("FILEBELT_NFS_UPGRADE_TEST_DATABASE_URL")
        .expect("FILEBELT_NFS_UPGRADE_TEST_DATABASE_URL is required");
    let database = Database::connect(&database_url, 2)
        .await
        .expect("connect NFS alias upgrade database");
    sqlx::raw_sql(include_str!("../../../migrations/postgres/roles.sql"))
        .execute(database.pool())
        .await
        .expect("apply roles");
    for migration in [
        include_str!("../../../migrations/postgres/000001_phase2_core.sql"),
        include_str!("../../../migrations/postgres/000002_phase4_mcp.sql"),
        include_str!("../../../migrations/postgres/000003_phase5_markdown.sql"),
        include_str!("../../../migrations/postgres/000004_phase6_mounts.sql"),
        include_str!("../../../migrations/postgres/000005_phase6_mount_vault.sql"),
        include_str!("../../../migrations/postgres/000006_phase7_documents.sql"),
        include_str!("../../../migrations/postgres/000007_phase8_compatibility.sql"),
        include_str!("../../../migrations/postgres/000008_phase8_media.sql"),
        include_str!("../../../migrations/postgres/000009_phase8_nfs.sql"),
        include_str!("../../../migrations/postgres/000010_onlyoffice_origin_isolation.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(database.pool())
            .await
            .expect("apply pre-namespace migration");
    }
    let tenant_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let group_id = Uuid::new_v4();
    let group_principal_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'nfs-alias-upgrade')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("insert upgrade tenant");
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) \
         VALUES ($1,$2,'user'),($1,$3,'group')",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert upgrade principals");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) \
         VALUES ($1,$2,$3,'Legacy NFS user')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(principal_id)
    .execute(database.pool())
    .await
    .expect("insert upgrade user");
    sqlx::query(
        "INSERT INTO public.groups (tenant_id,id,principal_id,display_name,name_key) \
         VALUES ($1,$2,$3,'Legacy NFS group','legacy-nfs-group')",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert upgrade group");
    sqlx::query(
        "INSERT INTO public.group_memberships \
         (tenant_id,group_id,user_principal_id,role) VALUES ($1,$2,$3,'member')",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(principal_id)
    .execute(database.pool())
    .await
    .expect("insert upgrade membership");
    for migration in [
        include_str!("../../../migrations/postgres/000011_security_descendant_shares.sql"),
        include_str!("../../../migrations/postgres/000012_nfs_authority.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(database.pool())
            .await
            .expect("apply final pre-namespace migration");
    }
    sqlx::query(
        "INSERT INTO filebelt_mount.nfs_posix_groups \
         (tenant_id,group_id,posix_name,projected_gid) VALUES ($1,$2,'legacy_group',62000)",
    )
    .bind(tenant_id)
    .bind(group_id)
    .execute(database.pool())
    .await
    .expect("insert upgrade POSIX group");
    let credential_id = insert_legacy_nfs_alias(
        &database,
        tenant_id,
        principal_id,
        group_id,
        "legacy_user@EXAMPLE.TEST",
        "legacy_user",
        61_000,
        62_000,
    )
    .await;

    let mut compatible = database
        .pool()
        .begin()
        .await
        .expect("begin compatible upgrade");
    sqlx::raw_sql(include_str!(
        "../../../migrations/postgres/000013_nfs_namespace.sql"
    ))
    .execute(&mut *compatible)
    .await
    .expect("migrate one compatible legacy alias");
    let migrated_identity: (Uuid, String, Uuid, i64, i64) = sqlx::query_as(
        "SELECT principal_id,posix_name,posix_group_id,projected_uid,projected_gid \
         FROM filebelt_mount.nfs_posix_users WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_one(&mut *compatible)
    .await
    .expect("read migrated immutable POSIX identity");
    assert_eq!(
        migrated_identity,
        (
            principal_id,
            "legacy_user".to_owned(),
            group_id,
            61_000,
            62_000
        )
    );
    compatible
        .rollback()
        .await
        .expect("roll back compatible fixture");

    sqlx::query(
        "UPDATE filebelt_mount.nfs_principal_mappings \
         SET revoked_at=clock_timestamp(),projected_gid=62001 \
         WHERE tenant_id=$1 AND kerberos_principal='legacy_user@EXAMPLE.TEST'",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("create valid revoked legacy group projection mismatch");
    let mismatched_before: (i64, bool) = sqlx::query_as(
        "SELECT projected_gid,revoked_at IS NOT NULL \
         FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND kerberos_principal='legacy_user@EXAMPLE.TEST'",
    )
    .bind(tenant_id)
    .fetch_one(database.pool())
    .await
    .expect("snapshot legacy group projection mismatch");
    let mut group_mismatch = database
        .pool()
        .begin()
        .await
        .expect("begin group mismatch upgrade");
    let error = sqlx::raw_sql(include_str!(
        "../../../migrations/postgres/000013_nfs_namespace.sql"
    ))
    .execute(&mut *group_mismatch)
    .await
    .expect_err("legacy group projection mismatch must block migration");
    assert_eq!(
        error.as_database_error().and_then(|error| error.code()),
        Some("23514".into())
    );
    group_mismatch
        .rollback()
        .await
        .expect("roll back group mismatch upgrade");
    let mismatched_after: (i64, bool) = sqlx::query_as(
        "SELECT projected_gid,revoked_at IS NOT NULL \
         FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND kerberos_principal='legacy_user@EXAMPLE.TEST'",
    )
    .bind(tenant_id)
    .fetch_one(database.pool())
    .await
    .expect("read rejected legacy group projection mismatch");
    assert_eq!(mismatched_after, mismatched_before);
    sqlx::query(
        "UPDATE filebelt_mount.nfs_principal_mappings \
         SET projected_gid=62000,revoked_at=NULL \
         WHERE tenant_id=$1 AND kerberos_principal='legacy_user@EXAMPLE.TEST'",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("restore compatible legacy alias");

    let second_credential_id = insert_legacy_nfs_alias(
        &database,
        tenant_id,
        principal_id,
        group_id,
        "legacy_alias@EXAMPLE.TEST",
        "legacy_alias",
        61_001,
        62_000,
    )
    .await;
    let before: Vec<(String, Uuid, String, i64, i64, i64, bool)> = sqlx::query_as(
        "SELECT kerberos_principal,credential_id,posix_name,projected_uid,projected_gid,\
                generation,revoked_at IS NOT NULL \
         FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND principal_id=$2 ORDER BY kerberos_principal",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_all(database.pool())
    .await
    .expect("snapshot inconsistent legacy aliases");
    let mut inconsistent = database
        .pool()
        .begin()
        .await
        .expect("begin inconsistent upgrade");
    let error = sqlx::raw_sql(include_str!(
        "../../../migrations/postgres/000013_nfs_namespace.sql"
    ))
    .execute(&mut *inconsistent)
    .await
    .expect_err("inconsistent legacy aliases must block migration");
    assert_eq!(
        error.as_database_error().and_then(|error| error.code()),
        Some("23514".into())
    );
    inconsistent
        .rollback()
        .await
        .expect("roll back rejected upgrade");
    let after: Vec<(String, Uuid, String, i64, i64, i64, bool)> = sqlx::query_as(
        "SELECT kerberos_principal,credential_id,posix_name,projected_uid,projected_gid,\
                generation,revoked_at IS NOT NULL \
         FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND principal_id=$2 ORDER BY kerberos_principal",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_all(database.pool())
    .await
    .expect("read rejected legacy aliases");
    assert_eq!(
        after, before,
        "rejected migration must not mutate alias rows"
    );
    assert_eq!(before.len(), 2);
    assert!(before.iter().any(|row| row.1 == credential_id));
    assert!(before.iter().any(|row| row.1 == second_credential_id));
    let registry_absent: bool =
        sqlx::query_scalar("SELECT to_regclass('filebelt_mount.nfs_posix_users') IS NULL")
            .fetch_one(database.pool())
            .await
            .expect("verify rejected registry DDL rolled back");
    assert!(registry_absent);
}

#[allow(clippy::too_many_arguments)]
async fn insert_legacy_nfs_alias(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
    group_id: Uuid,
    kerberos_principal: &str,
    posix_name: &str,
    projected_uid: i64,
    projected_gid: i64,
) -> Uuid {
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO filebelt_mount.credentials \
         (tenant_id,id,principal_id,protocol,username,verifier_kind,read_only,expires_at) \
         VALUES ($1,$2,$3,'nfs',$4,'kerberos_principal',false,'infinity'::timestamptz)",
    )
    .bind(tenant_id)
    .bind(credential_id)
    .bind(principal_id)
    .bind(credential_id.to_string())
    .execute(database.pool())
    .await
    .expect("insert legacy NFS credential");
    sqlx::query(
        "INSERT INTO filebelt_mount.nfs_principal_mappings \
         (tenant_id,kerberos_principal,principal_id,credential_id,posix_name,posix_group_id,\
          projected_uid,projected_gid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tenant_id)
    .bind(kerberos_principal)
    .bind(principal_id)
    .bind(credential_id)
    .bind(posix_name)
    .bind(group_id)
    .bind(projected_uid)
    .bind(projected_gid)
    .execute(database.pool())
    .await
    .expect("insert valid migration-000012 NFS alias");
    credential_id
}

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
    assert_principal_disable_fanout_is_non_recursive(&database).await;

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
    assert!(
        table_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.nfs_replay_slots",
            "SELECT"
        )
        .await
    );
    assert!(
        !table_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.nfs_replay_slots",
            "UPDATE"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.prepare_nfs_replay_sequence(uuid,uuid,text,text,integer,bigint,integer,bigint)"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.authorize_nfs_handle_open(uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint,text[])"
        )
        .await
    );
    assert!(
        !function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.authorize_nfs_operation(uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint,boolean)"
        )
        .await
    );
    assert!(
        !function_privilege(
            &database,
            "filebelt_io",
            "filebelt_mount.authorize_nfs_handle_open(uuid,uuid,bigint,bytea,uuid,uuid,bigint,bigint,bigint,bigint,bigint,text[])"
        )
        .await
    );
    for (role, expected) in [
        ("filebelt_vfs", true),
        ("filebelt_io", false),
        ("filebelt_api", false),
    ] {
        assert_eq!(
            function_privilege(
                &database,
                role,
                "filebelt_mount.lock_nfs_replay_receipt(uuid,uuid,text,text,integer,bigint,integer,text,bytea,bigint)"
            )
            .await,
            expected,
            "unexpected exact NFS replay-lock privilege for {role}"
        );
    }
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
    for role in ["filebelt_io", "filebelt_maintenance"] {
        for function in [
            "filebelt_mount.claim_nfs_staging_cleanup(uuid,uuid,uuid,uuid)",
            "filebelt_mount.claim_next_nfs_staging_cleanup(uuid,uuid,uuid)",
            "filebelt_mount.heartbeat_nfs_staging_cleanup(uuid,uuid,uuid,uuid,bigint)",
            "filebelt_mount.mark_nfs_staging_cleanup_physical_deleted(uuid,uuid,uuid,uuid,bigint)",
            "filebelt_mount.complete_nfs_staging_cleanup(uuid,uuid,uuid,uuid,bigint)",
        ] {
            assert!(
                function_privilege(&database, role, function).await,
                "{role} must execute exact cleanup transition {function}"
            );
        }
    }
    assert!(
        !function_privilege(
            &database,
            "filebelt_api",
            "filebelt_mount.claim_next_nfs_staging_cleanup(uuid,uuid,uuid)"
        )
        .await
    );
    assert!(
        !table_privilege(
            &database,
            "filebelt_io",
            "filebelt_mount.nfs_staging_cleanup_jobs",
            "SELECT"
        )
        .await,
        "the byte worker must use the typed cleanup functions, not scan jobs"
    );
    assert!(
        table_privilege(
            &database,
            "filebelt_recovery",
            "filebelt_mount.nfs_staging_cleanup_jobs",
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
    assert!(
        table_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.nfs_replay_receipts",
            "INSERT"
        )
        .await
    );
    assert!(
        !table_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.nfs_replay_receipts",
            "UPDATE"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.create_session_principal(uuid,uuid)"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.reconcile_nfs_export_manifest(uuid,text,bigint,bigint,bigint,bytea,bigint[],bigint[],bytea[])"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_recovery",
            "filebelt_mount.advance_nfs_restore_generation(uuid,bigint)"
        )
        .await
    );
    assert!(
        !function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.advance_nfs_restore_generation(uuid,bigint)"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.create_nfs_session(uuid,text,bytea,text,bigint,inet,timestamp with time zone,uuid,uuid)"
        )
        .await
    );
    assert!(!table_privilege(&database, "filebelt_vfs", "public.principals", "INSERT").await);
    assert!(
        !table_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.nfs_principal_mappings",
            "INSERT"
        )
        .await
    );
    assert!(
        column_privilege(
            &database,
            "filebelt_api",
            "filebelt_mount.nfs_exports",
            "desired_state",
            "UPDATE"
        )
        .await
    );
    assert!(
        !column_privilege(
            &database,
            "filebelt_api",
            "filebelt_mount.nfs_exports",
            "applied_state",
            "UPDATE"
        )
        .await
    );
    assert!(
        !column_privilege(
            &database,
            "filebelt_vfs",
            "filebelt_mount.nfs_exports",
            "applied_state",
            "UPDATE"
        )
        .await
    );

    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=12 AND success)",
    )
    .fetch_one(database.pool())
    .await
    .expect("query migration ledger");
    assert!(applied, "the NFS authority migration is required");

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'mount-test')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("insert throttle tenant");
    let principal_id = Uuid::new_v4();
    let group_principal_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) \
         VALUES ($1,$2,'user'),($1,$3,'group')",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert mount test principals");
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) \
         VALUES ($1,$2,$3,'NFS User')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(principal_id)
    .execute(database.pool())
    .await
    .expect("insert mount test user");
    let group_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.groups (tenant_id,id,principal_id,display_name,name_key) \
         VALUES ($1,$2,$3,'NFS Users','nfs-users')",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert mount test group");
    sqlx::query(
        "INSERT INTO public.group_memberships (tenant_id,group_id,user_principal_id,role) \
         VALUES ($1,$2,$3,'member')",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(principal_id)
    .execute(database.pool())
    .await
    .expect("insert NFS primary group membership");
    let drive_id = Uuid::new_v4();
    let second_drive_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.drives \
         (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES \
         ($1,$2,$3,'private','NFS drive',1073741824),\
         ($1,$4,$3,'private','Second NFS drive',1073741824)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(principal_id)
    .bind(second_drive_id)
    .execute(database.pool())
    .await
    .expect("insert NFS drives");
    let root_node_id = Uuid::new_v4();
    let second_root_node_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES \
         ($1,$2,$3,NULL,'directory','',''),\
         ($1,$4,$5,NULL,'directory','','')",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_node_id)
    .bind(second_drive_id)
    .bind(second_root_node_id)
    .execute(database.pool())
    .await
    .expect("insert NFS drive roots");
    sqlx::query(
        "INSERT INTO public.node_ancestry \
         (tenant_id,drive_id,ancestor_id,descendant_id,depth) VALUES \
         ($1,$2,$3,$3,0),($1,$4,$5,$5,0)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_node_id)
    .bind(second_drive_id)
    .bind(second_root_node_id)
    .execute(database.pool())
    .await
    .expect("insert NFS root ancestry");
    let seeded_state: String =
        sqlx::query_scalar("SELECT state FROM filebelt_mount.nfs_feature_state WHERE tenant_id=$1")
            .bind(tenant_id)
            .fetch_one(database.pool())
            .await
            .expect("tenant-local NFS feature state");
    assert_eq!(seeded_state, "disabled");
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

    let posix_fingerprint = [1_u8; 32];
    let posix_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "POST /api/v1/admin/mounts/nfs/posix-groups",
        key: "register-primary-posix-group",
        request_fingerprint: &posix_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let created_posix = expect_idempotent_created(
        database
            .register_nfs_posix_group_idempotent(
                tenant_id,
                principal_id,
                group_id,
                "nfs_users",
                42_000,
                &posix_idempotency,
                |record| {
                    serde_json::to_value(json!({
                        "group_id":record.group_id,
                        "posix_name":record.posix_name,
                        "projected_gid":record.projected_gid,
                    }))
                },
            )
            .await
            .expect("register immutable NFS POSIX group idempotently"),
    );
    assert_eq!(created_posix.response_status, 201);
    let replayed_posix = expect_idempotent_replayed(
        database
            .register_nfs_posix_group_idempotent(
                tenant_id,
                principal_id,
                group_id,
                "nfs_users",
                42_000,
                &posix_idempotency,
                |_| panic!("an exact retry must not rerender the response"),
            )
            .await
            .expect("replay immutable NFS POSIX group response"),
    );
    assert_eq!(replayed_posix.response_body, created_posix.response_body);
    let posix_group = database
        .list_nfs_posix_groups(tenant_id)
        .await
        .expect("list immutable NFS POSIX groups")
        .into_iter()
        .find(|record| record.group_id == group_id)
        .expect("registered immutable NFS POSIX group");
    assert_eq!(posix_group.projected_gid, 42_000);
    assert!(
        sqlx::query(
            "UPDATE filebelt_mount.nfs_posix_groups SET posix_name='renamed' \
             WHERE tenant_id=$1 AND group_id=$2",
        )
        .bind(tenant_id)
        .bind(group_id)
        .execute(database.pool())
        .await
        .is_err(),
        "POSIX group names and GIDs must remain immutable"
    );

    let concurrent_group_principal_id = Uuid::new_v4();
    let concurrent_group_id = Uuid::new_v4();
    let rollback_group_principal_id = Uuid::new_v4();
    let rollback_group_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) \
         VALUES ($1,$2,'group'),($1,$3,'group')",
    )
    .bind(tenant_id)
    .bind(concurrent_group_principal_id)
    .bind(rollback_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert idempotency test group principals");
    sqlx::query(
        "INSERT INTO public.groups (tenant_id,id,principal_id,display_name,name_key) VALUES \
         ($1,$2,$3,'Concurrent NFS Group','concurrent-nfs-group'),\
         ($1,$4,$5,'Rollback NFS Group','rollback-nfs-group')",
    )
    .bind(tenant_id)
    .bind(concurrent_group_id)
    .bind(concurrent_group_principal_id)
    .bind(rollback_group_id)
    .bind(rollback_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert idempotency test groups");
    let concurrent_fingerprint = [2_u8; 32];
    let concurrent_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "POST /api/v1/admin/mounts/nfs/posix-groups",
        key: "concurrent-posix-group",
        request_fingerprint: &concurrent_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let (left, right) = tokio::join!(
        database.register_nfs_posix_group_idempotent(
            tenant_id,
            principal_id,
            concurrent_group_id,
            "concurrent_nfs",
            42_001,
            &concurrent_idempotency,
            |record| serde_json::to_value(json!({"group_id":record.group_id})),
        ),
        database.register_nfs_posix_group_idempotent(
            tenant_id,
            principal_id,
            concurrent_group_id,
            "concurrent_nfs",
            42_001,
            &concurrent_idempotency,
            |record| serde_json::to_value(json!({"group_id":record.group_id})),
        )
    );
    let outcomes = [
        left.expect("first concurrent idempotent group write"),
        right.expect("second concurrent idempotent group write"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, NfsAdminIdempotentWrite::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, NfsAdminIdempotentWrite::Replayed(_)))
            .count(),
        1
    );
    let concurrent_projection_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_posix_groups \
         WHERE tenant_id=$1 AND group_id=$2",
    )
    .bind(tenant_id)
    .bind(concurrent_group_id)
    .fetch_one(database.pool())
    .await
    .expect("count concurrent NFS POSIX group projection");
    let concurrent_audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.audit_events \
         WHERE tenant_id=$1 AND resource_id=$2 AND action='mount.nfs.posix_group.register'",
    )
    .bind(tenant_id)
    .bind(concurrent_group_id)
    .fetch_one(database.pool())
    .await
    .expect("count concurrent NFS POSIX group audit");
    let concurrent_outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.outbox_events \
         WHERE tenant_id=$1 AND aggregate_id=$2 \
           AND topic='filebelt.v1.mount.nfs.posix_group.changed'",
    )
    .bind(tenant_id)
    .bind(concurrent_group_id)
    .fetch_one(database.pool())
    .await
    .expect("count concurrent NFS POSIX group outbox event");
    assert_eq!(concurrent_projection_count, 1);
    assert_eq!(concurrent_audit_count, 1);
    assert_eq!(concurrent_outbox_count, 1);

    let rollback_fingerprint = [3_u8; 32];
    let rollback_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "POST /api/v1/admin/mounts/nfs/posix-groups",
        key: "rollback-posix-group",
        request_fingerprint: &rollback_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    assert!(matches!(
        database
            .register_nfs_posix_group_idempotent(
                tenant_id,
                principal_id,
                rollback_group_id,
                "rollback_nfs",
                42_002,
                &rollback_idempotency,
                |_| serde_json::from_str::<Value>("{"),
            )
            .await,
        Err(DatabaseError::InvalidPersistedValue)
    ));
    let rollback_counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM filebelt_mount.nfs_posix_groups WHERE tenant_id=$1 AND group_id=$2),\
           (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='mount.nfs.posix_group.register'),\
           (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND topic='filebelt.v1.mount.nfs.posix_group.changed'),\
           (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route=$4 AND key=$5)",
    )
    .bind(tenant_id)
    .bind(rollback_group_id)
    .bind(principal_id)
    .bind(rollback_idempotency.route)
    .bind(rollback_idempotency.key)
    .fetch_one(database.pool())
    .await
    .expect("verify failed response finalization rollback");
    assert_eq!(rollback_counts, (0, 0, 0, 0));

    let feature_fingerprint = [4_u8; 32];
    let feature_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "PUT /api/v1/admin/mounts/nfs/feature",
        key: "enter-preflight",
        request_fingerprint: &feature_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 200,
    };
    let created_feature = expect_idempotent_created(
        database
            .transition_nfs_feature_state_idempotent(
                tenant_id,
                principal_id,
                1,
                NfsFeatureState::Preflight,
                &feature_idempotency,
                |record| {
                    serde_json::to_value(json!({
                        "state":record.state.as_str(),
                        "generation":record.generation,
                        "desired_manifest_generation":record.manifest_generation,
                        "applied_manifest_generation":record.applied_manifest_generation,
                        "manifest_applied":false,
                        "applied_gateway_id":record.applied_gateway_id,
                        "applied_gateway_epoch":record.applied_gateway_epoch,
                        "restore_generation":record.restore_generation,
                    }))
                },
            )
            .await
            .expect("enter NFS preflight idempotently"),
    );
    assert_eq!(created_feature.response_status, 200);
    let replayed_feature = expect_idempotent_replayed(
        database
            .transition_nfs_feature_state_idempotent(
                tenant_id,
                principal_id,
                1,
                NfsFeatureState::Preflight,
                &feature_idempotency,
                |_| panic!("an exact feature retry must not rerender"),
            )
            .await
            .expect("replay NFS preflight transition"),
    );
    assert_eq!(
        replayed_feature.response_body,
        created_feature.response_body
    );
    let reused_feature_fingerprint = [5_u8; 32];
    assert!(matches!(
        database
            .transition_nfs_feature_state_idempotent(
                tenant_id,
                principal_id,
                2,
                NfsFeatureState::Disabled,
                &NfsAdminIdempotency {
                    principal_id,
                    route: feature_idempotency.route,
                    key: feature_idempotency.key,
                    request_fingerprint: &reused_feature_fingerprint,
                    legacy_request_fingerprint: None,
                    response_status: 200,
                },
                |_| panic!("key reuse must not execute or rerender"),
            )
            .await
            .expect("classify NFS feature idempotency key reuse"),
        NfsAdminIdempotentWrite::KeyReused
    ));
    let feature = database
        .nfs_feature_state(tenant_id)
        .await
        .expect("read idempotently transitioned NFS feature");
    assert_eq!(feature.generation, 2, "retry must not advance generation");

    let export_fingerprint = [6_u8; 32];
    let export_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "POST /api/v1/admin/mounts/nfs/exports",
        key: "register-primary-export",
        request_fingerprint: &export_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let created_export = expect_idempotent_created(
        database
            .register_nfs_export_idempotent(
                tenant_id,
                principal_id,
                drive_id,
                7,
                &export_idempotency,
                |record| {
                    serde_json::to_value(json!({
                        "drive_id":record.drive_id,
                        "export_id":record.export_id,
                        "export_path":record.export_path,
                        "desired_state":record.desired_state.as_str(),
                        "applied_state":record.applied_state.as_str(),
                        "desired_generation":record.desired_generation,
                        "applied_generation":record.applied_generation,
                        "in_sync":record.desired_state == record.applied_state
                            && record.desired_generation == record.applied_generation,
                    }))
                },
            )
            .await
            .expect("register disabled NFS export idempotently"),
    );
    assert_eq!(created_export.response_status, 201);
    let replayed_export = expect_idempotent_replayed(
        database
            .register_nfs_export_idempotent(
                tenant_id,
                principal_id,
                drive_id,
                7,
                &export_idempotency,
                |_| panic!("an exact export retry must not rerender"),
            )
            .await
            .expect("replay disabled NFS export registration"),
    );
    assert_eq!(replayed_export.response_body, created_export.response_body);
    let denied_export_fingerprint = [11_u8; 32];
    let denied_export_idempotency = NfsAdminIdempotency {
        principal_id: rollback_group_principal_id,
        route: "POST /api/v1/admin/mounts/nfs/exports",
        key: "denied-export",
        request_fingerprint: &denied_export_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    assert!(matches!(
        database
            .register_nfs_export_idempotent(
                tenant_id,
                rollback_group_principal_id,
                second_drive_id,
                8,
                &denied_export_idempotency,
                |record| serde_json::to_value(json!({"export_id":record.export_id})),
            )
            .await,
        Err(DatabaseError::NotFound)
    ));
    let denied_export_counts: (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM filebelt_mount.nfs_exports WHERE tenant_id=$1 AND drive_id=$2),\
           (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route=$4 AND key=$5)",
    )
    .bind(tenant_id)
    .bind(second_drive_id)
    .bind(rollback_group_principal_id)
    .bind(denied_export_idempotency.route)
    .bind(denied_export_idempotency.key)
    .fetch_one(database.pool())
    .await
    .expect("verify denied export transaction rollback");
    assert_eq!(denied_export_counts, (0, 0));
    let export = database
        .list_nfs_exports(tenant_id)
        .await
        .expect("list idempotently registered NFS exports")
        .into_iter()
        .find(|record| record.drive_id == drive_id)
        .expect("idempotently registered disabled NFS export");
    assert_eq!(export.export_path, format!("/filebelt/{drive_id}"));
    assert_eq!(export.applied_generation, 0);
    assert!(
        sqlx::query(
            "INSERT INTO filebelt_mount.nfs_exports \
             (tenant_id,drive_id,export_id,desired_state,applied_state,\
              desired_generation,applied_generation) \
             VALUES ($1,$2,8,'active','active',1,1)",
        )
        .bind(tenant_id)
        .bind(second_drive_id)
        .execute(database.pool())
        .await
        .is_err(),
        "direct inserts must not bypass staged export reconciliation"
    );
    let stage_fingerprint = [7_u8; 32];
    let stage_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "PUT /api/v1/admin/mounts/nfs/exports/{drive_id}",
        key: "stage-primary-export",
        request_fingerprint: &stage_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 200,
    };
    let created_stage = expect_idempotent_created(
        database
            .stage_nfs_export_idempotent(
                tenant_id,
                principal_id,
                drive_id,
                export.desired_generation,
                NfsExportState::Active,
                &stage_idempotency,
                |record| {
                    serde_json::to_value(json!({
                        "drive_id":record.drive_id,
                        "export_id":record.export_id,
                        "export_path":record.export_path,
                        "desired_state":record.desired_state.as_str(),
                        "applied_state":record.applied_state.as_str(),
                        "desired_generation":record.desired_generation,
                        "applied_generation":record.applied_generation,
                        "in_sync":record.desired_state == record.applied_state
                            && record.desired_generation == record.applied_generation,
                    }))
                },
            )
            .await
            .expect("stage NFS export activation idempotently"),
    );
    assert_eq!(created_stage.response_status, 200);
    let replayed_stage = expect_idempotent_replayed(
        database
            .stage_nfs_export_idempotent(
                tenant_id,
                principal_id,
                drive_id,
                export.desired_generation,
                NfsExportState::Active,
                &stage_idempotency,
                |_| panic!("an exact export-stage retry must not rerender"),
            )
            .await
            .expect("replay NFS export activation stage"),
    );
    assert_eq!(replayed_stage.response_body, created_stage.response_body);
    let staged = database
        .list_nfs_exports(tenant_id)
        .await
        .expect("list staged NFS exports")
        .into_iter()
        .find(|record| record.drive_id == drive_id)
        .expect("idempotently staged NFS export");
    assert!(matches!(
        database
            .upsert_nfs_principal_mapping(&UpsertNfsPrincipalMappingInput {
                tenant_id,
                actor_principal_id: principal_id,
                principal_id,
                kerberos_principal: "root@EXAMPLE.TEST",
                projected_uid: 41_001,
                projected_gid: 42_000,
                allowed_drive_ids: &[drive_id],
                expected_generation: None,
            })
            .await,
        Err(DatabaseError::InvalidPersistedValue)
    ));
    let mapping_input = UpsertNfsPrincipalMappingInput {
        tenant_id,
        actor_principal_id: principal_id,
        principal_id,
        kerberos_principal: "Nfs_User@EXAMPLE.TEST",
        projected_uid: 41_000,
        projected_gid: 42_000,
        allowed_drive_ids: &[drive_id],
        expected_generation: None,
    };
    assert!(
        database
            .upsert_nfs_principal_mapping_idempotent(
                &mapping_input,
                &NfsAdminIdempotency {
                    principal_id,
                    route: "POST /api/v1/admin/mounts/nfs/mappings",
                    key: "direct-activation-is-forbidden",
                    request_fingerprint: &[14_u8; 32],
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |_| panic!("direct activation must never render authority"),
            )
            .await
            .is_err(),
        "the database must reject the legacy direct-activation path"
    );
    let _approved_mapping = approve_test_nfs_mapping(
        &database,
        tenant_id,
        principal_id,
        principal_id,
        mapping_input.kerberos_principal,
        mapping_input.projected_uid,
        mapping_input.projected_gid,
        mapping_input.allowed_drive_ids,
    )
    .await;
    let mapping = database
        .list_nfs_principal_mappings(tenant_id)
        .await
        .expect("list idempotently created NFS mappings")
        .into_iter()
        .find(|record| record.kerberos_principal == "Nfs_User@EXAMPLE.TEST")
        .expect("idempotently created NFS Kerberos projection");
    let persisted_mapping_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND kerberos_principal='Nfs_User@EXAMPLE.TEST'",
    )
    .bind(tenant_id)
    .fetch_one(database.pool())
    .await
    .expect("count idempotently created NFS mapping");
    assert_eq!(persisted_mapping_count, 1);
    assert_nfs_alias_identity_authority(
        &database,
        tenant_id,
        principal_id,
        group_id,
        drive_id,
        mapping.projected_uid,
        mapping.projected_gid,
    )
    .await;
    let credential_expiry: String = sqlx::query_scalar(
        "SELECT expires_at::text FROM filebelt_mount.credentials \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(mapping.credential_id)
    .fetch_one(database.pool())
    .await
    .expect("NFS projection expiry");
    assert_eq!(credential_expiry, "infinity");
    assert!(
        sqlx::query(
            "DELETE FROM public.group_memberships \
             WHERE tenant_id=$1 AND group_id=$2 AND user_principal_id=$3",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(principal_id)
        .execute(database.pool())
        .await
        .is_err(),
        "an active mapping must retain its registered primary-group membership"
    );
    assert_nfs_admin_drive_access_revocation_races(&database, &database_url).await;

    let gateway_epoch = database
        .claim_mount_gateway_epoch(tenant_id, "nfs", "nfs", "nfs-gateway-0")
        .await
        .expect("claim NFS gateway epoch");
    let nfs_lease_seconds: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM lease_expires_at-statement_timestamp())::double precision \
         FROM filebelt_mount.gateway_epochs WHERE tenant_id=$1 AND protocol='nfs'",
    )
    .bind(tenant_id)
    .fetch_one(database.pool())
    .await
    .expect("read NFS gateway lease");
    assert!((29.0..=30.0).contains(&nfs_lease_seconds));
    assert!(
        database
            .transition_nfs_feature_state(
                tenant_id,
                principal_id,
                feature.generation,
                NfsFeatureState::Active,
            )
            .await
            .is_err(),
        "activation must fail until an export is fully applied active"
    );
    let binding_digest = [17_u8; 32];
    assert!(matches!(
        database
            .create_nfs_mount_session(&CreateNfsMountSessionInput {
                tenant_id,
                kerberos_principal: "Nfs_User@EXAMPLE.TEST",
                gss_binding_digest: &binding_digest,
                gateway_id: "nfs-gateway-0",
                gateway_epoch,
                source_address: "192.0.2.42",
                gss_expires_at_unix_seconds: 2_000_000_000,
            })
            .await,
        Err(DatabaseError::NotFound)
    ));
    let manifest = database
        .nfs_export_manifest(tenant_id)
        .await
        .expect("read authoritative desired NFS export manifest");
    assert_eq!(manifest.manifest_generation, 3);
    assert_eq!(manifest.applied_manifest_generation, 0);
    assert_eq!(manifest.restore_generation, 1);
    assert_eq!(manifest.exports.len(), 1);
    assert_eq!(manifest.exports[0].export_id, 7);
    assert_eq!(manifest.exports[0].root_node_id, root_node_id);
    assert_eq!(manifest.exports[0].root_node_generation, 1);
    let manifest_digest = [41_u8; 32];
    let root_handle_digest = [42_u8; 32];
    let applied = database
        .reconcile_nfs_export_manifest(&ReconcileNfsExportManifestInput {
            tenant_id,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            feature_generation: feature.generation,
            manifest_generation: manifest.manifest_generation,
            manifest_digest: &manifest_digest,
            export_ids: &[manifest.exports[0].export_id],
            export_generations: &[manifest.exports[0].export_generation],
            root_handle_digests: &[root_handle_digest],
        })
        .await
        .expect("acknowledge the exact applied NFS export manifest");
    assert_eq!(applied.manifest_generation, 3);
    let activating_generation = feature.generation;
    let feature = database
        .transition_nfs_feature_state(
            tenant_id,
            principal_id,
            activating_generation,
            NfsFeatureState::Active,
        )
        .await
        .expect("activate tenant-local NFS feature after gateway/export preflight");
    assert_eq!(feature.state, NfsFeatureState::Active);
    assert_eq!(feature.manifest_generation, 3);
    assert_eq!(feature.applied_manifest_generation, 3);
    let legacy_feature_fingerprint = [12_u8; 32];
    let legacy_feature_body = json!({
        "state":feature.state.as_str(),
        "generation":feature.generation,
        "desired_manifest_generation":feature.manifest_generation,
        "applied_manifest_generation":feature.applied_manifest_generation,
        "manifest_applied":true,
        "applied_gateway_id":feature.applied_gateway_id,
        "applied_gateway_epoch":feature.applied_gateway_epoch,
        "restore_generation":feature.restore_generation,
    });
    database
        .store_idempotency_response(
            tenant_id,
            principal_id,
            "PUT /api/v1/admin/mounts/nfs/feature",
            "legacy-active-feature",
            &legacy_feature_fingerprint,
            200,
            &legacy_feature_body,
        )
        .await
        .expect("seed rolling-upgrade NFS idempotency response");
    let legacy_replay = expect_idempotent_replayed(
        database
            .transition_nfs_feature_state_idempotent(
                tenant_id,
                principal_id,
                activating_generation,
                NfsFeatureState::Active,
                &NfsAdminIdempotency {
                    principal_id,
                    route: "PUT /api/v1/admin/mounts/nfs/feature",
                    key: "legacy-active-feature",
                    request_fingerprint: &legacy_feature_fingerprint,
                    legacy_request_fingerprint: None,
                    response_status: 200,
                },
                |_| panic!("a rolling-upgrade retry must use the prior exact response"),
            )
            .await
            .expect("replay pre-upgrade split NFS idempotency record"),
    );
    assert_eq!(legacy_replay.response_body, legacy_feature_body);
    let first_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "Nfs_User@EXAMPLE.TEST",
            gss_binding_digest: &binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.42",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("create NFS session");
    let retried_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "Nfs_User@EXAMPLE.TEST",
            gss_binding_digest: &binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.42",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("reuse context-bound NFS session");
    assert_eq!(
        first_session.session.session_id,
        retried_session.session.session_id
    );
    assert_eq!(
        first_session.absolute_expires_at_unix_seconds,
        retried_session.absolute_expires_at_unix_seconds,
        "retrying one GSS context must not extend its absolute session lifetime"
    );
    let rescheduled_relay_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "Nfs_User@EXAMPLE.TEST",
            gss_binding_digest: &binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.44",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("create a fresh session after the observed relay peer changes");
    assert_ne!(
        first_session.session.session_id, rescheduled_relay_session.session.session_id,
        "the immediate relay peer remains a conservative session-reuse fence"
    );
    assert_eq!(first_session.session.allowed_drive_ids, vec![drive_id]);
    assert_eq!(first_session.allowed_export_ids, vec![7]);
    assert_eq!(first_session.posix_name, "nfs_user");
    assert_eq!(first_session.primary_group_name, "nfs_users");
    assert_eq!(first_session.manifest_generation, 3);
    assert_eq!(first_session.restore_generation, 1);
    let resolution_alias_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_one(database.pool())
    .await
    .expect("count active aliases before handle resolution");
    assert_eq!(resolution_alias_count, 2);
    let alias_owner_resolution = database
        .resolve_nfs_handle(
            &first_session.session,
            &binding_digest,
            7,
            root_node_id,
            Some(1),
        )
        .await
        .expect("resolve one coherent owner projection with two active Kerberos aliases");
    assert_eq!(alias_owner_resolution.target.node_id, root_node_id);
    assert_eq!(alias_owner_resolution.target.projected_uid, 41_000);
    assert_eq!(alias_owner_resolution.target.owner_name, "nfs_user");
    assert_eq!(alias_owner_resolution.path.len(), 1);
    assert_eq!(
        alias_owner_resolution.path[0].metadata.node_id,
        root_node_id
    );
    assert_eq!(
        alias_owner_resolution.path[0].metadata.projected_uid,
        41_000
    );
    assert_eq!(
        alias_owner_resolution.path[0].metadata.owner_name,
        "nfs_user"
    );
    let expiry_bounded: bool = sqlx::query_scalar(
        "SELECT absolute_expires_at<=clock_timestamp()+interval '4 hours' \
           AND absolute_expires_at<=to_timestamp(2000000000) \
         FROM filebelt_mount.sessions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .fetch_one(database.pool())
    .await
    .expect("NFS session GSS expiry fence");
    assert!(expiry_bounded);
    let effective_expiry: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM absolute_expires_at))::bigint \
         FROM filebelt_mount.sessions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .fetch_one(database.pool())
    .await
    .expect("read effective NFS session expiry");
    assert_eq!(
        first_session.absolute_expires_at_unix_seconds,
        effective_expiry
    );
    let end_binding_digest = [30_u8; 32];
    let ending_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "Nfs_User@EXAMPLE.TEST",
            gss_binding_digest: &end_binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.43",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("create dedicated EndSession replay fixture");
    let end_request_digest = [29_u8; 32];
    let end_response_bytes = [0x08_u8, 0x01];
    let end_response_digest = [28_u8; 32];
    let end_context = NfsReplayContext {
        tenant_id,
        mount_session_id: ending_session.session.session_id,
        client_id: "nfs-client-end",
        nfs_session_id: "nfs-session-end",
        slot_id: 2,
        sequence_id: 1,
        operation_index: 0,
        operation: "end_session",
        request_digest: &end_request_digest,
        gateway_epoch,
    };
    let ended = database
        .end_nfs_mount_session(&EndNfsSessionInput {
            session: &ending_session.session,
            gss_binding_digest: &end_binding_digest,
            replay: RecordNfsReplayReceiptInput {
                context: end_context.clone(),
                response_bytes: &end_response_bytes,
                response_digest: &end_response_digest,
            },
            reason_code: "client_end",
        })
        .await
        .expect("close dedicated NFS session with its replay receipt");
    assert_eq!(ended.outcome, "applied");
    assert_eq!(
        database
            .lookup_applied_nfs_end_session_replay(
                &end_context,
                "nfs-gateway-0",
                ending_session.session.credential_generation,
                ending_session.session.authorization_generation,
                Some(&end_binding_digest),
                "client_end",
            )
            .await
            .expect("look up externally admitted EndSession replay"),
        Some(ended.replay.clone())
    );
    assert_eq!(
        database
            .lookup_applied_nfs_end_session_replay(
                &end_context,
                "nfs-gateway-0",
                ending_session.session.credential_generation,
                ending_session.session.authorization_generation,
                Some(&end_binding_digest),
                "different_reason",
            )
            .await
            .expect("reject EndSession replay under a different close reason"),
        None
    );
    let replay_request_digest = [31_u8; 32];
    let replay_response_digest = [32_u8; 32];
    let replay_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-client-1",
        nfs_session_id: "nfs-session-1",
        slot_id: 7,
        sequence_id: 9,
        operation_index: 3,
        operation: "set_xattr",
        request_digest: &replay_request_digest,
        gateway_epoch,
    };
    let replay = database
        .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
            context: replay_context.clone(),
            response_bytes: &[0x08, 0x01],
            response_digest: &replay_response_digest,
        })
        .await
        .expect("persist exact NFS operation replay response");
    assert_eq!(replay.response_bytes, vec![0x08, 0x01]);
    let (drive_acl_generation, drive_namespace_generation): (i64, i64) = sqlx::query_as(
        "SELECT acl_generation,namespace_generation FROM drives \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .fetch_one(database.pool())
    .await
    .expect("read replay authorization drive generations");
    let replay_authorization = NfsMutationAuthorization {
        drive_id,
        resource_id: root_node_id,
        membership_generation: first_session.session.membership_generation,
        drive_acl_generation,
        drive_namespace_generation,
        resource_acl_generation: alias_owner_resolution.target.acl_generation,
        resource_namespace_generation: alias_owner_resolution.target.namespace_generation,
    };
    assert_eq!(
        database
            .select_authorized_nfs_replay_receipt(
                &first_session.session,
                &binding_digest,
                &replay_context,
                std::slice::from_ref(&replay_authorization),
                None,
            )
            .await
            .expect("select replay under one locked live authority projection"),
        Some(replay.clone())
    );
    assert_eq!(
        database
            .lookup_nfs_replay_candidate(&replay_context)
            .await
            .expect("look up NFS replay response")
            .expect("stored NFS replay response"),
        replay
    );
    assert_eq!(
        database
            .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
                context: replay_context.clone(),
                response_bytes: &[0x08, 0x02],
                response_digest: &[33_u8; 32],
            })
            .await
            .expect("same slot sequence replays the persisted response"),
        replay
    );
    let later_request_digest = [34_u8; 32];
    let later_response_digest = [35_u8; 32];
    let later_context = NfsReplayContext {
        operation_index: 6,
        operation: "remove_xattr",
        request_digest: &later_request_digest,
        ..replay_context.clone()
    };
    let later = database
        .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
            context: later_context.clone(),
            response_bytes: &[0x08, 0x03],
            response_digest: &later_response_digest,
        })
        .await
        .expect("a later forwarded compound operation may skip local operation indexes");
    assert_eq!(
        database
            .lookup_nfs_replay_candidate(&replay_context)
            .await
            .expect("retransmit the first forwarded operation"),
        Some(replay.clone())
    );
    assert_eq!(
        database
            .lookup_nfs_replay_candidate(&later_context)
            .await
            .expect("retransmit the later forwarded operation"),
        Some(later)
    );
    let missing_request_digest = [36_u8; 32];
    let missing_context = NfsReplayContext {
        operation_index: 4,
        operation: "set_xattr",
        request_digest: &missing_request_digest,
        ..replay_context.clone()
    };
    assert!(matches!(
        database
            .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
                context: missing_context,
                response_bytes: &[0x08, 0x04],
                response_digest: &[37_u8; 32],
            })
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    let next_request_digest = [38_u8; 32];
    let next_context = NfsReplayContext {
        sequence_id: 12,
        operation_index: 3,
        operation: "set_xattr",
        request_digest: &next_request_digest,
        ..replay_context.clone()
    };
    database
        .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
            context: next_context.clone(),
            response_bytes: &[0x08, 0x05],
            response_digest: &[39_u8; 32],
        })
        .await
        .expect("a higher observed sequence may skip locally handled compounds");
    assert!(matches!(
        database.lookup_nfs_replay_candidate(&replay_context).await,
        Err(DatabaseError::StaleGeneration)
    ));
    let concurrent_request_digest = [45_u8; 32];
    let concurrent_response_digest = [46_u8; 32];
    let concurrent_context = NfsReplayContext {
        sequence_id: 20,
        operation_index: 3,
        operation: "set_attributes",
        request_digest: &concurrent_request_digest,
        ..next_context
    };
    let first_input = RecordNfsReplayReceiptInput {
        context: concurrent_context.clone(),
        response_bytes: &[0x08, 0x06],
        response_digest: &concurrent_response_digest,
    };
    let second_input = RecordNfsReplayReceiptInput {
        context: concurrent_context.clone(),
        response_bytes: &[0x08, 0x06],
        response_digest: &concurrent_response_digest,
    };
    let (first, second) = tokio::join!(
        database.record_nfs_replay_receipt(&first_input),
        database.record_nfs_replay_receipt(&second_input)
    );
    let concurrent_replay = first.expect("first concurrent next sequence");
    assert_eq!(
        concurrent_replay,
        second.expect("second concurrent next sequence")
    );
    let replay_slot: (i64, i32, i64, bool, bool) = sqlx::query_as(
        "SELECT slot.current_sequence_id,slot.max_operation_index,\
                count(receipt.operation_index)::bigint,\
                bool_and(receipt.expires_at-receipt.created_at>interval '90 seconds'),\
                bool_and(receipt.expires_at=mount_session.absolute_expires_at) \
         FROM filebelt_mount.nfs_replay_slots AS slot \
         JOIN filebelt_mount.nfs_replay_receipts AS receipt \
           ON receipt.tenant_id=slot.tenant_id \
          AND receipt.mount_session_id=slot.mount_session_id \
          AND receipt.nfs_session_id=slot.nfs_session_id AND receipt.slot_id=slot.slot_id \
         JOIN filebelt_mount.sessions AS mount_session \
           ON mount_session.tenant_id=slot.tenant_id \
          AND mount_session.id=slot.mount_session_id \
         WHERE slot.tenant_id=$1 AND slot.mount_session_id=$2 \
           AND slot.nfs_session_id='nfs-session-1' AND slot.slot_id=7 \
         GROUP BY slot.current_sequence_id,slot.max_operation_index",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .fetch_one(database.pool())
    .await
    .expect("read bounded durable replay slot high-water");
    assert_eq!(replay_slot, (20, 3, 1, true, true));

    // Exercise byte-plane terminal retries and the two-phase cleanup job while
    // the NFS session/export authority is still active.
    sqlx::query(
        "UPDATE filebelt_mount.gateway_epochs \
         SET lease_expires_at=clock_timestamp()+interval '30 seconds' \
         WHERE tenant_id=$1 AND protocol='nfs' AND gateway_id='nfs-gateway-0'",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("refresh fixture NFS gateway lease");
    let backend_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.storage_backends \
         (tenant_id,id,kind,capacity_total_bytes,capacity_free_bytes,\
          capacity_checked_at,storage_ready) \
         VALUES ($1,$2,'posix',1073741824,1073741824,clock_timestamp(),true)",
    )
    .bind(tenant_id)
    .bind(backend_id)
    .execute(database.pool())
    .await
    .expect("insert NFS cleanup storage backend");
    let flushing_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "flush",
        "flushing",
        "staging",
    )
    .await;
    let finalizing_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "finalize",
        "committing",
        "finalized",
    )
    .await;
    let aborted_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "abort",
        "aborted",
        "abandoned",
    )
    .await;
    let deleted_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "delete",
        "expired",
        "deleted",
    )
    .await;
    assert_terminal_io_recovery(
        &database,
        &flushing_writer,
        MountIoOperation::Flush,
        MountIoCompletion::Flush {
            logical_size_bytes: 0,
            blake3: [81_u8; 32],
            chunks: Vec::new(),
        },
        101,
    )
    .await;
    assert_terminal_io_recovery(
        &database,
        &finalizing_writer,
        MountIoOperation::Finalize,
        MountIoCompletion::Finalize {
            logical_size_bytes: 0,
            blake3: [91_u8; 32],
            chunks: Vec::new(),
        },
        103,
    )
    .await;
    assert_terminal_io_recovery(
        &database,
        &aborted_writer,
        MountIoOperation::Abort,
        MountIoCompletion::Abort,
        105,
    )
    .await;

    // Terminal preauthorization is internal: it creates one durable pending
    // protocol identity and one short-lived admission, but no client replay.
    // A restarted VFS can inspect/reissue it, and only the live-fenced Flush
    // finalizer records the client-visible response.
    let inherited_vfs_login = "filebelt_nfs_mount_it_vfs_login";
    let inherited_io_login = "filebelt_nfs_mount_it_io_login";
    let inherited_api_login = "filebelt_nfs_mount_it_api_login";
    sqlx::raw_sql(
        "DROP ROLE IF EXISTS filebelt_nfs_mount_it_vfs_login;\
         DROP ROLE IF EXISTS filebelt_nfs_mount_it_io_login;\
         DROP ROLE IF EXISTS filebelt_nfs_mount_it_api_login;\
         CREATE ROLE filebelt_nfs_mount_it_vfs_login LOGIN INHERIT \
           PASSWORD 'filebelt-nfs-role-test';\
         CREATE ROLE filebelt_nfs_mount_it_io_login LOGIN INHERIT \
           PASSWORD 'filebelt-nfs-role-test';\
         CREATE ROLE filebelt_nfs_mount_it_api_login LOGIN INHERIT \
           PASSWORD 'filebelt-nfs-role-test';\
         GRANT filebelt_vfs TO filebelt_nfs_mount_it_vfs_login;\
         GRANT filebelt_io TO filebelt_nfs_mount_it_io_login;\
         GRANT filebelt_api TO filebelt_nfs_mount_it_api_login;",
    )
    .execute(database.pool())
    .await
    .expect("create deployment-like inherited NFS login roles");
    let inherited_vfs_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::from_str(&database_url)
                .expect("parse mount test database URL for VFS login")
                .username(inherited_vfs_login)
                .password("filebelt-nfs-role-test"),
        )
        .await
        .expect("connect as deployment-like inherited VFS login");
    let inherited_vfs_url = PgConnectOptions::from_str(&database_url)
        .expect("parse mount test database URL for VFS database client")
        .username(inherited_vfs_login)
        .password("filebelt-nfs-role-test")
        .to_url_lossy()
        .to_string();
    let inherited_vfs_database = Database::connect(&inherited_vfs_url, 2)
        .await
        .expect("connect database client as deployment-like inherited VFS login");
    assert_eq!(
        inherited_vfs_database
            .select_authorized_nfs_replay_receipt(
                &first_session.session,
                &binding_digest,
                &concurrent_context,
                std::slice::from_ref(&replay_authorization),
                None,
            )
            .await
            .expect("select admitted replay through deployment-like VFS role"),
        Some(concurrent_replay)
    );
    let inherited_io_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::from_str(&database_url)
                .expect("parse mount test database URL for I/O login")
                .username(inherited_io_login)
                .password("filebelt-nfs-role-test"),
        )
        .await
        .expect("connect as deployment-like inherited I/O login");
    let inherited_api_url = PgConnectOptions::from_str(&database_url)
        .expect("parse mount test database URL for API login")
        .username(inherited_api_login)
        .password("filebelt-nfs-role-test")
        .to_url_lossy()
        .to_string();
    let inherited_api_database = Database::connect(&inherited_api_url, 2)
        .await
        .expect("connect as deployment-like inherited API login");
    let api_role_fingerprint = [10_u8; 32];
    let api_role_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "POST /api/v1/admin/mounts/nfs/posix-groups",
        key: "api-role-posix-group",
        request_fingerprint: &api_role_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let api_role_created = expect_idempotent_created(
        inherited_api_database
            .register_nfs_posix_group_idempotent(
                tenant_id,
                principal_id,
                rollback_group_id,
                "rollback_nfs",
                42_002,
                &api_role_idempotency,
                |record| serde_json::to_value(json!({"group_id":record.group_id})),
            )
            .await
            .expect("create idempotent NFS authority through inherited API login"),
    );
    let api_role_replayed = expect_idempotent_replayed(
        inherited_api_database
            .register_nfs_posix_group_idempotent(
                tenant_id,
                principal_id,
                rollback_group_id,
                "rollback_nfs",
                42_002,
                &api_role_idempotency,
                |_| panic!("API-role exact retry must not rerender"),
            )
            .await
            .expect("replay idempotent NFS authority through inherited API login"),
    );
    assert_eq!(
        api_role_replayed.response_body,
        api_role_created.response_body
    );
    assert_nfs_conflict_admin_idempotency(
        &database,
        &inherited_api_database,
        &first_session,
        tenant_id,
        user_id,
        principal_id,
        drive_id,
        root_node_id,
        backend_id,
    )
    .await;
    let protocol_flush_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "protocol-flush",
        "flushing",
        "staging",
    )
    .await;
    let flush_request_digest = [106_u8; 32];
    let flush_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-flush-client",
        nfs_session_id: "nfs-flush-session",
        slot_id: 8,
        sequence_id: 1,
        operation_index: 3,
        operation: "flush",
        request_digest: &flush_request_digest,
        gateway_epoch,
    };
    let flush_protocol_operation_id = Uuid::new_v4();
    let flush_capability_id = Uuid::new_v4();
    let flush_nonce = [107_u8; 32];
    let flush_claims = [108_u8; 32];
    let flush_expires_at = mount_capability_expiry();
    let flush_preauthorization = PreauthorizeMountIoOperationInput {
        io: BeginMountIoOperationInput {
            fence: &protocol_flush_writer.fence,
            capability_id: flush_capability_id,
            nonce_digest: &flush_nonce,
            claims_digest: &flush_claims,
            operation: MountIoOperation::Flush,
            range_start: None,
            range_end: None,
            content_blake3: None,
            expires_at_unix_seconds: flush_expires_at,
        },
        protocol_operation_id: flush_protocol_operation_id,
        context: flush_context.clone(),
    };
    let first_flush_preauthorization = database
        .preauthorize_mount_io_operation(&flush_preauthorization)
        .await
        .expect("preauthorize exact internal Flush work");
    assert!(!first_flush_preauthorization.resumed);
    let resumed_flush_preauthorization = database
        .preauthorize_mount_io_operation(&flush_preauthorization)
        .await
        .expect("resume exact internal Flush preauthorization");
    assert!(resumed_flush_preauthorization.resumed);
    let inspected_flush = database
        .inspect_pending_mount_io_operation(&flush_context)
        .await
        .expect("inspect pending internal Flush")
        .expect("pending Flush exists");
    assert_eq!(
        inspected_flush.protocol_operation_id,
        flush_protocol_operation_id
    );
    assert_eq!(
        inspected_flush.worker_state,
        PendingMountIoWorkerState::Admission
    );
    assert_eq!(inspected_flush.operation_id, None);
    let substituted_flush_claims = [109_u8; 32];
    assert!(matches!(
        database
            .preauthorize_mount_io_operation(&PreauthorizeMountIoOperationInput {
                io: BeginMountIoOperationInput {
                    claims_digest: &substituted_flush_claims,
                    ..flush_preauthorization.io.clone()
                },
                protocol_operation_id: flush_protocol_operation_id,
                context: flush_context.clone(),
            })
            .await,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration)
    ));
    let reissued_flush_capability_id = Uuid::new_v4();
    let reissued_flush_nonce = [110_u8; 32];
    let reissued_flush_claims = [111_u8; 32];
    let reissued_flush_expires_at = mount_capability_expiry();
    let reissued_flush = database
        .reissue_mount_io_operation(&ReissueMountIoOperationInput {
            context: flush_context.clone(),
            fence: &protocol_flush_writer.fence,
            protocol_operation_id: flush_protocol_operation_id,
            stable_operation_id: None,
            operation: MountIoOperation::Flush,
            content_blake3: None,
            range_start: None,
            range_end: None,
            new_capability_id: reissued_flush_capability_id,
            new_nonce_digest: &reissued_flush_nonce,
            new_claims_digest: &reissued_flush_claims,
            new_expires_at_unix_seconds: reissued_flush_expires_at,
        })
        .await
        .expect("reissue lost internal Flush bearer");
    assert_eq!(reissued_flush.capability_id, reissued_flush_capability_id);
    assert!(matches!(
        database
            .begin_mount_io_operation(&flush_preauthorization.io)
            .await,
        Err(DatabaseError::StaleGeneration | DatabaseError::Conflict)
    ));
    let reissued_flush_io = BeginMountIoOperationInput {
        fence: &protocol_flush_writer.fence,
        capability_id: reissued_flush_capability_id,
        nonce_digest: &reissued_flush_nonce,
        claims_digest: &reissued_flush_claims,
        operation: MountIoOperation::Flush,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: reissued_flush_expires_at,
    };
    assert!(matches!(
        database
            .begin_mount_io_operation(&reissued_flush_io)
            .await
            .expect("begin reissued internal Flush"),
        MountIoAdmission::Execute(_)
    ));
    let flush_blake3 = [112_u8; 32];
    database
        .complete_mount_io_flush(&reissued_flush_io, 0, &flush_blake3, &[])
        .await
        .expect("complete exact internal Flush byte-plane work");
    let completed_flush = database
        .inspect_pending_mount_io_operation(&flush_context)
        .await
        .expect("inspect completed internal Flush")
        .expect("completed Flush remains pending protocol finalization");
    assert_eq!(
        completed_flush.worker_state,
        PendingMountIoWorkerState::Completed
    );
    let flush_replay_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_replay_receipts \
         WHERE tenant_id=$1 AND mount_session_id=$2 AND nfs_session_id=$3 \
           AND slot_id=$4 AND sequence_id=$5 AND operation_index=$6",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .bind(flush_context.nfs_session_id)
    .bind(flush_context.slot_id)
    .bind(flush_context.sequence_id)
    .bind(flush_context.operation_index)
    .fetch_one(database.pool())
    .await
    .expect("count Flush replay rows before finalization");
    assert_eq!(flush_replay_count, 0);
    let flush_response_digest = [113_u8; 32];
    let flush_replay = RecordNfsReplayReceiptInput {
        context: flush_context.clone(),
        response_bytes: &[0x08, 0x41],
        response_digest: &flush_response_digest,
    };
    let mut stale_flush_transaction = database
        .pool()
        .begin()
        .await
        .expect("begin rollback-only stale Flush finalization test");
    sqlx::query(
        "UPDATE filebelt_mount.gateway_epochs \
         SET lease_expires_at=clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1 AND protocol='nfs' AND gateway_id='nfs-gateway-0'",
    )
    .bind(tenant_id)
    .execute(&mut *stale_flush_transaction)
    .await
    .expect("expire gateway after Flush byte-plane completion");
    assert!(
        finalize_nfs_internal_io_as(
            &mut *stale_flush_transaction,
            &FinalizeNfsInternalIoReplayInput {
                session: &first_session.session,
                gss_binding_digest: &binding_digest,
                fence: &protocol_flush_writer.fence,
                replay: flush_replay.clone(),
                operation: MountIoOperation::Flush,
            },
        )
        .await
        .is_err(),
        "completed byte-plane work must not finalize under an expired gateway lease"
    );
    stale_flush_transaction
        .rollback()
        .await
        .expect("roll back stale Flush finalization fixture");
    let finalized_flush = database
        .finalize_nfs_internal_io_replay(&FinalizeNfsInternalIoReplayInput {
            session: &first_session.session,
            gss_binding_digest: &binding_digest,
            fence: &protocol_flush_writer.fence,
            replay: flush_replay.clone(),
            operation: MountIoOperation::Flush,
        })
        .await
        .expect("finalize sole client-visible Flush replay");
    assert!(!finalized_flush.replayed);
    let replayed_flush = database
        .finalize_nfs_internal_io_replay(&FinalizeNfsInternalIoReplayInput {
            session: &first_session.session,
            gss_binding_digest: &binding_digest,
            fence: &protocol_flush_writer.fence,
            replay: flush_replay,
            operation: MountIoOperation::Flush,
        })
        .await
        .expect("replay exact finalized Flush response");
    assert!(replayed_flush.replayed);

    // Exercise the security-definer boundary through deployment-like LOGIN
    // roles, not an owner connection with SET ROLE. VFS may mint/finalize only
    // the exact internal operation, while I/O may consume and complete only
    // that opaque admission and cannot scan or forge the backing authority.
    let role_flush_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "inherited-role-flush",
        "flushing",
        "staging",
    )
    .await;
    let role_flush_request_digest = [114_u8; 32];
    let role_flush_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-role-flush-client",
        nfs_session_id: "nfs-role-flush-session",
        slot_id: 9,
        sequence_id: 1,
        operation_index: 3,
        operation: "flush",
        request_digest: &role_flush_request_digest,
        gateway_epoch,
    };
    let role_flush_nonce = [115_u8; 32];
    let role_flush_claims = [116_u8; 32];
    let role_flush_io = BeginMountIoOperationInput {
        fence: &role_flush_writer.fence,
        capability_id: Uuid::new_v4(),
        nonce_digest: &role_flush_nonce,
        claims_digest: &role_flush_claims,
        operation: MountIoOperation::Flush,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: mount_capability_expiry(),
    };
    let role_flush_preauthorization = PreauthorizeMountIoOperationInput {
        io: role_flush_io.clone(),
        protocol_operation_id: Uuid::new_v4(),
        context: role_flush_context.clone(),
    };
    assert!(
        preauthorize_mount_io_as(&inherited_vfs_pool, &role_flush_preauthorization)
            .await
            .expect("inherited VFS login preauthorizes exact Flush")
    );
    assert!(
        !preauthorize_mount_io_as(&inherited_vfs_pool, &role_flush_preauthorization)
            .await
            .expect("inherited VFS login resumes exact Flush")
    );
    assert!(
        sqlx::query("SELECT count(*) FROM filebelt_mount.nfs_pending_protocol_operations")
            .fetch_one(&inherited_vfs_pool)
            .await
            .is_err(),
        "inherited VFS login must not scan pending-operation storage"
    );
    let invented_role_flush = BeginMountIoOperationInput {
        capability_id: Uuid::new_v4(),
        ..role_flush_io.clone()
    };
    assert!(
        begin_mount_io_as(&inherited_io_pool, &invented_role_flush)
            .await
            .is_err(),
        "inherited I/O login must not invent an opaque admission"
    );
    assert!(
        begin_mount_io_as(&inherited_io_pool, &role_flush_io)
            .await
            .expect("inherited I/O login begins exact Flush")
            > 0
    );
    assert_eq!(
        read_mount_io_as(&inherited_io_pool, &role_flush_io)
            .await
            .expect("inherited I/O login reads exact receipt"),
        1
    );
    let role_flush_blake3 = [117_u8; 32];
    let role_flush_outcome = MountIoCompletion::Flush {
        logical_size_bytes: 0,
        blake3: role_flush_blake3,
        chunks: Vec::new(),
    };
    assert_eq!(
        complete_mount_io_as(&inherited_io_pool, &role_flush_io, &role_flush_outcome)
            .await
            .expect("inherited I/O login completes exact Flush"),
        serde_json::to_value(&role_flush_outcome).expect("serialize role Flush outcome")
    );
    for query in [
        "SELECT count(*) FROM filebelt_mount.nfs_io_receipts",
        "SELECT count(*) FROM filebelt_mount.nfs_write_operations",
        "UPDATE filebelt_mount.write_sessions SET fencing_token=fencing_token+1",
        "UPDATE filebelt_mount.write_chunks SET state='published'",
    ] {
        assert!(
            sqlx::query(query)
                .execute(&inherited_io_pool)
                .await
                .is_err(),
            "inherited I/O login must not scan or mutate raw NFS authority: {query}"
        );
    }
    let role_staging_payload_id: Uuid = sqlx::query_scalar(
        "SELECT staging_payload_id FROM filebelt_mount.write_sessions \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(role_flush_writer.fence.write_session_id)
    .fetch_one(database.pool())
    .await
    .expect("read inherited-role staging payload identity");
    assert!(
        sqlx::query(
            "UPDATE public.payload_objects SET state='deleted' \
             WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(role_staging_payload_id)
        .execute(&inherited_io_pool)
        .await
        .is_err(),
        "inherited I/O login must not mutate a raw NFS staging payload"
    );
    let role_flush_response_digest = [118_u8; 32];
    let role_flush_replay = RecordNfsReplayReceiptInput {
        context: role_flush_context,
        response_bytes: &[0x08, 0x42],
        response_digest: &role_flush_response_digest,
    };
    let role_flush_finalize = FinalizeNfsInternalIoReplayInput {
        session: &first_session.session,
        gss_binding_digest: &binding_digest,
        fence: &role_flush_writer.fence,
        replay: role_flush_replay,
        operation: MountIoOperation::Flush,
    };
    assert!(
        !finalize_nfs_internal_io_as(&inherited_vfs_pool, &role_flush_finalize)
            .await
            .expect("inherited VFS login finalizes exact Flush response")
    );
    assert!(
        finalize_nfs_internal_io_as(&inherited_vfs_pool, &role_flush_finalize)
            .await
            .expect("inherited VFS login replays exact Flush response")
    );

    // DeleteStaging is an internal cleanup phase, not a generic worker-owned
    // terminal success. BEGIN must enqueue its exact cleanup identity in SQL;
    // only the leased two-phase cleanup may complete the durable receipt.
    let role_delete_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "inherited-role-delete",
        "expired",
        "abandoned",
    )
    .await;
    let role_delete_request_digest = [180_u8; 32];
    let role_delete_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-role-delete-client",
        nfs_session_id: "nfs-role-delete-session",
        slot_id: 11,
        sequence_id: 1,
        operation_index: 3,
        operation: "close",
        request_digest: &role_delete_request_digest,
        gateway_epoch,
    };
    let role_delete_nonce = [181_u8; 32];
    let role_delete_claims = [182_u8; 32];
    let role_delete_io = BeginMountIoOperationInput {
        fence: &role_delete_writer.fence,
        capability_id: Uuid::new_v4(),
        nonce_digest: &role_delete_nonce,
        claims_digest: &role_delete_claims,
        operation: MountIoOperation::DeleteStaging,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: mount_capability_expiry(),
    };
    assert!(
        preauthorize_mount_io_as(
            &inherited_vfs_pool,
            &PreauthorizeMountIoOperationInput {
                io: role_delete_io.clone(),
                protocol_operation_id: Uuid::new_v4(),
                context: role_delete_context.clone(),
            },
        )
        .await
        .expect("inherited VFS login preauthorizes internal DeleteStaging")
    );
    assert!(
        begin_mount_io_as(&inherited_io_pool, &role_delete_io)
            .await
            .expect("inherited I/O login begins exact DeleteStaging")
            > 0
    );
    let delete_job_identity: (Vec<u8>, String, String) = sqlx::query_as(
        "SELECT source_nonce_digest,completion_kind,state \
         FROM filebelt_mount.nfs_staging_cleanup_jobs \
         WHERE tenant_id=$1 AND write_session_id=$2",
    )
    .bind(tenant_id)
    .bind(role_delete_writer.fence.write_session_id)
    .fetch_one(database.pool())
    .await
    .expect("read SQL-enqueued DeleteStaging cleanup identity");
    assert_eq!(delete_job_identity.0, role_delete_nonce);
    assert_eq!(delete_job_identity.1, "delete_staging");
    assert_eq!(delete_job_identity.2, "pending");
    assert!(
        complete_mount_io_as(
            &inherited_io_pool,
            &role_delete_io,
            &MountIoCompletion::DeleteStaging,
        )
        .await
        .is_err(),
        "generic I/O completion must not complete DeleteStaging"
    );
    let role_delete_worker_id = Uuid::new_v4();
    let role_delete_job_fence: i64 = sqlx::query_scalar(
        "SELECT job_fencing_token \
         FROM filebelt_mount.claim_nfs_staging_cleanup($1,$2,$3,$4)",
    )
    .bind(tenant_id)
    .bind(backend_id)
    .bind(role_delete_writer.fence.write_session_id)
    .bind(role_delete_worker_id)
    .fetch_one(&inherited_io_pool)
    .await
    .expect("inherited I/O login leases DeleteStaging cleanup");
    sqlx::query("SELECT filebelt_mount.mark_nfs_staging_cleanup_physical_deleted($1,$2,$3,$4,$5)")
        .bind(tenant_id)
        .bind(backend_id)
        .bind(role_delete_writer.fence.write_session_id)
        .bind(role_delete_worker_id)
        .bind(role_delete_job_fence)
        .execute(&inherited_io_pool)
        .await
        .expect("inherited I/O login marks DeleteStaging bytes deleted");
    sqlx::query("SELECT filebelt_mount.complete_nfs_staging_cleanup($1,$2,$3,$4,$5)")
        .bind(tenant_id)
        .bind(backend_id)
        .bind(role_delete_writer.fence.write_session_id)
        .bind(role_delete_worker_id)
        .bind(role_delete_job_fence)
        .execute(&inherited_io_pool)
        .await
        .expect("inherited I/O login completes DeleteStaging cleanup");
    let role_delete_outcome: Value = sqlx::query_scalar(
        "SELECT outcome FROM filebelt_mount.read_nfs_io_receipt($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(tenant_id)
    .bind(role_delete_nonce.as_slice())
    .bind(role_delete_io.capability_id)
    .bind(role_delete_writer.fence.write_session_id)
    .bind("delete_staging")
    .bind(role_delete_claims.as_slice())
    .bind(None::<Vec<u8>>)
    .fetch_one(&inherited_io_pool)
    .await
    .expect("read cleanup-owned DeleteStaging outcome");
    assert_eq!(
        role_delete_outcome,
        serde_json::json!({"kind":"delete_staging"})
    );
    let cleanup_owned_terminal: bool = sqlx::query_scalar(
        "SELECT filebelt_mount.require_completed_nfs_internal_terminal(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .bind(role_delete_context.client_id)
    .bind(role_delete_context.nfs_session_id)
    .bind(role_delete_context.slot_id)
    .bind(role_delete_context.sequence_id)
    .bind(role_delete_context.operation_index)
    .bind(role_delete_context.operation)
    .bind(role_delete_context.request_digest.as_slice())
    .bind(gateway_epoch)
    .bind(role_delete_writer.fence.handle_id)
    .fetch_one(&inherited_vfs_pool)
    .await
    .expect("inherited VFS login verifies cleanup-owned DeleteStaging");
    assert!(cleanup_owned_terminal);

    // Finalize persists physical truth and may outlive its short worker lease.
    // COMMIT therefore binds the exact completed Finalize receipt and pending
    // protocol identity, then rechecks live VFS/session/handle generations and
    // the writer's absolute lifetime instead of the expired worker lease.
    let commit_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "finalize-lease-recovery",
        "flushing",
        "staging",
    )
    .await;
    let commit_request_digest = [119_u8; 32];
    let commit_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-commit-lease-client",
        nfs_session_id: "nfs-commit-lease-session",
        slot_id: 10,
        sequence_id: 1,
        operation_index: 3,
        operation: "commit",
        request_digest: &commit_request_digest,
        gateway_epoch,
    };
    let commit_finalize_nonce = [120_u8; 32];
    let commit_finalize_claims = [121_u8; 32];
    let commit_finalize_io = BeginMountIoOperationInput {
        fence: &commit_writer.fence,
        capability_id: Uuid::new_v4(),
        nonce_digest: &commit_finalize_nonce,
        claims_digest: &commit_finalize_claims,
        operation: MountIoOperation::Finalize,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: mount_capability_expiry(),
    };
    database
        .preauthorize_mount_io_operation(&PreauthorizeMountIoOperationInput {
            io: commit_finalize_io.clone(),
            protocol_operation_id: Uuid::new_v4(),
            context: commit_context.clone(),
        })
        .await
        .expect("preauthorize Finalize for lease-independent COMMIT");
    assert!(matches!(
        database
            .begin_mount_io_operation(&commit_finalize_io)
            .await
            .expect("begin Finalize for lease-independent COMMIT"),
        MountIoAdmission::Execute(_)
    ));
    let commit_payload_digest = [122_u8; 32];
    database
        .complete_mount_io_finalize(&commit_finalize_io, 0, &commit_payload_digest, &[])
        .await
        .expect("complete physical Finalize before COMMIT restart");
    sqlx::query(
        "UPDATE filebelt_mount.write_sessions \
         SET lease_expires_at=clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1 AND id=$2 AND state='committing'",
    )
    .bind(tenant_id)
    .bind(commit_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("expire only the short worker lease after Finalize completion");
    let drive_namespace_generation: i64 = sqlx::query_scalar(
        "SELECT namespace_generation FROM public.drives WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .fetch_one(database.pool())
    .await
    .expect("read current drive namespace generation for COMMIT");
    let commit_success_digest = [123_u8; 32];
    let commit_conflict_digest = [124_u8; 32];
    let commit_input = CommitNfsWriteInput {
        context: commit_context,
        gss_binding_digest: &binding_digest,
        authorization: filebelt_database::mount::NfsMutationAuthorization {
            drive_id,
            resource_id: commit_writer.fence.node_id,
            membership_generation: commit_writer.fence.membership_generation,
            drive_acl_generation: commit_writer.fence.drive_acl_generation,
            drive_namespace_generation,
            resource_acl_generation: commit_writer.fence.resource_acl_generation,
            resource_namespace_generation: commit_writer.fence.namespace_generation,
        },
        write_session_id: commit_writer.fence.write_session_id,
        fencing_token: commit_writer.fence.fencing_token,
        version_id: Uuid::new_v4(),
        conflict_id: Uuid::new_v4(),
        success_response_bytes: &[0x08, 0x43],
        success_response_digest: &commit_success_digest,
        conflict_response_bytes: &[0x08, 0x44],
        conflict_response_digest: &commit_conflict_digest,
    };
    let wrong_commit_binding = [125_u8; 32];
    assert!(matches!(
        database
            .commit_nfs_write(&CommitNfsWriteInput {
                gss_binding_digest: &wrong_commit_binding,
                ..commit_input.clone()
            })
            .await,
        Err(DatabaseError::StaleGeneration | DatabaseError::Conflict)
    ));
    assert!(matches!(
        database
            .commit_nfs_write(&CommitNfsWriteInput {
                authorization: filebelt_database::mount::NfsMutationAuthorization {
                    resource_namespace_generation: commit_writer.fence.namespace_generation + 1,
                    ..commit_input.authorization.clone()
                },
                ..commit_input.clone()
            })
            .await,
        Err(DatabaseError::StaleGeneration | DatabaseError::Conflict)
    ));
    let lease_recovered_commit = database
        .commit_nfs_write(&commit_input)
        .await
        .expect("commit exact completed Finalize after worker lease expiry");
    assert!(!lease_recovered_commit.replayed);
    assert_eq!(lease_recovered_commit.outcome, "applied");
    assert_eq!(
        lease_recovered_commit.resource_id,
        Some(commit_writer.fence.node_id)
    );
    let replayed_lease_recovered_commit = database
        .commit_nfs_write(&commit_input)
        .await
        .expect("replay exact lease-recovered COMMIT response");
    assert!(replayed_lease_recovered_commit.replayed);
    assert_eq!(
        replayed_lease_recovered_commit.replay.response_bytes,
        lease_recovered_commit.replay.response_bytes
    );

    // Finalize durably enqueues a lock-only job. Its lease is independently
    // reclaimable after a crash, and completing it never deletes the payload.
    let lock_worker_one = Uuid::new_v4();
    let lock_worker_two = Uuid::new_v4();
    let first_lock_cleanup = database
        .claim_mount_write_lock_cleanup(
            tenant_id,
            backend_id,
            finalizing_writer.fence.write_session_id,
            lock_worker_one,
        )
        .await
        .expect("claim Finalize lock-only cleanup");
    assert_eq!(first_lock_cleanup.job_state, "leased");
    assert!(
        database
            .claim_mount_write_lock_cleanup(
                tenant_id,
                backend_id,
                finalizing_writer.fence.write_session_id,
                lock_worker_two,
            )
            .await
            .is_err(),
        "a second worker must not steal a live lock-cleanup lease"
    );
    database
        .heartbeat_mount_write_lock_cleanup(&first_lock_cleanup)
        .await
        .expect("heartbeat Finalize lock-only cleanup");
    sqlx::query(
        "UPDATE filebelt_mount.nfs_write_lock_cleanup_jobs \
         SET lease_expires_at=clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1 AND write_session_id=$2",
    )
    .bind(tenant_id)
    .bind(finalizing_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("simulate lock-only cleanup crash");
    let reclaimed_lock_cleanup = database
        .claim_next_mount_write_lock_cleanup(tenant_id, backend_id, lock_worker_two)
        .await
        .expect("reclaim expired lock-only cleanup lease")
        .expect("Finalize lock-only cleanup remains discoverable");
    assert_eq!(reclaimed_lock_cleanup.job_state, "leased");
    assert!(reclaimed_lock_cleanup.job_fencing_token > first_lock_cleanup.job_fencing_token);
    assert!(
        database
            .complete_mount_write_lock_cleanup(&first_lock_cleanup)
            .await
            .is_err(),
        "the stale lock-cleanup owner cannot acknowledge another worker's lease"
    );
    database
        .complete_mount_write_lock_cleanup(&reclaimed_lock_cleanup)
        .await
        .expect("acknowledge verified lock removal");
    database
        .complete_mount_write_lock_cleanup(&reclaimed_lock_cleanup)
        .await
        .expect("retry exact lock-removal acknowledgement");
    let completed_lock_cleanup = database
        .claim_mount_write_lock_cleanup(
            tenant_id,
            backend_id,
            finalizing_writer.fence.write_session_id,
            lock_worker_two,
        )
        .await
        .expect("return the exact completed lock-only job");
    assert_eq!(completed_lock_cleanup.job_state, "completed");
    let finalized_payload_state: String = sqlx::query_scalar(
        "SELECT payload.state FROM filebelt_mount.write_sessions AS writer \
         JOIN public.payload_objects AS payload \
           ON payload.tenant_id=writer.tenant_id AND payload.id=writer.staging_payload_id \
         WHERE writer.tenant_id=$1 AND writer.id=$2",
    )
    .bind(tenant_id)
    .bind(finalizing_writer.fence.write_session_id)
    .fetch_one(database.pool())
    .await
    .expect("read finalized payload after lock-only cleanup");
    assert_eq!(finalized_payload_state, "finalized");

    // A completed byte-plane range blocks every later plan until VFS applies
    // its authoritative extent and NFS replay response. That apply remains
    // recoverable after the short worker lease expires and renews the writer.
    let range_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "range-recovery",
        "open",
        "staging",
    )
    .await;
    let range_content_digest = [121_u8; 32];
    let range_plan_request_digest = [122_u8; 32];
    let range_plan_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-range-client",
        nfs_session_id: "nfs-range-session",
        slot_id: 9,
        sequence_id: 1,
        operation_index: 3,
        operation: "sparse_write",
        request_digest: &range_plan_request_digest,
        gateway_epoch,
    };
    let first_range_operation_id = Uuid::new_v4();
    let first_range_capability_id = Uuid::new_v4();
    let first_range_nonce = [124_u8; 32];
    let first_range_claims = [125_u8; 32];
    let first_range_expires_at = mount_capability_expiry();
    let first_range_chunks = [MountWriteChunkPlan {
        chunk_number: 0,
        source_payload_id: None,
        source_chunk_number: None,
        staging_locator: Uuid::new_v4(),
        size_bytes: 1,
        dirty: true,
    }];
    let first_range_plan_input = ExtendNfsWriteChunksInput {
        fence: &range_writer.fence,
        context: range_plan_context.clone(),
        nonce_digest: &first_range_nonce,
        claims_digest: &first_range_claims,
        expires_at_unix_seconds: first_range_expires_at,
        required_reservation_bytes: 1,
        operation_id: first_range_operation_id,
        capability_id: first_range_capability_id,
        operation: MountWriteRangeOperation::WriteData,
        content_blake3: Some(&range_content_digest),
        range_start: 0,
        range_end: 0,
        chunks: &first_range_chunks,
    };
    let first_range_plan = database
        .extend_mount_write_chunks(&first_range_plan_input)
        .await
        .expect("plan the first exact NFS byte range");
    assert_eq!(first_range_plan.reserved_bytes, 1);
    assert!(!first_range_plan.resumed);
    let resumed_first_range = database
        .extend_mount_write_chunks(&first_range_plan_input)
        .await
        .expect("resume the exact pending NFS byte range");
    assert!(resumed_first_range.resumed);
    assert_eq!(resumed_first_range.operation_id, first_range_operation_id);
    assert_eq!(resumed_first_range.reserved_bytes, 1);
    let pending_plan_counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM filebelt_mount.nfs_pending_protocol_operations \
             WHERE tenant_id=$1 AND write_session_id=$2),\
           (SELECT count(*) FROM filebelt_mount.nfs_io_admissions \
             WHERE tenant_id=$1 AND write_session_id=$2),\
           (SELECT count(*) FROM filebelt_mount.nfs_write_operations \
             WHERE tenant_id=$1 AND write_session_id=$2),\
           (SELECT count(*) FROM filebelt_mount.nfs_replay_receipts \
             WHERE tenant_id=$1 AND mount_session_id=$3 \
               AND nfs_session_id=$4 AND slot_id=$5),\
           (SELECT reserved_bytes FROM filebelt_mount.write_sessions \
             WHERE tenant_id=$1 AND id=$2)",
    )
    .bind(tenant_id)
    .bind(range_writer.fence.write_session_id)
    .bind(first_session.session.session_id)
    .bind(range_plan_context.nfs_session_id)
    .bind(range_plan_context.slot_id)
    .fetch_one(database.pool())
    .await
    .expect("read exact pending plan inventory");
    assert_eq!(pending_plan_counts, (1, 1, 1, 0, 1));
    let substituted_nonce = [126_u8; 32];
    assert!(matches!(
        database
            .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
                fence: &range_writer.fence,
                context: range_plan_context.clone(),
                nonce_digest: &substituted_nonce,
                claims_digest: &first_range_claims,
                expires_at_unix_seconds: first_range_expires_at,
                required_reservation_bytes: 1,
                operation_id: first_range_operation_id,
                capability_id: first_range_capability_id,
                operation: MountWriteRangeOperation::WriteData,
                content_blake3: Some(&range_content_digest),
                range_start: 0,
                range_end: 0,
                chunks: &first_range_chunks,
            })
            .await,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration)
    ));
    let substituted_request_digest = [126_u8; 32];
    assert!(matches!(
        database
            .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
                fence: &range_writer.fence,
                context: NfsReplayContext {
                    request_digest: &substituted_request_digest,
                    ..range_plan_context.clone()
                },
                nonce_digest: &first_range_nonce,
                claims_digest: &first_range_claims,
                expires_at_unix_seconds: first_range_expires_at,
                required_reservation_bytes: 1,
                operation_id: first_range_operation_id,
                capability_id: first_range_capability_id,
                operation: MountWriteRangeOperation::WriteData,
                content_blake3: Some(&range_content_digest),
                range_start: 0,
                range_end: 0,
                chunks: &first_range_chunks,
            })
            .await,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration)
    ));
    let substituted_chunks = [MountWriteChunkPlan {
        staging_locator: Uuid::new_v4(),
        ..first_range_chunks[0].clone()
    }];
    assert!(matches!(
        database
            .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
                fence: &range_writer.fence,
                context: range_plan_context.clone(),
                nonce_digest: &first_range_nonce,
                claims_digest: &first_range_claims,
                expires_at_unix_seconds: first_range_expires_at,
                required_reservation_bytes: 1,
                operation_id: first_range_operation_id,
                capability_id: first_range_capability_id,
                operation: MountWriteRangeOperation::WriteData,
                content_blake3: Some(&range_content_digest),
                range_start: 0,
                range_end: 0,
                chunks: &substituted_chunks,
            })
            .await,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration)
    ));
    let inspected_first_range = database
        .inspect_pending_mount_io_operation(&range_plan_context)
        .await
        .expect("inspect the restart-stable NFS range plan")
        .expect("pending NFS range plan exists");
    assert_eq!(
        inspected_first_range.protocol_operation_id,
        first_range_operation_id
    );
    assert_eq!(
        inspected_first_range.operation_id,
        Some(first_range_operation_id)
    );
    assert_eq!(
        inspected_first_range.worker_state,
        PendingMountIoWorkerState::Admission
    );
    let reissued_range_capability_id = Uuid::new_v4();
    let reissued_range_nonce = [127_u8; 32];
    let reissued_range_claims = [128_u8; 32];
    let reissued_range_expires_at = mount_capability_expiry();
    let reissued_first_range = database
        .reissue_mount_io_operation(&ReissueMountIoOperationInput {
            context: range_plan_context.clone(),
            fence: &range_writer.fence,
            protocol_operation_id: first_range_operation_id,
            stable_operation_id: Some(first_range_operation_id),
            operation: MountIoOperation::WriteData,
            content_blake3: Some(&range_content_digest),
            range_start: Some(0),
            range_end: Some(0),
            new_capability_id: reissued_range_capability_id,
            new_nonce_digest: &reissued_range_nonce,
            new_claims_digest: &reissued_range_claims,
            new_expires_at_unix_seconds: reissued_range_expires_at,
        })
        .await
        .expect("atomically reissue the pending range bearer");
    assert_eq!(
        reissued_first_range.operation_id,
        Some(first_range_operation_id)
    );
    assert_eq!(
        reissued_first_range.capability_id,
        reissued_range_capability_id
    );
    let resolved_reissued_range = database
        .admit_mount_write_range(
            &range_writer.fence,
            reissued_range_capability_id,
            MountWriteRangeOperation::WriteData,
            0,
            0,
        )
        .await
        .expect("resolve reissued bearer to the stable range plan");
    assert_eq!(
        resolved_reissued_range.operation_id,
        first_range_operation_id
    );
    let old_range_io = BeginMountIoOperationInput {
        fence: &range_writer.fence,
        capability_id: first_range_capability_id,
        nonce_digest: &first_range_nonce,
        claims_digest: &first_range_claims,
        operation: MountIoOperation::WriteData,
        range_start: Some(0),
        range_end: Some(0),
        content_blake3: Some(&range_content_digest),
        expires_at_unix_seconds: first_range_expires_at,
    };
    assert!(matches!(
        database.begin_mount_io_operation(&old_range_io).await,
        Err(DatabaseError::StaleGeneration | DatabaseError::Conflict)
    ));
    let first_range_io = BeginMountIoOperationInput {
        fence: &range_writer.fence,
        capability_id: reissued_range_capability_id,
        nonce_digest: &reissued_range_nonce,
        claims_digest: &reissued_range_claims,
        operation: MountIoOperation::WriteData,
        range_start: Some(0),
        range_end: Some(0),
        content_blake3: Some(&range_content_digest),
        expires_at_unix_seconds: reissued_range_expires_at,
    };
    assert!(matches!(
        database
            .begin_mount_io_operation(&first_range_io)
            .await
            .expect("claim first exact byte-plane range"),
        MountIoAdmission::Execute(_)
    ));
    let first_range_outcome = MountIoCompletion::RangeMutation {
        logical_size_bytes: 1,
        reservation_delta_bytes: 1,
    };
    assert_eq!(
        database
            .complete_mount_io_operation(&first_range_io, &first_range_outcome)
            .await
            .expect("persist byte-plane range completion"),
        first_range_outcome
    );
    let io_completed_state: String = sqlx::query_scalar(
        "SELECT state FROM filebelt_mount.nfs_write_operations \
         WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3",
    )
    .bind(tenant_id)
    .bind(range_writer.fence.write_session_id)
    .bind(first_range_operation_id)
    .fetch_one(database.pool())
    .await
    .expect("read byte-plane-completed operation state");
    assert_eq!(io_completed_state, "io_completed");
    let early_replay_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_replay_receipts \
         WHERE tenant_id=$1 AND mount_session_id=$2 AND nfs_session_id=$3 \
           AND slot_id=$4 AND sequence_id=$5 AND operation_index=$6",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .bind(range_plan_context.nfs_session_id)
    .bind(range_plan_context.slot_id)
    .bind(range_plan_context.sequence_id)
    .bind(range_plan_context.operation_index)
    .fetch_one(database.pool())
    .await
    .expect("count client replay rows before authoritative range apply");
    assert_eq!(early_replay_count, 0);

    let second_range_content_digest = [126_u8; 32];
    let second_range_plan_request_digest = [127_u8; 32];
    let second_range_context = NfsReplayContext {
        sequence_id: 2,
        operation_index: 3,
        request_digest: &second_range_plan_request_digest,
        ..range_plan_context.clone()
    };
    let second_range_operation_id = Uuid::new_v4();
    let second_range_nonce = [129_u8; 32];
    let second_range_claims = [130_u8; 32];
    let second_range_expires_at = mount_capability_expiry();
    let second_range_chunks = [
        first_range_chunks[0].clone(),
        MountWriteChunkPlan {
            chunk_number: 1,
            source_payload_id: None,
            source_chunk_number: None,
            staging_locator: Uuid::new_v4(),
            size_bytes: 1,
            dirty: true,
        },
    ];
    assert!(matches!(
        database
            .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
                fence: &range_writer.fence,
                context: second_range_context.clone(),
                nonce_digest: &second_range_nonce,
                claims_digest: &second_range_claims,
                expires_at_unix_seconds: second_range_expires_at,
                required_reservation_bytes: 2,
                operation_id: second_range_operation_id,
                capability_id: Uuid::new_v4(),
                operation: MountWriteRangeOperation::WriteData,
                content_blake3: Some(&second_range_content_digest),
                range_start: 1,
                range_end: 1,
                chunks: &second_range_chunks,
            })
            .await,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration)
    ));
    sqlx::query(
        "UPDATE filebelt_mount.write_sessions \
         SET lease_expires_at=clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(range_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("simulate worker crash after byte-plane completion");
    let skipped_io_completed = database
        .sweep_expired_nfs_writers(tenant_id, 100)
        .await
        .expect("sweep short-lease-expired writers");
    assert!(
        skipped_io_completed
            .iter()
            .all(|writer| writer.write_session_id != range_writer.fence.write_session_id),
        "an io_completed range remains recoverable until its absolute expiry"
    );
    sqlx::query(
        "UPDATE filebelt_mount.gateway_epochs \
         SET lease_expires_at=clock_timestamp()+interval '30 seconds' \
         WHERE tenant_id=$1 AND protocol='nfs' AND gateway_id='nfs-gateway-0'",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("refresh gateway before VFS extent acknowledgement");
    let apply_response_digest = [130_u8; 32];
    let substituted_range_digest = [131_u8; 32];
    let substituted_apply_response_digest = [132_u8; 32];
    assert!(
        database
            .apply_nfs_write_extent(&ApplyNfsWriteExtentInput {
                session: &first_session.session,
                gss_binding_digest: &binding_digest,
                fence: &range_writer.fence,
                replay: RecordNfsReplayReceiptInput {
                    context: range_plan_context.clone(),
                    response_bytes: &[0x08, 0x22],
                    response_digest: &substituted_apply_response_digest,
                },
                operation_id: first_range_operation_id,
                operation: MountWriteRangeOperation::WriteData,
                range_start: 0,
                range_end: 0,
                data_digest: Some(&substituted_range_digest),
            })
            .await
            .is_err(),
        "a substituted range digest must fail closed"
    );
    let apply_input = ApplyNfsWriteExtentInput {
        session: &first_session.session,
        gss_binding_digest: &binding_digest,
        fence: &range_writer.fence,
        replay: RecordNfsReplayReceiptInput {
            context: range_plan_context.clone(),
            response_bytes: &[0x08, 0x23],
            response_digest: &apply_response_digest,
        },
        operation_id: first_range_operation_id,
        operation: MountWriteRangeOperation::WriteData,
        range_start: 0,
        range_end: 0,
        data_digest: Some(&range_content_digest),
    };
    let applied_range = database
        .apply_nfs_write_extent(&apply_input)
        .await
        .expect("apply io_completed range after worker lease expiry");
    assert_eq!(applied_range.logical_size_bytes, 1);
    assert_eq!(applied_range.extents.len(), 1);
    assert!(!applied_range.extents[0].is_hole);
    let replayed_range = database
        .apply_nfs_write_extent(&apply_input)
        .await
        .expect("replay exact applied NFS range result");
    assert!(replayed_range.replayed);
    assert_eq!(replayed_range.extents, applied_range.extents);
    let applied_state: (String, bool) = sqlx::query_as(
        "SELECT operation.state,writer.lease_expires_at>clock_timestamp() \
         FROM filebelt_mount.nfs_write_operations AS operation \
         JOIN filebelt_mount.write_sessions AS writer \
           ON writer.tenant_id=operation.tenant_id AND writer.id=operation.write_session_id \
         WHERE operation.tenant_id=$1 AND operation.write_session_id=$2 \
           AND operation.operation_id=$3",
    )
    .bind(tenant_id)
    .bind(range_writer.fence.write_session_id)
    .bind(first_range_operation_id)
    .fetch_one(database.pool())
    .await
    .expect("read VFS-applied range state");
    assert_eq!(applied_state, ("applied".into(), true));
    assert_nfs_range_recovery_case(
        &database,
        &first_session,
        &binding_digest,
        &range_writer,
        NfsRangeRecoveryCase {
            identity_byte: 131,
            operation_id: second_range_operation_id,
            operation: MountWriteRangeOperation::WriteData,
            range_start: 1,
            range_end: 1,
            required_reservation_bytes: 2,
            chunks: &second_range_chunks,
            content_blake3: Some(&second_range_content_digest),
            worker_outcome: MountIoCompletion::RangeMutation {
                logical_size_bytes: 2,
                reservation_delta_bytes: 1,
            },
            expected_logical_size: 2,
            expected_seek_offset: None,
            expect_authority_conflict: false,
        },
    )
    .await;
    let three_range_chunks = [
        second_range_chunks[0].clone(),
        second_range_chunks[1].clone(),
        MountWriteChunkPlan {
            chunk_number: 2,
            source_payload_id: None,
            source_chunk_number: None,
            staging_locator: Uuid::new_v4(),
            size_bytes: 1,
            dirty: true,
        },
    ];
    assert_nfs_range_recovery_case(
        &database,
        &first_session,
        &binding_digest,
        &range_writer,
        NfsRangeRecoveryCase {
            identity_byte: 137,
            operation_id: Uuid::new_v4(),
            operation: MountWriteRangeOperation::Allocate,
            range_start: 2,
            range_end: 2,
            required_reservation_bytes: 3,
            chunks: &three_range_chunks,
            content_blake3: None,
            worker_outcome: MountIoCompletion::RangeMutation {
                logical_size_bytes: 3,
                reservation_delta_bytes: 1,
            },
            expected_logical_size: 3,
            expected_seek_offset: None,
            expect_authority_conflict: false,
        },
    )
    .await;
    let invalid_seek_request_digest = [147_u8; 32];
    let invalid_seek_nonce = [148_u8; 32];
    let invalid_seek_claims = [149_u8; 32];
    assert!(matches!(
        database
            .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
                fence: &range_writer.fence,
                context: NfsReplayContext {
                    tenant_id,
                    mount_session_id: first_session.session.session_id,
                    client_id: "nfs-invalid-seek",
                    nfs_session_id: "nfs-invalid-seek",
                    slot_id: 148,
                    sequence_id: 1,
                    operation_index: 3,
                    operation: "sparse_control",
                    request_digest: &invalid_seek_request_digest,
                    gateway_epoch,
                },
                nonce_digest: &invalid_seek_nonce,
                claims_digest: &invalid_seek_claims,
                expires_at_unix_seconds: mount_capability_expiry(),
                required_reservation_bytes: 3,
                operation_id: Uuid::new_v4(),
                capability_id: Uuid::new_v4(),
                operation: MountWriteRangeOperation::SeekData,
                content_blake3: None,
                range_start: 0,
                range_end: 2,
                chunks: &three_range_chunks,
            })
            .await,
        Err(DatabaseError::InvalidPersistedValue)
    ));
    assert_nfs_range_recovery_case(
        &database,
        &first_session,
        &binding_digest,
        &range_writer,
        NfsRangeRecoveryCase {
            identity_byte: 143,
            operation_id: Uuid::new_v4(),
            operation: MountWriteRangeOperation::HoleDeallocate,
            range_start: 1,
            range_end: 1,
            required_reservation_bytes: 3,
            chunks: &three_range_chunks,
            content_blake3: None,
            worker_outcome: MountIoCompletion::RangeMutation {
                logical_size_bytes: 3,
                reservation_delta_bytes: 0,
            },
            expected_logical_size: 3,
            expected_seek_offset: None,
            expect_authority_conflict: false,
        },
    )
    .await;
    assert_nfs_range_recovery_case(
        &database,
        &first_session,
        &binding_digest,
        &range_writer,
        NfsRangeRecoveryCase {
            identity_byte: 149,
            operation_id: Uuid::new_v4(),
            operation: MountWriteRangeOperation::SeekData,
            range_start: 0,
            range_end: 0,
            required_reservation_bytes: 3,
            chunks: &three_range_chunks,
            content_blake3: None,
            worker_outcome: MountIoCompletion::Seek { offset: Some(0) },
            expected_logical_size: 3,
            expected_seek_offset: Some(Some(0)),
            expect_authority_conflict: false,
        },
    )
    .await;
    assert_nfs_range_recovery_case(
        &database,
        &first_session,
        &binding_digest,
        &range_writer,
        NfsRangeRecoveryCase {
            identity_byte: 151,
            operation_id: Uuid::new_v4(),
            operation: MountWriteRangeOperation::SeekHole,
            range_start: 0,
            range_end: 0,
            required_reservation_bytes: 3,
            chunks: &three_range_chunks,
            content_blake3: None,
            worker_outcome: MountIoCompletion::Seek { offset: Some(1) },
            expected_logical_size: 3,
            expected_seek_offset: Some(Some(1)),
            expect_authority_conflict: false,
        },
    )
    .await;
    assert_nfs_range_recovery_case(
        &database,
        &first_session,
        &binding_digest,
        &range_writer,
        NfsRangeRecoveryCase {
            identity_byte: 157,
            operation_id: Uuid::new_v4(),
            operation: MountWriteRangeOperation::SeekHole,
            range_start: 0,
            range_end: 0,
            required_reservation_bytes: 3,
            chunks: &three_range_chunks,
            content_blake3: None,
            worker_outcome: MountIoCompletion::Seek { offset: Some(2) },
            expected_logical_size: 3,
            expected_seek_offset: None,
            expect_authority_conflict: true,
        },
    )
    .await;
    sqlx::query(
        "UPDATE filebelt_mount.write_sessions \
         SET created_at=clock_timestamp()-interval '2 hours',\
             expires_at=clock_timestamp()-interval '1 hour',\
             lease_expires_at=clock_timestamp()-interval '1 hour' \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(range_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("absolutely expire the mismatched-seek writer for cleanup");
    let swept_range = database
        .sweep_expired_nfs_writers(tenant_id, 100)
        .await
        .expect("fence the unrecoverable expired seek writer");
    assert!(
        swept_range
            .iter()
            .any(|writer| writer.write_session_id == range_writer.fence.write_session_id)
    );
    let range_cleanup_worker = Uuid::new_v4();
    let range_cleanup = database
        .claim_mount_staging_cleanup(
            tenant_id,
            backend_id,
            range_writer.fence.write_session_id,
            range_cleanup_worker,
        )
        .await
        .expect("claim swept range-writer cleanup");
    database
        .mark_mount_staging_cleanup_physical_deleted(&range_cleanup)
        .await
        .expect("mark swept range-writer payload deleted");
    database
        .complete_mount_staging_cleanup(&range_cleanup)
        .await
        .expect("complete swept range-writer cleanup");

    sqlx::query("SELECT filebelt_mount.enqueue_nfs_staging_cleanup($1,$2,'write_aborted',NULL)")
        .bind(tenant_id)
        .bind(aborted_writer.fence.write_session_id)
        .execute(database.pool())
        .await
        .expect("enqueue request-independent cleanup job");
    let worker_one = Uuid::new_v4();
    let worker_two = Uuid::new_v4();
    let mut denied = database
        .pool()
        .begin()
        .await
        .expect("begin denied role check");
    sqlx::query("SET LOCAL ROLE filebelt_api")
        .execute(&mut *denied)
        .await
        .expect("assume API role");
    assert!(
        sqlx::query("SELECT * FROM filebelt_mount.claim_next_nfs_staging_cleanup($1,$2,$3)")
            .bind(tenant_id)
            .bind(backend_id)
            .bind(worker_one)
            .fetch_optional(&mut *denied)
            .await
            .is_err(),
        "the API role must not claim physical cleanup work"
    );
    denied.rollback().await.expect("rollback denied role check");

    let mut role_claim = database.pool().begin().await.expect("begin I/O role claim");
    sqlx::query("SET LOCAL ROLE filebelt_io")
        .execute(&mut *role_claim)
        .await
        .expect("assume I/O role");
    let role_claimed_state: String = sqlx::query_scalar(
        "SELECT job_state FROM filebelt_mount.claim_nfs_staging_cleanup($1,$2,$3,$4)",
    )
    .bind(tenant_id)
    .bind(backend_id)
    .bind(aborted_writer.fence.write_session_id)
    .bind(worker_one)
    .fetch_one(&mut *role_claim)
    .await
    .expect("claim cleanup through the real I/O role");
    assert_eq!(role_claimed_state, "leased");
    role_claim.commit().await.expect("commit I/O role claim");

    let mut raw_scan = database
        .pool()
        .begin()
        .await
        .expect("begin raw scan denial");
    sqlx::query("SET LOCAL ROLE filebelt_io")
        .execute(&mut *raw_scan)
        .await
        .expect("assume I/O role for raw scan");
    assert!(
        sqlx::query("SELECT write_session_id FROM filebelt_mount.nfs_staging_cleanup_jobs")
            .fetch_optional(&mut *raw_scan)
            .await
            .is_err(),
        "the I/O role must not scan cleanup jobs directly"
    );
    raw_scan.rollback().await.expect("rollback raw scan denial");

    let first_cleanup = database
        .claim_mount_staging_cleanup(
            tenant_id,
            backend_id,
            aborted_writer.fence.write_session_id,
            worker_one,
        )
        .await
        .expect("return the exact live request cleanup lease");
    assert_eq!(first_cleanup.job_state, "leased");
    assert!(
        database
            .claim_next_mount_staging_cleanup(tenant_id, backend_id, worker_two)
            .await
            .expect("exclude another maintenance claimant")
            .is_none(),
        "a live request-path lease must exclude maintenance claim-next"
    );
    database
        .heartbeat_mount_staging_cleanup(&first_cleanup)
        .await
        .expect("heartbeat exact cleanup lease");
    database
        .mark_mount_staging_cleanup_physical_deleted(&first_cleanup)
        .await
        .expect("persist physical deletion before lock removal");
    let physical_state: (String, String, i64) = sqlx::query_as(
        "SELECT job.state,payload.state,job.attempts \
         FROM filebelt_mount.nfs_staging_cleanup_jobs AS job \
         JOIN public.payload_objects AS payload \
           ON payload.tenant_id=job.tenant_id AND payload.id=job.payload_id \
         WHERE job.tenant_id=$1 AND job.write_session_id=$2",
    )
    .bind(tenant_id)
    .bind(aborted_writer.fence.write_session_id)
    .fetch_one(database.pool())
    .await
    .expect("read physical-deleted cleanup state");
    assert_eq!(
        physical_state,
        ("physical_deleted".into(), "deleted".into(), 1)
    );
    sqlx::query(
        "UPDATE filebelt_mount.nfs_staging_cleanup_jobs \
         SET lease_expires_at=clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1 AND write_session_id=$2",
    )
    .bind(tenant_id)
    .bind(aborted_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("simulate crash after physical-deleted marker");
    let reclaimed = database
        .claim_next_mount_staging_cleanup(tenant_id, backend_id, worker_two)
        .await
        .expect("reclaim physical-deleted cleanup after lease expiry")
        .expect("physical-deleted cleanup remains discoverable");
    assert_eq!(reclaimed.job_state, "physical_deleted");
    assert!(reclaimed.job_fencing_token > first_cleanup.job_fencing_token);
    assert!(
        database
            .heartbeat_mount_staging_cleanup(&first_cleanup)
            .await
            .is_err(),
        "the prior worker cannot extend a reclaimed cleanup lease"
    );
    assert!(
        database
            .complete_mount_staging_cleanup(&first_cleanup)
            .await
            .is_err(),
        "the prior worker cannot finish a reclaimed cleanup"
    );
    database
        .mark_mount_staging_cleanup_physical_deleted(&reclaimed)
        .await
        .expect("idempotently confirm physical deletion after crash");
    database
        .complete_mount_staging_cleanup(&reclaimed)
        .await
        .expect("complete after verified lock removal");
    database
        .complete_mount_staging_cleanup(&reclaimed)
        .await
        .expect("exact cleanup completion retry is idempotent");
    let completed_attempts: i64 = sqlx::query_scalar(
        "SELECT attempts FROM filebelt_mount.nfs_staging_cleanup_jobs \
         WHERE tenant_id=$1 AND write_session_id=$2 AND state='completed'",
    )
    .bind(tenant_id)
    .bind(aborted_writer.fence.write_session_id)
    .fetch_one(database.pool())
    .await
    .expect("read completed cleanup attempts");
    assert_eq!(completed_attempts, 2);

    // Recover a job whose direct DeleteStaging path already marked the payload
    // deleted before its durable cleanup/lock acknowledgement.
    sqlx::query(
        "SELECT filebelt_mount.enqueue_nfs_staging_cleanup($1,$2,'delete_staging_retry',NULL)",
    )
    .bind(tenant_id)
    .bind(deleted_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("enqueue already-deleted payload cleanup");
    let deleted_cleanup = database
        .claim_next_mount_staging_cleanup(tenant_id, backend_id, worker_two)
        .await
        .expect("claim already-deleted payload cleanup")
        .expect("already-deleted cleanup remains discoverable");
    assert_eq!(deleted_cleanup.payload.state, "deleted");
    database
        .mark_mount_staging_cleanup_physical_deleted(&deleted_cleanup)
        .await
        .expect("idempotently mark an already-deleted payload");
    database
        .complete_mount_staging_cleanup(&deleted_cleanup)
        .await
        .expect("complete already-deleted payload cleanup");

    let deleting_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "deleting",
        "expired",
        "deleting",
    )
    .await;
    sqlx::query(
        "SELECT filebelt_mount.enqueue_nfs_staging_cleanup($1,$2,'delete_staging_retry',NULL)",
    )
    .bind(tenant_id)
    .bind(deleting_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("enqueue deleting payload cleanup");
    let deleting_cleanup = database
        .claim_next_mount_staging_cleanup(tenant_id, backend_id, worker_two)
        .await
        .expect("claim deleting payload cleanup")
        .expect("deleting cleanup remains discoverable");
    assert_eq!(deleting_cleanup.payload.state, "deleting");
    database
        .mark_mount_staging_cleanup_physical_deleted(&deleting_cleanup)
        .await
        .expect("finish a deletion that crashed in deleting state");
    let same_physical_cleanup = database
        .claim_mount_staging_cleanup(
            tenant_id,
            backend_id,
            deleting_writer.fence.write_session_id,
            worker_two,
        )
        .await
        .expect("re-enter physical-deleted phase before lock acknowledgement");
    assert_eq!(same_physical_cleanup.job_state, "physical_deleted");
    database
        .complete_mount_staging_cleanup(&same_physical_cleanup)
        .await
        .expect("complete after simulated lock-removal crash retry");

    // An expired unknown receipt enters exactly the same lease machine rather
    // than a separate request-path completion transition.
    let request_cleanup_writer = insert_test_mount_writer(
        &database,
        &first_session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "request-cleanup",
        "expired",
        "abandoned",
    )
    .await;
    sqlx::query(
        "UPDATE filebelt_mount.write_sessions \
         SET created_at=clock_timestamp()-interval '2 hours',\
             expires_at=clock_timestamp()-interval '1 hour',\
             lease_expires_at=clock_timestamp()-interval '1 hour' \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(request_cleanup_writer.fence.write_session_id)
    .execute(database.pool())
    .await
    .expect("expire request cleanup writer");
    let request_nonce = [111_u8; 32];
    let request_claims = [112_u8; 32];
    let request_capability_id = Uuid::new_v4();
    insert_pending_terminal_io_receipt(
        &database,
        &request_cleanup_writer,
        MountIoOperation::Abort,
        request_capability_id,
        &request_nonce,
        &request_claims,
        true,
    )
    .await;
    let request_input = BeginMountIoOperationInput {
        fence: &request_cleanup_writer.fence,
        capability_id: request_capability_id,
        nonce_digest: &request_nonce,
        claims_digest: &request_claims,
        operation: MountIoOperation::Abort,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: 2_000_000_000,
    };
    let request_cleanup = match database
        .begin_mount_io_operation(&request_input)
        .await
        .expect("fence an expired pending request into cleanup")
    {
        MountIoAdmission::CleanupRequired(cleanup) => cleanup,
        _ => panic!("expired pending request must require cleanup"),
    };
    assert_eq!(
        request_cleanup.storage.staging_payload.backend_id,
        backend_id
    );
    let request_job = database
        .claim_mount_staging_cleanup(
            request_cleanup.tenant_id,
            request_cleanup.storage.staging_payload.backend_id,
            request_cleanup.write_session_id,
            worker_two,
        )
        .await
        .expect("request path exact-claims the shared cleanup job");
    assert_eq!(request_job.source_nonce_digest, Some(request_nonce));
    database
        .mark_mount_staging_cleanup_physical_deleted(&request_job)
        .await
        .expect("mark request cleanup physical deletion");
    database
        .complete_mount_staging_cleanup(&request_job)
        .await
        .expect("complete request cleanup after lock removal");
    assert_eq!(
        database
            .lookup_mount_io_completion(&request_input)
            .await
            .expect("lookup cleaned request receipt"),
        MountIoLookup::Completed(MountIoCompletion::Cleanup)
    );

    assert_nfs_read_only_handle_authority(
        &database,
        &inherited_vfs_database,
        &first_session,
        tenant_id,
        principal_id,
        group_id,
        drive_id,
        root_node_id,
        backend_id,
        gateway_epoch,
        &binding_digest,
    )
    .await;

    assert!(
        database
            .stage_nfs_export(
                tenant_id,
                principal_id,
                drive_id,
                staged.desired_generation,
                NfsExportState::Draining,
            )
            .await
            .is_err(),
        "an export cannot drain before the gateway drain is durable"
    );
    let replay_mapping = database
        .list_nfs_principal_mappings(tenant_id)
        .await
        .expect("list mappings for replay revocation race")
        .into_iter()
        .find(|record| record.kerberos_principal == "second_alias@EXAMPLE.TEST")
        .expect("active secondary mapping for replay revocation race");
    let replay_binding_digest = [53_u8; 32];
    let replay_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "second_alias@EXAMPLE.TEST",
            gss_binding_digest: &replay_binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.44",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("create mapping-revocation replay session");
    let revocation_request_digest = [54_u8; 32];
    let revocation_context = NfsReplayContext {
        tenant_id,
        mount_session_id: replay_session.session.session_id,
        client_id: "nfs-client-revocation-race",
        nfs_session_id: "nfs-session-revocation-race",
        slot_id: 1,
        sequence_id: 1,
        operation_index: 0,
        operation: "stat",
        request_digest: &revocation_request_digest,
        gateway_epoch,
    };
    let revocation_replay = database
        .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
            context: revocation_context.clone(),
            response_bytes: &[0x08, 0x07],
            response_digest: &[55_u8; 32],
        })
        .await
        .expect("persist mapping-revocation replay receipt");
    let revocation_resolution = database
        .resolve_nfs_handle(
            &replay_session.session,
            &replay_binding_digest,
            7,
            root_node_id,
            Some(1),
        )
        .await
        .expect("resolve current replay revocation resource");
    let (revocation_drive_acl, revocation_drive_namespace): (i64, i64) = sqlx::query_as(
        "SELECT acl_generation,namespace_generation FROM drives \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .fetch_one(database.pool())
    .await
    .expect("read current replay revocation drive generations");
    let revocation_authorization = NfsMutationAuthorization {
        drive_id,
        resource_id: root_node_id,
        membership_generation: replay_session.session.membership_generation,
        drive_acl_generation: revocation_drive_acl,
        drive_namespace_generation: revocation_drive_namespace,
        resource_acl_generation: revocation_resolution.target.acl_generation,
        resource_namespace_generation: revocation_resolution.target.namespace_generation,
    };
    let mut revocation_barrier = database
        .pool()
        .begin()
        .await
        .expect("begin mapping-revocation replay barrier");
    sqlx::query(
        "SELECT 1 FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND credential_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(replay_mapping.credential_id)
    .execute(&mut *revocation_barrier)
    .await
    .expect("lock replay mapping before revocation");
    let revoker = Database::connect(
        &postgres_url_with_application_name(&database_url, "nfs_replay_mapping_revoker"),
        1,
    )
    .await
    .expect("connect replay mapping revoker");
    let revoker_task = tokio::spawn(async move {
        revoker
            .revoke_nfs_principal_mapping(
                tenant_id,
                principal_id,
                replay_mapping.credential_id,
                replay_mapping.generation,
            )
            .await
    });
    wait_for_postgres_lock(
        database.pool(),
        "nfs_replay_mapping_revoker",
        "update filebelt_mount.nfs_principal_mappings",
    )
    .await;
    assert_eq!(
        database
            .select_authorized_nfs_replay_receipt(
                &replay_session.session,
                &replay_binding_digest,
                &revocation_context,
                std::slice::from_ref(&revocation_authorization),
                None,
            )
            .await
            .expect("selection linearizes before blocked mapping revocation"),
        Some(revocation_replay)
    );
    revocation_barrier
        .commit()
        .await
        .expect("release replay mapping revocation barrier");
    revoker_task
        .await
        .expect("join replay mapping revoker")
        .expect("commit replay mapping revocation");
    assert!(matches!(
        database
            .select_authorized_nfs_replay_receipt(
                &replay_session.session,
                &replay_binding_digest,
                &revocation_context,
                std::slice::from_ref(&revocation_authorization),
                None,
            )
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    let first_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "Nfs_User@EXAMPLE.TEST",
            gss_binding_digest: &binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.42",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("refresh primary NFS session after alias policy generation change");
    database
        .drain_mount_gateway_epoch(
            tenant_id,
            "nfs",
            "nfs",
            "nfs-gateway-0",
            gateway_epoch,
            "rolling_restart",
        )
        .await
        .expect("persist NFS gateway drain");
    database
        .admit_mount_session(
            tenant_id,
            first_session.session.session_id,
            "nfs",
            "nfs-gateway-0",
            gateway_epoch,
            first_session.session.credential_generation,
            first_session.session.authorization_generation,
            Some(&binding_digest),
        )
        .await
        .expect("admit an existing NFS session during its bounded gateway drain");
    assert!(matches!(
        database
            .claim_mount_gateway_epoch(tenant_id, "nfs", "nfs", "nfs-gateway-0")
            .await,
        Err(DatabaseError::AdmissionLimited)
    ));
    assert!(matches!(
        database
            .create_nfs_mount_session(&CreateNfsMountSessionInput {
                tenant_id,
                kerberos_principal: "Nfs_User@EXAMPLE.TEST",
                gss_binding_digest: &[18_u8; 32],
                gateway_id: "nfs-gateway-0",
                gateway_epoch,
                source_address: "192.0.2.43",
                gss_expires_at_unix_seconds: 2_000_000_000,
            })
            .await,
        Err(DatabaseError::NotFound)
    ));
    let feature = database
        .transition_nfs_feature_state(
            tenant_id,
            principal_id,
            feature.generation,
            NfsFeatureState::Draining,
        )
        .await
        .expect("fence sessions before changing the active export manifest");
    let session_state: String = sqlx::query_scalar(
        "SELECT state FROM filebelt_mount.sessions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(first_session.session.session_id)
    .fetch_one(database.pool())
    .await
    .expect("read feature-fenced NFS session");
    assert_eq!(session_state, "draining");
    database
        .admit_mount_session(
            tenant_id,
            first_session.session.session_id,
            "nfs",
            "nfs-gateway-0",
            gateway_epoch,
            first_session.session.credential_generation,
            first_session.session.authorization_generation,
            Some(&binding_digest),
        )
        .await
        .expect("admit an existing NFS session during the feature drain deadline");
    let draining = database
        .stage_nfs_export(
            tenant_id,
            principal_id,
            drive_id,
            staged.desired_generation,
            NfsExportState::Draining,
        )
        .await
        .expect("stage export drain");
    assert!(matches!(
        database
            .stage_nfs_export(
                tenant_id,
                principal_id,
                drive_id,
                draining.desired_generation,
                NfsExportState::Disabled,
            )
            .await,
        Err(DatabaseError::Conflict)
    ));
    let draining_manifest = database
        .nfs_export_manifest(tenant_id)
        .await
        .expect("read desired drain manifest generation");
    assert!(draining_manifest.exports.is_empty());
    database
        .reconcile_nfs_export_manifest(&ReconcileNfsExportManifestInput {
            tenant_id,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            feature_generation: draining_manifest.feature_generation,
            manifest_generation: draining_manifest.manifest_generation,
            manifest_digest: &[43_u8; 32],
            export_ids: &[],
            export_generations: &[],
            root_handle_digests: &[],
        })
        .await
        .expect("reconcile the exact whole-set export drain");
    database
        .stage_nfs_export(
            tenant_id,
            principal_id,
            drive_id,
            draining.desired_generation,
            NfsExportState::Disabled,
        )
        .await
        .expect("disable only after drain reconciliation");
    let disabled_authority = database
        .nfs_feature_state(tenant_id)
        .await
        .expect("read desired disabled manifest generation");
    database
        .reconcile_nfs_export_manifest(&ReconcileNfsExportManifestInput {
            tenant_id,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            feature_generation: disabled_authority.generation,
            manifest_generation: disabled_authority.manifest_generation,
            manifest_digest: &[44_u8; 32],
            export_ids: &[],
            export_generations: &[],
            root_handle_digests: &[],
        })
        .await
        .expect("acknowledge the exact disabled export manifest");
    database
        .transition_nfs_feature_state(
            tenant_id,
            principal_id,
            feature.generation,
            NfsFeatureState::Disabled,
        )
        .await
        .expect("disable NFS only after all exports are reconciled disabled");
    let restore_generation = database
        .advance_nfs_restore_generation(tenant_id, 1)
        .await
        .expect("advance recovery-only NFS restore generation while disabled");
    assert_eq!(restore_generation, 2);
    let disabled_feature = database
        .nfs_feature_state(tenant_id)
        .await
        .expect("read post-restore NFS authority fence");
    assert_eq!(disabled_feature.restore_generation, 2);
    assert!(matches!(
        database.nfs_export_manifest(tenant_id).await,
        Err(DatabaseError::AdmissionLimited)
    ));
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

    let revoke_fingerprint = [9_u8; 32];
    let revoke_idempotency = NfsAdminIdempotency {
        principal_id,
        route: "DELETE /api/v1/admin/mounts/nfs/mappings/{credential_id}",
        key: "revoke-primary-mapping",
        request_fingerprint: &revoke_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 204,
    };
    let created_revoke = expect_idempotent_created(
        inherited_api_database
            .revoke_nfs_principal_mapping_idempotent(
                tenant_id,
                principal_id,
                mapping.credential_id,
                mapping.generation,
                &revoke_idempotency,
                || serde_json::to_value(()),
            )
            .await
            .expect("revoke NFS mapping idempotently"),
    );
    assert_eq!(created_revoke.response_status, 204);
    assert_eq!(created_revoke.response_body, Value::Null);
    let replayed_revoke = expect_idempotent_replayed(
        inherited_api_database
            .revoke_nfs_principal_mapping_idempotent(
                tenant_id,
                principal_id,
                mapping.credential_id,
                mapping.generation,
                &revoke_idempotency,
                || panic!("an exact revoke retry must not rerender"),
            )
            .await
            .expect("replay NFS mapping revocation"),
    );
    assert_eq!(replayed_revoke.response_status, 204);
    assert_eq!(replayed_revoke.response_body, Value::Null);
    let revoked_mapping: (i64, bool) = sqlx::query_as(
        "SELECT generation,revoked_at IS NOT NULL FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND credential_id=$2",
    )
    .bind(tenant_id)
    .bind(mapping.credential_id)
    .fetch_one(database.pool())
    .await
    .expect("read idempotently revoked NFS mapping");
    assert_eq!(revoked_mapping, (mapping.generation + 1, true));

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
    inherited_vfs_database.pool().close().await;
    inherited_vfs_pool.close().await;
    inherited_io_pool.close().await;
    inherited_api_database.pool().close().await;
    sqlx::raw_sql(
        "DROP ROLE filebelt_nfs_mount_it_vfs_login;\
         DROP ROLE filebelt_nfs_mount_it_io_login;\
         DROP ROLE filebelt_nfs_mount_it_api_login;",
    )
    .execute(database.pool())
    .await
    .expect("drop deployment-like inherited NFS login roles");
}

#[allow(clippy::too_many_arguments)]
async fn assert_nfs_conflict_admin_idempotency(
    database: &Database,
    inherited_api_database: &Database,
    session: &NfsMountSessionProjection,
    tenant_id: Uuid,
    user_id: Uuid,
    actor_principal_id: Uuid,
    drive_id: Uuid,
    root_node_id: Uuid,
    backend_id: Uuid,
) {
    let api_session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.api_sessions \
         (tenant_id,id,user_id,principal_id,token_key_generation,token_digest,csrf_digest,\
          idle_expires_at,absolute_expires_at) \
         VALUES ($1,$2,$3,$4,1,$5,$6,clock_timestamp()+interval '15 minutes',\
                 clock_timestamp()+interval '1 hour')",
    )
    .bind(tenant_id)
    .bind(api_session_id)
    .bind(user_id)
    .bind(actor_principal_id)
    .bind(vec![181_u8; 32])
    .bind(vec![182_u8; 32])
    .execute(database.pool())
    .await
    .expect("insert NFS conflict API session");
    let generations: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT principal.generation,drive.acl_generation,drive.namespace_generation,\
                node.acl_generation,node.namespace_generation \
         FROM public.principals AS principal \
         JOIN public.drives AS drive ON drive.tenant_id=principal.tenant_id \
         JOIN public.nodes AS node ON node.tenant_id=drive.tenant_id AND node.drive_id=drive.id \
         WHERE principal.tenant_id=$1 AND principal.id=$2 \
           AND drive.id=$3 AND node.id=$4",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .bind(drive_id)
    .bind(root_node_id)
    .fetch_one(database.pool())
    .await
    .expect("read NFS conflict-copy authorization generations");

    let copy_writer = insert_test_mount_writer(
        database,
        session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "conflict-copy",
        "conflicted",
        "finalized",
    )
    .await;
    let copy_conflict_id =
        insert_retained_nfs_conflict(database, session, &copy_writer, false).await;
    let listed = inherited_api_database
        .list_nfs_write_conflicts(tenant_id, actor_principal_id)
        .await
        .expect("list caller-owned retained NFS conflict");
    assert!(
        listed
            .iter()
            .any(|conflict| conflict.id == copy_conflict_id)
    );
    let copy_fingerprint = [183_u8; 32];
    let copy_idempotency = NfsAdminIdempotency {
        principal_id: actor_principal_id,
        route: "POST /api/v1/admin/mounts/nfs/conflicts/{conflict_id}/copy",
        key: "copy-retained-conflict",
        request_fingerprint: &copy_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let copy_input = filebelt_database::mount::CopyNfsWriteConflictInput {
        tenant_id,
        actor_principal_id,
        api_session_id,
        conflict_id: copy_conflict_id,
        authorization: filebelt_database::mount::NfsMutationAuthorization {
            drive_id,
            resource_id: root_node_id,
            membership_generation: generations.0,
            drive_acl_generation: generations.1,
            drive_namespace_generation: generations.2,
            resource_acl_generation: generations.3,
            resource_namespace_generation: generations.4,
        },
        display_name: "Recovered conflict.txt",
    };
    let created_copy = expect_idempotent_created(
        inherited_api_database
            .copy_nfs_write_conflict_idempotent(&copy_input, &copy_idempotency, |record| {
                serde_json::to_value(json!({
                    "conflict_id":record.conflict_id,
                    "drive_id":record.drive_id,
                    "node_id":record.node_id,
                    "version_id":record.version_id,
                    "display_name":record.display_name,
                    "size_bytes":record.size_bytes,
                    "blake3":record.blake3,
                }))
            })
            .await
            .expect("copy retained conflict idempotently"),
    );
    let replayed_copy = expect_idempotent_replayed(
        inherited_api_database
            .copy_nfs_write_conflict_idempotent(&copy_input, &copy_idempotency, |_| {
                panic!("exact conflict-copy replay must not allocate another node")
            })
            .await
            .expect("replay retained conflict copy"),
    );
    assert_eq!(replayed_copy.response_body, created_copy.response_body);
    let copied_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM public.nodes WHERE tenant_id=$1 AND drive_id=$2 \
              AND parent_id=$3 AND display_name='Recovered conflict.txt'),\
           (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 \
              AND action='mount.nfs.conflict.copy' AND resource_id=($4::uuid)),\
           (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 \
              AND principal_id=$5 AND route=$6 AND key=$7)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_node_id)
    .bind(
        created_copy.response_body["node_id"]
            .as_str()
            .expect("copied node UUID"),
    )
    .bind(actor_principal_id)
    .bind(copy_idempotency.route)
    .bind(copy_idempotency.key)
    .fetch_one(database.pool())
    .await
    .expect("count atomic conflict-copy effects");
    assert_eq!(copied_counts, (1, 1, 1));

    let discard_writer = insert_test_mount_writer(
        database,
        session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "conflict-discard",
        "conflicted",
        "finalized",
    )
    .await;
    let discard_conflict_id =
        insert_retained_nfs_conflict(database, session, &discard_writer, false).await;
    let discard_fingerprint = [184_u8; 32];
    let discard_idempotency = NfsAdminIdempotency {
        principal_id: actor_principal_id,
        route: "DELETE /api/v1/admin/mounts/nfs/conflicts/{conflict_id}",
        key: "discard-retained-conflict",
        request_fingerprint: &discard_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 204,
    };
    let created_discard = expect_idempotent_created(
        inherited_api_database
            .discard_nfs_write_conflict_idempotent(
                tenant_id,
                actor_principal_id,
                api_session_id,
                discard_conflict_id,
                &discard_idempotency,
                || serde_json::to_value(()),
            )
            .await
            .expect("discard retained conflict idempotently"),
    );
    assert_eq!(created_discard.response_body, Value::Null);
    let replayed_discard = expect_idempotent_replayed(
        inherited_api_database
            .discard_nfs_write_conflict_idempotent(
                tenant_id,
                actor_principal_id,
                api_session_id,
                discard_conflict_id,
                &discard_idempotency,
                || panic!("exact conflict discard replay must not mutate cleanup authority"),
            )
            .await
            .expect("replay retained conflict discard"),
    );
    assert_eq!(replayed_discard.response_body, Value::Null);
    let discard_state: (String, String, String, i64) = sqlx::query_as(
        "SELECT conflict.state,payload.state,writer.state,\
                (SELECT count(*) FROM public.idempotency_records \
                 WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key=$4) \
         FROM filebelt_mount.nfs_write_conflicts AS conflict \
         JOIN filebelt_mount.write_sessions AS writer \
           ON writer.tenant_id=conflict.tenant_id AND writer.id=conflict.write_session_id \
         JOIN public.payload_objects AS payload \
           ON payload.tenant_id=conflict.tenant_id AND payload.id=conflict.staging_payload_id \
         WHERE conflict.tenant_id=$1 AND conflict.id=$5",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .bind(discard_idempotency.route)
    .bind(discard_idempotency.key)
    .bind(discard_conflict_id)
    .fetch_one(database.pool())
    .await
    .expect("read atomically discarded conflict");
    assert_eq!(
        discard_state,
        ("discarded".into(), "abandoned".into(), "expired".into(), 1)
    );
    complete_test_conflict_cleanup(database, tenant_id, backend_id, &discard_writer).await;

    let rollback_writer = insert_test_mount_writer(
        database,
        session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "conflict-render-rollback",
        "conflicted",
        "finalized",
    )
    .await;
    let rollback_conflict_id =
        insert_retained_nfs_conflict(database, session, &rollback_writer, false).await;
    let rollback_fingerprint = [185_u8; 32];
    let rollback_idempotency = NfsAdminIdempotency {
        principal_id: actor_principal_id,
        route: "POST /api/v1/admin/mounts/nfs/conflicts/{conflict_id}/copy",
        key: "rollback-conflict-copy-response",
        request_fingerprint: &rollback_fingerprint,
        legacy_request_fingerprint: None,
        response_status: 201,
    };
    let rollback_generations: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT principal.generation,drive.acl_generation,drive.namespace_generation,\
                node.acl_generation,node.namespace_generation \
         FROM public.principals AS principal \
         JOIN public.drives AS drive ON drive.tenant_id=principal.tenant_id \
         JOIN public.nodes AS node ON node.tenant_id=drive.tenant_id AND node.drive_id=drive.id \
         WHERE principal.tenant_id=$1 AND principal.id=$2 \
           AND drive.id=$3 AND node.id=$4",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .bind(drive_id)
    .bind(root_node_id)
    .fetch_one(database.pool())
    .await
    .expect("refresh conflict-copy rollback generations");
    let rollback_input = filebelt_database::mount::CopyNfsWriteConflictInput {
        conflict_id: rollback_conflict_id,
        authorization: filebelt_database::mount::NfsMutationAuthorization {
            drive_id,
            resource_id: root_node_id,
            membership_generation: rollback_generations.0,
            drive_acl_generation: rollback_generations.1,
            drive_namespace_generation: rollback_generations.2,
            resource_acl_generation: rollback_generations.3,
            resource_namespace_generation: rollback_generations.4,
        },
        display_name: "Must roll back.txt",
        ..copy_input
    };
    let render_error = serde_json::from_str::<Value>("{")
        .expect_err("invalid JSON must produce a response rendering error");
    assert!(matches!(
        inherited_api_database
            .copy_nfs_write_conflict_idempotent(&rollback_input, &rollback_idempotency, |_| Err(
                render_error
            ),)
            .await,
        Err(DatabaseError::InvalidPersistedValue)
    ));
    let rollback_state: (String, String, String, i64, i64) = sqlx::query_as(
        "SELECT conflict.state,payload.state,writer.state,\
                (SELECT count(*) FROM public.nodes WHERE tenant_id=$1 AND drive_id=$2 \
                   AND parent_id=$3 AND display_name='Must roll back.txt'),\
                (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 \
                   AND principal_id=$4 AND route=$5 AND key=$6) \
         FROM filebelt_mount.nfs_write_conflicts AS conflict \
         JOIN filebelt_mount.write_sessions AS writer \
           ON writer.tenant_id=conflict.tenant_id AND writer.id=conflict.write_session_id \
         JOIN public.payload_objects AS payload \
           ON payload.tenant_id=conflict.tenant_id AND payload.id=conflict.staging_payload_id \
         WHERE conflict.tenant_id=$1 AND conflict.id=$7",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_node_id)
    .bind(actor_principal_id)
    .bind(rollback_idempotency.route)
    .bind(rollback_idempotency.key)
    .bind(rollback_conflict_id)
    .fetch_one(database.pool())
    .await
    .expect("verify conflict-copy response failure rollback");
    assert_eq!(
        rollback_state,
        (
            "retained".into(),
            "finalized".into(),
            "conflicted".into(),
            0,
            0
        )
    );

    let expired_writer = insert_test_mount_writer(
        database,
        session,
        tenant_id,
        drive_id,
        root_node_id,
        backend_id,
        "conflict-expiry",
        "conflicted",
        "finalized",
    )
    .await;
    let expired_conflict_id =
        insert_retained_nfs_conflict(database, session, &expired_writer, true).await;
    let swept = database
        .sweep_expired_nfs_write_conflicts(tenant_id, 10)
        .await
        .expect("sweep expired retained NFS conflict");
    assert!(
        swept
            .iter()
            .any(|record| record.conflict_id == expired_conflict_id)
    );
    let swept_state: (String, String, String, i64) = sqlx::query_as(
        "SELECT conflict.state,payload.state,writer.state,\
                (SELECT count(*) FROM filebelt_mount.nfs_staging_cleanup_jobs \
                 WHERE tenant_id=$1 AND write_session_id=writer.id) \
         FROM filebelt_mount.nfs_write_conflicts AS conflict \
         JOIN filebelt_mount.write_sessions AS writer \
           ON writer.tenant_id=conflict.tenant_id AND writer.id=conflict.write_session_id \
         JOIN public.payload_objects AS payload \
           ON payload.tenant_id=conflict.tenant_id AND payload.id=conflict.staging_payload_id \
         WHERE conflict.tenant_id=$1 AND conflict.id=$2",
    )
    .bind(tenant_id)
    .bind(expired_conflict_id)
    .fetch_one(database.pool())
    .await
    .expect("read expired conflict sweep result");
    assert_eq!(
        swept_state,
        ("expired".into(), "abandoned".into(), "expired".into(), 1)
    );
    complete_test_conflict_cleanup(database, tenant_id, backend_id, &expired_writer).await;
}

async fn complete_test_conflict_cleanup(
    database: &Database,
    tenant_id: Uuid,
    backend_id: Uuid,
    writer: &TestMountWriter,
) {
    let cleanup_worker_id = Uuid::new_v4();
    let cleanup = database
        .claim_mount_staging_cleanup(
            tenant_id,
            backend_id,
            writer.fence.write_session_id,
            cleanup_worker_id,
        )
        .await
        .expect("claim swept conflict cleanup fixture");
    database
        .mark_mount_staging_cleanup_physical_deleted(&cleanup)
        .await
        .expect("mark swept conflict payload physically deleted");
    database
        .complete_mount_staging_cleanup(&cleanup)
        .await
        .expect("complete swept conflict cleanup fixture");
}

async fn insert_retained_nfs_conflict(
    database: &Database,
    session: &NfsMountSessionProjection,
    writer: &TestMountWriter,
    expired: bool,
) -> Uuid {
    let conflict_id = Uuid::new_v4();
    let (payload_id, logical_size_bytes): (Uuid, i64) = sqlx::query_as(
        "SELECT staging_payload_id,logical_size_bytes \
         FROM filebelt_mount.write_sessions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(writer.fence.tenant_id)
    .bind(writer.fence.write_session_id)
    .fetch_one(database.pool())
    .await
    .expect("read retained conflict staging payload");
    let restore_generation: i64 = sqlx::query_scalar(
        "SELECT restore_generation FROM filebelt_mount.nfs_feature_state WHERE tenant_id=$1",
    )
    .bind(writer.fence.tenant_id)
    .fetch_one(database.pool())
    .await
    .expect("read retained conflict restore generation");
    let query = if expired {
        sqlx::query(
            "INSERT INTO filebelt_mount.nfs_write_conflicts \
             (tenant_id,id,write_session_id,mount_session_id,drive_id,node_id,staging_payload_id,\
              logical_size_bytes,gateway_epoch,restore_generation,created_at,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,\
                     statement_timestamp()-interval '8 days',\
                     statement_timestamp()-interval '1 day')",
        )
    } else {
        sqlx::query(
            "INSERT INTO filebelt_mount.nfs_write_conflicts \
             (tenant_id,id,write_session_id,mount_session_id,drive_id,node_id,staging_payload_id,\
              logical_size_bytes,gateway_epoch,restore_generation,created_at,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,\
                     statement_timestamp(),statement_timestamp()+interval '7 days')",
        )
    };
    query
        .bind(writer.fence.tenant_id)
        .bind(conflict_id)
        .bind(writer.fence.write_session_id)
        .bind(session.session.session_id)
        .bind(writer.fence.drive_id)
        .bind(writer.fence.node_id)
        .bind(payload_id)
        .bind(logical_size_bytes)
        .bind(writer.fence.gateway_epoch)
        .bind(restore_generation)
        .execute(database.pool())
        .await
        .expect("insert retained NFS conflict fixture");
    conflict_id
}

#[allow(clippy::too_many_arguments)]
async fn assert_nfs_alias_identity_authority(
    database: &Database,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    primary_group_id: Uuid,
    drive_id: Uuid,
    projected_uid: i64,
    projected_gid: i64,
) {
    let alias = approve_test_nfs_mapping(
        database,
        tenant_id,
        actor_principal_id,
        actor_principal_id,
        "second_alias@EXAMPLE.TEST",
        projected_uid,
        projected_gid,
        &[drive_id],
    )
    .await;
    let alias_identities: Vec<(String, String, i64, Uuid, i64)> = sqlx::query_as(
        "SELECT mapping.kerberos_principal,mapping.posix_name,mapping.projected_uid,\
                mapping.posix_group_id,mapping.projected_gid \
         FROM filebelt_mount.nfs_principal_mappings AS mapping \
         WHERE mapping.tenant_id=$1 AND mapping.principal_id=$2 \
           AND mapping.revoked_at IS NULL ORDER BY mapping.kerberos_principal",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .fetch_all(database.pool())
    .await
    .expect("read active NFS aliases");
    assert_eq!(alias_identities.len(), 2);
    assert!(alias_identities.iter().all(|identity| {
        identity.1 == "nfs_user"
            && identity.2 == projected_uid
            && identity.3 == primary_group_id
            && identity.4 == projected_gid
    }));
    database
        .revoke_nfs_principal_mapping(
            tenant_id,
            actor_principal_id,
            alias.credential_id,
            alias.generation,
        )
        .await
        .expect("revoke one alias without disabling its sibling");
    let policy_enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM filebelt_mount.policies \
         WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("read shared NFS alias policy");
    assert!(
        policy_enabled,
        "one revoked alias must not disable its sibling"
    );
    let reactivated = approve_test_nfs_mapping(
        database,
        tenant_id,
        actor_principal_id,
        actor_principal_id,
        "second_alias@EXAMPLE.TEST",
        projected_uid,
        projected_gid,
        &[drive_id],
    )
    .await;
    assert_eq!(reactivated.generation, alias.generation + 2);
    assert!(matches!(
        database
            .upsert_nfs_principal_mapping(&UpsertNfsPrincipalMappingInput {
                tenant_id,
                actor_principal_id,
                principal_id: actor_principal_id,
                kerberos_principal: "second_alias@EXAMPLE.TEST",
                projected_uid: projected_uid + 1,
                projected_gid,
                allowed_drive_ids: &[drive_id],
                expected_generation: Some(reactivated.generation),
            })
            .await,
        Err(DatabaseError::Conflict)
    ));
    let active_alias_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("count active aliases after exact reactivation");
    assert_eq!(active_alias_count, 2);
}

#[allow(clippy::too_many_arguments)]
async fn assert_nfs_read_only_handle_authority(
    database: &Database,
    inherited_vfs_database: &Database,
    writable_session: &NfsMountSessionProjection,
    tenant_id: Uuid,
    admin_principal_id: Uuid,
    primary_group_id: Uuid,
    drive_id: Uuid,
    root_node_id: Uuid,
    backend_id: Uuid,
    gateway_epoch: i64,
    writable_binding_digest: &[u8; 32],
) {
    // The established writable path must still use the mutation authorizer.
    let writable_node_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) \
         VALUES ($1,$2,$3,$4,'file','writable-open','writable-open')",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(writable_node_id)
    .bind(root_node_id)
    .execute(database.pool())
    .await
    .expect("insert writable-open file");
    let writable_generations: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT drive.acl_generation,drive.namespace_generation,\
                node.acl_generation,node.namespace_generation \
         FROM public.drives AS drive JOIN public.nodes AS node \
           ON node.tenant_id=drive.tenant_id AND node.drive_id=drive.id \
         WHERE drive.tenant_id=$1 AND drive.id=$2 AND node.id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(writable_node_id)
    .fetch_one(database.pool())
    .await
    .expect("read writable-open generations");
    let writable_request_digest = [131_u8; 32];
    let writable_response_digest = [132_u8; 32];
    let writable_conflict_digest = [133_u8; 32];
    let writable_actions = vec!["WRITE_CONTENT".to_owned(), "CREATE_VERSION".to_owned()];
    let writable_open = inherited_vfs_database
        .open_nfs_mount_handle(&OpenNfsHandleInput {
            session: &writable_session.session,
            gss_binding_digest: writable_binding_digest,
            replay: RecordNfsReplayReceiptInput {
                context: NfsReplayContext {
                    tenant_id,
                    mount_session_id: writable_session.session.session_id,
                    client_id: "nfs-writable-open-client",
                    nfs_session_id: "nfs-writable-open-session",
                    slot_id: 12,
                    sequence_id: 1,
                    operation_index: 3,
                    operation: "open",
                    request_digest: &writable_request_digest,
                    gateway_epoch,
                },
                response_bytes: &[0x08, 0x51],
                response_digest: &writable_response_digest,
            },
            conflict_response_bytes: &[0x08, 0x52],
            conflict_response_digest: &writable_conflict_digest,
            handle_id: Uuid::new_v4(),
            authorization: filebelt_database::mount::NfsMutationAuthorization {
                drive_id,
                resource_id: writable_node_id,
                membership_generation: writable_session.session.membership_generation,
                drive_acl_generation: writable_generations.0,
                drive_namespace_generation: writable_generations.1,
                resource_acl_generation: writable_generations.2,
                resource_namespace_generation: writable_generations.3,
            },
            expected_version_id: None,
            access_actions: &writable_actions,
            share_read: true,
            share_write: true,
            share_delete: true,
        })
        .await
        .expect("open writable handle through inherited VFS login");
    assert!(writable_open.handle.is_some());
    assert!(!writable_open.replayed);

    let read_principal_id = Uuid::new_v4();
    let read_user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user')")
        .bind(tenant_id)
        .bind(read_principal_id)
        .execute(database.pool())
        .await
        .expect("insert read-only NFS principal");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) \
         VALUES ($1,$2,$3,'Read-only NFS user')",
    )
    .bind(tenant_id)
    .bind(read_user_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("insert read-only NFS user");
    sqlx::query(
        "INSERT INTO public.group_memberships (tenant_id,group_id,user_principal_id,role) \
         VALUES ($1,$2,$3,'member')",
    )
    .bind(tenant_id)
    .bind(primary_group_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("insert read-only NFS primary-group membership");
    let read_mapping = approve_test_nfs_mapping(
        database,
        tenant_id,
        admin_principal_id,
        read_principal_id,
        "readonly_user@EXAMPLE.TEST",
        43_000,
        42_000,
        &[drive_id],
    )
    .await;
    sqlx::query(
        "UPDATE filebelt_mount.policies \
         SET read_only=true,authorization_generation=authorization_generation+1,\
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'",
    )
    .bind(tenant_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("make read-only NFS policy authoritative");
    sqlx::query(
        "UPDATE filebelt_mount.credentials SET read_only=true \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_mapping.credential_id)
    .execute(database.pool())
    .await
    .expect("make read-only NFS credential authoritative");
    let read_generations_aligned: bool = sqlx::query_scalar(
        "SELECT credential.authorization_generation=policy.authorization_generation \
         FROM filebelt_mount.credentials AS credential \
         JOIN filebelt_mount.policies AS policy \
           ON policy.tenant_id=credential.tenant_id \
          AND policy.principal_id=credential.principal_id \
          AND policy.protocol=credential.protocol \
         WHERE credential.tenant_id=$1 AND credential.id=$2 \
           AND credential.read_only AND policy.read_only",
    )
    .bind(tenant_id)
    .bind(read_mapping.credential_id)
    .fetch_one(database.pool())
    .await
    .expect("verify read-only policy and credential generations");
    assert!(read_generations_aligned);
    let read_binding_digest = [134_u8; 32];
    let mut read_session = database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id,
            kerberos_principal: "readonly_user@EXAMPLE.TEST",
            gss_binding_digest: &read_binding_digest,
            gateway_id: "nfs-gateway-0",
            gateway_epoch,
            source_address: "192.0.2.82",
            gss_expires_at_unix_seconds: 2_000_000_000,
        })
        .await
        .expect("create read-only NFS session");
    assert!(read_session.session.read_only);

    let read_node_id = Uuid::new_v4();
    let payload_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let content_digest = [135_u8; 32];
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) \
         VALUES ($1,$2,$3,$4,'file','read-only-open','read-only-open',$5)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(read_node_id)
    .bind(root_node_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("insert read-only-open file");
    sqlx::query(
        "INSERT INTO public.payload_objects \
         (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3) \
         VALUES ($1,$2,$3,$4,$5,'whole','finalized',0,$6)",
    )
    .bind(tenant_id)
    .bind(payload_id)
    .bind(drive_id)
    .bind(backend_id)
    .bind(Uuid::new_v4())
    .bind(content_digest.as_slice())
    .execute(database.pool())
    .await
    .expect("insert read-only-open payload");
    sqlx::query(
        "INSERT INTO public.file_versions \
         (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,created_by) \
         VALUES ($1,$2,$3,1,$4,0,$5,$6)",
    )
    .bind(tenant_id)
    .bind(read_node_id)
    .bind(version_id)
    .bind(payload_id)
    .bind(content_digest.as_slice())
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("insert read-only-open version");
    sqlx::query(
        "UPDATE public.nodes SET head_version_id=$4 \
         WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(read_node_id)
    .bind(version_id)
    .execute(database.pool())
    .await
    .expect("publish read-only-open version");
    sqlx::query(
        "UPDATE public.nodes SET namespace_generation=namespace_generation+7 \
         WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(read_node_id)
    .execute(database.pool())
    .await
    .expect("make drive and node namespace generations observably distinct");
    let read_authorization = {
        let generations: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT drive.acl_generation,drive.namespace_generation,\
                    node.acl_generation,node.namespace_generation \
             FROM public.drives AS drive JOIN public.nodes AS node \
               ON node.tenant_id=drive.tenant_id AND node.drive_id=drive.id \
             WHERE drive.tenant_id=$1 AND drive.id=$2 AND node.id=$3",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(read_node_id)
        .fetch_one(database.pool())
        .await
        .expect("read read-only-open generations");
        assert_ne!(generations.1, generations.3);
        filebelt_database::mount::NfsMutationAuthorization {
            drive_id,
            resource_id: read_node_id,
            membership_generation: read_session.session.membership_generation,
            drive_acl_generation: generations.0,
            drive_namespace_generation: generations.1,
            resource_acl_generation: generations.2,
            resource_namespace_generation: generations.3,
        }
    };
    let common_snapshot = database
        .authorization_snapshot(tenant_id, read_principal_id, drive_id, read_node_id)
        .await
        .expect("read common authorization snapshot for node generation evidence");
    assert_eq!(
        common_snapshot.namespace_generation,
        read_authorization.drive_namespace_generation
    );
    assert_eq!(
        common_snapshot.resource_namespace_generation,
        read_authorization.resource_namespace_generation
    );
    assert_ne!(
        common_snapshot.namespace_generation,
        common_snapshot.resource_namespace_generation
    );
    let nfs_snapshot = database
        .nfs_authorization_snapshot(
            &read_session.session,
            &read_binding_digest,
            drive_id,
            read_node_id,
        )
        .await
        .expect("read NFS authorization snapshot with distinct generations");
    assert_eq!(
        nfs_snapshot.snapshot.namespace_generation,
        read_authorization.drive_namespace_generation
    );
    assert_eq!(
        nfs_snapshot.snapshot.resource_namespace_generation,
        read_authorization.resource_namespace_generation
    );
    let activity_before: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM last_activity_at)*1000000)::bigint \
         FROM filebelt_mount.sessions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .fetch_one(database.pool())
    .await
    .expect("read session activity before read-only Open");
    let read_request_digest = [136_u8; 32];
    let read_response_digest = [137_u8; 32];
    let read_conflict_digest = [138_u8; 32];
    let read_actions = vec!["READ_METADATA".to_owned(), "READ_CONTENT".to_owned()];
    let read_handle_id = Uuid::new_v4();
    let read_input = OpenNfsHandleInput {
        session: &read_session.session,
        gss_binding_digest: &read_binding_digest,
        replay: RecordNfsReplayReceiptInput {
            context: NfsReplayContext {
                tenant_id,
                mount_session_id: read_session.session.session_id,
                client_id: "nfs-readonly-open-client",
                nfs_session_id: "nfs-readonly-open-session",
                slot_id: 13,
                sequence_id: 1,
                operation_index: 3,
                operation: "open",
                request_digest: &read_request_digest,
                gateway_epoch,
            },
            response_bytes: &[0x08, 0x53],
            response_digest: &read_response_digest,
        },
        conflict_response_bytes: &[0x08, 0x54],
        conflict_response_digest: &read_conflict_digest,
        handle_id: read_handle_id,
        authorization: read_authorization.clone(),
        expected_version_id: Some(version_id),
        access_actions: &read_actions,
        share_read: true,
        share_write: true,
        share_delete: true,
    };
    let opened = inherited_vfs_database
        .open_nfs_mount_handle(&read_input)
        .await
        .expect("atomically open read handle through inherited VFS login");
    assert!(!opened.replayed);
    assert_eq!(
        opened.handle.as_ref().map(|handle| handle.id),
        Some(read_handle_id)
    );
    let replayed = inherited_vfs_database
        .open_nfs_mount_handle(&read_input)
        .await
        .expect("replay exact read-only Open response");
    assert!(replayed.replayed);
    assert_eq!(replayed.handle, opened.handle);
    assert_eq!(replayed.replay.response_bytes, opened.replay.response_bytes);
    let activity_after: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM last_activity_at)*1000000)::bigint \
         FROM filebelt_mount.sessions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .fetch_one(database.pool())
    .await
    .expect("read session activity after read-only Open");
    assert!(activity_after > activity_before);

    let mutating_actions = vec!["WRITE_CONTENT".to_owned(), "CREATE_VERSION".to_owned()];
    let bypass = sqlx::query(
        "SELECT user_principal_id FROM filebelt_mount.authorize_nfs_handle_open(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .bind(gateway_epoch)
    .bind(read_binding_digest.as_slice())
    .bind(drive_id)
    .bind(read_node_id)
    .bind(read_authorization.membership_generation)
    .bind(read_authorization.drive_acl_generation)
    .bind(read_authorization.drive_namespace_generation)
    .bind(read_authorization.resource_acl_generation)
    .bind(read_authorization.resource_namespace_generation)
    .bind(&mutating_actions)
    .fetch_one(inherited_vfs_database.pool())
    .await;
    assert!(matches!(
        bypass,
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("42501")
    ));
    let writable_authority = sqlx::query(
        "SELECT user_principal_id FROM filebelt_mount.authorize_nfs_mutation(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .bind(gateway_epoch)
    .bind(read_binding_digest.as_slice())
    .bind(drive_id)
    .bind(read_node_id)
    .bind(read_authorization.membership_generation)
    .bind(read_authorization.drive_acl_generation)
    .bind(read_authorization.drive_namespace_generation)
    .bind(read_authorization.resource_acl_generation)
    .bind(read_authorization.resource_namespace_generation)
    .fetch_one(inherited_vfs_database.pool())
    .await;
    assert!(matches!(
        writable_authority,
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("40001")
    ));
    let write_request_digest = [139_u8; 32];
    let write_response_digest = [140_u8; 32];
    let write_conflict_digest = [141_u8; 32];
    assert!(matches!(
        inherited_vfs_database
            .open_nfs_mount_handle(&OpenNfsHandleInput {
                session: &read_session.session,
                gss_binding_digest: &read_binding_digest,
                replay: RecordNfsReplayReceiptInput {
                    context: NfsReplayContext {
                        tenant_id,
                        mount_session_id: read_session.session.session_id,
                        client_id: "nfs-readonly-write-client",
                        nfs_session_id: "nfs-readonly-write-session",
                        slot_id: 14,
                        sequence_id: 1,
                        operation_index: 3,
                        operation: "open",
                        request_digest: &write_request_digest,
                        gateway_epoch,
                    },
                    response_bytes: &[0x08, 0x55],
                    response_digest: &write_response_digest,
                },
                conflict_response_bytes: &[0x08, 0x56],
                conflict_response_digest: &write_conflict_digest,
                handle_id: Uuid::new_v4(),
                authorization: read_authorization.clone(),
                expected_version_id: Some(version_id),
                access_actions: &mutating_actions,
                share_read: true,
                share_write: true,
                share_delete: true,
            })
            .await,
        Err(DatabaseError::InvalidPersistedValue)
    ));

    let stale_request_digest = [142_u8; 32];
    let stale_response_digest = [143_u8; 32];
    let stale_conflict_digest = [144_u8; 32];
    assert!(matches!(
        inherited_vfs_database
            .open_nfs_mount_handle(&OpenNfsHandleInput {
                session: &read_session.session,
                gss_binding_digest: &read_binding_digest,
                replay: RecordNfsReplayReceiptInput {
                    context: NfsReplayContext {
                        tenant_id,
                        mount_session_id: read_session.session.session_id,
                        client_id: "nfs-readonly-stale-client",
                        nfs_session_id: "nfs-readonly-stale-session",
                        slot_id: 15,
                        sequence_id: 1,
                        operation_index: 3,
                        operation: "open",
                        request_digest: &stale_request_digest,
                        gateway_epoch,
                    },
                    response_bytes: &[0x08, 0x57],
                    response_digest: &stale_response_digest,
                },
                conflict_response_bytes: &[0x08, 0x58],
                conflict_response_digest: &stale_conflict_digest,
                handle_id: Uuid::new_v4(),
                authorization: filebelt_database::mount::NfsMutationAuthorization {
                    resource_namespace_generation: read_authorization.resource_namespace_generation
                        + 1,
                    ..read_authorization.clone()
                },
                expected_version_id: Some(version_id),
                access_actions: &read_actions,
                share_read: true,
                share_write: true,
                share_delete: true,
            })
            .await,
        Err(DatabaseError::StaleGeneration)
    ));

    let stale_drive_request_digest = [145_u8; 32];
    let stale_drive_response_digest = [146_u8; 32];
    let stale_drive_conflict_digest = [147_u8; 32];
    assert!(matches!(
        inherited_vfs_database
            .open_nfs_mount_handle(&OpenNfsHandleInput {
                session: &read_session.session,
                gss_binding_digest: &read_binding_digest,
                replay: RecordNfsReplayReceiptInput {
                    context: NfsReplayContext {
                        tenant_id,
                        mount_session_id: read_session.session.session_id,
                        client_id: "nfs-readonly-stale-drive-client",
                        nfs_session_id: "nfs-readonly-stale-drive-session",
                        slot_id: 19,
                        sequence_id: 1,
                        operation_index: 3,
                        operation: "open",
                        request_digest: &stale_drive_request_digest,
                        gateway_epoch,
                    },
                    response_bytes: &[0x08, 0x5f],
                    response_digest: &stale_drive_response_digest,
                },
                conflict_response_bytes: &[0x08, 0x60],
                conflict_response_digest: &stale_drive_conflict_digest,
                handle_id: Uuid::new_v4(),
                authorization: filebelt_database::mount::NfsMutationAuthorization {
                    drive_namespace_generation: read_authorization.drive_namespace_generation + 1,
                    ..read_authorization.clone()
                },
                expected_version_id: Some(version_id),
                access_actions: &read_actions,
                share_read: true,
                share_write: true,
                share_delete: true,
            })
            .await,
        Err(DatabaseError::StaleGeneration)
    ));

    sqlx::query(
        "UPDATE filebelt_mount.policies \
         SET enabled=false,authorization_generation=authorization_generation+1,\
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'",
    )
    .bind(tenant_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("disable read-only NFS policy");
    assert_read_open_denied(
        inherited_vfs_database,
        &read_session,
        &read_binding_digest,
        &read_authorization,
        version_id,
        &read_actions,
        gateway_epoch,
        145,
        "policy-disabled",
    )
    .await;
    sqlx::query(
        "UPDATE filebelt_mount.policies \
         SET enabled=true,authorization_generation=authorization_generation+1,\
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'",
    )
    .bind(tenant_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("restore read-only NFS policy");
    let restored_authorization_generation: i64 = sqlx::query_scalar(
        "SELECT credential.authorization_generation \
         FROM filebelt_mount.credentials AS credential \
         JOIN filebelt_mount.policies AS policy \
           ON policy.tenant_id=credential.tenant_id \
          AND policy.principal_id=credential.principal_id \
          AND policy.protocol=credential.protocol \
         WHERE credential.tenant_id=$1 AND credential.id=$2 \
           AND credential.authorization_generation=policy.authorization_generation",
    )
    .bind(tenant_id)
    .bind(read_mapping.credential_id)
    .fetch_one(database.pool())
    .await
    .expect("read restored policy generation");
    sqlx::query(
        "UPDATE filebelt_mount.sessions SET authorization_generation=$3 \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .bind(restored_authorization_generation)
    .execute(database.pool())
    .await
    .expect("refresh read-only session fixture policy generation");
    read_session.session.authorization_generation = restored_authorization_generation;

    sqlx::query(
        "UPDATE public.principals SET disabled_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_principal_id)
    .execute(database.pool())
    .await
    .expect("disable read-only NFS principal");
    assert_read_open_denied(
        inherited_vfs_database,
        &read_session,
        &read_binding_digest,
        &read_authorization,
        version_id,
        &read_actions,
        gateway_epoch,
        148,
        "principal-disabled",
    )
    .await;
    let restored_membership_generation: i64 = sqlx::query_scalar(
        "UPDATE public.principals SET disabled_at=NULL \
         WHERE tenant_id=$1 AND id=$2 RETURNING generation",
    )
    .bind(tenant_id)
    .bind(read_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("restore read-only NFS principal");
    sqlx::query(
        "UPDATE filebelt_mount.sessions SET membership_generation=$3 \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .bind(restored_membership_generation)
    .execute(database.pool())
    .await
    .expect("refresh read-only session fixture membership generation");
    read_session.session.membership_generation = restored_membership_generation;

    sqlx::query(
        "UPDATE filebelt_mount.credentials \
         SET revoked_at=clock_timestamp(),credential_generation=credential_generation+1 \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(read_mapping.credential_id)
    .execute(database.pool())
    .await
    .expect("revoke read-only NFS credential");
    let refreshed_authorization = filebelt_database::mount::NfsMutationAuthorization {
        membership_generation: restored_membership_generation,
        ..read_authorization
    };
    assert_read_open_denied(
        inherited_vfs_database,
        &read_session,
        &read_binding_digest,
        &refreshed_authorization,
        version_id,
        &read_actions,
        gateway_epoch,
        151,
        "credential-revoked",
    )
    .await;
    sqlx::query(
        "UPDATE filebelt_mount.sessions SET state='closed',closed_at=clock_timestamp(),\
         close_reason='credential_revoked',last_activity_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2 AND state IN ('active','draining')",
    )
    .bind(tenant_id)
    .bind(read_session.session.session_id)
    .execute(database.pool())
    .await
    .expect("close the revoked read-only NFS session fixture");
}

#[allow(clippy::too_many_arguments)]
async fn assert_read_open_denied(
    inherited_vfs_database: &Database,
    session: &NfsMountSessionProjection,
    gss_binding_digest: &[u8; 32],
    authorization: &filebelt_database::mount::NfsMutationAuthorization,
    version_id: Uuid,
    read_actions: &[String],
    gateway_epoch: i64,
    digest_seed: u8,
    client_suffix: &str,
) {
    let request_digest = [digest_seed; 32];
    let response_digest = [digest_seed.wrapping_add(1); 32];
    let conflict_digest = [digest_seed.wrapping_add(2); 32];
    let client_id = format!("nfs-readonly-{client_suffix}-client");
    let nfs_session_id = format!("nfs-readonly-{client_suffix}-session");
    assert!(matches!(
        inherited_vfs_database
            .open_nfs_mount_handle(&OpenNfsHandleInput {
                session: &session.session,
                gss_binding_digest,
                replay: RecordNfsReplayReceiptInput {
                    context: NfsReplayContext {
                        tenant_id: session.session.tenant_id,
                        mount_session_id: session.session.session_id,
                        client_id: &client_id,
                        nfs_session_id: &nfs_session_id,
                        slot_id: i32::from(digest_seed),
                        sequence_id: 1,
                        operation_index: 3,
                        operation: "open",
                        request_digest: &request_digest,
                        gateway_epoch,
                    },
                    response_bytes: &[0x08, digest_seed],
                    response_digest: &response_digest,
                },
                conflict_response_bytes: &[0x08, digest_seed.wrapping_add(3)],
                conflict_response_digest: &conflict_digest,
                handle_id: Uuid::new_v4(),
                authorization: authorization.clone(),
                expected_version_id: Some(version_id),
                access_actions: read_actions,
                share_read: true,
                share_write: true,
                share_delete: true,
            })
            .await,
        Err(DatabaseError::StaleGeneration | DatabaseError::Conflict)
    ));
}

async fn assert_principal_disable_fanout_is_non_recursive(database: &Database) {
    let tenant_id = Uuid::new_v4();
    let creator_principal_id = Uuid::new_v4();
    let target_principal_id = Uuid::new_v4();
    let creator_user_id = Uuid::new_v4();
    let drive_id = Uuid::new_v4();
    let root_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let share_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'principal-fanout-regression')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("insert principal fanout regression tenant");
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) \
         VALUES ($1,$2,'user'),($1,$3,'user')",
    )
    .bind(tenant_id)
    .bind(creator_principal_id)
    .bind(target_principal_id)
    .execute(database.pool())
    .await
    .expect("insert principal fanout regression principals");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) \
         VALUES ($1,$2,$3,'Principal Fanout Creator')",
    )
    .bind(tenant_id)
    .bind(creator_user_id)
    .bind(creator_principal_id)
    .execute(database.pool())
    .await
    .expect("insert principal fanout regression user");
    sqlx::query(
        "INSERT INTO public.drives \
         (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) \
         VALUES ($1,$2,$3,'private','Principal fanout drive',1073741824)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(creator_principal_id)
    .execute(database.pool())
    .await
    .expect("insert principal fanout regression drive");
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) \
         VALUES ($1,$2,$3,NULL,'directory','','')",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(root_id)
    .execute(database.pool())
    .await
    .expect("insert principal fanout regression root");
    sqlx::query(
        "INSERT INTO public.api_sessions \
         (tenant_id,id,user_id,principal_id,token_key_generation,token_digest,csrf_digest,\
          idle_expires_at,absolute_expires_at) \
         VALUES ($1,$2,$3,$4,1,$5,$6,clock_timestamp()+interval '15 minutes',\
                 clock_timestamp()+interval '1 hour')",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(creator_user_id)
    .bind(creator_principal_id)
    .bind(vec![71_u8; 32])
    .bind(vec![72_u8; 32])
    .execute(database.pool())
    .await
    .expect("insert principal fanout regression session");
    sqlx::query(
        "INSERT INTO public.authorization_generations \
         (tenant_id,session_id,principal_id,drive_id,resource_id,membership_generation,\
          drive_acl_generation,namespace_generation,resource_acl_generation,session_expires_at) \
         VALUES ($1,$2,$3,$4,$5,1,1,1,1,clock_timestamp()+interval '1 hour')",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(creator_principal_id)
    .bind(drive_id)
    .bind(root_id)
    .execute(database.pool())
    .await
    .expect("insert principal fanout authorization projection");
    sqlx::query(
        "UPDATE filebelt_security.tenant_descendant_share_admission \
         SET state='open',generation=generation+1,updated_at=clock_timestamp() \
         WHERE tenant_id=$1",
    )
    .bind(tenant_id)
    .execute(database.pool())
    .await
    .expect("open principal fanout descendant-share fixture");
    sqlx::query(
        "INSERT INTO public.direct_shares \
         (tenant_id,id,drive_id,resource_id,target_principal_id,preset,inheritance,\
          created_by,authorization_model_version) \
         VALUES ($1,$2,$3,$4,$5,'viewer','self_and_descendants',$6,1)",
    )
    .bind(tenant_id)
    .bind(share_id)
    .bind(drive_id)
    .bind(root_id)
    .bind(target_principal_id)
    .bind(creator_principal_id)
    .execute(database.pool())
    .await
    .expect("insert recursive share for principal fanout regression");

    let baseline: (i64, i64, i64) = sqlx::query_as(
        "SELECT principal.generation,drive.acl_generation,\
         (SELECT count(*) FROM public.authorization_generations \
          WHERE tenant_id=$1 AND principal_id=$2) \
         FROM public.principals principal JOIN public.drives drive \
           ON drive.tenant_id=principal.tenant_id \
         WHERE principal.tenant_id=$1 AND principal.id=$2 AND drive.id=$3",
    )
    .bind(tenant_id)
    .bind(creator_principal_id)
    .bind(drive_id)
    .fetch_one(database.pool())
    .await
    .expect("read principal fanout baseline");
    assert_eq!(baseline.2, 1);

    let mut generation_only = database
        .pool()
        .begin()
        .await
        .expect("begin generation-only principal update");
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *generation_only)
        .await
        .expect("bound generation-only trigger regression");
    sqlx::query(
        "UPDATE public.principals SET generation=generation+1 \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(creator_principal_id)
    .execute(&mut *generation_only)
    .await
    .expect("generation-only principal update terminates");
    generation_only
        .commit()
        .await
        .expect("commit generation-only principal update");
    let generation_only_state: (i64, i64, i64) = sqlx::query_as(
        "SELECT principal.generation,drive.acl_generation,\
         (SELECT count(*) FROM public.authorization_generations \
          WHERE tenant_id=$1 AND principal_id=$2) \
         FROM public.principals principal JOIN public.drives drive \
           ON drive.tenant_id=principal.tenant_id \
         WHERE principal.tenant_id=$1 AND principal.id=$2 AND drive.id=$3",
    )
    .bind(tenant_id)
    .bind(creator_principal_id)
    .bind(drive_id)
    .fetch_one(database.pool())
    .await
    .expect("read generation-only principal state");
    assert_eq!(
        generation_only_state,
        (baseline.0 + 1, baseline.1, baseline.2)
    );

    let mut disable = database
        .pool()
        .begin()
        .await
        .expect("begin principal disable update");
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *disable)
        .await
        .expect("bound principal disable trigger regression");
    sqlx::query(
        "UPDATE public.principals SET disabled_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(creator_principal_id)
    .execute(&mut *disable)
    .await
    .expect("principal disable fanout terminates");
    disable
        .commit()
        .await
        .expect("commit principal disable update");
    let disabled_state: (i64, i64, i64, bool) = sqlx::query_as(
        "SELECT principal.generation,drive.acl_generation,\
         (SELECT count(*) FROM public.authorization_generations \
          WHERE tenant_id=$1 AND principal_id=$2),principal.disabled_at IS NOT NULL \
         FROM public.principals principal JOIN public.drives drive \
           ON drive.tenant_id=principal.tenant_id \
         WHERE principal.tenant_id=$1 AND principal.id=$2 AND drive.id=$3",
    )
    .bind(tenant_id)
    .bind(creator_principal_id)
    .bind(drive_id)
    .fetch_one(database.pool())
    .await
    .expect("read disabled principal fanout state");
    assert_eq!(
        disabled_state,
        (
            generation_only_state.0 + 1,
            generation_only_state.1 + 1,
            0,
            true,
        )
    );
}

#[allow(unreachable_code)]
async fn assert_nfs_admin_drive_access_revocation_races(database: &Database, database_url: &str) {
    let race_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await
        .expect("connect NFS admin revocation-race pool");
    let tenant_id = Uuid::new_v4();
    let actor_principal_id = Uuid::new_v4();
    let replacement_owner_principal_id = Uuid::new_v4();
    let target_principal_id = Uuid::new_v4();
    let access_group_principal_id = Uuid::new_v4();
    let posix_group_principal_id = Uuid::new_v4();
    let actor_user_id = Uuid::new_v4();
    let replacement_owner_user_id = Uuid::new_v4();
    let target_user_id = Uuid::new_v4();
    let access_group_id = Uuid::new_v4();
    let posix_group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'nfs-admin-race')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("insert NFS admin revocation-race tenant");
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) VALUES \
         ($1,$2,'user'),($1,$3,'user'),($1,$4,'user'),($1,$5,'group'),($1,$6,'group')",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .bind(replacement_owner_principal_id)
    .bind(target_principal_id)
    .bind(access_group_principal_id)
    .bind(posix_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race principals");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) VALUES \
         ($1,$2,$3,'NFS Race Actor'),($1,$4,$5,'NFS Race Owner'),\
         ($1,$6,$7,'NFS Race Mapping Target')",
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(actor_principal_id)
    .bind(replacement_owner_user_id)
    .bind(replacement_owner_principal_id)
    .bind(target_user_id)
    .bind(target_principal_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race users");
    sqlx::query(
        "INSERT INTO public.groups (tenant_id,id,principal_id,display_name,name_key) VALUES \
         ($1,$2,$3,'NFS Race Access','nfs-race-access'),\
         ($1,$4,$5,'NFS Race POSIX','nfs-race-posix')",
    )
    .bind(tenant_id)
    .bind(access_group_id)
    .bind(access_group_principal_id)
    .bind(posix_group_id)
    .bind(posix_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race groups");
    sqlx::query(
        "INSERT INTO public.group_memberships \
         (tenant_id,group_id,user_principal_id,role) VALUES \
         ($1,$2,$3,'member'),($1,$4,$5,'member')",
    )
    .bind(tenant_id)
    .bind(access_group_id)
    .bind(actor_principal_id)
    .bind(posix_group_id)
    .bind(target_principal_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race memberships");

    let register_drive_id = Uuid::new_v4();
    let stage_drive_id = Uuid::new_v4();
    let mapping_drive_id = Uuid::new_v4();
    let register_root_id = Uuid::new_v4();
    let stage_root_id = Uuid::new_v4();
    let mapping_root_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.drives \
         (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES \
         ($1,$2,$3,'private','Register race',1073741824),\
         ($1,$4,$5,'private','Stage race',1073741824),\
         ($1,$6,$5,'private','Mapping race',1073741824)",
    )
    .bind(tenant_id)
    .bind(register_drive_id)
    .bind(actor_principal_id)
    .bind(stage_drive_id)
    .bind(replacement_owner_principal_id)
    .bind(mapping_drive_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race drives");
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES \
         ($1,$2,$3,NULL,'directory','',''),($1,$4,$5,NULL,'directory','',''),\
         ($1,$6,$7,NULL,'directory','','')",
    )
    .bind(tenant_id)
    .bind(register_drive_id)
    .bind(register_root_id)
    .bind(stage_drive_id)
    .bind(stage_root_id)
    .bind(mapping_drive_id)
    .bind(mapping_root_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race roots");
    let stage_acl_id = Uuid::new_v4();
    let mapping_acl_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.acl_entries \
         (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation) VALUES \
         ($1,$2,$3,$4,$5,'READ_METADATA','allow','self',$5,1),\
         ($1,$6,$7,$8,$9,'READ_METADATA','allow','self',$5,1)",
    )
    .bind(tenant_id)
    .bind(stage_drive_id)
    .bind(stage_root_id)
    .bind(stage_acl_id)
    .bind(actor_principal_id)
    .bind(mapping_drive_id)
    .bind(mapping_root_id)
    .bind(mapping_acl_id)
    .bind(access_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert NFS admin revocation-race ACLs");
    database
        .transition_nfs_feature_state(tenant_id, actor_principal_id, 1, NfsFeatureState::Preflight)
        .await
        .expect("enter NFS race tenant preflight");
    database
        .register_nfs_posix_group(
            tenant_id,
            actor_principal_id,
            posix_group_id,
            "nfs_race_users",
            52_000,
        )
        .await
        .expect("register NFS race POSIX group");
    let stage_export = database
        .register_nfs_export(tenant_id, actor_principal_id, stage_drive_id, 102)
        .await
        .expect("register stage-race export prerequisite");

    // These first three races hold only the lock taken by the real authority
    // mutation itself. The NFS admin write sees the pre-revocation snapshot,
    // performs its own mutation, and then must fail fast at the final NOWAIT
    // fence. That proves both SQLSTATE 55P03 mapping and rollback of the
    // transaction-local idempotency placeholder, audit, and outbox rows.
    let mut owner_revocation = race_pool.begin().await.expect("begin owner revocation");
    sqlx::query("UPDATE public.drives SET owner_principal_id=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(register_drive_id)
        .bind(replacement_owner_principal_id)
        .execute(&mut *owner_revocation)
        .await
        .expect("apply concurrent drive ownership revocation");
    let fingerprint = [61_u8; 32];
    let owner_race = database
        .register_nfs_export_idempotent(
            tenant_id,
            actor_principal_id,
            register_drive_id,
            101,
            &NfsAdminIdempotency {
                principal_id: actor_principal_id,
                route: "POST /api/v1/admin/mounts/nfs/exports",
                key: "ownership-revocation-wins",
                request_fingerprint: &fingerprint,
                legacy_request_fingerprint: None,
                response_status: 201,
            },
            |record| serde_json::to_value(json!({"export_id":record.export_id})),
        )
        .await;
    assert!(matches!(owner_race, Err(DatabaseError::StaleGeneration)));
    owner_revocation
        .commit()
        .await
        .expect("commit drive ownership revocation");
    let owner_race_counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM filebelt_mount.nfs_exports WHERE tenant_id=$1 AND drive_id=$2),\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='mount.nfs.export.register'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND topic='filebelt.v1.mount.nfs.export.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='POST /api/v1/admin/mounts/nfs/exports' AND key='ownership-revocation-wins')",
    )
    .bind(tenant_id)
    .bind(register_drive_id)
    .bind(actor_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("verify ownership-revoked export rollback");
    assert_eq!(owner_race_counts, (0, 0, 0, 0));

    let stage_outbox_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 \
         AND topic='filebelt.v1.mount.nfs.export.changed'",
    )
    .bind(tenant_id)
    .bind(stage_drive_id)
    .fetch_one(database.pool())
    .await
    .expect("count stage-race prerequisite outbox");
    let mut acl_revocation = race_pool.begin().await.expect("begin ACL revocation");
    sqlx::query("DELETE FROM public.acl_entries WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(stage_acl_id)
        .execute(&mut *acl_revocation)
        .await
        .expect("apply concurrent ACL revocation");
    let fingerprint = [62_u8; 32];
    let stage_race = database
        .stage_nfs_export_idempotent(
            tenant_id,
            actor_principal_id,
            stage_drive_id,
            stage_export.desired_generation,
            NfsExportState::Active,
            &NfsAdminIdempotency {
                principal_id: actor_principal_id,
                route: "PUT /api/v1/admin/mounts/nfs/exports/{drive_id}",
                key: "acl-revocation-wins",
                request_fingerprint: &fingerprint,
                legacy_request_fingerprint: None,
                response_status: 200,
            },
            |record| serde_json::to_value(json!({"generation":record.desired_generation})),
        )
        .await;
    assert!(matches!(stage_race, Err(DatabaseError::StaleGeneration)));
    acl_revocation
        .commit()
        .await
        .expect("commit drive ACL revocation");
    let stage_race_state: (String, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT export.desired_state,export.desired_generation,\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='mount.nfs.export.stage'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND topic='filebelt.v1.mount.nfs.export.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='PUT /api/v1/admin/mounts/nfs/exports/{drive_id}' AND key='acl-revocation-wins') \
         FROM filebelt_mount.nfs_exports export WHERE export.tenant_id=$1 AND export.drive_id=$2",
    )
    .bind(tenant_id)
    .bind(stage_drive_id)
    .bind(actor_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("verify ACL-revoked export-stage rollback");
    assert_eq!(
        stage_race_state,
        ("disabled".to_owned(), 1, 0, stage_outbox_before, 0)
    );

    let mut membership_revocation = race_pool
        .begin()
        .await
        .expect("begin membership revocation");
    sqlx::query(
        "DELETE FROM public.group_memberships \
         WHERE tenant_id=$1 AND group_id=$2 AND user_principal_id=$3",
    )
    .bind(tenant_id)
    .bind(access_group_id)
    .bind(actor_principal_id)
    .execute(&mut *membership_revocation)
    .await
    .expect("apply concurrent membership revocation");
    let fingerprint = [63_u8; 32];
    let mapping_race = database
        .upsert_nfs_principal_mapping_idempotent(
            &UpsertNfsPrincipalMappingInput {
                tenant_id,
                actor_principal_id,
                principal_id: target_principal_id,
                kerberos_principal: "race_target@EXAMPLE.TEST",
                projected_uid: 51_000,
                projected_gid: 52_000,
                allowed_drive_ids: &[mapping_drive_id],
                expected_generation: None,
            },
            &NfsAdminIdempotency {
                principal_id: actor_principal_id,
                route: "POST /api/v1/admin/mounts/nfs/mappings",
                key: "membership-revocation-wins",
                request_fingerprint: &fingerprint,
                legacy_request_fingerprint: None,
                response_status: 201,
            },
            |record| serde_json::to_value(json!({"credential_id":record.credential_id})),
        )
        .await;
    assert!(
        mapping_race.is_err(),
        "legacy direct mapping activation must fail before authority is created"
    );
    membership_revocation
        .commit()
        .await
        .expect("commit group-membership revocation");
    let mapping_race_counts: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM filebelt_mount.nfs_principal_mappings WHERE tenant_id=$1 AND kerberos_principal='race_target@EXAMPLE.TEST'),\
         (SELECT count(*) FROM filebelt_mount.credentials WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'),\
         (SELECT count(*) FROM filebelt_mount.policies WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'),\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND target_principal_id=$2 AND action='mount.nfs.mapping.update'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND topic='filebelt.v1.mount.nfs.mapping.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='POST /api/v1/admin/mounts/nfs/mappings' AND key='membership-revocation-wins')",
    )
    .bind(tenant_id)
    .bind(target_principal_id)
    .bind(actor_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("verify membership-revoked mapping rollback");
    assert_eq!(mapping_race_counts, (0, 0, 0, 0, 0, 0));

    // A disabled actor is not an administrative authority even when it owns
    // the selected drive. Cover both a disable visible to the optimistic
    // snapshot and a real concurrent disable whose row lock collides with the
    // final NOWAIT fence. Neither failure may leave the transaction-local
    // export, audit, outbox, or idempotency receipt behind.
    let disabled_actor_id = Uuid::new_v4();
    let disabled_actor_user_id = Uuid::new_v4();
    let disabled_drive_id = Uuid::new_v4();
    let disabled_root_id = Uuid::new_v4();
    let concurrent_actor_id = Uuid::new_v4();
    let concurrent_actor_user_id = Uuid::new_v4();
    let concurrent_drive_id = Uuid::new_v4();
    let concurrent_root_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) \
         VALUES ($1,$2,'user'),($1,$3,'user')",
    )
    .bind(tenant_id)
    .bind(disabled_actor_id)
    .bind(concurrent_actor_id)
    .execute(database.pool())
    .await
    .expect("insert disabled-actor race principals");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) VALUES \
         ($1,$2,$3,'Disabled NFS Admin'),($1,$4,$5,'Concurrent Disabled NFS Admin')",
    )
    .bind(tenant_id)
    .bind(disabled_actor_user_id)
    .bind(disabled_actor_id)
    .bind(concurrent_actor_user_id)
    .bind(concurrent_actor_id)
    .execute(database.pool())
    .await
    .expect("insert disabled-actor race users");
    sqlx::query(
        "INSERT INTO public.drives \
         (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES \
         ($1,$2,$3,'private','Disabled actor race',1073741824),\
         ($1,$4,$5,'private','Concurrent disable race',1073741824)",
    )
    .bind(tenant_id)
    .bind(disabled_drive_id)
    .bind(disabled_actor_id)
    .bind(concurrent_drive_id)
    .bind(concurrent_actor_id)
    .execute(database.pool())
    .await
    .expect("insert disabled-actor race drives");
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES \
         ($1,$2,$3,NULL,'directory','',''),($1,$4,$5,NULL,'directory','','')",
    )
    .bind(tenant_id)
    .bind(disabled_drive_id)
    .bind(disabled_root_id)
    .bind(concurrent_drive_id)
    .bind(concurrent_root_id)
    .execute(database.pool())
    .await
    .expect("insert disabled-actor race roots");

    sqlx::query(
        "UPDATE public.principals SET disabled_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(disabled_actor_id)
    .execute(database.pool())
    .await
    .expect("disable NFS admin before optimistic snapshot");
    let disabled_fingerprint = [66_u8; 32];
    let disabled_result = database
        .register_nfs_export_idempotent(
            tenant_id,
            disabled_actor_id,
            disabled_drive_id,
            106,
            &NfsAdminIdempotency {
                principal_id: disabled_actor_id,
                route: "POST /api/v1/admin/mounts/nfs/exports",
                key: "disabled-before-snapshot",
                request_fingerprint: &disabled_fingerprint,
                legacy_request_fingerprint: None,
                response_status: 201,
            },
            |record| serde_json::to_value(json!({"export_id":record.export_id})),
        )
        .await;
    assert!(matches!(disabled_result, Err(DatabaseError::NotFound)));
    let disabled_counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM filebelt_mount.nfs_exports WHERE tenant_id=$1 AND drive_id=$2),\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND actor_principal_id=$3 AND resource_id=$2 AND action='mount.nfs.export.register'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND topic='filebelt.v1.mount.nfs.export.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='POST /api/v1/admin/mounts/nfs/exports' AND key='disabled-before-snapshot')",
    )
    .bind(tenant_id)
    .bind(disabled_drive_id)
    .bind(disabled_actor_id)
    .fetch_one(database.pool())
    .await
    .expect("verify pre-disabled actor rollback");
    assert_eq!(disabled_counts, (0, 0, 0, 0));

    let mut concurrent_disable = race_pool
        .begin()
        .await
        .expect("begin concurrent actor disable");
    sqlx::query(
        "UPDATE public.principals SET disabled_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(concurrent_actor_id)
    .execute(&mut *concurrent_disable)
    .await
    .expect("apply concurrent actor disable");
    let concurrent_fingerprint = [67_u8; 32];
    let concurrent_result = database
        .register_nfs_export_idempotent(
            tenant_id,
            concurrent_actor_id,
            concurrent_drive_id,
            107,
            &NfsAdminIdempotency {
                principal_id: concurrent_actor_id,
                route: "POST /api/v1/admin/mounts/nfs/exports",
                key: "concurrent-actor-disable",
                request_fingerprint: &concurrent_fingerprint,
                legacy_request_fingerprint: None,
                response_status: 201,
            },
            |record| serde_json::to_value(json!({"export_id":record.export_id})),
        )
        .await;
    assert!(matches!(
        concurrent_result,
        Err(DatabaseError::StaleGeneration)
    ));
    concurrent_disable
        .commit()
        .await
        .expect("commit concurrent actor disable");
    let concurrent_counts: (i64, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM filebelt_mount.nfs_exports WHERE tenant_id=$1 AND drive_id=$2),\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND actor_principal_id=$3 AND resource_id=$2 AND action='mount.nfs.export.register'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND topic='filebelt.v1.mount.nfs.export.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='POST /api/v1/admin/mounts/nfs/exports' AND key='concurrent-actor-disable'),\
         (SELECT disabled_at IS NOT NULL FROM public.principals WHERE tenant_id=$1 AND id=$3)",
    )
    .bind(tenant_id)
    .bind(concurrent_drive_id)
    .bind(concurrent_actor_id)
    .fetch_one(database.pool())
    .await
    .expect("verify concurrent-disabled actor rollback");
    assert_eq!(concurrent_counts, (0, 0, 0, 0, true));

    // The remaining race fixtures exercised the removed direct-activation
    // path. Proposal/approval concurrency is covered by its dedicated
    // transaction tests; do not wait for an audit lock that an old binary can
    // no longer reach.
    race_pool.close().await;
    return;

    // A mapping that spans two drives must not acquire drive generation locks
    // before its own membership/mapping writes. Pause on an unrelated audit
    // table after the mapping rows exist, revoke both ACLs in one statement,
    // and prove the final recheck rolls the whole write back without a lock
    // cycle or an idempotency receipt.
    let multi_drive_ids = [Uuid::new_v4(), Uuid::new_v4()];
    let multi_root_ids = [Uuid::new_v4(), Uuid::new_v4()];
    let multi_acl_ids = [Uuid::new_v4(), Uuid::new_v4()];
    sqlx::query(
        "INSERT INTO public.drives \
         (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES \
         ($1,$2,$3,'private','Multi race one',1073741824),\
         ($1,$4,$3,'private','Multi race two',1073741824)",
    )
    .bind(tenant_id)
    .bind(multi_drive_ids[0])
    .bind(replacement_owner_principal_id)
    .bind(multi_drive_ids[1])
    .execute(database.pool())
    .await
    .expect("insert multi-drive race drives");
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES \
         ($1,$2,$3,NULL,'directory','',''),($1,$4,$5,NULL,'directory','','')",
    )
    .bind(tenant_id)
    .bind(multi_drive_ids[0])
    .bind(multi_root_ids[0])
    .bind(multi_drive_ids[1])
    .bind(multi_root_ids[1])
    .execute(database.pool())
    .await
    .expect("insert multi-drive race roots");
    sqlx::query(
        "INSERT INTO public.acl_entries \
         (tenant_id,drive_id,resource_id,id,principal_id,action,effect,inheritance,created_by,generation) VALUES \
         ($1,$2,$3,$4,$5,'READ_METADATA','allow','self',$5,1),\
         ($1,$6,$7,$8,$5,'READ_METADATA','allow','self',$5,1)",
    )
    .bind(tenant_id)
    .bind(multi_drive_ids[0])
    .bind(multi_root_ids[0])
    .bind(multi_acl_ids[0])
    .bind(actor_principal_id)
    .bind(multi_drive_ids[1])
    .bind(multi_root_ids[1])
    .bind(multi_acl_ids[1])
    .execute(database.pool())
    .await
    .expect("insert multi-drive race ACLs");

    let multi_database = Database::connect(
        &postgres_url_with_application_name(database_url, "nfs_admin_multi_acl_race"),
        1,
    )
    .await
    .expect("connect multi-drive admin race database");
    let mut multi_barrier = race_pool
        .begin()
        .await
        .expect("begin multi-drive non-authority barrier");
    sqlx::query("LOCK TABLE public.audit_events IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *multi_barrier)
        .await
        .expect("lock multi-drive audit barrier");
    let multi_task_database = multi_database.clone();
    let multi_mapping = tokio::spawn(async move {
        let fingerprint = [64_u8; 32];
        multi_task_database
            .upsert_nfs_principal_mapping_idempotent(
                &UpsertNfsPrincipalMappingInput {
                    tenant_id,
                    actor_principal_id,
                    principal_id: target_principal_id,
                    kerberos_principal: "multi_race_target@EXAMPLE.TEST",
                    projected_uid: 51_001,
                    projected_gid: 52_000,
                    allowed_drive_ids: &multi_drive_ids,
                    expected_generation: None,
                },
                &NfsAdminIdempotency {
                    principal_id: actor_principal_id,
                    route: "POST /api/v1/admin/mounts/nfs/mappings",
                    key: "multi-acl-revocation-wins",
                    request_fingerprint: &fingerprint,
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |record| serde_json::to_value(json!({"credential_id":record.credential_id})),
            )
            .await
    });
    wait_for_postgres_lock(
        &race_pool,
        "nfs_admin_multi_acl_race",
        "insert into audit_events",
    )
    .await;
    sqlx::query("DELETE FROM public.acl_entries WHERE tenant_id=$1 AND id=ANY($2)")
        .bind(tenant_id)
        .bind(&multi_acl_ids[..])
        .execute(&race_pool)
        .await
        .expect("revoke both multi-drive ACLs in one statement");
    multi_barrier
        .commit()
        .await
        .expect("release multi-drive audit barrier");
    let multi_result = tokio::time::timeout(std::time::Duration::from_secs(10), multi_mapping)
        .await
        .expect("multi-drive mapping race must not deadlock")
        .expect("join multi-drive mapping race");
    assert!(matches!(multi_result, Err(DatabaseError::NotFound)));
    let multi_counts: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM filebelt_mount.nfs_principal_mappings WHERE tenant_id=$1 AND kerberos_principal='multi_race_target@EXAMPLE.TEST'),\
         (SELECT count(*) FROM filebelt_mount.credentials WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'),\
         (SELECT count(*) FROM filebelt_mount.policies WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'),\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND target_principal_id=$2 AND action='mount.nfs.mapping.update'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND topic='filebelt.v1.mount.nfs.mapping.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='POST /api/v1/admin/mounts/nfs/mappings' AND key='multi-acl-revocation-wins'),\
         (SELECT count(*) FROM public.acl_entries WHERE tenant_id=$1 AND id=ANY($4))",
    )
    .bind(tenant_id)
    .bind(target_principal_id)
    .bind(actor_principal_id)
    .bind(&multi_acl_ids[..])
    .fetch_one(database.pool())
    .await
    .expect("verify multi-drive ACL race rollback");
    assert_eq!(multi_counts, (0, 0, 0, 0, 0, 0, 0));
    multi_database.pool().close().await;

    // Self-mapping takes a key-share lock on its primary POSIX membership.
    // Pause only at the later audit insert, issue a plain membership DELETE,
    // observe its real row-lock wait, then release the mapping. The mapping's
    // membership -> principal order must complete, and the backstop must reject
    // the now-stale delete instead of deadlocking with the final authority lock.
    let self_principal_id = Uuid::new_v4();
    let self_user_id = Uuid::new_v4();
    let self_group_principal_id = Uuid::new_v4();
    let self_group_id = Uuid::new_v4();
    let self_drive_id = Uuid::new_v4();
    let self_root_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user'),($1,$3,'group')",
    )
    .bind(tenant_id)
    .bind(self_principal_id)
    .bind(self_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert self-mapping race principals");
    sqlx::query(
        "INSERT INTO public.users (tenant_id,id,principal_id,display_name) \
         VALUES ($1,$2,$3,'NFS Self Race')",
    )
    .bind(tenant_id)
    .bind(self_user_id)
    .bind(self_principal_id)
    .execute(database.pool())
    .await
    .expect("insert self-mapping race user");
    sqlx::query(
        "INSERT INTO public.groups (tenant_id,id,principal_id,display_name,name_key) \
         VALUES ($1,$2,$3,'NFS Self POSIX','nfs-self-posix')",
    )
    .bind(tenant_id)
    .bind(self_group_id)
    .bind(self_group_principal_id)
    .execute(database.pool())
    .await
    .expect("insert self-mapping race group");
    sqlx::query(
        "INSERT INTO public.group_memberships (tenant_id,group_id,user_principal_id,role) \
         VALUES ($1,$2,$3,'member')",
    )
    .bind(tenant_id)
    .bind(self_group_id)
    .bind(self_principal_id)
    .execute(database.pool())
    .await
    .expect("insert self-mapping primary membership");
    sqlx::query(
        "INSERT INTO public.drives \
         (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) \
         VALUES ($1,$2,$3,'private','Self mapping race',1073741824)",
    )
    .bind(tenant_id)
    .bind(self_drive_id)
    .bind(self_principal_id)
    .execute(database.pool())
    .await
    .expect("insert self-mapping race drive");
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) \
         VALUES ($1,$2,$3,NULL,'directory','','')",
    )
    .bind(tenant_id)
    .bind(self_drive_id)
    .bind(self_root_id)
    .execute(database.pool())
    .await
    .expect("insert self-mapping race root");
    database
        .register_nfs_posix_group(
            tenant_id,
            actor_principal_id,
            self_group_id,
            "nfs_self_users",
            53_000,
        )
        .await
        .expect("register self-mapping POSIX group");

    let self_database = Database::connect(
        &postgres_url_with_application_name(database_url, "nfs_admin_self_mapping_race"),
        1,
    )
    .await
    .expect("connect self-mapping admin race database");
    let delete_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&postgres_url_with_application_name(
            database_url,
            "nfs_admin_self_membership_delete",
        ))
        .await
        .expect("connect self-mapping membership-delete pool");
    let mut self_barrier = race_pool
        .begin()
        .await
        .expect("begin self-mapping non-authority barrier");
    sqlx::query("LOCK TABLE public.audit_events IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *self_barrier)
        .await
        .expect("lock self-mapping audit barrier");
    let self_task_database = self_database.clone();
    let self_mapping = tokio::spawn(async move {
        let fingerprint = [65_u8; 32];
        self_task_database
            .upsert_nfs_principal_mapping_idempotent(
                &UpsertNfsPrincipalMappingInput {
                    tenant_id,
                    actor_principal_id: self_principal_id,
                    principal_id: self_principal_id,
                    kerberos_principal: "self_race@EXAMPLE.TEST",
                    projected_uid: 51_002,
                    projected_gid: 53_000,
                    allowed_drive_ids: &[self_drive_id],
                    expected_generation: None,
                },
                &NfsAdminIdempotency {
                    principal_id: self_principal_id,
                    route: "POST /api/v1/admin/mounts/nfs/mappings",
                    key: "self-membership-race",
                    request_fingerprint: &fingerprint,
                    legacy_request_fingerprint: None,
                    response_status: 201,
                },
                |record| serde_json::to_value(json!({"credential_id":record.credential_id})),
            )
            .await
    });
    wait_for_postgres_lock(
        &race_pool,
        "nfs_admin_self_mapping_race",
        "insert into audit_events",
    )
    .await;
    let delete_task_pool = delete_pool.clone();
    let membership_delete = tokio::spawn(async move {
        sqlx::query(
            "DELETE FROM public.group_memberships \
             WHERE tenant_id=$1 AND group_id=$2 AND user_principal_id=$3",
        )
        .bind(tenant_id)
        .bind(self_group_id)
        .bind(self_principal_id)
        .execute(&delete_task_pool)
        .await
    });
    wait_for_postgres_lock(
        &race_pool,
        "nfs_admin_self_membership_delete",
        "delete from public.group_memberships",
    )
    .await;
    self_barrier
        .commit()
        .await
        .expect("release self-mapping audit barrier");
    let self_result = tokio::time::timeout(std::time::Duration::from_secs(10), self_mapping)
        .await
        .expect("self mapping must not deadlock")
        .expect("join self-mapping race")
        .expect("self mapping wins before primary-membership delete");
    assert!(matches!(self_result, NfsAdminIdempotentWrite::Created(_)));
    let delete_error = tokio::time::timeout(std::time::Duration::from_secs(10), membership_delete)
        .await
        .expect("primary-membership delete must unblock")
        .expect("join primary-membership delete")
        .expect_err("primary-membership backstop must reject the stale delete");
    assert!(matches!(
        &delete_error,
        sqlx::Error::Database(error) if error.code().as_deref() == Some("23503")
    ));
    let self_counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM filebelt_mount.nfs_principal_mappings WHERE tenant_id=$1 AND kerberos_principal='self_race@EXAMPLE.TEST' AND revoked_at IS NULL),\
         (SELECT count(*) FROM public.group_memberships WHERE tenant_id=$1 AND group_id=$2 AND user_principal_id=$3),\
         (SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND target_principal_id=$3 AND action='mount.nfs.mapping.update'),\
         (SELECT count(*) FROM public.outbox_events WHERE tenant_id=$1 AND aggregate_type='nfs_mapping' AND topic='filebelt.v1.mount.nfs.mapping.changed'),\
         (SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$3 AND route='POST /api/v1/admin/mounts/nfs/mappings' AND key='self-membership-race')",
    )
    .bind(tenant_id)
    .bind(self_group_id)
    .bind(self_principal_id)
    .fetch_one(database.pool())
    .await
    .expect("verify self-mapping membership race");
    assert_eq!(self_counts, (1, 1, 1, 1, 1));
    delete_pool.close().await;
    self_database.pool().close().await;
    race_pool.close().await;
}

fn postgres_url_with_application_name(database_url: &str, application_name: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}application_name={application_name}")
}

async fn wait_for_postgres_lock(pool: &PgPool, application_name: &str, query_fragment: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND application_name=$1 \
                   AND wait_event_type='Lock' AND lower(query) LIKE '%' || lower($2) || '%')",
            )
            .bind(application_name)
            .bind(query_fragment)
            .fetch_one(pool)
            .await
            .expect("inspect PostgreSQL lock wait");
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{application_name} did not wait on the expected PostgreSQL lock for {query_fragment}"
        )
    });
}

struct TestMountWriter {
    fence: MountWriteCapabilityFence,
}

#[allow(clippy::too_many_arguments)]
async fn insert_test_mount_writer(
    database: &Database,
    session: &NfsMountSessionProjection,
    tenant_id: Uuid,
    drive_id: Uuid,
    root_node_id: Uuid,
    backend_id: Uuid,
    suffix: &str,
    writer_state: &str,
    payload_state: &str,
) -> TestMountWriter {
    let node_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.nodes \
         (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) \
         VALUES ($1,$2,$3,$4,'file',$5,$5)",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .bind(root_node_id)
    .bind(format!("io-{suffix}"))
    .execute(database.pool())
    .await
    .expect("insert terminal-recovery file node");
    let generations: (i64, i64, i64) = sqlx::query_as(
        "SELECT node.acl_generation,node.namespace_generation,drive.acl_generation \
         FROM public.nodes AS node JOIN public.drives AS drive \
           ON drive.tenant_id=node.tenant_id AND drive.id=node.drive_id \
         WHERE node.tenant_id=$1 AND node.drive_id=$2 AND node.id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .fetch_one(database.pool())
    .await
    .expect("read terminal-recovery generations");
    let payload_id = Uuid::new_v4();
    let locator = Uuid::new_v4();
    let payload_digest =
        matches!(payload_state, "finalized" | "deleting" | "deleted").then_some(vec![91_u8; 32]);
    sqlx::query(
        "INSERT INTO public.payload_objects \
         (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3) \
         VALUES ($1,$2,$3,$4,$5,'whole',$6,0,$7)",
    )
    .bind(tenant_id)
    .bind(payload_id)
    .bind(drive_id)
    .bind(backend_id)
    .bind(locator)
    .bind(payload_state)
    .bind(payload_digest)
    .execute(database.pool())
    .await
    .expect("insert terminal-recovery payload");
    let handle_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO filebelt_mount.handles \
         (tenant_id,id,session_id,drive_id,node_id,version_id,access_actions,\
          share_read,share_write,share_delete,credential_generation,\
          authorization_generation,membership_generation,drive_acl_generation,\
          namespace_generation,resource_acl_generation,gateway_epoch,expires_at) \
         VALUES ($1,$2,$3,$4,$5,NULL,ARRAY['READ_CONTENT','WRITE_CONTENT','CREATE_VERSION'],true,true,true,\
                 $6,$7,$8,$9,$10,$11,$12,clock_timestamp()+interval '1 hour')",
    )
    .bind(tenant_id)
    .bind(handle_id)
    .bind(session.session.session_id)
    .bind(drive_id)
    .bind(node_id)
    .bind(session.session.credential_generation)
    .bind(session.session.authorization_generation)
    .bind(session.session.membership_generation)
    .bind(generations.2)
    .bind(generations.1)
    .bind(generations.0)
    .bind(session.session.gateway_epoch)
    .execute(database.pool())
    .await
    .expect("insert terminal-recovery handle");
    let write_session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO filebelt_mount.write_sessions \
         (tenant_id,id,mount_session_id,handle_id,drive_id,node_id,staging_payload_id,\
          logical_size_bytes,reserved_bytes,state,fencing_token,gateway_epoch,\
          authorization_generation,lease_expires_at,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,0,0,$8,1,$9,$10,\
                 clock_timestamp()+interval '30 seconds',\
                 clock_timestamp()+interval '1 hour')",
    )
    .bind(tenant_id)
    .bind(write_session_id)
    .bind(session.session.session_id)
    .bind(handle_id)
    .bind(drive_id)
    .bind(node_id)
    .bind(payload_id)
    .bind(writer_state)
    .bind(session.session.gateway_epoch)
    .bind(session.session.authorization_generation)
    .execute(database.pool())
    .await
    .expect("insert terminal-recovery writer");
    TestMountWriter {
        fence: MountWriteCapabilityFence {
            tenant_id,
            principal_id: session.session.user_principal_id,
            mount_session_id: session.session.session_id,
            credential_id: session.session.credential_id,
            handle_id,
            drive_id,
            node_id,
            version_id: None,
            write_session_id,
            credential_generation: session.session.credential_generation,
            authorization_generation: session.session.authorization_generation,
            membership_generation: session.session.membership_generation,
            drive_acl_generation: generations.2,
            namespace_generation: generations.1,
            resource_acl_generation: generations.0,
            gateway_epoch: session.session.gateway_epoch,
            fencing_token: 1,
        },
    }
}

async fn insert_pending_terminal_io_receipt(
    database: &Database,
    writer: &TestMountWriter,
    operation: MountIoOperation,
    capability_id: Uuid,
    nonce_digest: &[u8; 32],
    claims_digest: &[u8; 32],
    expired: bool,
) {
    let query = if expired {
        sqlx::query(
            "INSERT INTO filebelt_mount.nfs_io_receipts \
             (tenant_id,nonce_digest,capability_id,write_session_id,operation,operation_ordinal,\
              claims_digest,created_at,expires_at) \
             VALUES ($1,$2,$3,$4,$5,1,$6,clock_timestamp()-interval '2 hours',\
                     clock_timestamp()-interval '1 hour')",
        )
    } else {
        sqlx::query(
            "INSERT INTO filebelt_mount.nfs_io_receipts \
             (tenant_id,nonce_digest,capability_id,write_session_id,operation,operation_ordinal,\
              claims_digest,created_at,expires_at) \
             VALUES ($1,$2,$3,$4,$5,1,$6,clock_timestamp(),\
                     clock_timestamp()+interval '1 hour')",
        )
    };
    query
        .bind(writer.fence.tenant_id)
        .bind(nonce_digest.as_slice())
        .bind(capability_id)
        .bind(writer.fence.write_session_id)
        .bind(operation.test_str())
        .bind(claims_digest.as_slice())
        .execute(database.pool())
        .await
        .expect("insert pending terminal I/O receipt");
}

async fn assert_terminal_io_recovery(
    database: &Database,
    writer: &TestMountWriter,
    operation: MountIoOperation,
    outcome: MountIoCompletion,
    identity_byte: u8,
) {
    let nonce_digest = [identity_byte; 32];
    let claims_digest = [identity_byte.wrapping_add(1); 32];
    let capability_id = Uuid::new_v4();
    insert_pending_terminal_io_receipt(
        database,
        writer,
        operation,
        capability_id,
        &nonce_digest,
        &claims_digest,
        false,
    )
    .await;
    let input = BeginMountIoOperationInput {
        fence: &writer.fence,
        capability_id,
        nonce_digest: &nonce_digest,
        claims_digest: &claims_digest,
        operation,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: 2_000_000_000,
    };
    assert_eq!(
        database
            .lookup_mount_io_completion(&input)
            .await
            .expect("look up pending terminal receipt"),
        MountIoLookup::Pending
    );
    let admission = database
        .begin_mount_io_operation(&input)
        .await
        .expect("recover terminal transition before response receipt");
    let completed = match admission {
        MountIoAdmission::Completed(completed) => completed,
        MountIoAdmission::Execute(_) => match &outcome {
            MountIoCompletion::Flush {
                logical_size_bytes,
                blake3,
                chunks,
            } => database
                .complete_mount_io_flush(&input, *logical_size_bytes, blake3, chunks)
                .await
                .expect("atomically complete recovered Flush transition"),
            MountIoCompletion::Finalize {
                logical_size_bytes,
                blake3,
                chunks,
            } => database
                .complete_mount_io_finalize(&input, *logical_size_bytes, blake3, chunks)
                .await
                .expect("atomically complete recovered Finalize transition"),
            MountIoCompletion::Abort => database
                .complete_mount_io_abort(&input)
                .await
                .expect("atomically complete recovered Abort transition"),
            _ => panic!("unsupported terminal recovery outcome: {outcome:?}"),
        },
        MountIoAdmission::CleanupRequired(cleanup) => {
            panic!("unexpected cleanup-required terminal retry: {cleanup:?}")
        }
    };
    assert_eq!(completed, outcome);
    assert_eq!(
        database
            .lookup_mount_io_completion(&input)
            .await
            .expect("look up completed terminal receipt"),
        MountIoLookup::Completed(outcome.clone())
    );
    assert!(matches!(
        database
            .begin_mount_io_operation(&input)
            .await
            .expect("return exact completed terminal retry"),
        MountIoAdmission::Completed(value) if value == outcome
    ));
}

async fn preauthorize_mount_io_as(
    pool: &PgPool,
    input: &PreauthorizeMountIoOperationInput<'_>,
) -> Result<bool, sqlx::Error> {
    let fence = input.io.fence;
    let context = &input.context;
    sqlx::query_scalar(
        "SELECT filebelt_mount.preauthorize_nfs_io(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)",
    )
    .bind(fence.tenant_id)
    .bind(fence.principal_id)
    .bind(fence.mount_session_id)
    .bind(fence.credential_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.version_id)
    .bind(fence.write_session_id)
    .bind(fence.credential_generation)
    .bind(fence.authorization_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.gateway_epoch)
    .bind(fence.fencing_token)
    .bind(context.client_id)
    .bind(context.nfs_session_id)
    .bind(context.slot_id)
    .bind(context.sequence_id)
    .bind(context.operation_index)
    .bind(context.operation)
    .bind(context.request_digest.as_slice())
    .bind(input.protocol_operation_id)
    .bind(input.io.capability_id)
    .bind(input.io.nonce_digest.as_slice())
    .bind(None::<Uuid>)
    .bind(input.io.operation.test_str())
    .bind(input.io.claims_digest.as_slice())
    .bind(input.io.content_blake3.map(|digest| digest.as_slice()))
    .bind(input.io.range_start)
    .bind(input.io.range_end)
    .bind(input.io.expires_at_unix_seconds)
    .fetch_one(pool)
    .await
}

async fn begin_mount_io_as(
    pool: &PgPool,
    input: &BeginMountIoOperationInput<'_>,
) -> Result<i64, sqlx::Error> {
    let fence = input.fence;
    sqlx::query_scalar(
        "SELECT filebelt_mount.begin_nfs_io_receipt(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23,$24)",
    )
    .bind(fence.tenant_id)
    .bind(fence.principal_id)
    .bind(fence.mount_session_id)
    .bind(fence.credential_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.version_id)
    .bind(fence.write_session_id)
    .bind(fence.credential_generation)
    .bind(fence.authorization_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.gateway_epoch)
    .bind(fence.fencing_token)
    .bind(input.capability_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.operation.test_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .bind(input.range_start)
    .bind(input.range_end)
    .fetch_one(pool)
    .await
}

async fn complete_mount_io_as(
    pool: &PgPool,
    input: &BeginMountIoOperationInput<'_>,
    outcome: &MountIoCompletion,
) -> Result<Value, sqlx::Error> {
    let fence = input.fence;
    sqlx::query_scalar(
        "SELECT filebelt_mount.complete_nfs_io_receipt(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23)",
    )
    .bind(fence.tenant_id)
    .bind(fence.principal_id)
    .bind(fence.mount_session_id)
    .bind(fence.credential_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.version_id)
    .bind(fence.write_session_id)
    .bind(fence.credential_generation)
    .bind(fence.authorization_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.gateway_epoch)
    .bind(fence.fencing_token)
    .bind(input.capability_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.operation.test_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .bind(serde_json::to_value(outcome).expect("serialize test I/O outcome"))
    .fetch_one(pool)
    .await
}

async fn read_mount_io_as(
    pool: &PgPool,
    input: &BeginMountIoOperationInput<'_>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.read_nfs_io_receipt($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(input.fence.tenant_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.capability_id)
    .bind(input.fence.write_session_id)
    .bind(input.operation.test_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .fetch_one(pool)
    .await
}

async fn finalize_nfs_internal_io_as<'e, E>(
    executor: E,
    input: &FinalizeNfsInternalIoReplayInput<'_>,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let fence = input.fence;
    let replay = &input.replay;
    sqlx::query_scalar(
        "SELECT replayed FROM filebelt_mount.finalize_nfs_internal_io_replay(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)",
    )
    .bind(fence.tenant_id)
    .bind(fence.principal_id)
    .bind(fence.mount_session_id)
    .bind(fence.credential_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.version_id)
    .bind(fence.write_session_id)
    .bind(fence.credential_generation)
    .bind(fence.authorization_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.gateway_epoch)
    .bind(fence.fencing_token)
    .bind(input.gss_binding_digest.as_slice())
    .bind(replay.context.client_id)
    .bind(replay.context.nfs_session_id)
    .bind(replay.context.slot_id)
    .bind(replay.context.sequence_id)
    .bind(replay.context.operation_index)
    .bind(replay.context.operation)
    .bind(replay.context.request_digest.as_slice())
    .bind(input.operation.test_str())
    .bind(replay.response_bytes)
    .bind(replay.response_digest.as_slice())
    .fetch_one(executor)
    .await
}

struct NfsRangeRecoveryCase<'a> {
    identity_byte: u8,
    operation_id: Uuid,
    operation: MountWriteRangeOperation,
    range_start: i64,
    range_end: i64,
    required_reservation_bytes: i64,
    chunks: &'a [MountWriteChunkPlan],
    content_blake3: Option<&'a [u8; 32]>,
    worker_outcome: MountIoCompletion,
    expected_logical_size: i64,
    expected_seek_offset: Option<Option<i64>>,
    expect_authority_conflict: bool,
}

async fn assert_nfs_range_recovery_case(
    database: &Database,
    session: &NfsMountSessionProjection,
    binding_digest: &[u8; 32],
    writer: &TestMountWriter,
    case: NfsRangeRecoveryCase<'_>,
) {
    let plan_request_digest = [case.identity_byte; 32];
    let nonce_digest = [case.identity_byte.wrapping_add(2); 32];
    let claims_digest = [case.identity_byte.wrapping_add(3); 32];
    let capability_id = Uuid::new_v4();
    let expires_at_unix_seconds = mount_capability_expiry();
    let protocol_operation = match case.operation {
        MountWriteRangeOperation::WriteData => "sparse_write",
        MountWriteRangeOperation::HoleDeallocate
        | MountWriteRangeOperation::Allocate
        | MountWriteRangeOperation::SeekData
        | MountWriteRangeOperation::SeekHole => "sparse_control",
    };
    let plan_context = NfsReplayContext {
        tenant_id: writer.fence.tenant_id,
        mount_session_id: session.session.session_id,
        client_id: "nfs-range-cases",
        nfs_session_id: "nfs-range-cases",
        slot_id: i32::from(case.identity_byte),
        sequence_id: 1,
        operation_index: 3,
        operation: protocol_operation,
        request_digest: &plan_request_digest,
        gateway_epoch: writer.fence.gateway_epoch,
    };
    let plan = database
        .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
            fence: &writer.fence,
            context: plan_context.clone(),
            nonce_digest: &nonce_digest,
            claims_digest: &claims_digest,
            expires_at_unix_seconds,
            required_reservation_bytes: case.required_reservation_bytes,
            operation_id: case.operation_id,
            capability_id,
            operation: case.operation,
            content_blake3: case.content_blake3,
            range_start: case.range_start,
            range_end: case.range_end,
            chunks: case.chunks,
        })
        .await
        .expect("plan typed NFS range operation");
    assert_eq!(plan.operation, case.operation);
    assert_eq!(plan.reserved_bytes, case.required_reservation_bytes);
    assert_eq!(plan.resulting_logical_size, case.expected_logical_size);

    let io_operation = match case.operation {
        MountWriteRangeOperation::WriteData => MountIoOperation::WriteData,
        MountWriteRangeOperation::HoleDeallocate => MountIoOperation::HoleDeallocate,
        MountWriteRangeOperation::Allocate => MountIoOperation::Allocate,
        MountWriteRangeOperation::SeekData => MountIoOperation::SeekData,
        MountWriteRangeOperation::SeekHole => MountIoOperation::SeekHole,
    };
    let io_input = BeginMountIoOperationInput {
        fence: &writer.fence,
        capability_id,
        nonce_digest: &nonce_digest,
        claims_digest: &claims_digest,
        operation: io_operation,
        range_start: Some(case.range_start),
        range_end: Some(case.range_end),
        content_blake3: case.content_blake3,
        expires_at_unix_seconds,
    };
    assert!(matches!(
        database
            .begin_mount_io_operation(&io_input)
            .await
            .expect("claim typed NFS range operation"),
        MountIoAdmission::Execute(_)
    ));
    assert_eq!(
        database
            .complete_mount_io_operation(&io_input, &case.worker_outcome)
            .await
            .expect("persist exact typed byte-plane outcome"),
        case.worker_outcome
    );
    let io_completed_state: String = sqlx::query_scalar(
        "SELECT state FROM filebelt_mount.nfs_write_operations \
         WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3",
    )
    .bind(writer.fence.tenant_id)
    .bind(writer.fence.write_session_id)
    .bind(case.operation_id)
    .fetch_one(database.pool())
    .await
    .expect("read typed byte-plane operation state");
    assert_eq!(io_completed_state, "io_completed");

    let authority_response_digest = [case.identity_byte.wrapping_add(5); 32];
    let authority_response_bytes = [0x08, case.identity_byte.wrapping_add(1)];
    let authority_context = plan_context.clone();
    if matches!(
        case.operation,
        MountWriteRangeOperation::SeekData | MountWriteRangeOperation::SeekHole
    ) {
        let input = SeekNfsWriteExtentInput {
            session: &session.session,
            gss_binding_digest: binding_digest,
            fence: &writer.fence,
            replay: RecordNfsReplayReceiptInput {
                context: authority_context,
                response_bytes: &authority_response_bytes,
                response_digest: &authority_response_digest,
            },
            operation_id: case.operation_id,
            operation: case.operation,
            range_start: case.range_start,
            range_end: case.range_end,
        };
        let result = database.seek_nfs_write_extent(&input).await;
        if case.expect_authority_conflict {
            assert!(matches!(result, Err(DatabaseError::Conflict)));
            let state: String = sqlx::query_scalar(
                "SELECT state FROM filebelt_mount.nfs_write_operations \
                 WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3",
            )
            .bind(writer.fence.tenant_id)
            .bind(writer.fence.write_session_id)
            .bind(case.operation_id)
            .fetch_one(database.pool())
            .await
            .expect("read mismatched seek operation state");
            assert_eq!(state, "io_completed");
            return;
        }
        let result = result.expect("apply authoritative NFS seek result");
        assert_eq!(result.logical_size_bytes, case.expected_logical_size);
        assert_eq!(result.seek_offset, case.expected_seek_offset.flatten());
        let replay = database
            .seek_nfs_write_extent(&input)
            .await
            .expect("replay exact NFS seek result");
        assert!(replay.replayed);
        assert_eq!(replay.seek_offset, result.seek_offset);
    } else {
        let input = ApplyNfsWriteExtentInput {
            session: &session.session,
            gss_binding_digest: binding_digest,
            fence: &writer.fence,
            replay: RecordNfsReplayReceiptInput {
                context: authority_context,
                response_bytes: &authority_response_bytes,
                response_digest: &authority_response_digest,
            },
            operation_id: case.operation_id,
            operation: case.operation,
            range_start: case.range_start,
            range_end: case.range_end,
            data_digest: case.content_blake3,
        };
        let result = database
            .apply_nfs_write_extent(&input)
            .await
            .expect("apply authoritative NFS mutation extent");
        assert_eq!(result.logical_size_bytes, case.expected_logical_size);
        assert_eq!(result.seek_offset, None);
        let replay = database
            .apply_nfs_write_extent(&input)
            .await
            .expect("replay exact NFS mutation extent");
        assert!(replay.replayed);
        assert_eq!(replay.extents, result.extents);
    }
    let applied_state: String = sqlx::query_scalar(
        "SELECT state FROM filebelt_mount.nfs_write_operations \
         WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3",
    )
    .bind(writer.fence.tenant_id)
    .bind(writer.fence.write_session_id)
    .bind(case.operation_id)
    .fetch_one(database.pool())
    .await
    .expect("read VFS-applied typed operation state");
    assert_eq!(applied_state, "applied");
}

trait MountIoOperationTestName {
    fn test_str(self) -> &'static str;
}

impl MountIoOperationTestName for MountIoOperation {
    fn test_str(self) -> &'static str {
        match self {
            MountIoOperation::WriteData => "write_data",
            MountIoOperation::HoleDeallocate => "hole_deallocate",
            MountIoOperation::Allocate => "allocate",
            MountIoOperation::SeekData => "seek_data",
            MountIoOperation::SeekHole => "seek_hole",
            MountIoOperation::Flush => "flush",
            MountIoOperation::Finalize => "finalize",
            MountIoOperation::Abort => "abort",
            MountIoOperation::DeleteStaging => "delete_staging",
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

async fn function_privilege(database: &Database, role: &str, function: &str) -> bool {
    sqlx::query_scalar("SELECT has_function_privilege($1,$2,'EXECUTE')")
        .bind(role)
        .bind(function)
        .fetch_one(database.pool())
        .await
        .expect("function privilege query")
}

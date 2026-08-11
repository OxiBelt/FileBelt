// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed mount schema and least-privilege contract checks.

use filebelt_database::mount::{
    CreateNfsMountSessionInput, NfsExportState, NfsFeatureState, NfsReplayContext,
    ReconcileNfsExportManifestInput, RecordNfsReplayReceiptInput, UpsertNfsPrincipalMappingInput,
};
use filebelt_database::{Database, DatabaseError};
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

    let posix_group = database
        .register_nfs_posix_group(tenant_id, principal_id, group_id, "nfs_users", 42_000)
        .await
        .expect("register immutable NFS POSIX group");
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

    let feature = database
        .transition_nfs_feature_state(tenant_id, principal_id, 1, NfsFeatureState::Preflight)
        .await
        .expect("enter NFS preflight without global Phase 8 activation");
    let export = database
        .register_nfs_export(tenant_id, principal_id, drive_id, 7)
        .await
        .expect("register disabled NFS export");
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
    let staged = database
        .stage_nfs_export(
            tenant_id,
            principal_id,
            drive_id,
            export.desired_generation,
            NfsExportState::Active,
        )
        .await
        .expect("stage NFS export activation");
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
    let mapping = database
        .upsert_nfs_principal_mapping(&UpsertNfsPrincipalMappingInput {
            tenant_id,
            actor_principal_id: principal_id,
            principal_id,
            kerberos_principal: "Nfs_User@EXAMPLE.TEST",
            projected_uid: 41_000,
            projected_gid: 42_000,
            allowed_drive_ids: &[drive_id],
            expected_generation: None,
        })
        .await
        .expect("create NFS Kerberos projection");
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
    let feature = database
        .transition_nfs_feature_state(
            tenant_id,
            principal_id,
            feature.generation,
            NfsFeatureState::Active,
        )
        .await
        .expect("activate tenant-local NFS feature after gateway/export preflight");
    assert_eq!(feature.state, NfsFeatureState::Active);
    assert_eq!(feature.manifest_generation, 3);
    assert_eq!(feature.applied_manifest_generation, 3);
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
    assert_eq!(first_session.session.allowed_drive_ids, vec![drive_id]);
    assert_eq!(first_session.allowed_export_ids, vec![7]);
    assert_eq!(first_session.posix_name, "nfs_user");
    assert_eq!(first_session.primary_group_name, "nfs_users");
    assert_eq!(first_session.manifest_generation, 3);
    assert_eq!(first_session.restore_generation, 1);
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
    let replay_request_digest = [31_u8; 32];
    let replay_response_digest = [32_u8; 32];
    let replay_context = NfsReplayContext {
        tenant_id,
        mount_session_id: first_session.session.session_id,
        client_id: "nfs-client-1",
        nfs_session_id: "nfs-session-1",
        slot_id: 7,
        sequence_id: 9,
        operation_index: 1,
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
    assert_eq!(
        database
            .lookup_nfs_replay_receipt(&replay_context)
            .await
            .expect("look up NFS replay response")
            .expect("stored NFS replay response"),
        replay
    );
    assert!(matches!(
        database
            .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
                context: replay_context,
                response_bytes: &[0x08, 0x02],
                response_digest: &[33_u8; 32],
            })
            .await,
        Err(DatabaseError::Conflict)
    ));
    assert!(matches!(
        database
            .stage_nfs_export(
                tenant_id,
                principal_id,
                drive_id,
                staged.desired_generation,
                NfsExportState::Draining,
            )
            .await,
        Err(DatabaseError::Conflict)
    ));
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

async fn function_privilege(database: &Database, role: &str, function: &str) -> bool {
    sqlx::query_scalar("SELECT has_function_privilege($1,$2,'EXECUTE')")
        .bind(role)
        .bind(function)
        .fetch_one(database.pool())
        .await
        .expect("function privilege query")
}

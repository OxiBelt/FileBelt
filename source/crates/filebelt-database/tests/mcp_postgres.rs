// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed MCP schema and least-privilege contract checks.

use filebelt_database::mcp::{
    McpBrokerOperationIdempotency, McpBrokerOperationStart, McpIdempotency, McpIdempotentWrite,
    McpMutationIdempotency, McpMutationStart, McpSecretEnvelope, NewCapabilitySnapshot,
    NewMcpApprovalRule, NewMcpDataGrant, NewMcpInvocation, NewMcpOAuthAttempt, NewMcpRegistration,
    NewMcpRunnerSlotReservation, RegistrationConfigurationUpdate,
};
use filebelt_database::{Database, DatabaseError};
use serde_json::json;
use sqlx::{Connection as _, PgConnection, Row as _};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_MCP_TEST_DATABASE_URL"]
async fn mcp_schema_enforces_tenant_isolation_and_secret_privileges() {
    let database_url = std::env::var("FILEBELT_MCP_TEST_DATABASE_URL")
        .expect("FILEBELT_MCP_TEST_DATABASE_URL is required");
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

    assert!(!schema_privilege(&database, "filebelt_api", "filebelt_mcp_vault", "USAGE").await);
    assert!(
        !table_privilege(
            &database,
            "filebelt_api",
            "filebelt_mcp_vault.secret_envelopes",
            "SELECT"
        )
        .await
    );
    assert!(
        table_privilege(
            &database,
            "filebelt_mcp_broker",
            "filebelt_mcp_vault.secret_envelopes",
            "UPDATE"
        )
        .await
    );
    assert!(
        !column_privilege(
            &database,
            "filebelt_recovery",
            "filebelt_mcp_vault.secret_envelopes",
            "ciphertext",
            "SELECT"
        )
        .await
    );
    assert!(
        column_privilege(
            &database,
            "filebelt_recovery",
            "filebelt_mcp_vault.secret_envelopes",
            "kek_generation",
            "SELECT"
        )
        .await
    );
    assert!(
        !column_privilege(
            &database,
            "filebelt_mcp_broker",
            "filebelt_mcp.registrations",
            "endpoint_uri",
            "UPDATE"
        )
        .await
    );
    assert!(
        function_privilege(
            &database,
            "filebelt_mcp_broker",
            "filebelt_mcp.replace_registration_configuration_and_erase(uuid,uuid,uuid,bigint,text,text,text,text,text,jsonb)",
            "EXECUTE"
        )
        .await
    );

    let tenant_id = Uuid::new_v4();
    let user_principal_id = Uuid::new_v4();
    let group_principal_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'mcp-test')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("tenant");
    sqlx::query(
        "INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user'),($1,$3,'group')",
    )
    .bind(tenant_id)
    .bind(user_principal_id)
    .bind(group_principal_id)
    .execute(database.pool())
    .await
    .expect("principals");

    let registration_id = Uuid::new_v4();
    let registration = database
        .mcp_create_registration(&NewMcpRegistration {
            tenant_id,
            id: registration_id,
            owner_principal_id: user_principal_id,
            owner_kind: "user",
            source_kind: "personal",
            template_id: None,
            display_name: "Safe server",
            description: "A test server",
            transport: "streamable_http",
            endpoint_uri: Some("https://mcp.example.test/rpc"),
            trust_profile: Some("public"),
            catalog_entry: None,
            policy: &json!({}),
        })
        .await
        .expect("registration");
    assert_eq!(registration.owner_principal_id, user_principal_id);
    verify_broker_config_erasure_boundary(&database, tenant_id, user_principal_id).await;
    let mismatch = database
        .mcp_create_registration(&NewMcpRegistration {
            tenant_id,
            id: Uuid::new_v4(),
            owner_principal_id: group_principal_id,
            owner_kind: "user",
            source_kind: "personal",
            template_id: None,
            display_name: "Invalid owner",
            description: "A rejected test server",
            transport: "streamable_http",
            endpoint_uri: Some("https://mcp.example.test/rpc"),
            trust_profile: Some("public"),
            catalog_entry: None,
            policy: &json!({}),
        })
        .await;
    assert!(matches!(mismatch, Err(DatabaseError::Sql(_))));

    let envelope = McpSecretEnvelope {
        tenant_id,
        registration_id,
        owner_principal_id: user_principal_id,
        issuer: "https://issuer.example.test".into(),
        secret_kind: "oauth_refresh".into(),
        credential_generation: 2,
        ciphertext: vec![1, 2, 3],
        nonce: vec![4; 12],
        wrapped_dek: vec![5; 48],
        wrap_nonce: vec![6; 12],
        kek_generation: 7,
        aad_version: 1,
    };
    database
        .mcp_replace_registration_secret(&envelope)
        .await
        .expect("store envelope");
    assert_eq!(
        database
            .mcp_secret_envelope(
                tenant_id,
                registration_id,
                user_principal_id,
                &envelope.issuer,
                &envelope.secret_kind,
            )
            .await
            .expect("read envelope")
            .ciphertext,
        envelope.ciphertext
    );
    assert!(matches!(
        database.mcp_replace_registration_secret(&envelope).await,
        Err(DatabaseError::StaleGeneration)
    ));

    let capability = json!({
        "name":"safe_read",
        "annotations":{"readOnlyHint":true},
        "inputSchema":{"type":"object"}
    });
    let capability_fingerprint =
        filebelt_mcp_policy::policy_json_digest(b"capability", &capability)
            .expect("capability fingerprint");
    let capability_document = json!({
        "tools":{"tools":[capability]},
        "resources":{"resources":[]},
        "prompts":{"prompts":[]},
    });
    let snapshot_id = Uuid::new_v4();
    database
        .mcp_store_capability_snapshot(&NewCapabilitySnapshot {
            tenant_id,
            id: snapshot_id,
            registration_id,
            credential_generation: 2,
            fingerprint: &filebelt_mcp_policy::policy_json_digest(
                b"capability-snapshot",
                &capability_document,
            )
            .expect("snapshot fingerprint"),
            protocol_version: "2026-07-28",
            document: &capability_document,
        })
        .await
        .expect("capability snapshot");
    database
        .mcp_review_capability(
            tenant_id,
            registration_id,
            snapshot_id,
            &capability_fingerprint,
            user_principal_id,
            "approved",
            &json!({}),
        )
        .await
        .expect("capability review");

    let oauth_attempt_id = Uuid::new_v4();
    database
        .mcp_begin_oauth_attempt(&NewMcpOAuthAttempt {
            tenant_id,
            id: oauth_attempt_id,
            registration_id,
            owner_principal_id: user_principal_id,
            credential_generation: 2,
            session_id: Uuid::new_v4(),
            state_digest: &[9; 32],
            issuer: "https://issuer.example.test",
            redirect_path: "/settings/mcp",
            ciphertext: &[1, 2, 3],
            nonce: &[10; 12],
            wrapped_dek: &[11; 48],
            wrap_nonce: &[12; 12],
            kek_generation: 7,
        })
        .await
        .expect("OAuth attempt");

    sqlx::query("UPDATE filebelt_mcp.registrations SET validation_state='valid',authentication_state='authorized',capability_state='approved',enabled=true WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(registration_id)
        .execute(database.pool())
        .await
        .expect("enable registration fixture");
    let drive_id = Uuid::new_v4();
    let root_id = Uuid::new_v4();
    let node_id = Uuid::new_v4();
    let backend_id = Uuid::new_v4();
    let payload_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.drives (tenant_id,id,owner_principal_id,kind,display_name,quota_bytes) VALUES ($1,$2,$3,'private','MCP test',1073741824)")
        .bind(tenant_id).bind(drive_id).bind(user_principal_id)
        .execute(database.pool()).await.expect("drive");
    sqlx::query("INSERT INTO public.nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key) VALUES ($1,$2,$3,NULL,'directory','',''),($1,$2,$4,$3,'file','input.txt','input.txt')")
        .bind(tenant_id).bind(drive_id).bind(root_id).bind(node_id)
        .execute(database.pool()).await.expect("nodes");
    sqlx::query("INSERT INTO public.storage_backends (tenant_id,id) VALUES ($1,$2)")
        .bind(tenant_id)
        .bind(backend_id)
        .execute(database.pool())
        .await
        .expect("backend");
    sqlx::query("INSERT INTO public.payload_objects (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,blake3) VALUES ($1,$2,$3,$4,$5,'whole','referenced',3,$6)")
        .bind(tenant_id).bind(payload_id).bind(drive_id).bind(backend_id)
        .bind(Uuid::new_v4()).bind(vec![7_u8; 32]).execute(database.pool()).await.expect("payload");
    sqlx::query("INSERT INTO public.file_versions (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,created_by) VALUES ($1,$2,$3,1,$4,3,$5,$6)")
        .bind(tenant_id).bind(node_id).bind(version_id).bind(payload_id)
        .bind(vec![7_u8; 32]).bind(user_principal_id).execute(database.pool()).await.expect("version");
    sqlx::query(
        "UPDATE public.nodes SET head_version_id=$4 WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .bind(version_id)
    .execute(database.pool())
    .await
    .expect("head version");

    let data_grant_id = Uuid::new_v4();
    let grant = NewMcpDataGrant {
        tenant_id,
        id: data_grant_id,
        principal_id: user_principal_id,
        registration_id,
        drive_id,
        resource_id: node_id,
        version_id,
        allow_metadata: true,
        allow_content: true,
        drive_acl_generation: 1,
        acl_generation: 1,
        namespace_generation: 1,
        created_by: user_principal_id,
        lifetime_seconds: 300,
    };
    database
        .mcp_create_data_grant(&grant)
        .await
        .expect("data grant");
    let listed = database
        .mcp_node_data_grants(tenant_id, drive_id, node_id)
        .await
        .expect("list data grants");
    assert_eq!(listed[0].registration_id, registration_id);
    assert_eq!(listed[0].version_id, version_id);
    assert_eq!(listed[0].registration_generation, 2);
    database
        .mcp_authority_snapshot(tenant_id, user_principal_id, registration_id, data_grant_id)
        .await
        .expect("exact authority snapshot");
    let mut wrong_version = grant;
    wrong_version.id = Uuid::new_v4();
    wrong_version.version_id = Uuid::new_v4();
    assert!(matches!(
        database.mcp_create_data_grant(&wrong_version).await,
        Err(DatabaseError::NotFound)
    ));

    let erase_revision = database
        .mcp_registration(tenant_id, user_principal_id, registration_id)
        .await
        .expect("registration before erase")
        .revision;
    let erased = database
        .mcp_cryptographically_erase_registration_at_revision(
            tenant_id,
            registration_id,
            user_principal_id,
            erase_revision,
        )
        .await
        .expect("cryptographic erase");
    assert!(!erased.state.enabled);
    assert_eq!(erased.credential_generation, 3);
    assert!(erased.revocation_generation > registration.revocation_generation);
    assert!(matches!(
        database
            .mcp_secret_envelope(
                tenant_id,
                registration_id,
                user_principal_id,
                &envelope.issuer,
                &envelope.secret_kind,
            )
            .await,
        Err(DatabaseError::NotFound)
    ));
    assert!(matches!(
        database
            .mcp_authority_snapshot(tenant_id, user_principal_id, registration_id, data_grant_id,)
            .await,
        Err(DatabaseError::NotFound)
    ));
    let invalidated: (bool, bool) = sqlx::query_as(
        "SELECT s.superseded_at IS NOT NULL,r.revoked_at IS NOT NULL FROM filebelt_mcp.capability_snapshots s JOIN filebelt_mcp.capability_reviews r ON r.tenant_id=s.tenant_id AND r.snapshot_id=s.id WHERE s.tenant_id=$1 AND s.id=$2",
    )
    .bind(tenant_id)
    .bind(snapshot_id)
    .fetch_one(database.pool())
    .await
    .expect("invalidated snapshot and review");
    assert_eq!(invalidated, (true, true));
    let oauth_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mcp.oauth_attempts WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(oauth_attempt_id)
    .fetch_one(database.pool())
    .await
    .expect("OAuth attempt count");
    assert_eq!(oauth_rows, 0);

    sqlx::query("UPDATE filebelt_mcp.registrations SET validation_state='valid',authentication_state='authorized',capability_state='approved',protocol_version='2026-07-28',enabled=true WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(registration_id)
        .execute(database.pool())
        .await
        .expect("re-enable invocation fixture");
    let generations = database
        .mcp_revocation_generations(tenant_id, user_principal_id, registration_id)
        .await
        .expect("invocation generations");
    let invocation_id = Uuid::new_v4();
    database
        .mcp_start_invocation(&NewMcpInvocation {
            tenant_id,
            id: invocation_id,
            registration_id,
            principal_id: user_principal_id,
            application_id: "test",
            primitive: "tool_call",
            capability_fingerprint: &capability_fingerprint,
            approval_id: None,
            registration_generation: generations.registration,
            authority_generation: generations.principal,
            admin_block_generation: generations.admin_block,
            request_bytes: 1,
            semantic_node_id: None,
            semantic_base_version_id: None,
            semantic_input_digest: None,
        })
        .await
        .expect("active invocation");
    database
        .mcp_create_admin_block_rule(
            tenant_id,
            Uuid::new_v4(),
            "registration",
            &registration_id.to_string(),
            "mcp.admin_test",
            user_principal_id,
        )
        .await
        .expect("admin block");
    let cancelled: (String, Option<String>) = sqlx::query_as(
        "SELECT state,reason_code FROM filebelt_mcp.invocations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(invocation_id)
    .fetch_one(database.pool())
    .await
    .expect("cancelled invocation");
    assert_eq!(
        cancelled,
        ("cancelled".into(), Some("mcp.admin_block_changed".into()))
    );
    assert!(
        database
            .mcp_revocation_generations(tenant_id, user_principal_id, registration_id)
            .await
            .expect("updated admin generation")
            .admin_block
            > generations.admin_block
    );

    verify_runner_slot_admission(&database, tenant_id, user_principal_id).await;
    verify_atomic_approval_idempotency(
        &database,
        tenant_id,
        registration_id,
        user_principal_id,
        &capability_fingerprint,
    )
    .await;
    verify_local_mutation_idempotency(&database, tenant_id, user_principal_id).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL in FILEBELT_MCP_TEST_DATABASE_URL"]
async fn mcp_local_mutations_commit_receipts_atomically() {
    let database_url = std::env::var("FILEBELT_MCP_TEST_DATABASE_URL")
        .expect("FILEBELT_MCP_TEST_DATABASE_URL is required");
    let database = Database::connect(&database_url, 4)
        .await
        .expect("connect test database");
    sqlx::raw_sql(include_str!("../../../migrations/postgres/roles.sql"))
        .execute(database.pool())
        .await
        .expect("apply roles");
    database.migrate().await.expect("apply migrations");
    let tenant_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,$2)")
        .bind(tenant_id)
        .bind(format!("mcp-idempotency-{tenant_id}"))
        .execute(database.pool())
        .await
        .expect("tenant");
    sqlx::query("INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user')")
        .bind(tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await
        .expect("principal");

    verify_local_mutation_idempotency(&database, tenant_id, principal_id).await;
    verify_broker_operation_idempotency(&database, tenant_id, principal_id).await;
}

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_MCP_TEST_DATABASE_URL"]
async fn broker_receipt_runtime_roles_enforce_narrow_grants() {
    let database_url = std::env::var("FILEBELT_MCP_TEST_DATABASE_URL")
        .expect("FILEBELT_MCP_TEST_DATABASE_URL is required");
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

    let tenant_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id,slug) VALUES ($1,'mcp-receipt-roles')")
        .bind(tenant_id)
        .execute(database.pool())
        .await
        .expect("receipt role tenant");
    sqlx::query("INSERT INTO public.principals (tenant_id,id,kind) VALUES ($1,$2,'user')")
        .bind(tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await
        .expect("receipt role principal");

    verify_broker_receipt_runtime_roles(&database, &database_url, tenant_id, principal_id).await;
}

async fn verify_broker_config_erasure_boundary(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
) {
    let registration_id = Uuid::new_v4();
    database
        .mcp_create_registration(&NewMcpRegistration {
            tenant_id,
            id: registration_id,
            owner_principal_id: principal_id,
            owner_kind: "user",
            source_kind: "personal",
            template_id: None,
            display_name: "Configuration boundary",
            description: "Before replacement",
            transport: "streamable_http",
            endpoint_uri: Some("https://old.example.test/rpc"),
            trust_profile: Some("public"),
            catalog_entry: None,
            policy: &json!({}),
        })
        .await
        .expect("configuration boundary registration");

    let mut denied = database.pool().begin().await.expect("denial transaction");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *denied)
        .await
        .expect("assume broker role");
    assert!(
        sqlx::query("UPDATE filebelt_mcp.registrations SET endpoint_uri='https://forbidden.example.test' WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(registration_id)
            .execute(&mut *denied)
            .await
            .is_err()
    );
    denied.rollback().await.expect("rollback denied update");

    let mut allowed = database.pool().begin().await.expect("definer transaction");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *allowed)
        .await
        .expect("assume broker role");
    sqlx::query("SELECT filebelt_mcp.replace_registration_configuration_and_erase($1,$2,$3,1,'Configuration boundary','After replacement','https://new.example.test/rpc','public',NULL,'{}'::jsonb)")
        .bind(tenant_id)
        .bind(registration_id)
        .bind(principal_id)
        .execute(&mut *allowed)
        .await
        .expect("broker-only definer function");
    allowed.commit().await.expect("commit definer operation");
    let changed = database
        .mcp_registration(tenant_id, principal_id, registration_id)
        .await
        .expect("changed registration");
    assert_eq!(
        changed.endpoint_uri.as_deref(),
        Some("https://new.example.test/rpc")
    );
    assert_eq!(changed.credential_generation, 2);
    assert_eq!(changed.revocation_generation, 2);
}

async fn verify_runner_slot_admission(database: &Database, tenant_id: Uuid, principal_id: Uuid) {
    let first = Uuid::new_v4();
    database
        .mcp_reserve_runner_slot(NewMcpRunnerSlotReservation {
            tenant_id,
            invocation_id: first,
            principal_id,
            tenant_limit: 2,
            principal_limit: 1,
            lease_seconds: 60,
        })
        .await
        .expect("reserve first runner");
    let second = Uuid::new_v4();
    assert!(matches!(
        database
            .mcp_reserve_runner_slot(NewMcpRunnerSlotReservation {
                tenant_id,
                invocation_id: second,
                principal_id,
                tenant_limit: 2,
                principal_limit: 1,
                lease_seconds: 60,
            })
            .await,
        Err(DatabaseError::AdmissionLimited)
    ));
    sqlx::query("UPDATE filebelt_mcp.runner_slot_reservations SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND invocation_id=$2")
        .bind(tenant_id)
        .bind(first)
        .execute(database.pool())
        .await
        .expect("expire reservation fixture");
    assert_eq!(
        database
            .mcp_expired_runner_slots(10)
            .await
            .expect("expired reservations")[0]
            .invocation_id,
        first
    );
    assert!(matches!(
        database
            .mcp_reserve_runner_slot(NewMcpRunnerSlotReservation {
                tenant_id,
                invocation_id: second,
                principal_id,
                tenant_limit: 2,
                principal_limit: 1,
                lease_seconds: 60,
            })
            .await,
        Err(DatabaseError::AdmissionLimited)
    ));
    database
        .mcp_release_runner_slot_after_confirmed_delete(tenant_id, first, principal_id)
        .await
        .expect("release after confirmed deletion");
    database
        .mcp_reserve_runner_slot(NewMcpRunnerSlotReservation {
            tenant_id,
            invocation_id: second,
            principal_id,
            tenant_limit: 2,
            principal_limit: 1,
            lease_seconds: 60,
        })
        .await
        .expect("reserve after release");
}

async fn verify_atomic_approval_idempotency(
    database: &Database,
    tenant_id: Uuid,
    registration_id: Uuid,
    principal_id: Uuid,
    fingerprint: &[u8; 32],
) {
    let intent_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    database
        .mcp_create_invocation_intent(
            tenant_id,
            intent_id,
            registration_id,
            principal_id,
            session_id,
            "test",
            "tool_call",
            fingerprint,
            &[13; 32],
            &[14; 32],
            &[15; 32],
        )
        .await
        .expect("invocation intent");
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();
    let first_body = json!({"id":first_id});
    let second_body = json!({"id":second_id});
    let request_fingerprint = [16; 32];
    let first = NewMcpApprovalRule {
        tenant_id,
        id: first_id,
        registration_id,
        principal_id,
        intent_id,
        session_id: Some(session_id),
        application_id: "test",
        primitive: "tool_call",
        capability_name: "safe_read",
        capability_fingerprint: fingerprint,
        argument_digest: &[13; 32],
        attachment_digest: &[14; 32],
        single_use: true,
        lifetime_seconds: 60,
    };
    let mut second = first.clone();
    second.id = second_id;
    let first_idempotency = McpIdempotency {
        principal_id,
        route: "POST /api/v1/mcp/invocation-intents/{intent_id}/approval",
        key: "same-key",
        request_fingerprint: &request_fingerprint,
        response_status: 201,
        response_body: &first_body,
    };
    let second_idempotency = McpIdempotency {
        principal_id,
        route: "POST /api/v1/mcp/invocation-intents/{intent_id}/approval",
        key: "same-key",
        request_fingerprint: &request_fingerprint,
        response_status: 201,
        response_body: &second_body,
    };
    let (left, right) = tokio::join!(
        database.mcp_create_approval_rule_idempotent(&first, &first_idempotency),
        database.mcp_create_approval_rule_idempotent(&second, &second_idempotency)
    );
    let bodies = [
        left.expect("first idempotent write"),
        right.expect("second idempotent write"),
    ]
    .map(|outcome| match outcome {
        McpIdempotentWrite::Created(record) | McpIdempotentWrite::Replayed(record) => {
            record.response_body
        }
        McpIdempotentWrite::KeyReused => panic!("matching request was rejected"),
    });
    assert_eq!(bodies[0], bodies[1]);
}

async fn verify_local_mutation_idempotency(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
) {
    let route = "POST /api/v1/mcp/registrations";
    let request_fingerprint = [31; 32];
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();
    let (left, right) = tokio::join!(
        create_registration_idempotently(
            database,
            tenant_id,
            principal_id,
            route,
            "local-concurrent",
            &request_fingerprint,
            first_id,
        ),
        create_registration_idempotently(
            database,
            tenant_id,
            principal_id,
            route,
            "local-concurrent",
            &request_fingerprint,
            second_id,
        ),
    );
    let bodies = [
        left.expect("first local mutation"),
        right.expect("second local mutation"),
    ]
    .map(|outcome| match outcome {
        McpIdempotentWrite::Created(record) | McpIdempotentWrite::Replayed(record) => {
            record.response_body
        }
        McpIdempotentWrite::KeyReused => panic!("matching local mutation was rejected"),
    });
    assert_eq!(bodies[0], bodies[1]);
    let created_id = bodies[0]["id"].as_str().expect("created identifier");
    let registration_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mcp.registrations WHERE tenant_id=$1 AND id IN ($2,$3)",
    )
    .bind(tenant_id)
    .bind(first_id)
    .bind(second_id)
    .fetch_one(database.pool())
    .await
    .expect("registration count");
    assert_eq!(registration_count, 1);
    assert!(created_id == first_id.to_string() || created_id == second_id.to_string());

    assert!(matches!(
        database
            .mcp_begin_mutation(&McpMutationIdempotency {
                tenant_id,
                principal_id,
                route,
                key: "local-concurrent",
                request_fingerprint: &[32; 32],
                legacy_request_fingerprint: None,
            })
            .await
            .expect("mismatched mutation admission"),
        McpMutationStart::KeyReused
    ));

    let rolled_back_id = Uuid::new_v4();
    let rollback_fingerprint = [33; 32];
    let mut pending = match database
        .mcp_begin_mutation(&McpMutationIdempotency {
            tenant_id,
            principal_id,
            route,
            key: "local-rollback",
            request_fingerprint: &rollback_fingerprint,
            legacy_request_fingerprint: None,
        })
        .await
        .expect("rollback mutation admission")
    {
        McpMutationStart::Started(transaction) => transaction,
        _ => panic!("fresh rollback key did not start"),
    };
    let rollback_policy = json!({});
    pending
        .create_registration(&test_registration_input(
            tenant_id,
            principal_id,
            rolled_back_id,
            "Rolled back",
            &rollback_policy,
        ))
        .await
        .expect("uncommitted registration");
    drop(pending);
    assert!(matches!(
        database
            .mcp_registration(tenant_id, principal_id, rolled_back_id)
            .await,
        Err(DatabaseError::NotFound)
    ));
    let replacement_id = Uuid::new_v4();
    let replacement = create_registration_idempotently(
        database,
        tenant_id,
        principal_id,
        route,
        "local-rollback",
        &rollback_fingerprint,
        replacement_id,
    )
    .await
    .expect("replacement after rollback");
    assert!(matches!(replacement, McpIdempotentWrite::Created(_)));
    let pending_receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM public.idempotency_records WHERE tenant_id=$1 AND principal_id=$2 AND route=$3 AND key IN ('local-concurrent','local-rollback') AND response_status=102")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(route)
        .fetch_one(database.pool())
        .await
        .expect("pending receipt count");
    assert_eq!(pending_receipts, 0);
}

async fn verify_broker_operation_idempotency(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
) {
    let registration_id = Uuid::new_v4();
    let policy = json!({});
    database
        .mcp_create_registration(&test_registration_input(
            tenant_id,
            principal_id,
            registration_id,
            "Broker operation",
            &policy,
        ))
        .await
        .expect("broker operation registration");
    let rollback_id = Uuid::new_v4();
    database
        .mcp_create_registration(&test_registration_input(
            tenant_id,
            principal_id,
            rollback_id,
            "Broker rollback",
            &policy,
        ))
        .await
        .expect("broker rollback registration");
    let rollback_operation_id = Uuid::new_v4();
    let mut pending = match database
        .mcp_begin_broker_operation(&McpBrokerOperationIdempotency {
            tenant_id,
            principal_id,
            registration_id: rollback_id,
            operation: "registration_configure",
            operation_id: rollback_operation_id,
            request_fingerprint: &[40; 32],
        })
        .await
        .expect("rollback broker admission")
    {
        McpBrokerOperationStart::Started(transaction) => transaction,
        _ => panic!("fresh rollback broker operation did not start"),
    };
    pending
        .configure_registration(&RegistrationConfigurationUpdate {
            tenant_id,
            registration_id: rollback_id,
            owner_principal_id: principal_id,
            expected_revision: 1,
            display_name: "Must roll back",
            description: "Uncommitted",
            endpoint_uri: Some("https://mcp.example.test/idempotency"),
            trust_profile: Some("public"),
            catalog_entry: None,
            policy: &policy,
        })
        .await
        .expect("uncommitted broker mutation");
    drop(pending);
    assert_eq!(
        database
            .mcp_registration(tenant_id, principal_id, rollback_id)
            .await
            .expect("rolled back broker registration")
            .revision,
        1
    );
    let rollback_receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND operation_id=$2")
        .bind(tenant_id)
        .bind(rollback_operation_id)
        .fetch_one(database.pool())
        .await
        .expect("rolled back broker receipt count");
    assert_eq!(rollback_receipts, 0);
    let operation_id = Uuid::new_v4();
    let request_fingerprint = [41; 32];
    let (left, right) = tokio::join!(
        configure_broker_operation(
            database,
            tenant_id,
            principal_id,
            registration_id,
            operation_id,
            &request_fingerprint,
        ),
        configure_broker_operation(
            database,
            tenant_id,
            principal_id,
            registration_id,
            operation_id,
            &request_fingerprint,
        ),
    );
    assert_eq!(
        left.expect("first broker operation"),
        right.expect("broker replay")
    );
    let changed = database
        .mcp_registration(tenant_id, principal_id, registration_id)
        .await
        .expect("configured registration");
    assert_eq!(changed.revision, 2);
    assert!(matches!(
        database
            .mcp_begin_broker_operation(&McpBrokerOperationIdempotency {
                tenant_id,
                principal_id,
                registration_id,
                operation: "registration_configure",
                operation_id,
                request_fingerprint: &[42; 32],
            })
            .await
            .expect("mismatch admission"),
        McpBrokerOperationStart::KeyReused
    ));
    assert!(matches!(
        database
            .mcp_begin_broker_operation(&McpBrokerOperationIdempotency {
                tenant_id,
                principal_id,
                registration_id: Uuid::new_v4(),
                operation: "credential_erase",
                operation_id,
                request_fingerprint: &request_fingerprint,
            })
            .await
            .expect("cross-scope mismatch admission"),
        McpBrokerOperationStart::KeyReused
    ));

    let public_fingerprint = [43; 32];
    let mut local = match database
        .mcp_begin_mutation(&McpMutationIdempotency {
            tenant_id,
            principal_id,
            route: "PATCH /api/v1/mcp/registrations/{registration_id}",
            key: "broker-operation",
            request_fingerprint: &public_fingerprint,
            legacy_request_fingerprint: None,
        })
        .await
        .expect("local continuation")
    {
        McpMutationStart::Started(transaction) => transaction,
        _ => panic!("fresh local continuation did not start"),
    };
    local
        .mark_broker_operation_applied(operation_id)
        .await
        .expect("mark API continuation");
    local
        .finalize(200, &json!({"id":registration_id}))
        .await
        .expect("finalize public receipt");
    sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET created_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 day' WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(operation_id)
        .execute(database.pool())
        .await
        .expect("expire completed broker receipt");

    let incomplete_id = Uuid::new_v4();
    sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint,result,created_at,expires_at) VALUES ($1,$2,$3,'credential_erase',$4,$5,$6,clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day')")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(registration_id)
        .bind(incomplete_id)
        .bind([44_u8; 32].as_slice())
        .bind(serde_json::to_value(&changed).expect("safe erased result"))
        .execute(database.pool())
        .await
        .expect("incomplete delete receipt");
    assert_eq!(
        database
            .purge_mcp_broker_operation_receipts(tenant_id, 1)
            .await
            .expect("bounded broker receipt cleanup"),
        1
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND operation_id=$2 AND api_completed_at IS NULL")
        .bind(tenant_id)
        .bind(incomplete_id)
        .fetch_one(database.pool())
        .await
        .expect("incomplete receipt count");
    assert_eq!(remaining, 1);
    assert!(matches!(
        database
            .mcp_begin_broker_operation(&McpBrokerOperationIdempotency {
                tenant_id,
                principal_id,
                registration_id,
                operation: "credential_erase",
                operation_id: incomplete_id,
                request_fingerprint: &[44; 32],
            })
            .await
            .expect("expired incomplete delete replay"),
        McpBrokerOperationStart::Replayed(_)
    ));
}

async fn verify_broker_receipt_runtime_roles(
    database: &Database,
    database_url: &str,
    tenant_id: Uuid,
    principal_id: Uuid,
) {
    let registration_id = Uuid::new_v4();
    let completion_id = Uuid::new_v4();
    let eligible_id = Uuid::new_v4();
    let incomplete_id = Uuid::new_v4();
    let broker_operation_id = Uuid::new_v4();
    let reset_race_id = Uuid::new_v4();
    sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint,result,expires_at) VALUES ($1,$2,$3,'credential_erase',$4,$5,'{}'::jsonb,clock_timestamp()+interval '1 day')")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(registration_id)
        .bind(completion_id)
        .bind([91_u8; 32].as_slice())
        .execute(database.pool())
        .await
        .expect("seed API completion receipt");
    sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint,result,api_completed_at,created_at,expires_at) VALUES ($1,$2,$3,'credential_erase',$4,$5,'{}'::jsonb,clock_timestamp(),clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day')")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(registration_id)
        .bind(eligible_id)
        .bind([92_u8; 32].as_slice())
        .execute(database.pool())
        .await
        .expect("seed eligible maintenance receipt");
    sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint,result,created_at,expires_at) VALUES ($1,$2,$3,'credential_erase',$4,$5,'{}'::jsonb,clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day')")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(registration_id)
        .bind(incomplete_id)
        .bind([93_u8; 32].as_slice())
        .execute(database.pool())
        .await
        .expect("seed incomplete maintenance receipt");
    sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint,result,api_completed_at,created_at,expires_at) VALUES ($1,$2,$3,'credential_erase',$4,$5,'{}'::jsonb,clock_timestamp(),clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day')")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(registration_id)
        .bind(reset_race_id)
        .bind([95_u8; 32].as_slice())
        .execute(database.pool())
        .await
        .expect("seed broker reset race receipt");

    let mut broker = database.pool().begin().await.expect("begin broker receipt");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *broker)
        .await
        .expect("assume MCP broker role");
    let admitted = sqlx::query("INSERT INTO filebelt_mcp.broker_operation_receipts (tenant_id,principal_id,registration_id,operation,operation_id,request_fingerprint) VALUES ($1,$2,$3,'credential_erase',$4,$5) ON CONFLICT DO NOTHING")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(registration_id)
        .bind(broker_operation_id)
        .bind([94_u8; 32].as_slice())
        .execute(&mut *broker)
        .await
        .expect("admit broker receipt through the MCP broker role")
        .rows_affected();
    assert_eq!(admitted, 1);
    let pending = sqlx::query("SELECT registration_id,operation,request_fingerprint,result,api_completed_at IS NOT NULL AS api_completed,expires_at<=clock_timestamp() AS expired FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 FOR UPDATE")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(broker_operation_id)
        .fetch_one(&mut *broker)
        .await
        .expect("read pending broker receipt through the MCP broker role");
    assert!(
        pending
            .get::<Option<serde_json::Value>, _>("result")
            .is_none()
    );
    let finalized = sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET result=$7 WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 AND registration_id=$4 AND operation=$5 AND request_fingerprint=$6 AND result IS NULL")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(broker_operation_id)
        .bind(registration_id)
        .bind("credential_erase")
        .bind([94_u8; 32].as_slice())
        .bind(json!({"revision": 1, "credential_generation": 1}))
        .execute(&mut *broker)
        .await
        .expect("finalize broker receipt through the MCP broker role")
        .rows_affected();
    assert_eq!(finalized, 1);
    broker.commit().await.expect("commit broker receipt");

    let mut broker_replay = database.pool().begin().await.expect("begin broker replay");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *broker_replay)
        .await
        .expect("assume MCP broker role for replay");
    let replayed = sqlx::query("SELECT registration_id,operation,request_fingerprint,result,api_completed_at IS NOT NULL AS api_completed,expires_at<=clock_timestamp() AS expired FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 FOR UPDATE")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(broker_operation_id)
        .fetch_one(&mut *broker_replay)
        .await
        .expect("replay broker receipt through the MCP broker role");
    assert_eq!(
        replayed.get::<Option<serde_json::Value>, _>("result"),
        Some(json!({"revision": 1, "credential_generation": 1}))
    );
    broker_replay.commit().await.expect("commit broker replay");

    let mut broker_denied = database.pool().begin().await.expect("begin broker denial");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *broker_denied)
        .await
        .expect("assume MCP broker role for denial");
    assert!(
        sqlx::query("DELETE FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(broker_operation_id)
            .execute(&mut *broker_denied)
            .await
            .is_err(),
        "the MCP broker role must not delete broker receipts"
    );
    broker_denied
        .rollback()
        .await
        .expect("rollback broker denial");

    let mut broker_select_denied = database
        .pool()
        .begin()
        .await
        .expect("begin broker select denial");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *broker_select_denied)
        .await
        .expect("assume MCP broker role for select denial");
    assert!(
        sqlx::query("SELECT created_at FROM filebelt_mcp.broker_operation_receipts")
            .fetch_optional(&mut *broker_select_denied)
            .await
            .is_err(),
        "the MCP broker role must not read broader receipt metadata"
    );
    broker_select_denied
        .rollback()
        .await
        .expect("rollback broker select denial");

    let mut broker_vault = database
        .pool()
        .begin()
        .await
        .expect("begin broker vault access");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *broker_vault)
        .await
        .expect("assume MCP broker role for vault access");
    sqlx::query("SELECT ciphertext FROM filebelt_mcp_vault.secret_envelopes")
        .fetch_optional(&mut *broker_vault)
        .await
        .expect("the MCP broker role may read encrypted vault envelopes");
    broker_vault
        .commit()
        .await
        .expect("commit broker vault access");

    let mut api = database
        .pool()
        .begin()
        .await
        .expect("begin API continuation");
    sqlx::query("SET LOCAL ROLE filebelt_api")
        .execute(&mut *api)
        .await
        .expect("assume API role");
    let marked = sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET api_completed_at=COALESCE(api_completed_at,clock_timestamp()) WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 AND result IS NOT NULL")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(completion_id)
        .execute(&mut *api)
        .await
        .expect("complete broker receipt through the API role")
        .rows_affected();
    assert_eq!(marked, 1);
    api.commit().await.expect("commit API continuation");

    let mut api_denied = database.pool().begin().await.expect("begin API denial");
    sqlx::query("SET LOCAL ROLE filebelt_api")
        .execute(&mut *api_denied)
        .await
        .expect("assume API role for denial");
    assert!(
        sqlx::query("SELECT created_at FROM filebelt_mcp.broker_operation_receipts")
            .fetch_optional(&mut *api_denied)
            .await
            .is_err(),
        "the API role must not read broader receipt metadata"
    );
    api_denied.rollback().await.expect("rollback API denial");

    let mut vault_denied = database.pool().begin().await.expect("begin vault denial");
    sqlx::query("SET LOCAL ROLE filebelt_api")
        .execute(&mut *vault_denied)
        .await
        .expect("assume API role for vault denial");
    assert!(
        sqlx::query("SELECT ciphertext FROM filebelt_mcp_vault.secret_envelopes")
            .fetch_optional(&mut *vault_denied)
            .await
            .is_err(),
        "the API role must not access the MCP vault"
    );
    vault_denied
        .rollback()
        .await
        .expect("rollback vault denial");

    let mut maintenance_select = database
        .pool()
        .begin()
        .await
        .expect("begin maintenance select denial");
    sqlx::query("SET LOCAL ROLE filebelt_maintenance")
        .execute(&mut *maintenance_select)
        .await
        .expect("assume maintenance role for select denial");
    assert!(
        sqlx::query("SELECT created_at FROM filebelt_mcp.broker_operation_receipts")
            .fetch_optional(&mut *maintenance_select)
            .await
            .is_err(),
        "the maintenance role must not read broader receipt metadata"
    );
    maintenance_select
        .rollback()
        .await
        .expect("rollback maintenance select denial");

    let mut maintenance_update = database
        .pool()
        .begin()
        .await
        .expect("begin maintenance update denial");
    sqlx::query("SET LOCAL ROLE filebelt_maintenance")
        .execute(&mut *maintenance_update)
        .await
        .expect("assume maintenance role for update denial");
    assert!(
        sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET api_completed_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
            .bind(tenant_id)
            .bind(principal_id)
            .bind(incomplete_id)
            .execute(&mut *maintenance_update)
            .await
            .is_err(),
        "the maintenance role must not update broker receipts"
    );
    maintenance_update
        .rollback()
        .await
        .expect("rollback maintenance update denial");

    let mut maintenance = database
        .pool()
        .begin()
        .await
        .expect("begin maintenance purge");
    sqlx::query("SET LOCAL ROLE filebelt_maintenance")
        .execute(&mut *maintenance)
        .await
        .expect("assume maintenance role");
    let removed = sqlx::query("DELETE FROM filebelt_mcp.broker_operation_receipts AS receipt WHERE (receipt.tenant_id,receipt.principal_id,receipt.operation_id) IN (SELECT candidate.tenant_id,candidate.principal_id,candidate.operation_id FROM filebelt_mcp.broker_operation_receipts AS candidate WHERE candidate.tenant_id=$1 AND candidate.result IS NOT NULL AND candidate.api_completed_at IS NOT NULL AND candidate.expires_at<=clock_timestamp() ORDER BY candidate.expires_at,candidate.operation_id LIMIT $2) AND receipt.result IS NOT NULL AND receipt.api_completed_at IS NOT NULL AND receipt.expires_at<=clock_timestamp()")
        .bind(tenant_id)
        .bind(1_i64)
        .execute(&mut *maintenance)
        .await
        .expect("purge the eligible broker receipt through the maintenance role")
        .rows_affected();
    assert_eq!(removed, 1);
    maintenance
        .commit()
        .await
        .expect("commit maintenance purge");

    let completed: bool = sqlx::query_scalar("SELECT api_completed_at IS NOT NULL FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(completion_id)
        .fetch_one(database.pool())
        .await
        .expect("completed API continuation");
    assert!(completed);
    let eligible_removed: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3)")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(eligible_id)
        .fetch_one(database.pool())
        .await
        .expect("eligible broker receipt removal");
    assert!(eligible_removed);
    let incomplete_retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 AND api_completed_at IS NULL)")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(incomplete_id)
        .fetch_one(database.pool())
        .await
        .expect("incomplete broker receipt retention");
    assert!(incomplete_retained);

    verify_broker_reset_wins_over_blocked_purge(
        database,
        database_url,
        tenant_id,
        principal_id,
        registration_id,
        reset_race_id,
    )
    .await;
}

async fn verify_broker_reset_wins_over_blocked_purge(
    database: &Database,
    database_url: &str,
    tenant_id: Uuid,
    principal_id: Uuid,
    registration_id: Uuid,
    operation_id: Uuid,
) {
    let mut observer = PgConnection::connect(database_url)
        .await
        .expect("connect purge race observer");
    let mut broker = database
        .pool()
        .begin()
        .await
        .expect("begin broker reset race");
    sqlx::query("SET LOCAL ROLE filebelt_mcp_broker")
        .execute(&mut *broker)
        .await
        .expect("assume MCP broker role for reset race");
    sqlx::query("SELECT result FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3 FOR UPDATE")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(operation_id)
        .fetch_one(&mut *broker)
        .await
        .expect("lock expired receipt before reset");

    let maintenance_pool = database.pool().clone();
    let maintenance_task = tokio::spawn(async move {
        let mut maintenance = maintenance_pool.begin().await?;
        sqlx::query("SET LOCAL ROLE filebelt_maintenance")
            .execute(&mut *maintenance)
            .await?;
        sqlx::query("SET LOCAL application_name='filebelt-mcp-purge-reset-race'")
            .execute(&mut *maintenance)
            .await?;
        let removed = sqlx::query("DELETE FROM filebelt_mcp.broker_operation_receipts AS receipt WHERE (receipt.tenant_id,receipt.principal_id,receipt.operation_id) IN (SELECT candidate.tenant_id,candidate.principal_id,candidate.operation_id FROM filebelt_mcp.broker_operation_receipts AS candidate WHERE candidate.tenant_id=$1 AND candidate.result IS NOT NULL AND candidate.api_completed_at IS NOT NULL AND candidate.expires_at<=clock_timestamp() ORDER BY candidate.expires_at,candidate.operation_id LIMIT $2) AND receipt.result IS NOT NULL AND receipt.api_completed_at IS NOT NULL AND receipt.expires_at<=clock_timestamp()")
            .bind(tenant_id)
            .bind(1_i64)
            .execute(&mut *maintenance)
            .await?
            .rows_affected();
        maintenance.commit().await?;
        Ok::<u64, sqlx::Error>(removed)
    });

    let mut purge_waiting = false;
    for _ in 0..100 {
        purge_waiting = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='filebelt-mcp-purge-reset-race' AND wait_event_type='Lock')")
            .fetch_one(&mut observer)
            .await
            .expect("observe blocked maintenance purge");
        if purge_waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        purge_waiting,
        "maintenance purge must wait on the broker row lock"
    );

    let reset = sqlx::query("UPDATE filebelt_mcp.broker_operation_receipts SET registration_id=$4,operation='credential_erase',request_fingerprint=$5,result=NULL,api_completed_at=NULL,created_at=clock_timestamp(),expires_at=clock_timestamp()+interval '24 hours' WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(operation_id)
        .bind(registration_id)
        .bind([96_u8; 32].as_slice())
        .execute(&mut *broker)
        .await
        .expect("reset expired receipt through the broker role")
        .rows_affected();
    assert_eq!(reset, 1);
    broker.commit().await.expect("commit broker reset race");

    let removed = maintenance_task
        .await
        .expect("join blocked maintenance purge")
        .expect("complete blocked maintenance purge");
    assert_eq!(removed, 0);
    let retained: bool = sqlx::query_scalar("SELECT result IS NULL AND api_completed_at IS NULL AND expires_at>clock_timestamp() FROM filebelt_mcp.broker_operation_receipts WHERE tenant_id=$1 AND principal_id=$2 AND operation_id=$3")
        .bind(tenant_id)
        .bind(principal_id)
        .bind(operation_id)
        .fetch_one(database.pool())
        .await
        .expect("broker-reset receipt survives blocked purge");
    assert!(retained);
}

async fn configure_broker_operation(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
    registration_id: Uuid,
    operation_id: Uuid,
    request_fingerprint: &[u8; 32],
) -> Result<serde_json::Value, DatabaseError> {
    match database
        .mcp_begin_broker_operation(&McpBrokerOperationIdempotency {
            tenant_id,
            principal_id,
            registration_id,
            operation: "registration_configure",
            operation_id,
            request_fingerprint,
        })
        .await?
    {
        McpBrokerOperationStart::Replayed(result) => Ok(result),
        McpBrokerOperationStart::KeyReused => Err(DatabaseError::Conflict),
        McpBrokerOperationStart::Started(mut transaction) => {
            let policy = json!({});
            let updated = transaction
                .configure_registration(&RegistrationConfigurationUpdate {
                    tenant_id,
                    registration_id,
                    owner_principal_id: principal_id,
                    expected_revision: 1,
                    display_name: "Broker operation configured",
                    description: "Atomic broker result",
                    endpoint_uri: Some("https://mcp.example.test/idempotency"),
                    trust_profile: Some("public"),
                    catalog_entry: None,
                    policy: &policy,
                })
                .await?;
            let result =
                serde_json::to_value(updated).map_err(|_| DatabaseError::InvalidPersistedValue)?;
            transaction.finalize(&result).await?;
            Ok(result)
        }
    }
}

async fn create_registration_idempotently(
    database: &Database,
    tenant_id: Uuid,
    principal_id: Uuid,
    route: &str,
    key: &str,
    request_fingerprint: &[u8; 32],
    registration_id: Uuid,
) -> Result<McpIdempotentWrite, DatabaseError> {
    let mut mutation = match database
        .mcp_begin_mutation(&McpMutationIdempotency {
            tenant_id,
            principal_id,
            route,
            key,
            request_fingerprint,
            legacy_request_fingerprint: None,
        })
        .await?
    {
        McpMutationStart::Started(transaction) => transaction,
        McpMutationStart::Replayed(record) => return Ok(McpIdempotentWrite::Replayed(record)),
        McpMutationStart::KeyReused => return Ok(McpIdempotentWrite::KeyReused),
    };
    let policy = json!({});
    let record = mutation
        .create_registration(&test_registration_input(
            tenant_id,
            principal_id,
            registration_id,
            "Atomic registration",
            &policy,
        ))
        .await?;
    mutation.finalize(201, &json!({"id":record.id})).await
}

fn test_registration_input<'a>(
    tenant_id: Uuid,
    principal_id: Uuid,
    registration_id: Uuid,
    display_name: &'a str,
    policy: &'a serde_json::Value,
) -> NewMcpRegistration<'a> {
    NewMcpRegistration {
        tenant_id,
        id: registration_id,
        owner_principal_id: principal_id,
        owner_kind: "user",
        source_kind: "personal",
        template_id: None,
        display_name,
        description: "Idempotency test",
        transport: "streamable_http",
        endpoint_uri: Some("https://mcp.example.test/idempotency"),
        trust_profile: Some("public"),
        catalog_entry: None,
        policy,
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

async fn column_privilege(
    database: &Database,
    role: &str,
    table: &str,
    column: &str,
    privilege: &str,
) -> bool {
    let row = sqlx::query("SELECT has_column_privilege($1,$2,$3,$4) AS allowed")
        .bind(role)
        .bind(table)
        .bind(column)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("column privilege");
    row.get("allowed")
}

async fn function_privilege(
    database: &Database,
    role: &str,
    function: &str,
    privilege: &str,
) -> bool {
    sqlx::query_scalar("SELECT has_function_privilege($1,$2,$3)")
        .bind(role)
        .bind(function)
        .bind(privilege)
        .fetch_one(database.pool())
        .await
        .expect("function privilege")
}

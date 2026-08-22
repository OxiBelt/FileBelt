// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL invariants for directory-level Git repository authority.

use filebelt_database::repository::{
    PrepareRepositoryOperationInput, PreparedMainSnapshotInput, PreparedRepositoryFileInput,
    PreparedRepositorySnapshotEntryInput, RepositoryObjectFormat, RepositoryRefChangeKind,
    RepositoryRefUpdateInput, RepositorySnapshotEntryKind,
};
use filebelt_database::{Database, DatabaseError};
use sqlx::Row as _;
use uuid::Uuid;

const TENANT: &str = "19000000-0000-4000-8000-000000000001";
const PRINCIPAL: &str = "19000000-0000-4000-8000-000000000002";
const USER: &str = "19000000-0000-4000-8000-000000000003";
const DRIVE: &str = "19000000-0000-4000-8000-000000000004";
const DRIVE_ROOT: &str = "19000000-0000-4000-8000-000000000005";
const REPOSITORY_ROOT: &str = "19000000-0000-4000-8000-000000000006";
const NESTED_ROOT: &str = "19000000-0000-4000-8000-000000000007";
const FILE_ROOT: &str = "19000000-0000-4000-8000-000000000008";
const SIBLING_ROOT: &str = "19000000-0000-4000-8000-000000000009";
const SECOND_DRIVE: &str = "19000000-0000-4000-8000-00000000000a";
const SECOND_DRIVE_ROOT: &str = "19000000-0000-4000-8000-00000000000b";
const REPOSITORY: &str = "19000000-0000-4000-8000-00000000000c";
const SHA1_REPOSITORY: &str = "19000000-0000-4000-8000-00000000000d";

#[tokio::test]
#[ignore = "requires an empty PostgreSQL database in FILEBELT_REPOSITORY_TEST_DATABASE_URL"]
async fn managed_repository_schema_fails_closed_and_finalizes_main_atomically() {
    let database_url = std::env::var("FILEBELT_REPOSITORY_TEST_DATABASE_URL")
        .expect("FILEBELT_REPOSITORY_TEST_DATABASE_URL is required");
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
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=19 AND success)",
    )
    .fetch_one(database.pool())
    .await
    .expect("migration ledger");
    assert!(applied, "managed repository migration must be applied");

    seed_namespace(&database).await;
    let tenant = id(TENANT);
    let repository = id(REPOSITORY);
    let actor = id(PRINCIPAL);

    let wrong_type = database
        .create_managed_repository(
            tenant,
            Uuid::new_v4(),
            id(DRIVE),
            id(FILE_ROOT),
            RepositoryObjectFormat::Sha256,
        )
        .await;
    assert!(matches!(wrong_type, Err(DatabaseError::Conflict)));

    let wrong_drive = database
        .create_managed_repository(
            tenant,
            Uuid::new_v4(),
            id(DRIVE),
            id(SECOND_DRIVE_ROOT),
            RepositoryObjectFormat::Sha256,
        )
        .await;
    assert!(matches!(wrong_drive, Err(DatabaseError::Conflict)));

    let created = database
        .create_managed_repository(
            tenant,
            repository,
            id(DRIVE),
            id(REPOSITORY_ROOT),
            RepositoryObjectFormat::Sha256,
        )
        .await
        .expect("create managed repository");
    assert_eq!(created.object_format, "sha256");
    assert_eq!(created.state, "compatibility");

    let nested = database
        .create_managed_repository(
            tenant,
            Uuid::new_v4(),
            id(DRIVE),
            id(NESTED_ROOT),
            RepositoryObjectFormat::Sha256,
        )
        .await;
    assert!(matches!(nested, Err(DatabaseError::Conflict)));

    let object_format_error = sqlx::query(
        "UPDATE filebelt_revision.managed_repositories SET object_format='sha1' \
         WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(repository)
    .execute(database.pool())
    .await
    .expect_err("object format must be immutable");
    assert_eq!(sqlstate(&object_format_error).as_deref(), Some("55000"));

    let root_type_error = sqlx::query(
        "UPDATE public.nodes SET kind='file' \
         WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
    )
    .bind(tenant)
    .bind(id(DRIVE))
    .bind(id(REPOSITORY_ROOT))
    .execute(database.pool())
    .await
    .expect_err("repository root must stay a directory");
    assert_eq!(sqlstate(&root_type_error).as_deref(), Some("55000"));

    let default_ref = database
        .managed_repository_ref(tenant, repository, "refs/heads/main")
        .await
        .expect("default main ref");
    assert!(default_ref.namespace_projection);
    assert_eq!(default_ref.generation, 0);
    assert_eq!(default_ref.oid, None);
    let rules = sqlx::query(
        r#"SELECT require_pull_request,required_approvals,require_status_checks,
                  require_deployments,dismiss_stale_reviews,block_force_push,
                  block_deletion,require_linear_history
           FROM filebelt_revision.managed_repository_rulesets
           WHERE tenant_id=$1 AND repository_id=$2 AND name='default-main'"#,
    )
    .bind(tenant)
    .bind(repository)
    .fetch_one(database.pool())
    .await
    .expect("default main rules");
    assert!(!rules.get::<bool, _>("require_pull_request"));
    assert_eq!(rules.get::<i32, _>("required_approvals"), 0);
    assert!(!rules.get::<bool, _>("require_status_checks"));
    assert!(!rules.get::<bool, _>("require_deployments"));
    assert!(rules.get::<bool, _>("dismiss_stale_reviews"));
    assert!(rules.get::<bool, _>("block_force_push"));
    assert!(rules.get::<bool, _>("block_deletion"));
    assert!(rules.get::<bool, _>("require_linear_history"));

    let first = operation(
        repository,
        actor,
        id("19000000-0000-4000-8000-000000000101"),
        id("19000000-0000-4000-8000-000000000102"),
        0x11,
        0,
        None,
        RepositoryRefChangeKind::Create,
        1,
    );
    assert!(matches!(
        database.prepare_managed_repository_operation(&first).await,
        Err(DatabaseError::Conflict)
    ));

    activate_for_foundation_test(&database, repository).await;
    database
        .prepare_managed_repository_operation(&first)
        .await
        .expect("prepare first main operation");
    let generation = database
        .finalize_managed_repository_operation(tenant, repository, first.operation_id)
        .await
        .expect("finalize first main operation");
    assert_eq!(generation, 2);
    let committed_ref = database
        .managed_repository_ref(tenant, repository, "refs/heads/main")
        .await
        .expect("committed main ref");
    assert_eq!(committed_ref.generation, 1);
    assert_eq!(committed_ref.oid, Some(oid(0x11)));
    assert_eq!(
        committed_ref.projected_snapshot_id,
        first.main_snapshot.as_ref().map(|snapshot| snapshot.id)
    );
    assert_operation_state(&database, first.operation_id, "committed").await;
    assert_snapshot_state(
        &database,
        first.main_snapshot.as_ref().expect("first snapshot").id,
        "projected",
    )
    .await;

    let stale = operation(
        repository,
        actor,
        id("19000000-0000-4000-8000-000000000111"),
        id("19000000-0000-4000-8000-000000000112"),
        0x21,
        0,
        None,
        RepositoryRefChangeKind::Create,
        1,
    );
    database
        .prepare_managed_repository_operation(&stale)
        .await
        .expect("prepare stale CAS operation");
    assert!(matches!(
        database
            .finalize_managed_repository_operation(tenant, repository, stale.operation_id)
            .await,
        Err(DatabaseError::StaleGeneration)
    ));
    assert_operation_state(&database, stale.operation_id, "prepared").await;
    assert_snapshot_state(
        &database,
        stale.main_snapshot.as_ref().expect("stale snapshot").id,
        "prepared",
    )
    .await;
    let unchanged_ref = database
        .managed_repository_ref(tenant, repository, "refs/heads/main")
        .await
        .expect("unchanged main ref");
    assert_eq!(unchanged_ref.generation, 1);
    assert_eq!(unchanged_ref.oid, Some(oid(0x11)));
    database
        .abort_managed_repository_operation(tenant, repository, stale.operation_id)
        .await
        .expect("abort stale operation");
    assert_operation_state(&database, stale.operation_id, "aborted").await;
    assert!(matches!(
        database
            .abort_managed_repository_operation(tenant, repository, first.operation_id)
            .await,
        Err(DatabaseError::Conflict)
    ));

    let incomplete = operation(
        repository,
        actor,
        id("19000000-0000-4000-8000-000000000121"),
        id("19000000-0000-4000-8000-000000000122"),
        0x31,
        1,
        Some(oid(0x11)),
        RepositoryRefChangeKind::FastForward,
        1,
    );
    database
        .prepare_managed_repository_operation(&incomplete)
        .await
        .expect("prepare incomplete projection");
    sqlx::query(
        "DELETE FROM filebelt_revision.managed_repository_snapshot_entries \
         WHERE tenant_id=$1 AND snapshot_id=$2",
    )
    .bind(tenant)
    .bind(incomplete.main_snapshot.as_ref().expect("snapshot").id)
    .execute(database.pool())
    .await
    .expect("simulate an incomplete durable snapshot");
    assert!(matches!(
        database
            .finalize_managed_repository_operation(tenant, repository, incomplete.operation_id)
            .await,
        Err(DatabaseError::Conflict)
    ));
    assert_operation_state(&database, incomplete.operation_id, "prepared").await;
    assert_eq!(
        database
            .managed_repository_ref(tenant, repository, "refs/heads/main")
            .await
            .expect("main ref after incomplete projection")
            .oid,
        Some(oid(0x11))
    );
    database
        .abort_managed_repository_operation(tenant, repository, incomplete.operation_id)
        .await
        .expect("abort incomplete projection");

    sqlx::query(
        r#"UPDATE filebelt_revision.managed_repository_rulesets
           SET require_status_checks=true,generation=generation+1
           WHERE tenant_id=$1 AND repository_id=$2 AND name='default-main'"#,
    )
    .bind(tenant)
    .bind(repository)
    .execute(database.pool())
    .await
    .expect("require a main status check");
    sqlx::query(
        r#"INSERT INTO filebelt_revision.managed_repository_required_checks(
             tenant_id,ruleset_id,repository_id,check_name
           ) VALUES ($1,$2,$2,'foundation')"#,
    )
    .bind(tenant)
    .bind(repository)
    .execute(database.pool())
    .await
    .expect("insert required check");
    let mut checked = operation(
        repository,
        actor,
        id("19000000-0000-4000-8000-000000000131"),
        id("19000000-0000-4000-8000-000000000132"),
        0x41,
        1,
        Some(oid(0x11)),
        RepositoryRefChangeKind::FastForward,
        1,
    );
    let first_entry = &first
        .main_snapshot
        .as_ref()
        .expect("first snapshot")
        .entries[0];
    checked
        .main_snapshot
        .as_mut()
        .expect("checked snapshot")
        .entries[0]
        .object_oid = first_entry.object_oid.clone();
    checked
        .main_snapshot
        .as_mut()
        .expect("checked snapshot")
        .entries[0]
        .file
        .as_mut()
        .expect("checked file")
        .blake3 = first_entry
        .file
        .as_ref()
        .expect("first file")
        .blake3
        .clone();
    database
        .prepare_managed_repository_operation(&checked)
        .await
        .expect("prepare checked operation");
    assert!(matches!(
        database
            .finalize_managed_repository_operation(tenant, repository, checked.operation_id)
            .await,
        Err(DatabaseError::Conflict)
    ));
    assert_operation_state(&database, checked.operation_id, "prepared").await;
    sqlx::query(
        r#"INSERT INTO filebelt_revision.managed_repository_check_runs(
             tenant_id,id,repository_id,object_format,commit_oid,check_name,
             attempt,state,completed_at
           ) VALUES ($1,$2,$3,'sha256',$4,'foundation',1,'success',clock_timestamp())"#,
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(repository)
    .bind(oid(0x41))
    .execute(database.pool())
    .await
    .expect("record successful check");
    assert_eq!(
        database
            .finalize_managed_repository_operation(tenant, repository, checked.operation_id)
            .await
            .expect("finalize checked operation"),
        3
    );
    let checked_ref = database
        .managed_repository_ref(tenant, repository, "refs/heads/main")
        .await
        .expect("checked main ref");
    assert_eq!(checked_ref.generation, 2);
    assert_eq!(checked_ref.oid, Some(oid(0x41)));
    let reused_content: (i64, i64) = sqlx::query_as(
        r#"SELECT count(DISTINCT content.id),count(version.id)
           FROM filebelt_revision.managed_repository_contents AS content
           JOIN filebelt_revision.managed_repository_file_versions AS version
             ON version.tenant_id=content.tenant_id AND version.content_id=content.id
           WHERE content.tenant_id=$1 AND content.repository_id=$2
             AND content.blob_oid=$3"#,
    )
    .bind(tenant)
    .bind(repository)
    .bind(
        &first
            .main_snapshot
            .as_ref()
            .expect("first snapshot")
            .entries[0]
            .object_oid,
    )
    .fetch_one(database.pool())
    .await
    .expect("shared blob content identity");
    assert_eq!(reused_content, (1, 2));

    let sha1_repository = id(SHA1_REPOSITORY);
    database
        .create_managed_repository(
            tenant,
            sha1_repository,
            id(DRIVE),
            id(SIBLING_ROOT),
            RepositoryObjectFormat::Sha1,
        )
        .await
        .expect("create sha1 repository");
    activate_for_foundation_test(&database, sha1_repository).await;
    let invalid_sha1 = operation(
        sha1_repository,
        actor,
        Uuid::new_v4(),
        Uuid::new_v4(),
        0x51,
        0,
        None,
        RepositoryRefChangeKind::Create,
        1,
    );
    assert!(matches!(
        database
            .prepare_managed_repository_operation(&invalid_sha1)
            .await,
        Err(DatabaseError::InvalidPersistedValue)
    ));

    for role in ["filebelt_api", "filebelt_revision", "filebelt_vfs"] {
        assert!(
            !table_privilege(
                &database,
                role,
                "filebelt_revision.managed_repositories",
                "SELECT"
            )
            .await,
            "{role} unexpectedly received repository authority"
        );
        assert!(
            !function_privilege(
                &database,
                role,
                "filebelt_revision.finalize_managed_repository_operation(uuid,uuid,uuid)",
                "EXECUTE"
            )
            .await,
            "{role} unexpectedly received repository writer authority"
        );
    }
}

async fn seed_namespace(database: &Database) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        r#"
        INSERT INTO tenants(id,slug) VALUES ('{TENANT}','repository-test');
        INSERT INTO principals(tenant_id,id,kind) VALUES ('{TENANT}','{PRINCIPAL}','user');
        INSERT INTO users(tenant_id,id,principal_id,display_name)
        VALUES ('{TENANT}','{USER}','{PRINCIPAL}','Repository User');
        INSERT INTO drives(tenant_id,id,owner_principal_id,kind,display_name,quota_bytes)
        VALUES
          ('{TENANT}','{DRIVE}','{PRINCIPAL}','private','Repository',1073741824),
          ('{TENANT}','{SECOND_DRIVE}','{PRINCIPAL}','private','Other',1073741824);
        INSERT INTO nodes(
          tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id
        ) VALUES
          ('{TENANT}','{DRIVE}','{DRIVE_ROOT}',NULL,'directory','','','{PRINCIPAL}'),
          ('{TENANT}','{DRIVE}','{REPOSITORY_ROOT}','{DRIVE_ROOT}','directory','repo','repo','{PRINCIPAL}'),
          ('{TENANT}','{DRIVE}','{NESTED_ROOT}','{REPOSITORY_ROOT}','directory','nested','nested','{PRINCIPAL}'),
          ('{TENANT}','{DRIVE}','{FILE_ROOT}','{DRIVE_ROOT}','file','file','file','{PRINCIPAL}'),
          ('{TENANT}','{DRIVE}','{SIBLING_ROOT}','{DRIVE_ROOT}','directory','sibling','sibling','{PRINCIPAL}'),
          ('{TENANT}','{SECOND_DRIVE}','{SECOND_DRIVE_ROOT}',NULL,'directory','','','{PRINCIPAL}');
        INSERT INTO node_ancestry(tenant_id,drive_id,ancestor_id,descendant_id,depth)
        VALUES
          ('{TENANT}','{DRIVE}','{DRIVE_ROOT}','{DRIVE_ROOT}',0),
          ('{TENANT}','{DRIVE}','{REPOSITORY_ROOT}','{REPOSITORY_ROOT}',0),
          ('{TENANT}','{DRIVE}','{NESTED_ROOT}','{NESTED_ROOT}',0),
          ('{TENANT}','{DRIVE}','{FILE_ROOT}','{FILE_ROOT}',0),
          ('{TENANT}','{DRIVE}','{SIBLING_ROOT}','{SIBLING_ROOT}',0),
          ('{TENANT}','{DRIVE}','{DRIVE_ROOT}','{REPOSITORY_ROOT}',1),
          ('{TENANT}','{DRIVE}','{DRIVE_ROOT}','{NESTED_ROOT}',2),
          ('{TENANT}','{DRIVE}','{REPOSITORY_ROOT}','{NESTED_ROOT}',1),
          ('{TENANT}','{DRIVE}','{DRIVE_ROOT}','{FILE_ROOT}',1),
          ('{TENANT}','{DRIVE}','{DRIVE_ROOT}','{SIBLING_ROOT}',1),
          ('{TENANT}','{SECOND_DRIVE}','{SECOND_DRIVE_ROOT}','{SECOND_DRIVE_ROOT}',0);
        "#
    )))
    .execute(database.pool())
    .await
    .expect("seed repository namespace");
}

#[allow(clippy::too_many_arguments)]
fn operation(
    repository_id: Uuid,
    actor_principal_id: Uuid,
    operation_id: Uuid,
    snapshot_id: Uuid,
    marker: u8,
    expected_generation: i64,
    expected_oid: Option<Vec<u8>>,
    change_kind: RepositoryRefChangeKind,
    declared_tree_entry_count: i32,
) -> PrepareRepositoryOperationInput {
    let commit_oid = oid(marker);
    PrepareRepositoryOperationInput {
        tenant_id: id(TENANT),
        repository_id,
        operation_id,
        actor_principal_id,
        request_fingerprint: vec![marker; 32],
        object_set_digest: vec![marker.wrapping_add(1); 32],
        pack_bytes: 4,
        commit_count: 1,
        max_changed_paths_per_commit: 1,
        max_tree_entries: 1,
        max_blob_bytes: 4,
        ref_updates: vec![RepositoryRefUpdateInput {
            ref_name: "refs/heads/main".to_owned(),
            expected_generation,
            expected_oid,
            new_oid: commit_oid.clone(),
            change_kind,
        }],
        main_snapshot: Some(PreparedMainSnapshotInput {
            id: snapshot_id,
            commit_oid,
            tree_oid: oid(marker.wrapping_add(2)),
            parent_snapshot_id: None,
            declared_tree_entry_count,
            entry_set_digest: vec![marker.wrapping_add(3); 32],
            entries: vec![PreparedRepositorySnapshotEntryInput {
                path: "README.md".to_owned(),
                path_key: "readme.md".to_owned(),
                parent_path: None,
                parent_path_key: None,
                kind: RepositorySnapshotEntryKind::File,
                object_oid: oid(marker.wrapping_add(4)),
                size_bytes: 4,
                file: Some(PreparedRepositoryFileInput {
                    content_id: Uuid::new_v4(),
                    version_id: Uuid::new_v4(),
                    blake3: vec![marker.wrapping_add(5); 32],
                }),
            }],
        }),
    }
}

async fn activate_for_foundation_test(database: &Database, repository_id: Uuid) {
    sqlx::query(
        r#"UPDATE filebelt_revision.managed_repositories
           SET state='active',source_revision='repository-test',
               verified_at=clock_timestamp(),activated_at=clock_timestamp()
           WHERE tenant_id=$1 AND id=$2 AND state='compatibility'"#,
    )
    .bind(id(TENANT))
    .bind(repository_id)
    .execute(database.pool())
    .await
    .expect("activate repository only inside foundation test");
}

async fn assert_operation_state(database: &Database, operation_id: Uuid, expected: &str) {
    let state: String = sqlx::query_scalar(
        r#"SELECT state FROM filebelt_revision.managed_repository_ref_operations
           WHERE tenant_id=$1 AND id=$2"#,
    )
    .bind(id(TENANT))
    .bind(operation_id)
    .fetch_one(database.pool())
    .await
    .expect("operation state");
    assert_eq!(state, expected);
}

async fn assert_snapshot_state(database: &Database, snapshot_id: Uuid, expected: &str) {
    let state: String = sqlx::query_scalar(
        r#"SELECT state FROM filebelt_revision.managed_repository_snapshots
           WHERE tenant_id=$1 AND id=$2"#,
    )
    .bind(id(TENANT))
    .bind(snapshot_id)
    .fetch_one(database.pool())
    .await
    .expect("snapshot state");
    assert_eq!(state, expected);
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

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(|code| code.into_owned())
}

fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("valid test UUID")
}

fn oid(marker: u8) -> Vec<u8> {
    vec![marker; 32]
}

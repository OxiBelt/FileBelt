// SPDX-License-Identifier: Apache-2.0

//! Dormant PostgreSQL authority for directory-level Git repositories.
//!
//! These methods intentionally have no production runtime grant in the
//! compatibility release.  They define and exercise the transactional
//! boundary that a later authorized coordinator can use after recovery and
//! deployment activation gates are complete.

use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use filebelt_domain::{LogicalPath, NormalizedName};

use super::{Database, DatabaseError};

pub const REPOSITORY_PACK_LIMIT_BYTES: i64 = 1_073_741_824;
pub const REPOSITORY_PUSH_COMMIT_LIMIT: i32 = 32;
pub const REPOSITORY_CHANGED_PATH_LIMIT: i32 = 10_000;
pub const REPOSITORY_TREE_ENTRY_LIMIT: i32 = 100_000;
pub const REPOSITORY_BLOB_LIMIT_BYTES: i64 = 104_857_600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryObjectFormat {
    Sha1,
    Sha256,
}

impl RepositoryObjectFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    #[must_use]
    pub const fn oid_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn parse(value: &str) -> Result<Self, DatabaseError> {
        match value {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(DatabaseError::InvalidPersistedValue),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedRepositoryRecord {
    pub id: Uuid,
    pub drive_id: Uuid,
    pub root_node_id: Uuid,
    pub object_format: String,
    pub state: String,
    pub generation: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedRepositoryRefRecord {
    pub ref_name: String,
    pub oid: Option<Vec<u8>>,
    pub generation: i64,
    pub namespace_projection: bool,
    pub projected_snapshot_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryRefChangeKind {
    Create,
    FastForward,
    Force,
}

impl RepositoryRefChangeKind {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::FastForward => "fast_forward",
            Self::Force => "force",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RepositoryRefUpdateInput {
    pub ref_name: String,
    pub expected_generation: i64,
    pub expected_oid: Option<Vec<u8>>,
    pub new_oid: Vec<u8>,
    pub change_kind: RepositoryRefChangeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySnapshotEntryKind {
    Directory,
    File,
}

impl RepositorySnapshotEntryKind {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }

    #[must_use]
    const fn git_mode(self) -> i32 {
        match self {
            Self::Directory => 16_384,
            Self::File => 33_188,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedRepositoryFileInput {
    pub content_id: Uuid,
    pub version_id: Uuid,
    pub blake3: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PreparedRepositorySnapshotEntryInput {
    pub path: String,
    pub path_key: String,
    pub parent_path: Option<String>,
    pub parent_path_key: Option<String>,
    pub kind: RepositorySnapshotEntryKind,
    pub object_oid: Vec<u8>,
    pub size_bytes: i64,
    pub file: Option<PreparedRepositoryFileInput>,
}

#[derive(Clone, Debug)]
pub struct PreparedMainSnapshotInput {
    pub id: Uuid,
    pub commit_oid: Vec<u8>,
    pub tree_oid: Vec<u8>,
    pub parent_snapshot_id: Option<Uuid>,
    pub declared_tree_entry_count: i32,
    pub entry_set_digest: Vec<u8>,
    pub entries: Vec<PreparedRepositorySnapshotEntryInput>,
}

#[derive(Clone, Debug)]
pub struct PrepareRepositoryOperationInput {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub operation_id: Uuid,
    pub actor_principal_id: Uuid,
    pub request_fingerprint: Vec<u8>,
    pub object_set_digest: Vec<u8>,
    pub pack_bytes: i64,
    pub commit_count: i32,
    pub max_changed_paths_per_commit: i32,
    pub max_tree_entries: i32,
    pub max_blob_bytes: i64,
    pub ref_updates: Vec<RepositoryRefUpdateInput>,
    pub main_snapshot: Option<PreparedMainSnapshotInput>,
}

struct RepositoryFence {
    format: RepositoryObjectFormat,
    repository_generation: i64,
    actor_generation: i64,
    drive_acl_generation: i64,
    namespace_generation: i64,
    root_acl_generation: i64,
}

impl Database {
    /// Creates a repository in the fail-closed `compatibility` state.  The
    /// migration trigger atomically adds the sole namespace projection ref and
    /// its safe-writable default ruleset.
    pub async fn create_managed_repository(
        &self,
        tenant_id: Uuid,
        repository_id: Uuid,
        drive_id: Uuid,
        root_node_id: Uuid,
        object_format: RepositoryObjectFormat,
    ) -> Result<ManagedRepositoryRecord, DatabaseError> {
        let row = sqlx::query(
            r#"INSERT INTO filebelt_revision.managed_repositories(
                 tenant_id,id,drive_id,root_node_id,object_format
               ) VALUES ($1,$2,$3,$4,$5)
               RETURNING id,drive_id,root_node_id,object_format,state,generation"#,
        )
        .bind(tenant_id)
        .bind(repository_id)
        .bind(drive_id)
        .bind(root_node_id)
        .bind(object_format.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(map_repository_error)?;
        Ok(ManagedRepositoryRecord {
            id: row.get("id"),
            drive_id: row.get("drive_id"),
            root_node_id: row.get("root_node_id"),
            object_format: row.get("object_format"),
            state: row.get("state"),
            generation: row.get("generation"),
        })
    }

    /// Prepares one all-or-nothing ref operation and, for a `main` update, its
    /// immutable namespace snapshot.  Preparation captures every generation
    /// that finalization revalidates under row locks.
    pub async fn prepare_managed_repository_operation(
        &self,
        input: &PrepareRepositoryOperationInput,
    ) -> Result<(), DatabaseError> {
        if input.ref_updates.is_empty()
            || input.request_fingerprint.len() != 32
            || input.object_set_digest.len() != 32
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }

        let mut transaction = self.pool.begin().await?;
        let fence_row = sqlx::query(
            r#"SELECT repository.object_format,repository.generation,
                      actor.generation AS actor_generation,
                      drive.acl_generation AS drive_acl_generation,
                      drive.namespace_generation,root.acl_generation AS root_acl_generation
               FROM filebelt_revision.managed_repositories AS repository
               JOIN public.principals AS actor
                 ON actor.tenant_id=repository.tenant_id AND actor.id=$3
               JOIN public.drives AS drive
                 ON drive.tenant_id=repository.tenant_id AND drive.id=repository.drive_id
               JOIN public.nodes AS root
                 ON root.tenant_id=repository.tenant_id
                AND root.drive_id=repository.drive_id AND root.id=repository.root_node_id
               WHERE repository.tenant_id=$1 AND repository.id=$2
                 AND repository.state='active' AND actor.disabled_at IS NULL
                 AND root.kind='directory' AND root.trash_root_id IS NULL
               FOR SHARE OF repository,actor,drive,root"#,
        )
        .bind(input.tenant_id)
        .bind(input.repository_id)
        .bind(input.actor_principal_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        let fence = RepositoryFence {
            format: RepositoryObjectFormat::parse(fence_row.get("object_format"))?,
            repository_generation: fence_row.get("generation"),
            actor_generation: fence_row.get("actor_generation"),
            drive_acl_generation: fence_row.get("drive_acl_generation"),
            namespace_generation: fence_row.get("namespace_generation"),
            root_acl_generation: fence_row.get("root_acl_generation"),
        };

        validate_operation_input(input, fence.format)?;
        sqlx::query(
            r#"INSERT INTO filebelt_revision.managed_repository_ref_operations(
                 tenant_id,id,repository_id,object_format,actor_principal_id,
                 request_fingerprint,object_set_digest,
                 expected_repository_generation,expected_actor_generation,
                 expected_drive_acl_generation,expected_namespace_generation,
                 expected_root_acl_generation,pack_bytes,commit_count,
                 max_changed_paths_per_commit,max_tree_entries,max_blob_bytes
               ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
               )"#,
        )
        .bind(input.tenant_id)
        .bind(input.operation_id)
        .bind(input.repository_id)
        .bind(fence.format.as_str())
        .bind(input.actor_principal_id)
        .bind(&input.request_fingerprint)
        .bind(&input.object_set_digest)
        .bind(fence.repository_generation)
        .bind(fence.actor_generation)
        .bind(fence.drive_acl_generation)
        .bind(fence.namespace_generation)
        .bind(fence.root_acl_generation)
        .bind(input.pack_bytes)
        .bind(input.commit_count)
        .bind(input.max_changed_paths_per_commit)
        .bind(input.max_tree_entries)
        .bind(input.max_blob_bytes)
        .execute(&mut *transaction)
        .await
        .map_err(map_repository_error)?;

        if let Some(snapshot) = &input.main_snapshot {
            sqlx::query(
                r#"INSERT INTO filebelt_revision.managed_repository_snapshots(
                     tenant_id,id,repository_id,operation_id,object_format,
                     commit_oid,tree_oid,parent_snapshot_id,tree_entry_count,entry_set_digest
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
            )
            .bind(input.tenant_id)
            .bind(snapshot.id)
            .bind(input.repository_id)
            .bind(input.operation_id)
            .bind(fence.format.as_str())
            .bind(&snapshot.commit_oid)
            .bind(&snapshot.tree_oid)
            .bind(snapshot.parent_snapshot_id)
            .bind(snapshot.declared_tree_entry_count)
            .bind(&snapshot.entry_set_digest)
            .execute(&mut *transaction)
            .await
            .map_err(map_repository_error)?;

            for entry in &snapshot.entries {
                if let Some(file) = &entry.file {
                    let content_id: Uuid = sqlx::query_scalar(
                        r#"INSERT INTO filebelt_revision.managed_repository_contents(
                             tenant_id,id,repository_id,object_format,blob_oid,size_bytes,blake3
                           ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                           ON CONFLICT (tenant_id,repository_id,blob_oid) DO UPDATE
                           SET blob_oid=EXCLUDED.blob_oid
                           WHERE managed_repository_contents.object_format=EXCLUDED.object_format
                             AND managed_repository_contents.size_bytes=EXCLUDED.size_bytes
                             AND managed_repository_contents.blake3=EXCLUDED.blake3
                             AND managed_repository_contents.state IN ('staged','referenced')
                           RETURNING id"#,
                    )
                    .bind(input.tenant_id)
                    .bind(file.content_id)
                    .bind(input.repository_id)
                    .bind(fence.format.as_str())
                    .bind(&entry.object_oid)
                    .bind(entry.size_bytes)
                    .bind(&file.blake3)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(map_repository_error)?
                    .ok_or(DatabaseError::Conflict)?;
                    sqlx::query(
                        r#"INSERT INTO filebelt_revision.managed_repository_file_versions(
                             tenant_id,id,repository_id,snapshot_id,content_id,object_format,
                             source_commit_oid,source_path_key
                           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
                    )
                    .bind(input.tenant_id)
                    .bind(file.version_id)
                    .bind(input.repository_id)
                    .bind(snapshot.id)
                    .bind(content_id)
                    .bind(fence.format.as_str())
                    .bind(&snapshot.commit_oid)
                    .bind(&entry.path_key)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_repository_error)?;
                }
                sqlx::query(
                    r#"INSERT INTO filebelt_revision.managed_repository_snapshot_entries(
                         tenant_id,repository_id,snapshot_id,object_format,path,path_key,
                         parent_path,parent_path_key,entry_kind,git_mode,object_oid,
                         size_bytes,version_id
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"#,
                )
                .bind(input.tenant_id)
                .bind(input.repository_id)
                .bind(snapshot.id)
                .bind(fence.format.as_str())
                .bind(&entry.path)
                .bind(&entry.path_key)
                .bind(&entry.parent_path)
                .bind(&entry.parent_path_key)
                .bind(entry.kind.as_str())
                .bind(entry.kind.git_mode())
                .bind(&entry.object_oid)
                .bind(entry.size_bytes)
                .bind(entry.file.as_ref().map(|file| file.version_id))
                .execute(&mut *transaction)
                .await
                .map_err(map_repository_error)?;
            }
        }

        for update in &input.ref_updates {
            let snapshot_id = if update.ref_name == "refs/heads/main" {
                Some(
                    input
                        .main_snapshot
                        .as_ref()
                        .ok_or(DatabaseError::InvalidPersistedValue)?
                        .id,
                )
            } else {
                None
            };
            sqlx::query(
                r#"INSERT INTO filebelt_revision.managed_repository_ref_operation_updates(
                     tenant_id,operation_id,repository_id,object_format,ref_name,
                     expected_generation,expected_oid,new_oid,change_kind,snapshot_id
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
            )
            .bind(input.tenant_id)
            .bind(input.operation_id)
            .bind(input.repository_id)
            .bind(fence.format.as_str())
            .bind(&update.ref_name)
            .bind(update.expected_generation)
            .bind(&update.expected_oid)
            .bind(&update.new_oid)
            .bind(update.change_kind.as_str())
            .bind(snapshot_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_repository_error)?;
        }

        transaction.commit().await?;
        Ok(())
    }

    /// Atomically revalidates authorization/namespace generations, every ref
    /// CAS, the complete `main` snapshot, and active status-check rules before
    /// advancing any ref.
    pub async fn finalize_managed_repository_operation(
        &self,
        tenant_id: Uuid,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        sqlx::query_scalar(
            "SELECT filebelt_revision.finalize_managed_repository_operation($1,$2,$3)",
        )
        .bind(tenant_id)
        .bind(repository_id)
        .bind(operation_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_repository_error)
    }

    pub async fn abort_managed_repository_operation(
        &self,
        tenant_id: Uuid,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let affected = sqlx::query(
            r#"UPDATE filebelt_revision.managed_repository_ref_operations
               SET state='aborted',terminal_at=clock_timestamp()
               WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 AND state='prepared'"#,
        )
        .bind(tenant_id)
        .bind(repository_id)
        .bind(operation_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_repository_error)?
        .rows_affected();
        if affected != 1 {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query(
            r#"INSERT INTO filebelt_revision.managed_repository_reconciliations(
                 tenant_id,id,repository_id,operation_id,kind
               ) VALUES ($1,$2,$3,$4,'retention')
               ON CONFLICT (tenant_id,repository_id,operation_id,kind) DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(repository_id)
        .bind(operation_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn managed_repository_ref(
        &self,
        tenant_id: Uuid,
        repository_id: Uuid,
        ref_name: &str,
    ) -> Result<ManagedRepositoryRefRecord, DatabaseError> {
        let row = sqlx::query(
            r#"SELECT ref_name,oid,generation,namespace_projection,projected_snapshot_id
               FROM filebelt_revision.managed_repository_refs
               WHERE tenant_id=$1 AND repository_id=$2 AND ref_name=$3"#,
        )
        .bind(tenant_id)
        .bind(repository_id)
        .bind(ref_name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(ManagedRepositoryRefRecord {
            ref_name: row.get("ref_name"),
            oid: row.get("oid"),
            generation: row.get("generation"),
            namespace_projection: row.get("namespace_projection"),
            projected_snapshot_id: row.get("projected_snapshot_id"),
        })
    }
}

fn validate_operation_input(
    input: &PrepareRepositoryOperationInput,
    format: RepositoryObjectFormat,
) -> Result<(), DatabaseError> {
    if !(0..=REPOSITORY_PACK_LIMIT_BYTES).contains(&input.pack_bytes)
        || !(0..=REPOSITORY_PUSH_COMMIT_LIMIT).contains(&input.commit_count)
        || !(0..=REPOSITORY_CHANGED_PATH_LIMIT).contains(&input.max_changed_paths_per_commit)
        || !(0..=REPOSITORY_TREE_ENTRY_LIMIT).contains(&input.max_tree_entries)
        || !(0..=REPOSITORY_BLOB_LIMIT_BYTES).contains(&input.max_blob_bytes)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let mut main_updates = 0_usize;
    for update in &input.ref_updates {
        validate_oid(&update.new_oid, format)?;
        if let Some(expected_oid) = &update.expected_oid {
            validate_oid(expected_oid, format)?;
        }
        if (update.change_kind == RepositoryRefChangeKind::Create) != update.expected_oid.is_none()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        if update.ref_name == "refs/heads/main" {
            main_updates += 1;
        }
    }
    if (main_updates == 1) != input.main_snapshot.is_some() {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    if let Some(snapshot) = &input.main_snapshot {
        validate_oid(&snapshot.commit_oid, format)?;
        validate_oid(&snapshot.tree_oid, format)?;
        if snapshot.entry_set_digest.len() != 32
            || usize::try_from(snapshot.declared_tree_entry_count).ok()
                != Some(snapshot.entries.len())
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        for entry in &snapshot.entries {
            validate_oid(&entry.object_oid, format)?;
            validate_snapshot_entry_path(entry)?;
            match (entry.kind, &entry.file) {
                (RepositorySnapshotEntryKind::Directory, None) if entry.size_bytes == 0 => {}
                (RepositorySnapshotEntryKind::File, Some(file))
                    if file.blake3.len() == 32
                        && (0..=REPOSITORY_BLOB_LIMIT_BYTES).contains(&entry.size_bytes) => {}
                _ => return Err(DatabaseError::InvalidPersistedValue),
            }
        }
    }
    Ok(())
}

fn validate_snapshot_entry_path(
    entry: &PreparedRepositorySnapshotEntryInput,
) -> Result<(), DatabaseError> {
    let components = entry
        .path
        .split('/')
        .map(|component| {
            let normalized =
                NormalizedName::new(component).map_err(|_| DatabaseError::InvalidPersistedValue)?;
            if normalized.display() != component || normalized.comparison_key() == ".git" {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            Ok(normalized)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    LogicalPath::from_components(components.clone())
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;

    let path_key = components
        .iter()
        .map(NormalizedName::comparison_key)
        .collect::<Vec<_>>()
        .join("/");
    if entry.path_key != path_key {
        return Err(DatabaseError::InvalidPersistedValue);
    }

    let parent = &components[..components.len() - 1];
    let parent_path = (!parent.is_empty()).then(|| {
        parent
            .iter()
            .map(NormalizedName::display)
            .collect::<Vec<_>>()
            .join("/")
    });
    let parent_path_key = (!parent.is_empty()).then(|| {
        parent
            .iter()
            .map(NormalizedName::comparison_key)
            .collect::<Vec<_>>()
            .join("/")
    });
    if entry.parent_path != parent_path || entry.parent_path_key != parent_path_key {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validate_oid(oid: &[u8], format: RepositoryObjectFormat) -> Result<(), DatabaseError> {
    if oid.len() == format.oid_len() {
        Ok(())
    } else {
        Err(DatabaseError::InvalidPersistedValue)
    }
}

fn map_repository_error(error: sqlx::Error) -> DatabaseError {
    match error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .as_deref()
    {
        Some("FBR01") => DatabaseError::StaleGeneration,
        Some("FBR02" | "FBR03" | "23505" | "23514") => DatabaseError::Conflict,
        _ => DatabaseError::Sql(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PreparedRepositorySnapshotEntryInput, RepositorySnapshotEntryKind,
        validate_snapshot_entry_path,
    };

    fn directory(path: &str, path_key: &str) -> PreparedRepositorySnapshotEntryInput {
        PreparedRepositorySnapshotEntryInput {
            path: path.to_owned(),
            path_key: path_key.to_owned(),
            parent_path: None,
            parent_path_key: None,
            kind: RepositorySnapshotEntryKind::Directory,
            object_oid: vec![1; 32],
            size_bytes: 0,
            file: None,
        }
    }

    #[test]
    fn snapshot_paths_use_the_shared_namespace_canonical_form() {
        assert!(validate_snapshot_entry_path(&directory("README", "readme")).is_ok());
        assert!(validate_snapshot_entry_path(&directory(".GiT", ".git")).is_err());
        assert!(validate_snapshot_entry_path(&directory("e\u{301}", "é")).is_err());

        let mut nested = directory("Docs/README", "docs/readme");
        nested.parent_path = Some("Docs".to_owned());
        nested.parent_path_key = Some("docs".to_owned());
        assert!(validate_snapshot_entry_path(&nested).is_ok());
        nested.parent_path_key = Some("Docs".to_owned());
        assert!(validate_snapshot_entry_path(&nested).is_err());
    }
}

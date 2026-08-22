// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-authoritative revision preferences and metadata projections.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{
    Database, DatabaseError, NodeRecord, ResourceMutationIdempotency, ResourceMutationWrite,
    lock_authorization_fence, node_from_row,
};
use crate::idempotency::{IdempotencyReservation, finalize, reserve};

pub const EDIT_LIMITS: [i64; 5] = [1_048_576, 2_097_152, 4_194_304, 8_388_608, 16_777_216];
pub const INLINE_LIMITS: [i64; 5] = [8_388_608, 16_777_216, 33_554_432, 67_108_864, 104_857_600];

#[allow(clippy::too_many_arguments)]
async fn update_content_class_policy_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    node_id: Uuid,
    expected_attribute_generation: i64,
    policy: &str,
    membership_generation: i64,
    drive_acl_generation: i64,
    namespace_generation: i64,
    resource_acl_generation: i64,
) -> Result<NodeRecord, DatabaseError> {
    if !matches!(policy, "auto" | "binary") {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    lock_authorization_fence(
        transaction,
        tenant_id,
        actor,
        session_id,
        drive_id,
        node_id,
        [
            membership_generation,
            drive_acl_generation,
            namespace_generation,
            resource_acl_generation,
        ],
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE nodes SET content_class_policy=$4,attribute_generation=attribute_generation+1, \
         updated_at=clock_timestamp() WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 \
         AND kind='file' AND attribute_generation=$5",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .bind(policy)
    .bind(expected_attribute_generation)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(DatabaseError::StaleGeneration);
    }
    sqlx::query(
        "UPDATE filebelt_collaboration.epochs e SET state='frozen', \
         freeze_reason='content_class_policy',fencing_token=fencing_token+1 \
         FROM filebelt_collaboration.rooms r WHERE r.tenant_id=$1 AND r.drive_id=$2 \
         AND r.node_id=$3 AND e.tenant_id=r.tenant_id AND e.room_id=r.id AND e.state='active'",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .execute(&mut **transaction)
    .await?;
    let row = sqlx::query(
        "SELECT n.*,n.updated_at::text AS updated_at_text,v.size_bytes,\
                v.ordinal AS version_ordinal,v.media_type AS head_media_type \
         FROM nodes n LEFT JOIN file_versions v ON v.tenant_id=n.tenant_id \
           AND v.node_id=n.id AND v.id=n.head_version_id \
         WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(node_id)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(node_from_row(&row))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TextPreferencesRecord {
    pub edit_limit_bytes: i64,
    pub inline_limit_bytes: i64,
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct RevisionComparisonRecord {
    pub repository_id: Uuid,
    pub base_commit_oid: String,
    pub target_commit_oid: String,
    pub base_size_bytes: i64,
    pub target_size_bytes: i64,
    pub base_final_newline: bool,
    pub target_final_newline: bool,
}

#[derive(Clone, Debug)]
pub struct RevisionBackfillLease {
    pub tenant_id: Uuid,
    pub content_id: Uuid,
    pub version_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub created_by: Uuid,
    pub legacy_payload_id: Uuid,
    pub size_bytes: i64,
    pub blake3: Vec<u8>,
    pub media_type: Option<String>,
    pub display_name: String,
    pub content_class_policy: String,
    pub ordinal: i64,
    pub created_at_unix_seconds: i64,
    pub fencing_token: i64,
    pub lease_owner: Uuid,
    pub repository_id: Option<Uuid>,
    pub expected_head_oid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RevisionChunkEvidence {
    pub id: Uuid,
    pub size_bytes: i32,
    pub blake3: Vec<u8>,
    pub newly_allocated: bool,
}

impl Database {
    /// Leases exactly one legacy content item only after the operator moves the
    /// tenant into the Release-A `backfilling` state.  The lease token is
    /// carried through every terminal write, so a superseded worker cannot
    /// commit a provider result.
    pub async fn lease_revision_backfill(
        &self,
        tenant_id: Uuid,
        lease_owner: Uuid,
        lease_seconds: i64,
    ) -> Result<Option<RevisionBackfillLease>, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "WITH candidate AS ( \
               SELECT j.content_id FROM filebelt_revision.backfill_jobs j \
               JOIN filebelt_revision.activation_state a ON a.tenant_id=j.tenant_id \
               WHERE j.tenant_id=$1 AND a.state='backfilling' \
                 AND (j.state='pending' OR (j.state='leased' AND j.lease_expires_at<=clock_timestamp())) \
                 AND j.next_attempt_at<=clock_timestamp() \
                 AND NOT EXISTS (SELECT 1 FROM filebelt_revision.contents prior \
                   JOIN public.file_versions prior_version ON prior_version.tenant_id=prior.tenant_id AND prior_version.content_id=prior.id \
                   WHERE prior.tenant_id=j.tenant_id AND prior.node_id=(SELECT node_id FROM filebelt_revision.contents WHERE tenant_id=j.tenant_id AND id=j.content_id) \
                     AND prior.state='legacy' AND prior_version.ordinal<(SELECT ordinal FROM public.file_versions WHERE tenant_id=j.tenant_id AND content_id=j.content_id)) \
               ORDER BY j.next_attempt_at,j.content_id FOR UPDATE OF j SKIP LOCKED LIMIT 1 \
             ), leased AS ( \
               UPDATE filebelt_revision.backfill_jobs j SET state='leased',attempt_count=attempt_count+1, \
                 fencing_token=fencing_token+1,lease_owner=$2, \
                 lease_expires_at=clock_timestamp()+make_interval(secs=>$3),updated_at=clock_timestamp() \
               FROM candidate WHERE j.tenant_id=$1 AND j.content_id=candidate.content_id \
               RETURNING j.content_id,j.fencing_token,j.lease_owner \
             ) \
             SELECT l.content_id,l.fencing_token,l.lease_owner,c.drive_id,c.node_id,c.legacy_payload_id, \
               c.size_bytes,c.blake3,c.media_type,n.display_name,n.content_class_policy, \
               v.id AS version_id,v.created_by,v.ordinal,extract(epoch FROM v.created_at)::bigint AS created_at_unix_seconds, \
               r.id AS repository_id,encode(r.projected_head_oid,'hex') AS expected_head_oid \
             FROM leased l JOIN filebelt_revision.contents c ON c.tenant_id=$1 AND c.id=l.content_id \
             JOIN public.file_versions v ON v.tenant_id=c.tenant_id AND v.content_id=c.id \
             JOIN public.nodes n ON n.tenant_id=c.tenant_id AND n.drive_id=c.drive_id AND n.id=c.node_id \
             LEFT JOIN filebelt_revision.git_repositories r ON r.tenant_id=c.tenant_id AND r.drive_id=c.drive_id AND r.node_id=c.node_id AND r.state='active'",
        )
        .bind(tenant_id).bind(lease_owner).bind(lease_seconds)
        .fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.map(|row| RevisionBackfillLease {
            tenant_id,
            content_id: row.get("content_id"),
            version_id: row.get("version_id"),
            drive_id: row.get("drive_id"),
            node_id: row.get("node_id"),
            created_by: row.get("created_by"),
            legacy_payload_id: row.get("legacy_payload_id"),
            size_bytes: row.get("size_bytes"),
            blake3: row.get("blake3"),
            media_type: row.get("media_type"),
            display_name: row.get("display_name"),
            content_class_policy: row.get("content_class_policy"),
            ordinal: row.get("ordinal"),
            created_at_unix_seconds: row.get("created_at_unix_seconds"),
            fencing_token: row.get("fencing_token"),
            lease_owner: row.get("lease_owner"),
            repository_id: row.get("repository_id"),
            expected_head_oid: row.get("expected_head_oid"),
        }))
    }

    pub async fn hold_revision_backfill(
        &self,
        tenant_id: Uuid,
        content_id: Uuid,
        owner: Uuid,
        fencing_token: i64,
        reason_code: &str,
        detail: &str,
    ) -> Result<(), DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query("UPDATE filebelt_revision.backfill_jobs SET state='held',lease_owner=NULL,lease_expires_at=NULL,last_error_code=$5,updated_at=clock_timestamp() WHERE tenant_id=$1 AND content_id=$2 AND state='leased' AND lease_owner=$3 AND fencing_token=$4 AND lease_expires_at>clock_timestamp()")
            .bind(tenant_id).bind(content_id).bind(owner).bind(fencing_token).bind(reason_code)
            .execute(&mut *tx).await?.rows_affected();
        if updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("INSERT INTO filebelt_revision.holds(tenant_id,content_id,reason_code,detail) VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,content_id) DO UPDATE SET reason_code=EXCLUDED.reason_code,detail=EXCLUDED.detail,resolved_at=NULL,resolution=NULL")
            .bind(tenant_id).bind(content_id).bind(reason_code).bind(detail).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_git_backfill(
        &self,
        lease: &RevisionBackfillLease,
        commit_oid: &str,
        tree_oid: &str,
        blob_oid: &str,
        final_newline: bool,
        repository_size_bytes: i64,
    ) -> Result<(), DatabaseError> {
        if repository_size_bytes < 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut tx = self.pool.begin().await?;
        let job = sqlx::query("SELECT 1 FROM filebelt_revision.backfill_jobs WHERE tenant_id=$1 AND content_id=$2 AND state='leased' AND lease_owner=$3 AND fencing_token=$4 AND lease_expires_at>clock_timestamp() FOR UPDATE")
            .bind(lease.tenant_id).bind(lease.content_id).bind(lease.lease_owner).bind(lease.fencing_token).fetch_optional(&mut *tx).await?;
        if job.is_none() {
            return Err(DatabaseError::StaleGeneration);
        }
        let repository_id = lease.repository_id.unwrap_or(lease.node_id);
        let previous_size: i64 = sqlx::query_scalar("SELECT allocated_bytes FROM filebelt_revision.git_repositories WHERE tenant_id=$1 AND drive_id=$2 AND node_id=$3 FOR UPDATE")
            .bind(lease.tenant_id).bind(lease.drive_id).bind(lease.node_id).fetch_optional(&mut *tx).await?.unwrap_or(0);
        let physical_delta = repository_size_bytes
            .checked_sub(previous_size)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        if physical_delta < 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let quota = sqlx::query("UPDATE public.drives SET used_physical_bytes=used_physical_bytes+$3 WHERE tenant_id=$1 AND id=$2 AND used_physical_bytes+reserved_bytes+$3<=quota_bytes RETURNING id")
            .bind(lease.tenant_id).bind(lease.drive_id).bind(physical_delta).fetch_optional(&mut *tx).await?;
        if quota.is_none() {
            return Err(DatabaseError::QuotaExceeded);
        }
        let repository_updated = sqlx::query("INSERT INTO filebelt_revision.git_repositories(tenant_id,id,drive_id,node_id,projected_head_oid,allocated_bytes) VALUES ($1,$2,$3,$4,decode($5,'hex'),$7) ON CONFLICT (tenant_id,drive_id,node_id) DO UPDATE SET projected_head_oid=decode($5,'hex'),allocated_bytes=$7,updated_at=clock_timestamp() WHERE filebelt_revision.git_repositories.projected_head_oid IS NOT DISTINCT FROM NULLIF(decode($6,'hex'),decode('','hex'))")
            .bind(lease.tenant_id).bind(repository_id).bind(lease.drive_id).bind(lease.node_id).bind(commit_oid).bind(lease.expected_head_oid.as_deref().unwrap_or("")).bind(repository_size_bytes)
            .execute(&mut *tx).await?.rows_affected();
        if repository_updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("INSERT INTO filebelt_revision.git_revisions(tenant_id,content_id,repository_id,drive_id,node_id,commit_oid,tree_oid,blob_oid,parent_commit_oid,ordinal,committed_at,final_newline) VALUES ($1,$2,$3,$4,$5,decode($6,'hex'),decode($7,'hex'),decode($8,'hex'),NULLIF(decode($9,'hex'),''::bytea),$10,to_timestamp($11),$12)")
            .bind(lease.tenant_id).bind(lease.content_id).bind(repository_id).bind(lease.drive_id).bind(lease.node_id).bind(commit_oid).bind(tree_oid).bind(blob_oid).bind(lease.expected_head_oid.as_deref().unwrap_or("")).bind(lease.ordinal).bind(lease.created_at_unix_seconds as f64).bind(final_newline).execute(&mut *tx).await?;
        let content_updated = sqlx::query("UPDATE filebelt_revision.contents SET backend='git_sha256',observed_class='text',state='referenced',legacy_payload_id=NULL WHERE tenant_id=$1 AND id=$2 AND state='legacy'")
            .bind(lease.tenant_id).bind(lease.content_id).execute(&mut *tx).await?.rows_affected();
        if content_updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let job_updated = sqlx::query("UPDATE filebelt_revision.backfill_jobs SET state='verified',lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND content_id=$2 AND state='leased' AND lease_owner=$3 AND fencing_token=$4")
            .bind(lease.tenant_id).bind(lease.content_id).bind(lease.lease_owner).bind(lease.fencing_token).execute(&mut *tx).await?.rows_affected();
        if job_updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Allocates stable per-drive digest identities before I/O publication.
    /// Existing digests are returned without a new physical allocation.
    pub async fn reserve_revision_chunks(
        &self,
        lease: &RevisionBackfillLease,
        chunks: &[(Vec<u8>, i32)],
    ) -> Result<Vec<RevisionChunkEvidence>, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let leased = sqlx::query("SELECT 1 FROM filebelt_revision.backfill_jobs WHERE tenant_id=$1 AND content_id=$2 AND state='leased' AND lease_owner=$3 AND fencing_token=$4 AND lease_expires_at>clock_timestamp() FOR UPDATE")
            .bind(lease.tenant_id).bind(lease.content_id).bind(lease.lease_owner).bind(lease.fencing_token).fetch_optional(&mut *tx).await?;
        if leased.is_none() {
            return Err(DatabaseError::StaleGeneration);
        }
        let mut output = Vec::with_capacity(chunks.len());
        for (digest, size) in chunks {
            if digest.len() != 32 || *size <= 0 || *size > 16_777_216 {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            let existing = sqlx::query("SELECT id,state,reference_count FROM filebelt_revision.chunk_objects WHERE tenant_id=$1 AND drive_id=$2 AND blake3=$3 AND size_bytes=$4 FOR UPDATE")
                .bind(lease.tenant_id).bind(lease.drive_id).bind(digest).bind(size).fetch_optional(&mut *tx).await?;
            let (id, newly_allocated) = if let Some(row) = existing {
                let id: Uuid = row.get("id");
                let state: String = row.get("state");
                let references: i64 = row.get("reference_count");
                match state.as_str() {
                    "referenced" => (id, false),
                    "staging" => (id, true),
                    "deleted" | "quarantined" if references == 0 => {
                        sqlx::query("UPDATE filebelt_revision.chunk_objects SET locator=$3,state='staging',referenced_at=NULL,quarantine_reason=NULL,fencing_token=fencing_token+1 WHERE tenant_id=$1 AND id=$2")
                            .bind(lease.tenant_id).bind(id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
                        (id, true)
                    }
                    _ => return Err(DatabaseError::StaleGeneration),
                }
            } else {
                let id = Uuid::new_v4();
                sqlx::query("INSERT INTO filebelt_revision.chunk_objects(tenant_id,id,drive_id,locator,size_bytes,blake3,state) VALUES ($1,$2,$3,$4,$5,$6,'staging')")
                    .bind(lease.tenant_id).bind(id).bind(lease.drive_id).bind(Uuid::new_v4()).bind(size).bind(digest).execute(&mut *tx).await?;
                (id, true)
            };
            output.push(RevisionChunkEvidence {
                id,
                size_bytes: *size,
                blake3: digest.clone(),
                newly_allocated,
            });
        }
        tx.commit().await?;
        Ok(output)
    }

    pub async fn commit_chunk_backfill(
        &self,
        lease: &RevisionBackfillLease,
        observed_class: &str,
        chunks: &[RevisionChunkEvidence],
    ) -> Result<(), DatabaseError> {
        if !matches!(observed_class, "office" | "binary") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut tx = self.pool.begin().await?;
        let leased = sqlx::query("SELECT 1 FROM filebelt_revision.backfill_jobs WHERE tenant_id=$1 AND content_id=$2 AND state='leased' AND lease_owner=$3 AND fencing_token=$4 AND lease_expires_at>clock_timestamp() FOR UPDATE")
            .bind(lease.tenant_id).bind(lease.content_id).bind(lease.lease_owner).bind(lease.fencing_token).fetch_optional(&mut *tx).await?;
        if leased.is_none() {
            return Err(DatabaseError::StaleGeneration);
        }
        let mut physical = 0_i64;
        let mut charged_chunks = HashSet::new();
        for chunk in chunks {
            let row = sqlx::query("SELECT size_bytes,blake3,reference_count,state FROM filebelt_revision.chunk_objects WHERE tenant_id=$1 AND id=$2 AND drive_id=$3 FOR UPDATE")
                .bind(lease.tenant_id).bind(chunk.id).bind(lease.drive_id).fetch_optional(&mut *tx).await?.ok_or(DatabaseError::StaleGeneration)?;
            if row.get::<i32, _>("size_bytes") != chunk.size_bytes
                || row.get::<Vec<u8>, _>("blake3") != chunk.blake3
                || !matches!(
                    row.get::<String, _>("state").as_str(),
                    "staging" | "referenced"
                )
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            if row.get::<i64, _>("reference_count") == 0 && charged_chunks.insert(chunk.id) {
                physical = physical
                    .checked_add(i64::from(chunk.size_bytes))
                    .ok_or(DatabaseError::InvalidPersistedValue)?;
            }
        }
        let drive = sqlx::query("UPDATE public.drives SET used_physical_bytes=used_physical_bytes+$3 WHERE tenant_id=$1 AND id=$2 AND used_physical_bytes+reserved_bytes+$3<=quota_bytes RETURNING id")
            .bind(lease.tenant_id).bind(lease.drive_id).bind(physical).fetch_optional(&mut *tx).await?;
        if drive.is_none() {
            return Err(DatabaseError::QuotaExceeded);
        }
        let manifest_id = Uuid::new_v4();
        sqlx::query("INSERT INTO filebelt_revision.chunk_manifests(tenant_id,id,content_id,drive_id,chunk_count,size_bytes,blake3,state) VALUES ($1,$2,$3,$4,$5,$6,$7,'referenced')")
            .bind(lease.tenant_id).bind(manifest_id).bind(lease.content_id).bind(lease.drive_id).bind(i32::try_from(chunks.len()).map_err(|_| DatabaseError::InvalidPersistedValue)?).bind(lease.size_bytes).bind(&lease.blake3).execute(&mut *tx).await?;
        let mut offset = 0_i64;
        for (index, chunk) in chunks.iter().enumerate() {
            sqlx::query("INSERT INTO filebelt_revision.chunk_members(tenant_id,manifest_id,drive_id,chunk_index,chunk_id,logical_offset,size_bytes) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                .bind(lease.tenant_id).bind(manifest_id).bind(lease.drive_id).bind(i32::try_from(index).map_err(|_| DatabaseError::InvalidPersistedValue)?).bind(chunk.id).bind(offset).bind(chunk.size_bytes).execute(&mut *tx).await?;
            offset += i64::from(chunk.size_bytes);
            sqlx::query("UPDATE filebelt_revision.chunk_objects SET state='referenced',referenced_at=COALESCE(referenced_at,clock_timestamp()),reference_count=reference_count+1 WHERE tenant_id=$1 AND id=$2 AND drive_id=$3 AND state IN ('staging','referenced')")
                .bind(lease.tenant_id).bind(chunk.id).bind(lease.drive_id).execute(&mut *tx).await?;
        }
        let content_updated = sqlx::query("UPDATE filebelt_revision.contents SET backend='shared_chunks',observed_class=$3,state='referenced',legacy_payload_id=NULL WHERE tenant_id=$1 AND id=$2 AND state='legacy'")
            .bind(lease.tenant_id).bind(lease.content_id).bind(observed_class).execute(&mut *tx).await?.rows_affected();
        if content_updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let job_updated = sqlx::query("UPDATE filebelt_revision.backfill_jobs SET state='verified',lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND content_id=$2 AND state='leased' AND lease_owner=$3 AND fencing_token=$4")
            .bind(lease.tenant_id).bind(lease.content_id).bind(lease.lease_owner).bind(lease.fencing_token).execute(&mut *tx).await?.rows_affected();
        if job_updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Moves a Release-A tenant to `ready` only when no legacy, pending, or
    /// held item remains.  This intentionally never activates writers.
    pub async fn mark_revision_ready_if_complete(
        &self,
        tenant_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        let updated = sqlx::query("UPDATE filebelt_revision.activation_state a SET state='ready',generation=generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND state='backfilling' AND source_revision IS NOT NULL AND NOT EXISTS (SELECT 1 FROM filebelt_revision.backfill_jobs j WHERE j.tenant_id=a.tenant_id AND j.state<>'verified') AND NOT EXISTS (SELECT 1 FROM filebelt_revision.holds h WHERE h.tenant_id=a.tenant_id AND h.resolved_at IS NULL) AND NOT EXISTS (SELECT 1 FROM filebelt_revision.contents c WHERE c.tenant_id=a.tenant_id AND c.state<>'referenced') AND NOT EXISTS (SELECT 1 FROM filebelt_revision.contents c LEFT JOIN filebelt_revision.git_revisions r ON r.tenant_id=c.tenant_id AND r.content_id=c.id LEFT JOIN filebelt_revision.git_repositories g ON g.tenant_id=r.tenant_id AND g.id=r.repository_id WHERE c.tenant_id=a.tenant_id AND c.backend='git_sha256' AND (r.content_id IS NULL OR g.state<>'active')) AND NOT EXISTS (SELECT 1 FROM filebelt_revision.contents c LEFT JOIN filebelt_revision.chunk_manifests m ON m.tenant_id=c.tenant_id AND m.content_id=c.id WHERE c.tenant_id=a.tenant_id AND c.backend='shared_chunks' AND (m.content_id IS NULL OR m.state<>'referenced' OR m.chunk_count<>(SELECT count(*) FROM filebelt_revision.chunk_members member WHERE member.tenant_id=m.tenant_id AND member.manifest_id=m.id) OR m.size_bytes<>COALESCE((SELECT sum(member.size_bytes) FROM filebelt_revision.chunk_members member WHERE member.tenant_id=m.tenant_id AND member.manifest_id=m.id),0))) AND NOT EXISTS (SELECT 1 FROM filebelt_revision.chunk_objects chunk WHERE chunk.tenant_id=a.tenant_id AND (chunk.state<>'referenced' OR chunk.reference_count<>(SELECT count(*) FROM filebelt_revision.chunk_members member WHERE member.tenant_id=chunk.tenant_id AND member.chunk_id=chunk.id)))")
            .bind(tenant_id).execute(&self.pool).await?.rows_affected();
        Ok(updated == 1)
    }
    /// Revalidates the API's session-bound READ_CONTENT fence immediately
    /// before an internal revision operation reaches a provider.  The API
    /// evaluates the Virtual ACL; this query makes that grant fail closed if
    /// the session, principal, drive, or node generations changed meanwhile.
    #[allow(clippy::too_many_arguments)]
    pub async fn revision_authorization_fence_matches(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        user_id: Uuid,
        principal_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<bool, DatabaseError> {
        let row = sqlx::query(
            "SELECT 1 \
             FROM authorization_generations g \
             JOIN api_sessions s ON s.tenant_id=g.tenant_id AND s.id=g.session_id \
             JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id \
             JOIN principals p ON p.tenant_id=g.tenant_id AND p.id=g.principal_id \
             JOIN drives d ON d.tenant_id=g.tenant_id AND d.id=g.drive_id \
             JOIN nodes n ON n.tenant_id=g.tenant_id AND n.drive_id=g.drive_id AND n.id=g.resource_id \
             WHERE g.tenant_id=$1 AND g.session_id=$2 AND u.id=$3 AND g.principal_id=$4 \
               AND g.drive_id=$5 AND g.resource_id=$6 \
               AND g.membership_generation=$7 AND g.drive_acl_generation=$8 \
               AND g.namespace_generation=$9 AND g.resource_acl_generation=$10 \
               AND g.session_expires_at>clock_timestamp() \
               AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() \
               AND s.absolute_expires_at>clock_timestamp() AND u.status='active' \
               AND p.disabled_at IS NULL AND p.generation=$7 AND d.acl_generation=$8 \
               AND n.namespace_generation=$9 AND n.acl_generation=$10 \
               AND n.kind='file' AND n.trash_root_id IS NULL",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(user_id)
        .bind(principal_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(membership_generation)
        .bind(drive_acl_generation)
        .bind(namespace_generation)
        .bind(resource_acl_generation)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn text_preferences(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<TextPreferencesRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT text_edit_limit_bytes,text_inline_limit_bytes,text_preference_generation \
             FROM user_preferences WHERE tenant_id=$1 AND user_id=$2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(TextPreferencesRecord {
            edit_limit_bytes: row.get("text_edit_limit_bytes"),
            inline_limit_bytes: row.get("text_inline_limit_bytes"),
            generation: row.get("text_preference_generation"),
        })
    }

    pub async fn update_text_preferences(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        expected_generation: i64,
        edit_limit_bytes: i64,
        inline_limit_bytes: i64,
    ) -> Result<TextPreferencesRecord, DatabaseError> {
        if !EDIT_LIMITS.contains(&edit_limit_bytes)
            || !INLINE_LIMITS.contains(&inline_limit_bytes)
            || inline_limit_bytes < edit_limit_bytes
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "UPDATE user_preferences SET text_edit_limit_bytes=$4,text_inline_limit_bytes=$5, \
             text_preference_generation=text_preference_generation+1 \
             WHERE tenant_id=$1 AND user_id=$2 AND text_preference_generation=$3 \
             RETURNING text_edit_limit_bytes,text_inline_limit_bytes,text_preference_generation",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(expected_generation)
        .bind(edit_limit_bytes)
        .bind(inline_limit_bytes)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(TextPreferencesRecord {
            edit_limit_bytes: row.get("text_edit_limit_bytes"),
            inline_limit_bytes: row.get("text_inline_limit_bytes"),
            generation: row.get("text_preference_generation"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_content_class_policy(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
        expected_attribute_generation: i64,
        policy: &str,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        update_content_class_policy_tx(
            &mut transaction,
            tenant_id,
            actor,
            session_id,
            drive_id,
            node_id,
            expected_attribute_generation,
            policy,
            membership_generation,
            drive_acl_generation,
            namespace_generation,
            resource_acl_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_content_class_policy_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        session_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
        expected_attribute_generation: i64,
        policy: &str,
        membership_generation: i64,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
        idempotency: &ResourceMutationIdempotency<'_>,
        render_response: F,
    ) -> Result<ResourceMutationWrite, DatabaseError>
    where
        F: FnOnce(&NodeRecord) -> Result<Value, DatabaseError>,
    {
        idempotency.validate_actor(actor)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool.begin().await?;
        match reserve(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(ResourceMutationWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(ResourceMutationWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let node = update_content_class_policy_tx(
                    &mut transaction,
                    tenant_id,
                    actor,
                    session_id,
                    drive_id,
                    node_id,
                    expected_attribute_generation,
                    policy,
                    membership_generation,
                    drive_acl_generation,
                    namespace_generation,
                    resource_acl_generation,
                )
                .await?;
                let response = render_response(&node)?;
                let record = finalize(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(ResourceMutationWrite::Created(record))
            }
        }
    }

    pub async fn revision_comparison(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
        base_version_id: Uuid,
        target_version_id: Uuid,
    ) -> Result<RevisionComparisonRecord, DatabaseError> {
        let rows = sqlx::query(
            "SELECT v.id,v.size_bytes,r.repository_id,encode(r.commit_oid,'hex') AS commit_oid,r.final_newline \
             FROM nodes n JOIN file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id \
             JOIN filebelt_revision.contents c ON c.tenant_id=v.tenant_id AND c.id=v.content_id \
             JOIN filebelt_revision.git_revisions r ON r.tenant_id=c.tenant_id AND r.content_id=c.id \
             WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 AND n.kind='file' \
             AND c.backend='git_sha256' AND c.observed_class='text' AND v.id IN ($4,$5) \
             ORDER BY v.id",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(base_version_id)
        .bind(target_version_id)
        .fetch_all(&self.pool)
        .await?;
        if rows.len() != 2 && base_version_id != target_version_id {
            return Err(DatabaseError::NotFound);
        }
        if base_version_id == target_version_id {
            let row = rows.first().ok_or(DatabaseError::NotFound)?;
            return Ok(RevisionComparisonRecord {
                repository_id: row.get("repository_id"),
                base_commit_oid: row.get("commit_oid"),
                target_commit_oid: row.get("commit_oid"),
                base_size_bytes: row.get("size_bytes"),
                target_size_bytes: row.get("size_bytes"),
                base_final_newline: row.get("final_newline"),
                target_final_newline: row.get("final_newline"),
            });
        }
        let find = |id: Uuid| rows.iter().find(|row| row.get::<Uuid, _>("id") == id);
        let base = find(base_version_id).ok_or(DatabaseError::NotFound)?;
        let target = find(target_version_id).ok_or(DatabaseError::NotFound)?;
        let repository_id = base.get("repository_id");
        if target.get::<Uuid, _>("repository_id") != repository_id {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        Ok(RevisionComparisonRecord {
            repository_id,
            base_commit_oid: base.get("commit_oid"),
            target_commit_oid: target.get("commit_oid"),
            base_size_bytes: base.get("size_bytes"),
            target_size_bytes: target.get("size_bytes"),
            base_final_newline: base.get("final_newline"),
            target_final_newline: target.get("final_newline"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_domains_match_the_public_contract() {
        assert_eq!(EDIT_LIMITS[1], 2 * 1024 * 1024);
        assert_eq!(INLINE_LIMITS[0], 8 * 1024 * 1024);
        assert!(INLINE_LIMITS.iter().all(|value| *value >= EDIT_LIMITS[0]));
    }

    #[test]
    fn content_policy_receipt_is_finalized_in_the_mutation_transaction() {
        let source = include_str!("revision.rs");
        let implementation = source
            .split_once("pub async fn update_content_class_policy_idempotent")
            .expect("idempotent content-policy mutation exists")
            .1;
        let reserve = implementation.find("reserve(&mut transaction").unwrap();
        let mutate = implementation
            .find("update_content_class_policy_tx(")
            .unwrap();
        let finalize = implementation.find("finalize(").unwrap();
        let commit = finalize
            + implementation[finalize..]
                .find("transaction.commit().await?")
                .unwrap();
        assert!(reserve < mutate);
        assert!(mutate < finalize);
        assert!(finalize < commit);
    }
}

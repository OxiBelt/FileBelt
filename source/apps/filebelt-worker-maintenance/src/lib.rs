// SPDX-License-Identifier: Apache-2.0

//! Durable PostgreSQL-leased maintenance and notification publication.

#![deny(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use filebelt_database::mount::{MountStagingCleanupJobRecord, MountWriteLockCleanupJobRecord};
use filebelt_database::{Database, DatabaseError, JobRecord, PayloadRecord};
use filebelt_events_protocol::EventEnvelope;
use filebelt_storage::{StorageError, StorageLayout};
use iggy::prelude::{
    Client as _, IggyClient, IggyDuration, IggyError, IggyExpiry, IggyMessage, MaxTopicSize,
    Partitioning,
};
use prost::Message as _;
use serde_json::Value;
use sqlx::Row as _;
use thiserror::Error;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

const JOB_LEASE_SECONDS: i64 = 30;
const JOB_HEARTBEAT_SECONDS: u64 = 10;
const JOB_MAX_RUNTIME_SECONDS: u64 = 6 * 60 * 60;
const OPERATION_TEMPORARY_GRACE_SECONDS: u64 = 24 * 60 * 60;
const RECONCILE_BATCH_SIZE: i64 = 100;
const RETENTION_BATCH_SIZE: i64 = 1_000;
const RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
const SCRUB_INTERVAL_SECONDS: u64 = 30 * 24 * 60 * 60;
const IGGY_PARTITIONS: u32 = 16;
const IGGY_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
pub struct Maintenance {
    database: Database,
    storage: StorageLayout,
    tenant_id: Uuid,
    backend_id: Uuid,
    worker_id: Uuid,
    orphan_grace_seconds: i64,
    expired_part_grace_seconds: i64,
}

#[derive(Clone, Debug, Default)]
pub struct ReconcileReport {
    pub reopened_finalizations: u64,
    pub expired_uploads: u64,
    pub expired_nfs_writers_enqueued: u64,
    pub expired_nfs_write_conflicts_enqueued: u64,
    pub expired_nfs_mapping_proposals: u64,
    pub purged_nfs_mapping_proposals: u64,
    pub orphan_jobs_created: u64,
    pub finalized_staging_sets_removed: u64,
    pub mount_staging_sets_removed: u64,
    pub mount_write_locks_removed: u64,
    pub writing_temporaries_removed: u64,
    pub finalizing_temporaries_removed: u64,
    pub scrub_jobs_created: u64,
    pub expired_capability_nonces_removed: u64,
    pub retained_consumer_deduplications_removed: u64,
    pub retained_outbox_events_removed: u64,
    pub collaboration_warnings_emitted: u64,
    pub collaboration_epochs_expired: u64,
    pub collaboration_payload_deletions_enqueued: u64,
    pub collaboration_objects_abandoned: u64,
    pub document_received_revisions_abandoned: u64,
    pub document_staging_revisions_abandoned: u64,
    pub document_terminal_revisions_released: u64,
    pub document_payload_deletions_enqueued: u64,
    pub document_launch_grants_purged: u64,
    pub document_session_events_purged: u64,
    pub document_operation_receipts_purged: u64,
    pub document_staging_locators_removed: u64,
    pub document_disconnected_participants_closed: u64,
    pub document_draining_sessions_expired: u64,
}

#[derive(Debug, Error)]
pub enum MaintenanceError {
    #[error("database maintenance failed: {0}")]
    Database(#[from] DatabaseError),
    #[error("database maintenance query failed: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("storage maintenance failed: {0}")]
    Storage(#[from] StorageError),
    #[error("job payload is invalid")]
    InvalidJob,
    #[error("job lease was lost")]
    LeaseLost,
    #[error("job exceeded its maximum runtime")]
    JobRuntimeExceeded,
    #[error("Iggy notification delivery failed")]
    Notification,
}

enum JobDisposition {
    Complete(&'static str),
    Deferred(i64),
}

impl Maintenance {
    #[must_use]
    pub fn new(
        database: Database,
        storage: StorageLayout,
        tenant_id: Uuid,
        backend_id: Uuid,
        orphan_grace_seconds: i64,
        expired_part_grace_seconds: i64,
    ) -> Self {
        Self {
            database,
            storage,
            tenant_id,
            backend_id,
            worker_id: Uuid::new_v4(),
            orphan_grace_seconds,
            expired_part_grace_seconds,
        }
    }
    pub async fn reconcile(&self) -> Result<ReconcileReport, MaintenanceError> {
        let reopened_finalizations = self
            .database
            .reopen_expired_upload_finalizations(self.tenant_id)
            .await?;
        let expired_uploads = self.database.expire_uploads(self.tenant_id).await?;
        let expired_nfs_writers_enqueued = self
            .database
            .sweep_expired_nfs_writers(
                self.tenant_id,
                i32::try_from(RECONCILE_BATCH_SIZE).expect("reconcile batch fits i32"),
            )
            .await?
            .len()
            .try_into()
            .map_err(|_| MaintenanceError::InvalidJob)?;
        let expired_nfs_mapping_proposals = self
            .database
            .expire_nfs_mapping_proposals(
                self.tenant_id,
                i32::try_from(RECONCILE_BATCH_SIZE).expect("reconcile batch fits i32"),
            )
            .await?;
        let purged_nfs_mapping_proposals = self
            .database
            .purge_nfs_mapping_proposals(
                self.tenant_id,
                i32::try_from(RECONCILE_BATCH_SIZE).expect("reconcile batch fits i32"),
            )
            .await?;
        let expired_nfs_write_conflicts_enqueued = self
            .database
            .sweep_expired_nfs_write_conflicts(
                self.tenant_id,
                i32::try_from(RECONCILE_BATCH_SIZE).expect("reconcile batch fits i32"),
            )
            .await?
            .len()
            .try_into()
            .map_err(|_| MaintenanceError::InvalidJob)?;
        let orphan_jobs_created = self.enqueue_finalized_orphans().await?;
        let finalized_staging_sets_removed = self.cleanup_finalized_staging().await?;
        let mount_staging_sets_removed = self.cleanup_mount_staging().await?;
        let mount_write_locks_removed = self.cleanup_mount_write_locks().await?;
        let storage = self.storage.clone();
        let temporary_cleanup = tokio::task::spawn_blocking(move || {
            storage.cleanup_operation_temporaries(
                Duration::from_secs(OPERATION_TEMPORARY_GRACE_SECONDS),
                usize::try_from(RECONCILE_BATCH_SIZE).expect("positive cleanup batch size"),
            )
        })
        .await
        .map_err(|_| StorageError::Join)??;
        let scrub_jobs_created = self.enqueue_scrub_jobs().await?;
        let expired_capability_nonces_removed = self.cleanup_expired_capability_nonces().await?;
        let (retained_consumer_deduplications_removed, retained_outbox_events_removed) =
            self.cleanup_retained_outbox().await?;
        let collaboration_retention = self
            .database
            .collaboration_retention_sweep(self.tenant_id, RECONCILE_BATCH_SIZE)
            .await?;
        let document_retention = self
            .database
            .document_revision_retention_sweep(self.tenant_id, RECONCILE_BATCH_SIZE)
            .await?;
        let document_reconnect = self
            .database
            .document_reconnect_sweep(self.tenant_id, RECONCILE_BATCH_SIZE)
            .await?;
        let document_staging_locators_removed = self.cleanup_document_finalized_staging().await?;
        Ok(ReconcileReport {
            reopened_finalizations,
            expired_uploads,
            expired_nfs_writers_enqueued,
            expired_nfs_write_conflicts_enqueued,
            expired_nfs_mapping_proposals,
            purged_nfs_mapping_proposals,
            orphan_jobs_created,
            finalized_staging_sets_removed,
            mount_staging_sets_removed,
            mount_write_locks_removed,
            writing_temporaries_removed: temporary_cleanup.writing_removed,
            finalizing_temporaries_removed: temporary_cleanup.finalizing_removed,
            scrub_jobs_created,
            expired_capability_nonces_removed,
            retained_consumer_deduplications_removed,
            retained_outbox_events_removed,
            collaboration_warnings_emitted: collaboration_retention.warnings_emitted,
            collaboration_epochs_expired: collaboration_retention.epochs_expired,
            collaboration_payload_deletions_enqueued: collaboration_retention
                .payload_deletions_enqueued,
            collaboration_objects_abandoned: collaboration_retention.objects_abandoned,
            document_received_revisions_abandoned: document_retention.received_abandoned,
            document_staging_revisions_abandoned: document_retention.staging_abandoned,
            document_terminal_revisions_released: document_retention.terminal_revisions_released,
            document_payload_deletions_enqueued: document_retention.payload_deletions_enqueued,
            document_launch_grants_purged: document_retention.launch_grants_purged,
            document_session_events_purged: document_retention.session_events_purged,
            document_operation_receipts_purged: document_retention.operation_receipts_purged,
            document_staging_locators_removed,
            document_disconnected_participants_closed: document_reconnect.participants_closed,
            document_draining_sessions_expired: document_reconnect.sessions_expired,
        })
    }

    pub async fn run_one_job(&self) -> Result<bool, MaintenanceError> {
        let Some(job) = self
            .database
            .claim_job(self.tenant_id, self.worker_id, JOB_LEASE_SECONDS)
            .await?
        else {
            return Ok(false);
        };
        let mut heartbeat = tokio::time::interval(Duration::from_secs(JOB_HEARTBEAT_SECONDS));
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let maximum_runtime = tokio::time::sleep(job_max_runtime());
        tokio::pin!(maximum_runtime);
        let work = self.handle_job(&job);
        tokio::pin!(work);
        let disposition = loop {
            tokio::select! {
                result = &mut work => break result,
                _ = heartbeat.tick() => self.heartbeat(&job).await?,
                () = &mut maximum_runtime => break Err(MaintenanceError::JobRuntimeExceeded),
            }
        };
        match disposition {
            Ok(JobDisposition::Complete(outcome)) => {
                self.database.complete_job(&job, outcome).await?
            }
            Ok(JobDisposition::Deferred(delay)) => self.defer_job(&job, delay).await?,
            Err(error) => {
                let retryable = !matches!(
                    error,
                    MaintenanceError::InvalidJob | MaintenanceError::LeaseLost
                );
                self.database
                    .fail_job(&job, error_code(&error), retryable)
                    .await?;
                if !retryable {
                    return Err(error);
                }
            }
        }
        Ok(true)
    }

    async fn handle_job(&self, job: &JobRecord) -> Result<JobDisposition, MaintenanceError> {
        match job.kind.as_str() {
            "upload_expire" => {
                self.database.expire_uploads(self.tenant_id).await?;
                Ok(JobDisposition::Complete("uploads_expired"))
            }
            "upload_reconcile" => self.reconcile_upload(job).await,
            "payload_delete" => self.delete_payload(job).await,
            "payload_scrub" => self.scrub_payload(job).await,
            "recursive_namespace" => Err(MaintenanceError::InvalidJob),
            _ => Err(MaintenanceError::InvalidJob),
        }
    }

    async fn reconcile_upload(&self, job: &JobRecord) -> Result<JobDisposition, MaintenanceError> {
        let upload_id = payload_uuid(&job.payload, "upload_id")?;
        let row = sqlx::query("SELECT state,EXTRACT(EPOCH FROM (expires_at + make_interval(secs=>$3) - clock_timestamp()))::bigint AS remaining FROM upload_sessions WHERE tenant_id=$1 AND id=$2")
            .bind(job.tenant_id)
            .bind(upload_id)
            .bind(self.expired_part_grace_seconds)
            .fetch_optional(self.database.pool())
            .await?
            .ok_or(MaintenanceError::InvalidJob)?;
        let state: String = row.get("state");
        let remaining: i64 = row.get("remaining");
        if !matches!(state.as_str(), "expired" | "aborted") {
            return Err(MaintenanceError::InvalidJob);
        }
        if remaining > 0 {
            return Ok(JobDisposition::Deferred(remaining));
        }
        let upload = self.database.upload(job.tenant_id, upload_id).await?;
        if upload.backend_id != self.backend_id {
            return Err(MaintenanceError::InvalidJob);
        }
        let parts = self.database.upload_parts(job.tenant_id, upload_id).await?;
        let payload = self
            .database
            .payload(job.tenant_id, upload.payload_id)
            .await?;
        if payload.backend_id != self.backend_id {
            return Err(MaintenanceError::InvalidJob);
        }
        let storage = self.storage.clone();
        tokio::task::spawn_blocking(move || {
            storage.remove_staging_parts(&parts)?;
            storage.delete_payload(&payload)
        })
        .await
        .map_err(|_| StorageError::Join)??;
        let updated = sqlx::query("UPDATE payload_objects SET state='abandoned' WHERE tenant_id=$1 AND id=$2 AND state='staging'")
            .bind(job.tenant_id)
            .bind(upload.payload_id)
            .execute(self.database.pool())
            .await?
            .rows_affected();
        if updated > 1 {
            return Err(MaintenanceError::InvalidJob);
        }
        Ok(JobDisposition::Complete("expired_parts_removed"))
    }

    async fn delete_payload(&self, job: &JobRecord) -> Result<JobDisposition, MaintenanceError> {
        let payload_id = payload_uuid(&job.payload, "payload_id")?;
        let payload = self.database.payload(job.tenant_id, payload_id).await?;
        if payload.backend_id != self.backend_id {
            return Err(MaintenanceError::InvalidJob);
        }
        if payload.state == "deleted" {
            return Ok(JobDisposition::Complete("already_deleted"));
        }
        if !matches!(
            payload.state.as_str(),
            "delete_intent" | "deleting" | "abandoned"
        ) {
            return Err(MaintenanceError::InvalidJob);
        }
        if payload.state == "delete_intent" {
            sqlx::query("UPDATE payload_objects SET state='deleting' WHERE tenant_id=$1 AND id=$2 AND state='delete_intent'")
                .bind(job.tenant_id)
                .bind(payload_id)
                .execute(self.database.pool())
                .await?;
        }
        let document_payload = self
            .database
            .document_payload_deletion_pending(job.tenant_id, payload_id)
            .await?;
        let storage = self.storage.clone();
        let payload_for_delete = payload.clone();
        let upload = match self
            .database
            .upload_for_payload(job.tenant_id, payload_id)
            .await
        {
            Ok(upload) => upload,
            Err(DatabaseError::NotFound) => {
                let storage = self.storage.clone();
                let payload_for_delete = payload.clone();
                tokio::task::spawn_blocking(move || {
                    storage.delete_payload(&payload_for_delete)?;
                    storage.remove_staging_locator(payload_for_delete.locator)
                })
                .await
                .map_err(|_| StorageError::Join)??;
                if document_payload {
                    self.database
                        .complete_document_payload_deletion(job.tenant_id, payload_id)
                        .await?;
                    return Ok(JobDisposition::Complete("document_payload_deleted"));
                }
                self.database
                    .complete_collaboration_payload_deletion(job.tenant_id, payload_id)
                    .await?;
                return Ok(JobDisposition::Complete("collaboration_payload_deleted"));
            }
            Err(error) => return Err(error.into()),
        };
        let parts = self
            .database
            .upload_parts(job.tenant_id, upload.upload_id)
            .await?;
        tokio::task::spawn_blocking(move || {
            storage.delete_payload(&payload_for_delete)?;
            storage.remove_staging_parts(&parts)
        })
        .await
        .map_err(|_| StorageError::Join)??;
        self.database
            .complete_orphan_payload_deletion(job.tenant_id, payload_id)
            .await?;
        Ok(JobDisposition::Complete("payload_deleted"))
    }

    async fn scrub_payload(&self, job: &JobRecord) -> Result<JobDisposition, MaintenanceError> {
        let payload_id = payload_uuid(&job.payload, "payload_id")?;
        let payload = self.database.payload(job.tenant_id, payload_id).await?;
        if payload.backend_id != self.backend_id {
            return Err(MaintenanceError::InvalidJob);
        }
        if payload.state == "quarantined" {
            return Ok(JobDisposition::Complete("already_quarantined"));
        }
        if !matches!(
            payload.state.as_str(),
            "referenced" | "finalized" | "quarantining"
        ) {
            return Err(MaintenanceError::InvalidJob);
        }

        if payload.state != "quarantining" {
            let upload = self
                .database
                .upload_for_payload(job.tenant_id, payload_id)
                .await?;
            let parts = self
                .database
                .upload_parts(job.tenant_id, upload.upload_id)
                .await?;
            let storage = self.storage.clone();
            let upload_for_verify = upload.clone();
            let payload_for_verify = payload.clone();
            let parts_for_verify = parts.clone();
            let verified = tokio::task::spawn_blocking(move || {
                storage.verify_finalized(&upload_for_verify, &payload_for_verify, &parts_for_verify)
            })
            .await
            .map_err(|_| StorageError::Join)?;
            let expected = payload
                .blake3
                .as_deref()
                .ok_or(MaintenanceError::InvalidJob)?;
            match verified {
                Ok(object) if object.digest.as_slice() == expected => {
                    return Ok(JobDisposition::Complete("payload_verified"));
                }
                Ok(_) | Err(StorageError::CorruptObject | StorageError::UnsafeObject) => {}
                Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let transitioned = sqlx::query("UPDATE payload_objects SET state='quarantining',quarantine_reason='digest_or_storage_invariant_mismatch' WHERE tenant_id=$1 AND id=$2 AND state IN ('referenced','finalized')")
                .bind(job.tenant_id)
                .bind(payload_id)
                .execute(self.database.pool())
                .await?
                .rows_affected();
            if transitioned != 1 {
                return Err(MaintenanceError::InvalidJob);
            }
        }

        let storage = self.storage.clone();
        let payload_for_quarantine = payload.clone();
        tokio::task::spawn_blocking(move || storage.quarantine_payload(&payload_for_quarantine))
            .await
            .map_err(|_| StorageError::Join)??;
        let transitioned = sqlx::query("UPDATE payload_objects SET state='quarantined' WHERE tenant_id=$1 AND id=$2 AND state='quarantining'")
            .bind(job.tenant_id)
            .bind(payload_id)
            .execute(self.database.pool())
            .await?
            .rows_affected();
        if transitioned != 1 {
            let reconciled = self.database.payload(job.tenant_id, payload_id).await?;
            if reconciled.state != "quarantined" {
                return Err(MaintenanceError::InvalidJob);
            }
        }
        Ok(JobDisposition::Complete("payload_quarantined"))
    }

    async fn heartbeat(&self, job: &JobRecord) -> Result<(), MaintenanceError> {
        let updated = sqlx::query("UPDATE jobs SET lease_expires_at=clock_timestamp()+make_interval(secs=>$4),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND fencing_token=$3")
            .bind(job.tenant_id)
            .bind(job.id)
            .bind(job.fencing_token)
            .bind(JOB_LEASE_SECONDS)
            .execute(self.database.pool())
            .await?
            .rows_affected();
        if updated != 1 {
            return Err(MaintenanceError::LeaseLost);
        }
        Ok(())
    }

    async fn defer_job(&self, job: &JobRecord, delay_seconds: i64) -> Result<(), MaintenanceError> {
        let mut transaction = self.database.pool().begin().await?;
        let updated = sqlx::query("UPDATE jobs SET state='retry_wait',available_at=clock_timestamp()+make_interval(secs=>$4),lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND fencing_token=$3")
            .bind(job.tenant_id)
            .bind(job.id)
            .bind(job.fencing_token)
            .bind(delay_seconds.max(1))
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        if updated != 1 {
            return Err(MaintenanceError::LeaseLost);
        }
        sqlx::query("UPDATE job_attempts SET finished_at=clock_timestamp(),outcome='deferred_for_retention' WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3")
            .bind(job.tenant_id)
            .bind(job.id)
            .bind(job.attempt)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn enqueue_finalized_orphans(&self) -> Result<u64, MaintenanceError> {
        let mut transaction = self.database.pool().begin().await?;
        let rows = sqlx::query("UPDATE payload_objects SET state='delete_intent',deletion_intent_at=clock_timestamp() WHERE (tenant_id,id) IN (SELECT p.tenant_id,p.id FROM payload_objects p WHERE p.tenant_id=$2 AND p.backend_id=$3 AND p.state='finalized' AND p.finalized_at<=clock_timestamp()-make_interval(secs=>$1) AND NOT EXISTS (SELECT 1 FROM filebelt_document.revisions r WHERE r.tenant_id=p.tenant_id AND r.payload_id=p.id) ORDER BY p.finalized_at FOR UPDATE SKIP LOCKED LIMIT 100) RETURNING tenant_id,id")
            .bind(self.orphan_grace_seconds)
            .bind(self.tenant_id)
            .bind(self.backend_id)
            .fetch_all(&mut *transaction)
            .await?;
        for row in &rows {
            let tenant_id: Uuid = row.get("tenant_id");
            let payload_id: Uuid = row.get("id");
            sqlx::query("INSERT INTO jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) VALUES ($1,$2,'payload_delete','queued',80,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(tenant_id)
                .bind(Uuid::new_v4())
                .bind(payload_id)
                .bind(format!("orphan:{payload_id}"))
                .bind(serde_json::json!({"payload_id": payload_id}))
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(rows.len() as u64)
    }

    async fn enqueue_scrub_jobs(&self) -> Result<u64, MaintenanceError> {
        let mut transaction = self.database.pool().begin().await?;
        let rows = sqlx::query("SELECT payload.id FROM payload_objects AS payload WHERE payload.tenant_id=$1 AND payload.backend_id=$2 AND payload.state IN ('referenced','finalized') AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.tenant_id=payload.tenant_id AND jobs.kind='payload_scrub' AND jobs.aggregate_id=payload.id AND jobs.created_at>clock_timestamp()-make_interval(secs=>$3)) ORDER BY COALESCE(payload.referenced_at,payload.finalized_at,payload.created_at),payload.id FOR UPDATE OF payload SKIP LOCKED LIMIT $4")
            .bind(self.tenant_id)
            .bind(self.backend_id)
            .bind(i64::try_from(SCRUB_INTERVAL_SECONDS).expect("scrub interval fits i64"))
            .bind(RECONCILE_BATCH_SIZE)
            .fetch_all(&mut *transaction)
            .await?;
        let period = scrub_period(SystemTime::now());
        let mut inserted = 0_u64;
        for row in rows {
            let payload_id: Uuid = row.get("id");
            inserted += sqlx::query("INSERT INTO jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) VALUES ($1,$2,'payload_scrub','queued',120,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(self.tenant_id)
                .bind(Uuid::new_v4())
                .bind(payload_id)
                .bind(format!("periodic:{payload_id}:{period}"))
                .bind(serde_json::json!({"payload_id": payload_id}))
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        }
        transaction.commit().await?;
        Ok(inserted)
    }

    async fn cleanup_expired_capability_nonces(&self) -> Result<u64, MaintenanceError> {
        let removed = sqlx::query("DELETE FROM capability_nonces WHERE ctid IN (SELECT ctid FROM capability_nonces WHERE tenant_id=$1 AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $2)")
            .bind(self.tenant_id)
            .bind(RETENTION_BATCH_SIZE)
            .execute(self.database.pool())
            .await?
            .rows_affected();
        Ok(removed)
    }

    async fn cleanup_retained_outbox(&self) -> Result<(u64, u64), MaintenanceError> {
        let mut transaction = self.database.pool().begin().await?;
        let event_ids = sqlx::query("SELECT id FROM outbox_events WHERE tenant_id=$1 AND published_at<=clock_timestamp()-make_interval(secs=>$2) ORDER BY published_at,id FOR UPDATE SKIP LOCKED LIMIT $3")
            .bind(self.tenant_id)
            .bind(RETENTION_SECONDS)
            .bind(RETENTION_BATCH_SIZE)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| row.get::<Uuid, _>("id"))
            .collect::<Vec<_>>();
        if event_ids.is_empty() {
            transaction.commit().await?;
            return Ok((0, 0));
        }
        let deduplications = sqlx::query(
            "DELETE FROM consumer_deduplication WHERE tenant_id=$1 AND event_id=ANY($2)",
        )
        .bind(self.tenant_id)
        .bind(&event_ids)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let events = sqlx::query("DELETE FROM outbox_events WHERE tenant_id=$1 AND id=ANY($2) AND published_at<=clock_timestamp()-make_interval(secs=>$3)")
            .bind(self.tenant_id)
            .bind(&event_ids)
            .bind(RETENTION_SECONDS)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        transaction.commit().await?;
        Ok((deduplications, events))
    }

    async fn cleanup_finalized_staging(&self) -> Result<u64, MaintenanceError> {
        let upload_ids = self
            .database
            .uploads_needing_staging_cleanup(self.tenant_id, self.backend_id, 100)
            .await?;
        let mut cleaned = 0_u64;
        for upload_id in upload_ids {
            let parts = self
                .database
                .upload_parts(self.tenant_id, upload_id)
                .await?;
            let storage = self.storage.clone();
            tokio::task::spawn_blocking(move || storage.remove_staging_parts(&parts))
                .await
                .map_err(|_| StorageError::Join)??;
            self.database
                .mark_upload_staging_cleaned(self.tenant_id, upload_id)
                .await?;
            cleaned += 1;
        }
        Ok(cleaned)
    }

    async fn cleanup_mount_staging(&self) -> Result<u64, MaintenanceError> {
        let mut cleaned = 0_u64;
        for _ in 0..RECONCILE_BATCH_SIZE {
            let Some(cleanup) = self
                .database
                .claim_next_mount_staging_cleanup(self.tenant_id, self.backend_id, self.worker_id)
                .await?
            else {
                break;
            };
            self.cleanup_mount_staging_job(cleanup).await?;
            cleaned = cleaned.checked_add(1).ok_or(MaintenanceError::InvalidJob)?;
        }
        Ok(cleaned)
    }

    async fn cleanup_mount_staging_job(
        &self,
        cleanup: MountStagingCleanupJobRecord,
    ) -> Result<(), MaintenanceError> {
        validate_mount_staging_cleanup(&cleanup, self.tenant_id, self.backend_id, self.worker_id)?;
        let (storage, guard) = acquire_revalidated_mount_cow_lock(
            self.storage.clone(),
            cleanup.write_session_id,
            || async {
                self.database
                    .heartbeat_mount_staging_cleanup(&cleanup)
                    .await
                    .map_err(MaintenanceError::from)
            },
        )
        .await?;

        let write_session_id = cleanup.write_session_id;
        let payload = cleanup.payload.clone();
        let deletion = tokio::task::spawn_blocking(move || {
            storage.delete_cow_staging(write_session_id, &payload)?;
            Ok::<_, StorageError>((storage, guard))
        });
        tokio::pin!(deletion);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(JOB_HEARTBEAT_SECONDS));
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let (storage, guard) = loop {
            tokio::select! {
                result = &mut deletion => {
                    break result.map_err(|_| StorageError::Join)??;
                }
                _ = heartbeat.tick() => {
                    if let Err(error) = self.database.heartbeat_mount_staging_cleanup(&cleanup).await {
                        // The blocking deletion cannot be cancelled safely. Wait for it to
                        // finish under the session flock, but do not complete the stale DB
                        // lease or unlink its lock inode.
                        let _ = (&mut deletion).await;
                        return Err(error.into());
                    }
                }
            }
        };

        // Revalidate after a potentially long deletion. A stale cleanup must
        // never acknowledge or unlink another worker's current lock domain.
        self.database
            .heartbeat_mount_staging_cleanup(&cleanup)
            .await?;
        self.database
            .mark_mount_staging_cleanup_physical_deleted(&cleanup)
            .await?;
        tokio::task::spawn_blocking(move || storage.remove_cow_lock(guard))
            .await
            .map_err(|_| StorageError::Join)??;
        self.database
            .complete_mount_staging_cleanup(&cleanup)
            .await?;
        Ok(())
    }

    async fn cleanup_mount_write_locks(&self) -> Result<u64, MaintenanceError> {
        let mut cleaned = 0_u64;
        for _ in 0..RECONCILE_BATCH_SIZE {
            let Some(cleanup) = self
                .database
                .claim_next_mount_write_lock_cleanup(
                    self.tenant_id,
                    self.backend_id,
                    self.worker_id,
                )
                .await?
            else {
                break;
            };
            self.cleanup_mount_write_lock_job(cleanup).await?;
            cleaned = cleaned.checked_add(1).ok_or(MaintenanceError::InvalidJob)?;
        }
        Ok(cleaned)
    }

    async fn cleanup_mount_write_lock_job(
        &self,
        cleanup: MountWriteLockCleanupJobRecord,
    ) -> Result<(), MaintenanceError> {
        validate_mount_write_lock_cleanup(
            &cleanup,
            self.tenant_id,
            self.backend_id,
            self.worker_id,
        )?;
        if cleanup.job_state == "completed" {
            return Ok(());
        }
        let (storage, guard) = acquire_revalidated_mount_cow_lock(
            self.storage.clone(),
            cleanup.write_session_id,
            || async {
                self.database
                    .heartbeat_mount_write_lock_cleanup(&cleanup)
                    .await
                    .map_err(MaintenanceError::from)
            },
        )
        .await?;
        tokio::task::spawn_blocking(move || storage.remove_cow_lock(guard))
            .await
            .map_err(|_| StorageError::Join)??;
        self.database
            .complete_mount_write_lock_cleanup(&cleanup)
            .await?;
        Ok(())
    }

    async fn cleanup_document_finalized_staging(&self) -> Result<u64, MaintenanceError> {
        let locators = self
            .database
            .document_finalized_staging_locators(
                self.tenant_id,
                self.backend_id,
                RECONCILE_BATCH_SIZE,
            )
            .await?;
        let mut cleaned = 0_u64;
        for locator in locators {
            let storage = self.storage.clone();
            tokio::task::spawn_blocking(move || storage.remove_staging_locator(locator))
                .await
                .map_err(|_| StorageError::Join)??;
            cleaned += 1;
        }
        Ok(cleaned)
    }
}

async fn acquire_revalidated_mount_cow_lock<F, Fut>(
    storage: StorageLayout,
    write_session_id: Uuid,
    revalidate: F,
) -> Result<(StorageLayout, filebelt_storage::CowLockGuard), MaintenanceError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), MaintenanceError>>,
{
    let (storage, mut guard) = tokio::task::spawn_blocking(move || {
        let mut guard = storage.lock_cow(write_session_id)?;
        // `spawn_blocking` outlives a cancelled async waiter. Keep cleanup
        // armed while ownership is in the join result so a stale detached
        // waiter cannot recreate an already completed terminal lock.
        guard.arm_remove_on_drop();
        Ok::<_, StorageError>((storage, guard))
    })
    .await
    .map_err(|_| StorageError::Join)??;
    // From this point the fenced cleanup lease, not task cancellation, owns
    // terminal unlink. In particular, a failed heartbeat must retain the lock
    // path for the next current lease holder.
    guard.disarm_remove_on_drop();
    revalidate().await?;
    Ok((storage, guard))
}

fn validate_mount_staging_cleanup(
    cleanup: &MountStagingCleanupJobRecord,
    tenant_id: Uuid,
    backend_id: Uuid,
    worker_id: Uuid,
) -> Result<(), MaintenanceError> {
    let payload: &PayloadRecord = &cleanup.payload;
    if cleanup.tenant_id != tenant_id
        || cleanup.backend_id != backend_id
        || cleanup.worker_id != worker_id
        || cleanup.write_session_id.is_nil()
        || cleanup.job_fencing_token <= 0
        || !matches!(cleanup.job_state.as_str(), "leased" | "physical_deleted")
        || !matches!(
            cleanup.completion_kind.as_str(),
            "cleanup" | "delete_staging"
        )
        || payload.tenant_id != tenant_id
        || payload.backend_id != backend_id
        || payload.payload_id.is_nil()
        || payload.locator.is_nil()
        || !matches!(payload.layout.as_str(), "whole" | "chunked")
        || !matches!(
            payload.state.as_str(),
            "staging" | "finalized" | "abandoned" | "deleting" | "deleted"
        )
    {
        return Err(MaintenanceError::InvalidJob);
    }
    Ok(())
}

fn validate_mount_write_lock_cleanup(
    cleanup: &MountWriteLockCleanupJobRecord,
    tenant_id: Uuid,
    backend_id: Uuid,
    worker_id: Uuid,
) -> Result<(), MaintenanceError> {
    if cleanup.tenant_id != tenant_id
        || cleanup.backend_id != backend_id
        || cleanup.worker_id != worker_id
        || cleanup.write_session_id.is_nil()
        || cleanup.staging_payload_id.is_nil()
        || cleanup.job_fencing_token <= 0
        || !matches!(cleanup.job_state.as_str(), "leased" | "completed")
    {
        return Err(MaintenanceError::InvalidJob);
    }
    Ok(())
}

pub struct IggyPublisher {
    database: Database,
    tenant_id: Uuid,
    client: IggyClient,
    stream: String,
    partitions: u32,
    retention_seconds: u64,
}

impl IggyPublisher {
    pub async fn connect(
        database: Database,
        tenant_id: Uuid,
        endpoint: &str,
        stream: String,
        partitions: u32,
    ) -> Result<Self, MaintenanceError> {
        let topology = phase2_iggy_topology(&stream, partitions)?;
        let client = IggyClient::from_connection_string(endpoint)
            .map_err(|_| MaintenanceError::Notification)?;
        client
            .connect()
            .await
            .map_err(|_| MaintenanceError::Notification)?;
        Ok(Self {
            database,
            tenant_id,
            client,
            stream,
            partitions: topology.partitions,
            retention_seconds: topology.retention_seconds,
        })
    }

    pub async fn publish_pending(&self, limit: i64) -> Result<u64, MaintenanceError> {
        let events = self.database.pending_outbox(self.tenant_id, limit).await?;
        let mut published = 0_u64;
        for (tenant_id, event_id, topic, payload) in events {
            if self.publish_event(tenant_id, &topic, payload).await.is_ok() {
                self.database
                    .mark_outbox_published(tenant_id, event_id)
                    .await?;
                published += 1;
            } else {
                self.database.mark_outbox_retry(tenant_id, event_id).await?;
            }
        }
        Ok(published)
    }

    async fn publish_event(
        &self,
        tenant_id: Uuid,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<(), IggyError> {
        let producer = self
            .client
            .producer(&self.stream, topic)?
            .create_stream_if_not_exists()
            .create_topic_if_not_exists(
                self.partitions,
                None,
                iggy_message_expiry(self.retention_seconds),
                MaxTopicSize::ServerDefault,
            )
            .build();
        producer.init().await?;
        let partition = outbox_partition(tenant_id, &payload, self.partitions);
        let message = IggyMessage::builder()
            .payload(Bytes::from(payload))
            .build()?;
        producer
            .send_with_partitioning(
                vec![message],
                Some(Arc::new(Partitioning::partition_id(partition))),
            )
            .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IggyTopology {
    partitions: u32,
    retention_seconds: u64,
}

fn phase2_iggy_topology(stream: &str, partitions: u32) -> Result<IggyTopology, MaintenanceError> {
    if stream != "filebelt" || partitions != IGGY_PARTITIONS {
        return Err(MaintenanceError::Notification);
    }
    Ok(IggyTopology {
        partitions,
        retention_seconds: IGGY_RETENTION_SECONDS,
    })
}

fn payload_uuid(payload: &Value, field: &str) -> Result<Uuid, MaintenanceError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(MaintenanceError::InvalidJob)
}

fn error_code(error: &MaintenanceError) -> &'static str {
    match error {
        MaintenanceError::Database(_) | MaintenanceError::Sql(_) => "database_unavailable",
        MaintenanceError::Storage(StorageError::CorruptObject | StorageError::UnsafeObject) => {
            "storage_integrity_failure"
        }
        MaintenanceError::Storage(_) => "storage_io_failure",
        MaintenanceError::InvalidJob => "invalid_job_payload",
        MaintenanceError::LeaseLost => "job_lease_lost",
        MaintenanceError::JobRuntimeExceeded => "job_runtime_exceeded",
        MaintenanceError::Notification => "notification_unavailable",
    }
}

fn scrub_period(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / SCRUB_INTERVAL_SECONDS
}

fn job_max_runtime() -> Duration {
    Duration::from_secs(JOB_MAX_RUNTIME_SECONDS)
}

fn iggy_message_expiry(retention_seconds: u64) -> IggyExpiry {
    IggyExpiry::ExpireDuration(IggyDuration::new_from_secs(retention_seconds))
}

fn outbox_partition(tenant_id: Uuid, payload: &[u8], partitions: u32) -> u32 {
    let mut partition_hasher = blake3::Hasher::new();
    partition_hasher.update(tenant_id.as_bytes());
    if let Ok(event) = EventEnvelope::decode(payload) {
        partition_hasher.update(event.aggregate_id.as_bytes());
    }
    let digest = partition_hasher.finalize();
    let prefix = [
        digest.as_bytes()[0],
        digest.as_bytes()[1],
        digest.as_bytes()[2],
        digest.as_bytes()[3],
    ];
    u32::from_le_bytes(prefix) % partitions + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn event_partition_is_stable_and_inside_configured_topology() {
        let tenant = Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("tenant ID");
        let payload = EventEnvelope {
            aggregate_id: "11111111-2222-4333-8444-555555555555".into(),
            ..EventEnvelope::default()
        }
        .encode_to_vec();
        let first = outbox_partition(tenant, &payload, 16);
        assert!((1..=16).contains(&first));
        assert_eq!(first, outbox_partition(tenant, &payload, 16));
    }

    #[test]
    fn invalid_job_uuid_is_rejected() {
        assert!(
            payload_uuid(
                &serde_json::json!({"payload_id": "not-a-uuid"}),
                "payload_id"
            )
            .is_err()
        );
    }

    #[test]
    fn reconciliation_includes_collaboration_retention_before_payload_jobs_run() {
        let source = include_str!("lib.rs");
        let reconcile = source
            .split_once("pub async fn reconcile")
            .expect("reconcile exists")
            .1
            .split_once("pub async fn run_one_job")
            .expect("job loop follows reconcile")
            .0;
        assert!(reconcile.contains("collaboration_retention_sweep"));
        assert!(reconcile.contains("collaboration_payload_deletions_enqueued"));
        assert!(reconcile.contains("collaboration_objects_abandoned"));
    }

    #[test]
    fn collaboration_payload_deletion_removes_staging_and_final_bytes() {
        let source = include_str!("lib.rs");
        let deletion = source
            .split_once("async fn delete_payload")
            .expect("payload deletion exists")
            .1
            .split_once("async fn scrub_payload")
            .expect("scrubbing follows deletion")
            .0;
        assert!(deletion.contains("storage.delete_payload(&payload_for_delete)?"));
        assert!(deletion.contains("storage.remove_staging_locator(payload_for_delete.locator)"));
        assert!(deletion.contains("complete_collaboration_payload_deletion"));
    }

    #[test]
    fn document_revision_reconciliation_preserves_final_bytes_and_cleans_links() {
        let source = include_str!("lib.rs");
        let reconcile = source
            .split_once("pub async fn reconcile")
            .expect("reconcile exists")
            .1
            .split_once("pub async fn run_one_job")
            .expect("job loop follows reconcile")
            .0;
        assert!(reconcile.contains("document_revision_retention_sweep"));
        assert!(reconcile.contains("cleanup_document_finalized_staging"));
        assert!(reconcile.contains("document_operation_receipts_purged"));
        assert!(reconcile.contains("document_terminal_revisions_released"));

        let orphan = source
            .split_once("async fn enqueue_finalized_orphans")
            .expect("orphan sweep exists")
            .1
            .split_once("async fn enqueue_scrub_jobs")
            .expect("scrub sweep follows orphan sweep")
            .0;
        assert!(orphan.contains("NOT EXISTS (SELECT 1 FROM filebelt_document.revisions"));

        let cleanup = source
            .split_once("async fn cleanup_document_finalized_staging")
            .expect("document staging cleanup exists")
            .1
            .split_once("}\n}")
            .expect("maintenance implementation closes")
            .0;
        assert!(cleanup.contains("document_finalized_staging_locators"));
        assert!(cleanup.contains("storage.remove_staging_locator(locator)"));
    }

    #[test]
    fn document_payload_jobs_use_the_document_terminal_transition() {
        let source = include_str!("lib.rs");
        let deletion = source
            .split_once("async fn delete_payload")
            .expect("payload deletion exists")
            .1
            .split_once("async fn scrub_payload")
            .expect("scrubbing follows deletion")
            .0;
        assert!(deletion.contains("document_payload_deletion_pending"));
        assert!(deletion.contains("complete_document_payload_deletion"));
    }

    #[test]
    fn mount_cleanup_uses_only_authoritative_cow_and_payload_paths() {
        let source = include_str!("lib.rs");
        let reconcile = source
            .split_once("pub async fn reconcile")
            .expect("reconcile exists")
            .1
            .split_once("pub async fn run_one_job")
            .expect("job loop follows reconcile")
            .0;
        assert!(
            reconcile.find("sweep_expired_nfs_writers").unwrap()
                < reconcile.find("cleanup_mount_staging").unwrap(),
            "expired writers must enter the authoritative job machine before it is drained"
        );
        assert!(
            reconcile.find("sweep_expired_nfs_write_conflicts").unwrap()
                < reconcile.find("cleanup_mount_staging").unwrap(),
            "retained conflicts must expire into the common job machine before it is drained"
        );
        let cleanup = source
            .split_once("async fn cleanup_mount_staging")
            .expect("mount staging cleanup exists")
            .1
            .split_once("async fn cleanup_document_finalized_staging")
            .expect("document cleanup follows mount cleanup")
            .0;
        assert!(cleanup.contains("claim_next_mount_staging_cleanup"));
        assert!(cleanup.contains("heartbeat_mount_staging_cleanup"));
        assert!(cleanup.contains("delete_cow_staging"));
        assert!(cleanup.contains("mark_mount_staging_cleanup_physical_deleted"));
        assert!(cleanup.contains("remove_cow_lock"));
        assert!(cleanup.contains("complete_mount_staging_cleanup"));
        assert!(!cleanup.contains("remove_staging_locator"));
        let deleted = cleanup.find("delete_cow_staging").expect("physical delete");
        let marked = cleanup
            .find("mark_mount_staging_cleanup_physical_deleted")
            .expect("physical marker");
        let unlocked = cleanup.find("remove_cow_lock").expect("lock removal");
        let completed = cleanup
            .find("complete_mount_staging_cleanup")
            .expect("terminal completion");
        assert!(deleted < marked && marked < unlocked && unlocked < completed);
    }

    #[test]
    fn finalized_mount_lock_cleanup_never_authorizes_payload_deletion() {
        let source = include_str!("lib.rs");
        let cleanup = source
            .split_once("async fn cleanup_mount_write_locks")
            .expect("mount lock cleanup exists")
            .1
            .split_once("async fn cleanup_document_finalized_staging")
            .expect("document cleanup follows mount lock cleanup")
            .0;
        assert!(cleanup.contains("claim_next_mount_write_lock_cleanup"));
        assert!(cleanup.contains("heartbeat_mount_write_lock_cleanup"));
        assert!(cleanup.contains("remove_cow_lock"));
        assert!(cleanup.contains("complete_mount_write_lock_cleanup"));
        assert!(!cleanup.contains("delete_cow_staging"));
        assert!(!cleanup.contains("delete_payload"));
        assert!(!cleanup.contains("remove_staging_locator"));
        let heartbeat = cleanup
            .find("heartbeat_mount_write_lock_cleanup")
            .expect("lease revalidation");
        let removed = cleanup.find("remove_cow_lock").expect("verified unlink");
        let completed = cleanup
            .find("complete_mount_write_lock_cleanup")
            .expect("fenced acknowledgement");
        assert!(heartbeat < removed && removed < completed);
    }

    #[tokio::test]
    async fn stale_cleanup_waiter_does_not_delete_or_unlink_after_lock_wait() {
        let temporary = tempfile::tempdir().expect("temporary storage");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure temporary root");
        let storage = StorageLayout::new(temporary.path().to_path_buf());
        storage.prepare().expect("prepare storage");
        let session_id = Uuid::new_v4();
        let payload = PayloadRecord {
            tenant_id: Uuid::new_v4(),
            payload_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            locator: Uuid::new_v4(),
            layout: "whole".to_owned(),
            state: "finalized".to_owned(),
            size_bytes: 4,
            blake3: None,
        };
        let payload_path = storage.payload_path(&payload).expect("payload path");
        std::fs::write(&payload_path, b"data").expect("payload bytes");
        let owner = storage.lock_cow(session_id).expect("owner lock");
        let waiting_storage = storage.clone();
        let waiter = tokio::spawn(async move {
            acquire_revalidated_mount_cow_lock(waiting_storage, session_id, || async {
                Err(MaintenanceError::LeaseLost)
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(owner);
        let error = waiter
            .await
            .expect("waiter task")
            .expect_err("stale lease must fail");
        assert!(matches!(error, MaintenanceError::LeaseLost));
        assert_eq!(
            std::fs::read(payload_path).expect("payload retained"),
            b"data"
        );
        let retry = storage.lock_cow(session_id).expect("lock path retained");
        drop(retry);
    }

    #[test]
    fn iggy_topology_is_fixed_to_sixteen_partitions_and_seven_days() {
        let topology = phase2_iggy_topology("filebelt", 16).expect("Phase 2 topology");
        assert_eq!(topology.partitions, 16);
        assert_eq!(topology.retention_seconds, 7 * 24 * 60 * 60);
        let IggyExpiry::ExpireDuration(expiry) = iggy_message_expiry(topology.retention_seconds)
        else {
            panic!("topology must use an explicit expiry");
        };
        assert_eq!(expiry.get_duration(), Duration::from_secs(7 * 24 * 60 * 60));
        assert!(phase2_iggy_topology("other", 16).is_err());
        assert!(phase2_iggy_topology("filebelt", 15).is_err());
    }

    #[test]
    fn scrub_periods_are_stable_thirty_day_buckets() {
        let first = UNIX_EPOCH + Duration::from_secs(SCRUB_INTERVAL_SECONDS - 1);
        let second = UNIX_EPOCH + Duration::from_secs(SCRUB_INTERVAL_SECONDS);
        assert_eq!(scrub_period(first), 0);
        assert_eq!(scrub_period(second), 1);
    }

    #[test]
    fn job_runtime_is_finite_and_longer_than_its_lease() {
        let runtime = job_max_runtime().as_secs();
        assert!(runtime > u64::try_from(JOB_LEASE_SECONDS).expect("lease"));
        assert!(runtime <= 24 * 60 * 60);
    }
}

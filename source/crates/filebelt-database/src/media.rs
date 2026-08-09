// SPDX-License-Identifier: Apache-2.0

//! Durable, fenced media-preview metadata. Payload and cache locators remain
//! deliberately absent: only the I/O service resolves physical storage.

use sqlx::Row;
use uuid::Uuid;

use crate::{Database, DatabaseError};

pub const MEDIA_MAX_ATTEMPTS: i32 = 3;
pub const MEDIA_PLAYBACK_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaPreviewState {
    Requested,
    Running,
    Verifying,
    Ready,
    Failed,
    Quarantined,
    Cancelled,
    Evicting,
    Evicted,
}

impl MediaPreviewState {
    fn parse(value: &str) -> Result<Self, DatabaseError> {
        match value {
            "requested" => Ok(Self::Requested),
            "running" => Ok(Self::Running),
            "verifying" => Ok(Self::Verifying),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            "quarantined" => Ok(Self::Quarantined),
            "cancelled" => Ok(Self::Cancelled),
            "evicting" => Ok(Self::Evicting),
            "evicted" => Ok(Self::Evicted),
            _ => Err(DatabaseError::InvalidPersistedValue),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Running => "running",
            Self::Verifying => "verifying",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
            Self::Cancelled => "cancelled",
            Self::Evicting => "evicting",
            Self::Evicted => "evicted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaPreviewRecord {
    pub id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub source_version_id: Uuid,
    pub state: MediaPreviewState,
    pub attempt_count: i32,
    pub job_epoch: i64,
    pub cache_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AdmitMediaPreviewInput<'a> {
    pub tenant_id: Uuid,
    pub preview_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub source_version_id: Uuid,
    pub requester_principal_id: Uuid,
    pub requester_session_id: Uuid,
    pub idempotency_key: &'a str,
    pub request_fingerprint: &'a [u8; 32],
    pub cache_key: &'a [u8; 32],
    pub profile_id: &'a str,
    pub profile_digest: &'a [u8; 32],
    pub transcoder_build_identity: &'a [u8; 32],
}

#[derive(Clone, Debug)]
pub struct StartMediaAttemptInput<'a> {
    pub tenant_id: Uuid,
    pub preview_id: Uuid,
    pub attempt_id: Uuid,
    pub source_capability_digest: &'a [u8; 32],
    pub output_capability_digest: &'a [u8; 32],
    pub callback_capability_digest: &'a [u8; 32],
}

#[derive(Clone, Debug)]
pub struct MediaAttemptRecord {
    pub id: Uuid,
    pub preview_id: Uuid,
    pub job_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct RecordVerifiedSegmentInput<'a> {
    pub tenant_id: Uuid,
    pub preview_id: Uuid,
    pub attempt_id: Uuid,
    pub job_epoch: i64,
    pub ordinal: i64,
    pub segment_id: Uuid,
    pub blake3: &'a [u8; 32],
    pub byte_length: i64,
    pub start_time_milliseconds: i64,
    pub duration_milliseconds: i64,
    pub initialization_segment: bool,
}

#[derive(Clone, Debug)]
pub struct PublishMediaManifestInput<'a> {
    pub tenant_id: Uuid,
    pub preview_id: Uuid,
    pub attempt_id: Uuid,
    pub job_epoch: i64,
    pub manifest_id: Uuid,
    pub manifest_blake3: &'a [u8; 32],
    pub manifest_byte_length: i64,
    pub cache_artifact_id: Uuid,
    pub charged_bytes: i64,
}

impl Database {
    pub async fn media_preview(
        &self,
        tenant_id: Uuid,
        preview_id: Uuid,
    ) -> Result<MediaPreviewRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT id,drive_id,node_id,source_version_id,state,attempt_count,job_epoch,cache_key FROM filebelt_media.previews WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(preview_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        preview_from_row(&row)
    }

    pub async fn cancel_media_preview(
        &self,
        tenant_id: Uuid,
        preview_id: Uuid,
    ) -> Result<MediaPreviewRecord, DatabaseError> {
        let row = sqlx::query(
            "UPDATE filebelt_media.previews SET cancellation_requested_at=COALESCE(cancellation_requested_at,clock_timestamp()),state=CASE WHEN state='requested' THEN 'cancelled' ELSE state END,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state IN ('requested','running','verifying') RETURNING id,drive_id,node_id,source_version_id,state,attempt_count,job_epoch,cache_key",
        )
        .bind(tenant_id)
        .bind(preview_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        preview_from_row(&row)
    }

    /// Creates exactly one durable request for an API session/idempotency key.
    /// Authorization is intentionally performed by the controller before this
    /// repository call; this projection persists only already-admitted state.
    pub async fn admit_media_preview(
        &self,
        input: AdmitMediaPreviewInput<'_>,
    ) -> Result<MediaPreviewRecord, DatabaseError> {
        validate_admission(&input)?;
        let mut transaction = self.pool.begin().await?;
        let existing = sqlx::query(
            "SELECT id,drive_id,node_id,source_version_id,state,attempt_count,job_epoch,cache_key,request_fingerprint \
             FROM filebelt_media.previews WHERE tenant_id=$1 AND requester_session_id=$2 AND idempotency_key=$3 FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(input.requester_session_id)
        .bind(input.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(row) = existing {
            let fingerprint: Vec<u8> = row.get("request_fingerprint");
            if fingerprint.as_slice() != input.request_fingerprint {
                return Err(DatabaseError::Conflict);
            }
            let record = preview_from_row(&row)?;
            transaction.commit().await?;
            return Ok(record);
        }
        let row = sqlx::query(
            "INSERT INTO filebelt_media.previews \
             (tenant_id,id,drive_id,node_id,source_version_id,requester_principal_id,requester_session_id,idempotency_key,request_fingerprint,cache_key,profile_id,profile_digest,transcoder_build_identity) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) \
             RETURNING id,drive_id,node_id,source_version_id,state,attempt_count,job_epoch,cache_key",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .bind(input.drive_id)
        .bind(input.node_id)
        .bind(input.source_version_id)
        .bind(input.requester_principal_id)
        .bind(input.requester_session_id)
        .bind(input.idempotency_key)
        .bind(input.request_fingerprint.as_slice())
        .bind(input.cache_key.as_slice())
        .bind(input.profile_id)
        .bind(input.profile_digest.as_slice())
        .bind(input.transcoder_build_identity.as_slice())
        .fetch_one(&mut *transaction)
        .await?;
        let record = preview_from_row(&row)?;
        transaction.commit().await?;
        Ok(record)
    }

    /// Starts a fenced attempt. A stale or cancelled preview never receives a
    /// new capability set, and infrastructure retries are capped at three.
    pub async fn start_media_attempt(
        &self,
        input: StartMediaAttemptInput<'_>,
    ) -> Result<MediaAttemptRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_media.previews SET state='running',attempt_count=attempt_count+1,job_epoch=job_epoch+1,updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND state='requested' AND cancellation_requested_at IS NULL AND attempt_count<$3 \
             RETURNING job_epoch",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .bind(MEDIA_MAX_ATTEMPTS)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let job_epoch: i64 = row.get("job_epoch");
        sqlx::query(
            "INSERT INTO filebelt_media.attempts \
             (tenant_id,id,preview_id,job_epoch,source_capability_digest,output_capability_digest,callback_capability_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(input.tenant_id)
        .bind(input.attempt_id)
        .bind(input.preview_id)
        .bind(job_epoch)
        .bind(input.source_capability_digest.as_slice())
        .bind(input.output_capability_digest.as_slice())
        .bind(input.callback_capability_digest.as_slice())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(MediaAttemptRecord {
            id: input.attempt_id,
            preview_id: input.preview_id,
            job_epoch,
        })
    }

    /// Records a segment only after the I/O layer has verified its immutable
    /// receipt. The caller must never use this method for adapter assertions.
    pub async fn record_verified_media_segment(
        &self,
        input: RecordVerifiedSegmentInput<'_>,
    ) -> Result<(), DatabaseError> {
        if input.ordinal < 0
            || input.byte_length <= 0
            || input.start_time_milliseconds < 0
            || input.duration_milliseconds <= 0
            || input.job_epoch <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let admitted = sqlx::query(
            "UPDATE filebelt_media.attempts a SET state='verifying' \
             FROM filebelt_media.previews p \
             WHERE a.tenant_id=$1 AND a.id=$2 AND a.preview_id=$3 AND a.job_epoch=$4 \
               AND a.state IN ('running','verifying') AND p.tenant_id=a.tenant_id AND p.id=a.preview_id \
               AND p.state IN ('running','verifying') AND p.job_epoch=a.job_epoch AND p.cancellation_requested_at IS NULL",
        )
        .bind(input.tenant_id)
        .bind(input.attempt_id)
        .bind(input.preview_id)
        .bind(input.job_epoch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if admitted != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let inserted = sqlx::query(
            "INSERT INTO filebelt_media.segment_receipts \
             (tenant_id,preview_id,attempt_id,job_epoch,ordinal,segment_id,blake3,byte_length,start_time_milliseconds,duration_milliseconds,initialization_segment) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .bind(input.attempt_id)
        .bind(input.job_epoch)
        .bind(input.ordinal)
        .bind(input.segment_id)
        .bind(input.blake3.as_slice())
        .bind(input.byte_length)
        .bind(input.start_time_milliseconds)
        .bind(input.duration_milliseconds)
        .bind(input.initialization_segment)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Publishes a monotonic manifest revision only when this exact fenced
    /// attempt has durable verified segment receipts.
    pub async fn publish_media_manifest(
        &self,
        input: PublishMediaManifestInput<'_>,
    ) -> Result<i64, DatabaseError> {
        if input.job_epoch <= 0 || input.manifest_byte_length <= 0 || input.charged_bytes <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let receipt_count: i64 = sqlx::query(
            "SELECT count(*) AS count FROM filebelt_media.segment_receipts \
             WHERE tenant_id=$1 AND preview_id=$2 AND attempt_id=$3 AND job_epoch=$4",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .bind(input.attempt_id)
        .bind(input.job_epoch)
        .fetch_one(&mut *transaction)
        .await?
        .get("count");
        if receipt_count == 0 {
            return Err(DatabaseError::Conflict);
        }
        let row = sqlx::query(
            "UPDATE filebelt_media.previews p SET state='ready',ready_at=clock_timestamp(),last_accessed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '30 days',updated_at=clock_timestamp() \
             FROM filebelt_media.attempts a \
             WHERE p.tenant_id=$1 AND p.id=$2 AND p.job_epoch=$3 AND p.state IN ('running','verifying') \
               AND a.tenant_id=p.tenant_id AND a.id=$4 AND a.preview_id=p.id AND a.job_epoch=p.job_epoch \
               AND a.state='verifying' AND p.cancellation_requested_at IS NULL \
             RETURNING p.id",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .bind(input.job_epoch)
        .bind(input.attempt_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let revision: i64 = sqlx::query(
            "SELECT COALESCE(max(revision),0)+1 AS revision FROM filebelt_media.manifest_revisions \
             WHERE tenant_id=$1 AND preview_id=$2",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .fetch_one(&mut *transaction)
        .await?
        .get("revision");
        sqlx::query(
            "INSERT INTO filebelt_media.manifest_revisions \
             (tenant_id,preview_id,revision,attempt_id,job_epoch,manifest_id,manifest_blake3,manifest_byte_length) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(input.tenant_id)
        .bind(input.preview_id)
        .bind(revision)
        .bind(input.attempt_id)
        .bind(input.job_epoch)
        .bind(input.manifest_id)
        .bind(input.manifest_blake3.as_slice())
        .bind(input.manifest_byte_length)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO filebelt_media.cache_artifacts \
             (tenant_id,id,preview_id,manifest_revision,charged_bytes,expires_at) \
             VALUES ($1,$2,$3,$4,$5,clock_timestamp()+interval '30 days')",
        )
        .bind(input.tenant_id)
        .bind(input.cache_artifact_id)
        .bind(input.preview_id)
        .bind(revision)
        .bind(input.charged_bytes)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_media.attempts SET state='complete',finished_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND job_epoch=$3 AND state='verifying'",
        )
        .bind(input.tenant_id)
        .bind(input.attempt_id)
        .bind(input.job_epoch)
        .execute(&mut *transaction)
        .await?;
        let _: Uuid = row.get("id");
        transaction.commit().await?;
        Ok(revision)
    }
}

fn validate_admission(input: &AdmitMediaPreviewInput<'_>) -> Result<(), DatabaseError> {
    if input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 256
        || input.profile_id.is_empty()
        || input.profile_id.len() > 128
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn preview_from_row(row: &sqlx::postgres::PgRow) -> Result<MediaPreviewRecord, DatabaseError> {
    let cache_key: Vec<u8> = row.get("cache_key");
    let cache_key: [u8; 32] = cache_key
        .try_into()
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    Ok(MediaPreviewRecord {
        id: row.get("id"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        source_version_id: row.get("source_version_id"),
        state: MediaPreviewState::parse(row.get::<String, _>("state").as_str())?,
        attempt_count: row.get("attempt_count"),
        job_epoch: row.get("job_epoch"),
        cache_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_migration_keeps_derivatives_authoritative_only_as_metadata() {
        let migration = include_str!("../../../migrations/postgres/000008_phase8_media.sql");
        for table in [
            "previews",
            "attempts",
            "reservations",
            "segment_receipts",
            "manifest_revisions",
            "cache_artifacts",
            "playback_sessions",
            "deletion_intents",
            "diagnostics",
        ] {
            assert!(migration.contains(&format!("filebelt_media.{table}")));
        }
        assert!(migration.contains("fencing_token"));
        assert!(migration.contains("interval '60 seconds'"));
        assert!(migration.contains("interval '30 days'"));
        assert!(!migration.contains("payload_locator"));
        assert!(!migration.contains("payload_path"));
    }

    #[test]
    fn media_states_and_limits_are_closed() {
        assert_eq!(MEDIA_MAX_ATTEMPTS, 3);
        assert_eq!(MEDIA_PLAYBACK_LIFETIME_SECONDS, 60);
        assert!(matches!(
            MediaPreviewState::parse("ready"),
            Ok(MediaPreviewState::Ready)
        ));
        assert!(matches!(
            MediaPreviewState::parse("adapter_claimed"),
            Err(DatabaseError::InvalidPersistedValue)
        ));
    }
}

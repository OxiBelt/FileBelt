// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral document-session persistence and commit fencing.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{
    Database, DatabaseError, insert_audit, insert_outbox, lock_authorization_fence, map_conflict,
};

pub const DOCUMENT_MAX_ACTIVE_PARTICIPANTS: i64 = 20;
pub const DOCUMENT_MAX_BYTES: i64 = 100 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct DocumentAuthorizationGenerations {
    pub membership: i64,
    pub drive_acl: i64,
    pub namespace: i64,
    pub resource_acl: i64,
}

impl DocumentAuthorizationGenerations {
    const fn as_array(self) -> [i64; 4] {
        [
            self.membership,
            self.drive_acl,
            self.namespace,
            self.resource_acl,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct CreateDocumentSessionInput<'a> {
    pub tenant_id: Uuid,
    pub actor_principal_id: Uuid,
    pub api_session_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub base_version_id: Uuid,
    pub provider_id: &'a str,
    pub mode: &'a str,
    pub generations: DocumentAuthorizationGenerations,
    pub maximum_active_participants: i64,
    pub maximum_document_bytes: i64,
    pub operation_digest: &'a [u8; 32],
    pub request_fingerprint: &'a [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentSessionRecord {
    pub id: Uuid,
    pub session_principal_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub base_version_id: Uuid,
    pub expected_head_version_id: Uuid,
    pub provider_id: String,
    pub state: String,
    pub fencing_token: i64,
    pub created_at: String,
    pub created_at_unix_microseconds: i64,
    pub absolute_expires_at: String,
    pub reconnect_until: String,
    pub closed_at: Option<String>,
    pub close_reason: Option<String>,
    /// Current authoritative node head only when this session is conflicted.
    pub conflict_head_version_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentParticipantRecord {
    pub id: Uuid,
    pub document_session_id: Uuid,
    pub user_principal_id: Uuid,
    pub api_session_id: Uuid,
    pub mode: String,
    pub state: String,
    pub display_name: String,
    pub created_at: String,
    pub last_activity_at: String,
    pub disconnected_until: Option<String>,
    pub generations: DocumentAuthorizationGenerations,
}

/// The narrow projection required to mint one document I/O capability. It
/// deliberately excludes payload locators; only the I/O worker resolves those.
#[derive(Clone, Debug)]
pub struct DocumentIoContext {
    pub session: DocumentSessionRecord,
    pub participant: DocumentParticipantRecord,
    pub revision: DocumentRevisionRecord,
    pub base_payload_id: Uuid,
    pub base_size_bytes: i64,
}

#[derive(Clone, Debug)]
pub struct DocumentLaunchIoContext {
    pub session: DocumentSessionRecord,
    pub participant: DocumentParticipantRecord,
    pub base_payload_id: Uuid,
    pub base_size_bytes: i64,
    pub base_media_type: String,
    pub source_display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentConflictCopyRecord {
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Uuid,
    pub display_name: String,
    pub media_type: String,
    pub size_bytes: i64,
    pub blake3: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentLaunchRecord {
    pub grant_id: Uuid,
    pub participant: DocumentParticipantRecord,
    pub session: DocumentSessionRecord,
    pub expires_at: String,
}

#[derive(Clone, Debug)]
pub struct DocumentSessionPageAnchor {
    pub created_at_unix_microseconds: i64,
    pub session_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct DocumentSessionPageRecord {
    pub launches: Vec<DocumentLaunchRecord>,
    pub next_anchor: Option<DocumentSessionPageAnchor>,
}

/// The complete, session-bound authorization context for one node-wide
/// manager listing. Keeping it as one input prevents a caller from losing a
/// fencing value when the paging surface evolves.
#[derive(Clone, Debug)]
pub struct ListDocumentSessionsForNodeInput {
    pub tenant_id: Uuid,
    pub actor_principal_id: Uuid,
    pub api_session_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub generations: DocumentAuthorizationGenerations,
    pub limit: u32,
    pub anchor: Option<DocumentSessionPageAnchor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentRevisionRecord {
    pub id: Uuid,
    pub document_session_id: Uuid,
    pub actor_participant_id: Uuid,
    pub kind: String,
    pub state: String,
    pub expected_head_version_id: Uuid,
    pub payload_id: Option<Uuid>,
    pub reserved_bytes: i64,
    pub size_bytes: Option<i64>,
    pub blake3: Option<Vec<u8>>,
    pub media_type: Option<String>,
    pub committed_version_id: Option<Uuid>,
    pub retained_until: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentPayloadAllocation {
    pub revision: DocumentRevisionRecord,
    pub payload_id: Uuid,
    pub backend_id: Uuid,
    pub locator: Uuid,
    pub fencing_token: i64,
}

#[derive(Clone, Debug)]
pub struct BeginDocumentRevisionInput<'a> {
    pub tenant_id: Uuid,
    pub document_session_id: Uuid,
    pub participant_id: Uuid,
    pub provider_event_digest: &'a [u8; 32],
    pub kind: &'a str,
    pub reserved_bytes: i64,
    pub media_type: &'a str,
}

#[derive(Clone, Debug)]
pub struct ReceiveDocumentCallbackInput<'a> {
    pub tenant_id: Uuid,
    pub document_session_id: Uuid,
    pub participant_id: Uuid,
    pub provider_event_digest: &'a [u8; 32],
    pub callback_kind: &'a str,
    pub revision_kind: Option<&'a str>,
    pub activity: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct ReceivedDocumentCallback {
    pub event_id: Uuid,
    pub revision: Option<ReceivedDocumentRevision>,
}

#[derive(Clone, Debug)]
pub struct ForceCloseDocumentSessionInput<'a> {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub actor_principal_id: Uuid,
    pub api_session_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub generations: DocumentAuthorizationGenerations,
    pub reason: &'a str,
}

#[derive(Clone, Debug)]
pub struct ReceivedDocumentRevision {
    pub id: Uuid,
    pub document_session_id: Uuid,
    pub participant_id: Uuid,
    pub provider_event_digest: Vec<u8>,
    pub kind: String,
    pub media_type: String,
    pub state: String,
}

/// Maintenance outcome for document revisions which can no longer become a
/// durable version because their session has closed or expired.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DocumentRevisionRetentionReport {
    pub received_abandoned: u64,
    pub staging_abandoned: u64,
    pub terminal_revisions_released: u64,
    pub payload_deletions_enqueued: u64,
    pub launch_grants_purged: u64,
    pub session_events_purged: u64,
    pub operation_receipts_purged: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DocumentReconnectSweepReport {
    pub participants_closed: u64,
    pub sessions_expired: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DocumentCommitResult {
    Committed { version_id: Uuid },
    NoOp { version_id: Uuid },
    Conflict { retained_until: String },
}

impl Database {
    pub async fn receive_document_callback(
        &self,
        input: &ReceiveDocumentCallbackInput<'_>,
    ) -> Result<ReceivedDocumentCallback, DatabaseError> {
        if !matches!(
            input.callback_kind,
            "editing" | "output_required" | "corrupted" | "closed_no_changes" | "force_save_error"
        ) || (input.callback_kind == "output_required"
            && !matches!(
                input.revision_kind,
                Some("checkpoint" | "user_save" | "final_save")
            ))
            || (input.callback_kind != "output_required" && input.revision_kind.is_some())
            || (input.callback_kind == "editing"
                && !matches!(input.activity, Some("connected" | "disconnected")))
            || (input.callback_kind != "editing" && input.activity.is_some())
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(event) = sqlx::query(
            "SELECT e.id,e.participant_id,e.event_kind,p.mode FROM filebelt_document.session_events e \
             JOIN filebelt_document.participants p ON p.tenant_id=e.tenant_id AND p.id=e.participant_id \
             WHERE e.tenant_id=$1 AND e.document_session_id=$2 AND e.provider_event_digest=$3 \
             FOR UPDATE OF e,p",
        )
        .bind(input.tenant_id)
        .bind(input.document_session_id)
        .bind(input.provider_event_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        {
            let event_id: Uuid = event.get("id");
            if event.get::<Option<Uuid>, _>("participant_id") != Some(input.participant_id)
                || event.get::<String, _>("event_kind") != input.callback_kind
            {
                return Err(DatabaseError::Conflict);
            }
            if input.callback_kind == "output_required"
                && !document_participant_can_write(&event.get::<String, _>("mode"))
            {
                return Err(DatabaseError::Conflict);
            }
            if input.callback_kind == "output_required" {
                let revision = self
                    .received_document_revision_by_digest(&mut transaction, input)
                    .await?;
                transaction.commit().await?;
                return Ok(ReceivedDocumentCallback {
                    event_id,
                    revision: Some(revision),
                });
            }
            if input.callback_kind != "editing" {
                transaction.commit().await?;
                return Ok(ReceivedDocumentCallback {
                    event_id,
                    revision: None,
                });
            }
            // ONLYOFFICE can repeat an earlier status-1 digest after a status
            // 4 transient disconnect. Editing events are an idempotent
            // activity projection, rather than an immutable output receipt,
            // so deliberately continue through the participant/session fence
            // and apply the current connected/disconnected transition again.
        }
        let participant = sqlx::query("SELECT p.user_principal_id,p.api_session_id,p.mode,p.state AS participant_state,p.membership_generation,p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation,s.drive_id,s.node_id,s.expected_head_version_id,s.state AS session_state,b.media_type FROM filebelt_document.participants p JOIN filebelt_document.sessions s ON s.tenant_id=p.tenant_id AND s.id=p.document_session_id JOIN file_versions b ON b.tenant_id=s.tenant_id AND b.node_id=s.node_id AND b.id=s.base_version_id WHERE p.tenant_id=$1 AND p.id=$2 AND p.document_session_id=$3 AND p.state IN ('active','disconnected') AND s.state IN ('active','draining') AND s.absolute_expires_at>clock_timestamp() AND (s.state='active' OR s.reconnect_until>clock_timestamp()) FOR UPDATE OF p,s")
            .bind(input.tenant_id).bind(input.participant_id).bind(input.document_session_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?;
        lock_authorization_fence(
            &mut transaction,
            input.tenant_id,
            participant.get("user_principal_id"),
            participant.get("api_session_id"),
            participant.get("drive_id"),
            participant.get("node_id"),
            [
                participant.get("membership_generation"),
                participant.get("drive_acl_generation"),
                participant.get("namespace_generation"),
                participant.get("resource_acl_generation"),
            ],
        )
        .await?;
        if input.callback_kind == "output_required"
            && !document_participant_can_write(&participant.get::<String, _>("mode"))
        {
            return Err(DatabaseError::Conflict);
        }
        let event_id = Uuid::new_v4();
        let event_id: Uuid = sqlx::query_scalar("INSERT INTO filebelt_document.session_events (tenant_id,id,document_session_id,participant_id,provider_event_digest,event_kind,outcome,reason_code) VALUES ($1,$2,$3,$4,$5,$6,'allowed',$6) ON CONFLICT (tenant_id,document_session_id,provider_event_digest) DO UPDATE SET id=filebelt_document.session_events.id WHERE filebelt_document.session_events.participant_id=EXCLUDED.participant_id AND filebelt_document.session_events.event_kind=EXCLUDED.event_kind RETURNING id")
            .bind(input.tenant_id).bind(event_id).bind(input.document_session_id).bind(input.participant_id).bind(input.provider_event_digest.as_slice()).bind(input.callback_kind).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        if input.activity == Some("connected") {
            sqlx::query("UPDATE filebelt_document.participants SET state='active',disconnected_until=NULL,closed_at=NULL,close_reason=NULL,last_activity_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state IN ('active','disconnected')")
                .bind(input.tenant_id).bind(input.participant_id).execute(&mut *transaction).await?;
            sqlx::query("UPDATE filebelt_document.sessions SET state='active',fencing_token=fencing_token+1,reconnect_until=LEAST(absolute_expires_at,clock_timestamp()+interval '100 seconds'),closed_at=NULL,close_reason=NULL WHERE tenant_id=$1 AND id=$2 AND state IN ('active','draining') AND (state='active' OR reconnect_until>clock_timestamp())")
                .bind(input.tenant_id).bind(input.document_session_id).execute(&mut *transaction).await?;
        } else if input.activity == Some("disconnected")
            || input.callback_kind == "closed_no_changes"
        {
            sqlx::query("UPDATE filebelt_document.participants SET state='disconnected',disconnected_until=clock_timestamp()+interval '100 seconds',last_activity_at=clock_timestamp(),close_reason='provider_disconnected' WHERE tenant_id=$1 AND id=$2 AND state IN ('active','disconnected')")
                .bind(input.tenant_id).bind(input.participant_id).execute(&mut *transaction).await?;
            sqlx::query("UPDATE filebelt_document.sessions s SET state='draining',fencing_token=fencing_token+1,reconnect_until=LEAST(s.absolute_expires_at,clock_timestamp()+interval '100 seconds'),close_reason='provider_reconnect_pending' WHERE tenant_id=$1 AND id=$2 AND state='active' AND NOT EXISTS (SELECT 1 FROM filebelt_document.participants p WHERE p.tenant_id=s.tenant_id AND p.document_session_id=s.id AND p.state='active')")
                .bind(input.tenant_id).bind(input.document_session_id).execute(&mut *transaction).await?;
        } else {
            sqlx::query("UPDATE filebelt_document.participants SET last_activity_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='active'")
                .bind(input.tenant_id).bind(input.participant_id).execute(&mut *transaction).await?;
        }
        if input.callback_kind != "output_required" {
            transaction.commit().await?;
            return Ok(ReceivedDocumentCallback {
                event_id,
                revision: None,
            });
        }
        let media_type: String = participant.get("media_type");
        let revision_id = Uuid::new_v4();
        let row = sqlx::query("INSERT INTO filebelt_document.revisions (tenant_id,id,document_session_id,actor_participant_id,provider_event_digest,kind,state,expected_head_version_id,media_type) VALUES ($1,$2,$3,$4,$5,$6,'received',$7,$8) ON CONFLICT (tenant_id,document_session_id,provider_event_digest) DO UPDATE SET id=filebelt_document.revisions.id WHERE filebelt_document.revisions.actor_participant_id=EXCLUDED.actor_participant_id AND filebelt_document.revisions.kind=EXCLUDED.kind AND filebelt_document.revisions.media_type=EXCLUDED.media_type RETURNING id,document_session_id,actor_participant_id,provider_event_digest,kind,media_type,state")
            .bind(input.tenant_id).bind(revision_id).bind(input.document_session_id).bind(input.participant_id).bind(input.provider_event_digest.as_slice()).bind(input.revision_kind).bind(participant.get::<Uuid,_>("expected_head_version_id")).bind(&media_type).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        transaction.commit().await?;
        Ok(ReceivedDocumentCallback {
            event_id,
            revision: Some(ReceivedDocumentRevision {
                id: row.get("id"),
                document_session_id: row.get("document_session_id"),
                participant_id: row.get("actor_participant_id"),
                provider_event_digest: row.get("provider_event_digest"),
                kind: row.get("kind"),
                media_type: row.get("media_type"),
                state: row.get("state"),
            }),
        })
    }

    async fn received_document_revision_by_digest(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &ReceiveDocumentCallbackInput<'_>,
    ) -> Result<ReceivedDocumentRevision, DatabaseError> {
        let row = sqlx::query("SELECT id,document_session_id,actor_participant_id,provider_event_digest,kind,media_type,state FROM filebelt_document.revisions WHERE tenant_id=$1 AND document_session_id=$2 AND provider_event_digest=$3")
            .bind(input.tenant_id).bind(input.document_session_id).bind(input.provider_event_digest.as_slice()).fetch_optional(&mut **transaction).await?.ok_or(DatabaseError::Conflict)?;
        let revision = ReceivedDocumentRevision {
            id: row.get("id"),
            document_session_id: row.get("document_session_id"),
            participant_id: row.get("actor_participant_id"),
            provider_event_digest: row.get("provider_event_digest"),
            kind: row.get("kind"),
            media_type: row.get("media_type"),
            state: row.get("state"),
        };
        if input.revision_kind != Some(revision.kind.as_str()) {
            return Err(DatabaseError::Conflict);
        }
        Ok(revision)
    }

    pub async fn received_document_revision(
        &self,
        tenant_id: Uuid,
        revision_id: Uuid,
    ) -> Result<ReceivedDocumentRevision, DatabaseError> {
        let row=sqlx::query("SELECT id,document_session_id,actor_participant_id,provider_event_digest,kind,media_type,state FROM filebelt_document.revisions WHERE tenant_id=$1 AND id=$2") .bind(tenant_id).bind(revision_id).fetch_optional(self.pool()).await?.ok_or(DatabaseError::NotFound)?;
        Ok(ReceivedDocumentRevision {
            id: row.get("id"),
            document_session_id: row.get("document_session_id"),
            participant_id: row.get("actor_participant_id"),
            provider_event_digest: row.get("provider_event_digest"),
            kind: row.get("kind"),
            media_type: row.get("media_type"),
            state: row.get("state"),
        })
    }
    pub async fn create_document_session(
        &self,
        input: &CreateDocumentSessionInput<'_>,
    ) -> Result<DocumentLaunchRecord, DatabaseError> {
        if input.provider_id.is_empty()
            || input.provider_id.len() > 64
            || !matches!(input.mode, "view" | "edit" | "comment" | "review")
            || !(1..=DOCUMENT_MAX_ACTIVE_PARTICIPANTS).contains(&input.maximum_active_participants)
            || !(1..=DOCUMENT_MAX_BYTES).contains(&input.maximum_document_bytes)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = document_operation_replay::<DocumentLaunchRecord>(
            &mut transaction,
            input.tenant_id,
            input.operation_digest,
            input.request_fingerprint,
            "create_session",
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(replay);
        }
        lock_authorization_fence(
            &mut transaction,
            input.tenant_id,
            input.actor_principal_id,
            input.api_session_id,
            input.drive_id,
            input.node_id,
            input.generations.as_array(),
        )
        .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:{}", input.tenant_id, input.provider_id))
            .execute(&mut *transaction)
            .await?;
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM filebelt_document.participants p \
             JOIN filebelt_document.sessions s ON s.tenant_id=p.tenant_id \
               AND s.id=p.document_session_id \
             WHERE p.tenant_id=$1 AND s.provider_id=$2 \
               AND (p.state='active' OR (p.state='disconnected' AND p.disconnected_until>clock_timestamp())) \
               AND (s.state='active' OR (s.state='draining' AND s.reconnect_until>clock_timestamp())) \
               AND s.absolute_expires_at>clock_timestamp()",
        )
        .bind(input.tenant_id)
        .bind(input.provider_id)
        .fetch_one(&mut *transaction)
        .await?;
        if active >= input.maximum_active_participants {
            return Err(DatabaseError::AdmissionLimited);
        }
        let head: Option<Uuid> = sqlx::query_scalar(
            "SELECT head_version_id FROM nodes WHERE tenant_id=$1 AND drive_id=$2 \
             AND id=$3 AND kind='file' AND trash_root_id IS NULL FOR SHARE",
        )
        .bind(input.tenant_id)
        .bind(input.drive_id)
        .bind(input.node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .flatten();
        let Some(head) = head else {
            return Err(DatabaseError::NotFound);
        };
        if head != input.base_version_id {
            return Err(DatabaseError::Conflict);
        }
        let base = sqlx::query("SELECT size_bytes,media_type FROM file_versions WHERE tenant_id=$1 AND node_id=$2 AND id=$3")
            .bind(input.tenant_id).bind(input.node_id).bind(input.base_version_id)
            .fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?;
        let size_bytes: i64 = base.get("size_bytes");
        let media_type: Option<String> = base.get("media_type");
        if size_bytes > input.maximum_document_bytes
            || !matches!(
                media_type.as_deref(),
                Some(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                )
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query(
            "UPDATE filebelt_document.sessions SET state='expired',fencing_token=fencing_token+1,\
             closed_at=clock_timestamp(),close_reason='reconnect_deadline_elapsed' \
             WHERE tenant_id=$1 AND provider_id=$2 AND node_id=$3 AND base_version_id=$4 \
               AND state='draining' AND reconnect_until<=clock_timestamp()",
        )
        .bind(input.tenant_id)
        .bind(input.provider_id)
        .bind(input.node_id)
        .bind(input.base_version_id)
        .execute(&mut *transaction)
        .await?;
        let session_row = sqlx::query(
            "SELECT id,session_principal_id,drive_id,node_id,base_version_id,\
             expected_head_version_id,provider_id,state,fencing_token,created_at::text,\
             absolute_expires_at::text,reconnect_until::text,close_reason \
             FROM filebelt_document.sessions WHERE tenant_id=$1 AND provider_id=$2 \
               AND node_id=$3 AND base_version_id=$4 AND state IN ('active','draining') \
             FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(input.provider_id)
        .bind(input.node_id)
        .bind(input.base_version_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let session = if let Some(row) = session_row {
            let session = document_session_from_row(&row);
            if session.state == "draining" {
                return Err(DatabaseError::Conflict);
            }
            session
        } else {
            let session_id = Uuid::new_v4();
            let session_principal_id = Uuid::new_v4();
            sqlx::query("SELECT filebelt_document.create_session_principal($1,$2)")
                .bind(input.tenant_id)
                .bind(session_principal_id)
                .execute(&mut *transaction)
                .await?;
            let row = sqlx::query(
                "INSERT INTO filebelt_document.sessions \
                 (tenant_id,id,session_principal_id,drive_id,node_id,provider_id,\
                  base_version_id,expected_head_version_id,created_by) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8) \
                 RETURNING id,session_principal_id,drive_id,node_id,base_version_id,\
                 expected_head_version_id,provider_id,state,fencing_token,created_at::text,\
                 (extract(epoch FROM created_at)*1000000)::bigint AS created_at_unix_microseconds,\
                 absolute_expires_at::text,reconnect_until::text,closed_at::text,close_reason",
            )
            .bind(input.tenant_id)
            .bind(session_id)
            .bind(session_principal_id)
            .bind(input.drive_id)
            .bind(input.node_id)
            .bind(input.provider_id)
            .bind(input.base_version_id)
            .bind(input.actor_principal_id)
            .fetch_one(&mut *transaction)
            .await?;
            document_session_from_row(&row)
        };
        let participant_id = Uuid::new_v4();
        let participant_row = sqlx::query(
            "INSERT INTO filebelt_document.participants \
             (tenant_id,id,document_session_id,user_principal_id,api_session_id,mode,\
              membership_generation,drive_acl_generation,namespace_generation,\
              resource_acl_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
             RETURNING id,document_session_id,user_principal_id,api_session_id,mode,state,\
               created_at::text AS participant_created_at,last_activity_at::text,disconnected_until::text,membership_generation,\
               drive_acl_generation,namespace_generation,resource_acl_generation",
        )
        .bind(input.tenant_id)
        .bind(participant_id)
        .bind(session.id)
        .bind(input.actor_principal_id)
        .bind(input.api_session_id)
        .bind(input.mode)
        .bind(input.generations.membership)
        .bind(input.generations.drive_acl)
        .bind(input.generations.namespace)
        .bind(input.generations.resource_acl)
        .fetch_one(&mut *transaction)
        .await?;
        let display_name: String = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(input.tenant_id)
        .bind(input.actor_principal_id)
        .fetch_one(&mut *transaction)
        .await?;
        let participant = document_participant_from_row(&participant_row, display_name);
        insert_audit(
            &mut transaction,
            input.tenant_id,
            Some(input.actor_principal_id),
            Some(session.session_principal_id),
            Some(input.node_id),
            "document.session.create",
            "allowed",
            "document_session_created",
            true,
            json!({"mode":input.mode,"provider_id":input.provider_id}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            input.tenant_id,
            "filebelt.v1.document.session.changed",
            "document_session",
            session.id,
            session.fencing_token,
        )
        .await?;
        let expires_at = session.absolute_expires_at.clone();
        let launch = DocumentLaunchRecord {
            grant_id: Uuid::nil(),
            participant,
            session,
            expires_at,
        };
        document_operation_record(
            &mut transaction,
            input.tenant_id,
            input.operation_digest,
            input.request_fingerprint,
            "create_session",
            &launch,
        )
        .await?;
        transaction.commit().await?;
        Ok(launch)
    }

    /// Issues a fresh opaque handoff token after rechecking the participant's
    /// active API session. Only its BLAKE3 digest is persisted.
    pub async fn issue_document_launch_grant(
        &self,
        tenant_id: Uuid,
        document_session_id: Uuid,
        actor_principal_id: Uuid,
        api_session_id: Uuid,
        token_digest: &[u8; 32],
    ) -> Result<i64, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let participant_id: Uuid = sqlx::query_scalar(
            "SELECT p.id FROM filebelt_document.participants p \
             JOIN filebelt_document.sessions s ON s.tenant_id=p.tenant_id \
               AND s.id=p.document_session_id WHERE p.tenant_id=$1 \
               AND p.document_session_id=$2 AND p.user_principal_id=$3 \
               AND p.api_session_id=$4 AND p.state='active' AND s.state='active' \
               AND s.absolute_expires_at>clock_timestamp() FOR UPDATE OF p,s",
        )
        .bind(tenant_id)
        .bind(document_session_id)
        .bind(actor_principal_id)
        .bind(api_session_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let consumed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_document.launch_grants \
             WHERE tenant_id=$1 AND participant_id=$2 AND consumed_at IS NOT NULL)",
        )
        .bind(tenant_id)
        .bind(participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        if consumed {
            return Err(DatabaseError::Conflict);
        }
        // A response loss before redemption remains recoverable: replace only
        // an unconsumed grant while the participant row lock serializes
        // concurrent handoff requests. Once consumed, this tab participant has
        // spent its one provider-launch lifetime.
        sqlx::query(
            "DELETE FROM filebelt_document.launch_grants WHERE tenant_id=$1 \
             AND participant_id=$2 AND consumed_at IS NULL",
        )
        .bind(tenant_id)
        .bind(participant_id)
        .execute(&mut *transaction)
        .await?;
        let expires_at: i64 = sqlx::query_scalar(
            "INSERT INTO filebelt_document.launch_grants \
             (tenant_id,id,participant_id,token_digest,expires_at) \
             VALUES ($1,$2,$3,$4,clock_timestamp()+interval '60 seconds') \
             RETURNING EXTRACT(EPOCH FROM expires_at)::bigint",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(participant_id)
        .bind(token_digest.as_slice())
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(expires_at)
    }

    pub async fn consume_document_launch_grant(
        &self,
        tenant_id: Uuid,
        token_digest: &[u8; 32],
    ) -> Result<DocumentLaunchRecord, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_document.launch_grants g SET consumed_at=clock_timestamp() \
             FROM filebelt_document.participants p,filebelt_document.sessions s,users u \
             WHERE g.tenant_id=$1 AND g.token_digest=$2 AND g.consumed_at IS NULL \
               AND g.expires_at>clock_timestamp() AND p.tenant_id=g.tenant_id \
               AND p.id=g.participant_id AND p.state='active' \
               AND s.tenant_id=p.tenant_id AND s.id=p.document_session_id \
               AND s.state='active' AND s.absolute_expires_at>clock_timestamp() \
               AND u.tenant_id=p.tenant_id AND u.principal_id=p.user_principal_id \
             RETURNING g.id AS grant_id,g.expires_at::text AS grant_expires_at,\
               p.id AS participant_id,p.document_session_id,p.user_principal_id,\
               p.api_session_id,p.mode,p.state AS participant_state,p.created_at::text AS participant_created_at,p.last_activity_at::text,\
               p.disconnected_until::text,p.membership_generation,p.drive_acl_generation,\
               p.namespace_generation,p.resource_acl_generation,u.display_name,\
               s.id,s.session_principal_id,s.drive_id,s.node_id,s.base_version_id,\
               s.expected_head_version_id,s.provider_id,s.state,s.fencing_token,\
               s.created_at::text,(extract(epoch FROM s.created_at)*1000000)::bigint AS created_at_unix_microseconds,\
               s.absolute_expires_at::text,s.reconnect_until::text,s.closed_at::text,\
             s.close_reason,NULL::uuid AS conflict_head_version_id",
        )
        .bind(tenant_id)
        .bind(token_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let result = DocumentLaunchRecord {
            grant_id: row.get("grant_id"),
            expires_at: row.get("grant_expires_at"),
            participant: DocumentParticipantRecord {
                id: row.get("participant_id"),
                document_session_id: row.get("document_session_id"),
                user_principal_id: row.get("user_principal_id"),
                api_session_id: row.get("api_session_id"),
                mode: row.get("mode"),
                state: row.get("participant_state"),
                display_name: row.get("display_name"),
                created_at: row.try_get("participant_created_at").unwrap_or_default(),
                last_activity_at: row.get("last_activity_at"),
                disconnected_until: row.get("disconnected_until"),
                generations: document_generations_from_row(&row),
            },
            session: document_session_from_row(&row),
        };
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn list_document_sessions_for_principal(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        limit: u32,
        anchor: Option<DocumentSessionPageAnchor>,
    ) -> Result<DocumentSessionPageRecord, DatabaseError> {
        let limit = page_limit(limit)?;
        let rows = sqlx::query(
            "WITH selected AS (\
               SELECT s.id,s.created_at FROM filebelt_document.sessions s \
               JOIN filebelt_document.participants owner ON owner.tenant_id=s.tenant_id \
                 AND owner.document_session_id=s.id AND owner.user_principal_id=$2 \
               WHERE s.tenant_id=$1 AND ($3::bigint IS NULL OR (s.created_at,s.id)<(timestamptz 'epoch' + $3::bigint * interval '1 microsecond',$4)) \
               ORDER BY s.created_at DESC,s.id DESC LIMIT $5\
             ) SELECT NULL::uuid AS grant_id,s.absolute_expires_at::text AS grant_expires_at,\
               p.id AS participant_id,p.document_session_id,p.user_principal_id,\
               p.api_session_id,p.mode,p.state AS participant_state,p.created_at::text AS participant_created_at,p.last_activity_at::text,\
               p.disconnected_until::text,p.membership_generation,p.drive_acl_generation,\
               p.namespace_generation,p.resource_acl_generation,u.display_name,\
               s.id,s.session_principal_id,s.drive_id,s.node_id,s.base_version_id,\
               s.expected_head_version_id,s.provider_id,s.state,s.fencing_token,\
               s.created_at::text,(extract(epoch FROM s.created_at)*1000000)::bigint AS created_at_unix_microseconds,\
               s.absolute_expires_at::text,s.reconnect_until::text,s.closed_at::text,s.close_reason,\
               CASE WHEN s.state='conflict' THEN n.head_version_id ELSE NULL END AS conflict_head_version_id \
             FROM selected x JOIN filebelt_document.sessions s ON s.id=x.id \
             JOIN filebelt_document.participants p ON s.tenant_id=p.tenant_id AND s.id=p.document_session_id \
             JOIN nodes n ON n.tenant_id=s.tenant_id AND n.drive_id=s.drive_id AND n.id=s.node_id \
             JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.user_principal_id \
             ORDER BY s.created_at DESC,s.id DESC,p.created_at ASC",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(anchor.as_ref().map(|value| value.created_at_unix_microseconds))
        .bind(anchor.map(|value| value.session_id))
        .bind(i64::try_from(limit).map_err(|_| DatabaseError::InvalidPersistedValue)? + 1)
        .fetch_all(self.pool())
        .await?;
        document_session_page_from_rows(rows, limit)
    }

    /// Returns node-wide participant projections only after taking the exact
    /// API-session authorization-generation share lock. This keeps the
    /// manager-list response in the same revocation fence as its admission.
    pub async fn list_document_sessions_for_node(
        &self,
        input: &ListDocumentSessionsForNodeInput,
    ) -> Result<DocumentSessionPageRecord, DatabaseError> {
        let limit = page_limit(input.limit)?;
        let mut transaction = self.pool().begin().await?;
        lock_authorization_fence(
            &mut transaction,
            input.tenant_id,
            input.actor_principal_id,
            input.api_session_id,
            input.drive_id,
            input.node_id,
            input.generations.as_array(),
        )
        .await?;
        let rows = sqlx::query(
            "WITH selected AS (\
               SELECT s.id,s.created_at FROM filebelt_document.sessions s \
               WHERE s.tenant_id=$1 AND s.drive_id=$2 AND s.node_id=$3 \
                 AND ($4::bigint IS NULL OR (s.created_at,s.id)<(timestamptz 'epoch' + $4::bigint * interval '1 microsecond',$5)) \
               ORDER BY s.created_at DESC,s.id DESC LIMIT $6\
             ) SELECT NULL::uuid AS grant_id,s.absolute_expires_at::text AS grant_expires_at,\
               p.id AS participant_id,p.document_session_id,p.user_principal_id,p.api_session_id,\
               p.mode,p.state AS participant_state,p.created_at::text AS participant_created_at,p.last_activity_at::text,p.disconnected_until::text,\
               p.membership_generation,p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation,\
               u.display_name,s.id,s.session_principal_id,s.drive_id,s.node_id,s.base_version_id,\
               s.expected_head_version_id,s.provider_id,s.state,s.fencing_token,s.created_at::text,\
               (extract(epoch FROM s.created_at)*1000000)::bigint AS created_at_unix_microseconds,\
               s.absolute_expires_at::text,s.reconnect_until::text,s.closed_at::text,s.close_reason,\
               CASE WHEN s.state='conflict' THEN n.head_version_id ELSE NULL END AS conflict_head_version_id \
             FROM selected x JOIN filebelt_document.sessions s ON s.id=x.id \
             JOIN filebelt_document.participants p ON s.tenant_id=p.tenant_id AND s.id=p.document_session_id \
             JOIN nodes n ON n.tenant_id=s.tenant_id AND n.drive_id=s.drive_id AND n.id=s.node_id \
             JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.user_principal_id \
             ORDER BY s.created_at DESC,s.id DESC,p.created_at ASC",
        )
        .bind(input.tenant_id)
        .bind(input.drive_id)
        .bind(input.node_id)
        .bind(
            input
                .anchor
                .as_ref()
                .map(|value| value.created_at_unix_microseconds),
        )
        .bind(input.anchor.as_ref().map(|value| value.session_id))
        .bind(i64::try_from(limit).map_err(|_| DatabaseError::InvalidPersistedValue)? + 1)
        .fetch_all(&mut *transaction)
        .await?;
        let page = document_session_page_from_rows(rows, limit)?;
        transaction.commit().await?;
        Ok(page)
    }

    /// Fetches one exact owned session and every durable participant. This is
    /// deliberately separate from cursor paging so old owned sessions remain
    /// addressable after they fall behind the first list page.
    pub async fn document_session_for_principal(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
    ) -> Result<Vec<DocumentLaunchRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT NULL::uuid AS grant_id,s.absolute_expires_at::text AS grant_expires_at,\
               p.id AS participant_id,p.document_session_id,p.user_principal_id,p.api_session_id,\
               p.mode,p.state AS participant_state,p.created_at::text AS participant_created_at,\
               p.last_activity_at::text,p.disconnected_until::text,p.membership_generation,\
               p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation,u.display_name,\
               s.id,s.session_principal_id,s.drive_id,s.node_id,s.base_version_id,s.expected_head_version_id,\
               s.provider_id,s.state,s.fencing_token,s.created_at::text,\
               (extract(epoch FROM s.created_at)*1000000)::bigint AS created_at_unix_microseconds,\
               s.absolute_expires_at::text,s.reconnect_until::text,s.closed_at::text,s.close_reason,\
               CASE WHEN s.state='conflict' THEN n.head_version_id ELSE NULL END AS conflict_head_version_id \
             FROM filebelt_document.sessions s JOIN filebelt_document.participants p \
               ON p.tenant_id=s.tenant_id AND p.document_session_id=s.id \
             JOIN nodes n ON n.tenant_id=s.tenant_id AND n.drive_id=s.drive_id AND n.id=s.node_id \
             JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.user_principal_id \
             WHERE s.tenant_id=$1 AND s.id=$2 AND EXISTS (SELECT 1 FROM filebelt_document.participants owner \
               WHERE owner.tenant_id=s.tenant_id AND owner.document_session_id=s.id AND owner.user_principal_id=$3) \
             ORDER BY p.created_at ASC",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        if rows.is_empty() {
            return Err(DatabaseError::NotFound);
        }
        Ok(document_session_page_from_rows(rows, 1)?.launches)
    }

    pub async fn revoke_document_participant(
        &self,
        tenant_id: Uuid,
        participant_id: Uuid,
        actor_principal_id: Uuid,
        reason: &str,
    ) -> Result<bool, DatabaseError> {
        if reason.is_empty() || reason.len() > 96 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_document.participants SET state='revoked',closed_at=clock_timestamp(),\
             close_reason=$4 WHERE tenant_id=$1 AND id=$2 AND user_principal_id=$3 \
             AND state IN ('active','disconnected') RETURNING document_session_id",
        )
        .bind(tenant_id)
        .bind(participant_id)
        .bind(actor_principal_id)
        .bind(reason)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(false);
        };
        let session_id: Uuid = row.get("document_session_id");
        sqlx::query(
            "UPDATE filebelt_document.sessions s SET state='revoked',\
             fencing_token=fencing_token+1,closed_at=clock_timestamp(),close_reason=$3 \
             WHERE tenant_id=$1 AND id=$2 AND state IN ('active','draining') AND NOT EXISTS (\
               SELECT 1 FROM filebelt_document.participants p WHERE p.tenant_id=s.tenant_id \
                 AND p.document_session_id=s.id AND p.state IN ('active','disconnected'))",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(reason)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            None,
            "document.participant.revoke",
            "allowed",
            reason,
            true,
            json!({"participant_id":participant_id,"document_session_id":session_id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    /// Force-closes a session after the API has independently authorized the
    /// actor. Closing increments the session fence so every outstanding
    /// document I/O capability becomes unusable before payload access.
    pub async fn force_close_document_session(
        &self,
        input: &ForceCloseDocumentSessionInput<'_>,
    ) -> Result<bool, DatabaseError> {
        if input.reason.is_empty() || input.reason.len() > 96 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let stored = sqlx::query(
            "SELECT drive_id,node_id FROM filebelt_document.sessions WHERE tenant_id=$1 AND id=$2 \
             AND state IN ('active','draining') FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(input.session_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if stored.get::<Uuid, _>("drive_id") != input.drive_id
            || stored.get::<Uuid, _>("node_id") != input.node_id
        {
            return Err(DatabaseError::StaleGeneration);
        }
        lock_authorization_fence(
            &mut transaction,
            input.tenant_id,
            input.actor_principal_id,
            input.api_session_id,
            input.drive_id,
            input.node_id,
            input.generations.as_array(),
        )
        .await?;
        let row = sqlx::query(
            "UPDATE filebelt_document.sessions SET state='revoked',fencing_token=fencing_token+1,\
             closed_at=clock_timestamp(),close_reason=$3 WHERE tenant_id=$1 AND id=$2 \
             AND state IN ('active','draining') RETURNING id",
        )
        .bind(input.tenant_id)
        .bind(input.session_id)
        .bind(input.reason)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(_) = row else {
            transaction.commit().await?;
            return Ok(false);
        };
        sqlx::query(
            "UPDATE filebelt_document.participants SET state='closed',closed_at=clock_timestamp(),\
             close_reason=$3 WHERE tenant_id=$1 AND document_session_id=$2 \
             AND state IN ('active','disconnected')",
        )
        .bind(input.tenant_id)
        .bind(input.session_id)
        .bind(input.reason)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            input.tenant_id,
            Some(input.actor_principal_id),
            None,
            None,
            "document.session.force_close",
            "allowed",
            input.reason,
            true,
            json!({"document_session_id":input.session_id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_document_conflict_copy(
        &self,
        tenant_id: Uuid,
        document_session_id: Uuid,
        actor_principal_id: Uuid,
        api_session_id: Uuid,
        target_parent_id: Uuid,
        expected_parent_namespace_generation: i64,
        generations: DocumentAuthorizationGenerations,
        display_name: &str,
        operation_digest: &[u8; 32],
        request_fingerprint: &[u8; 32],
    ) -> Result<DocumentConflictCopyRecord, DatabaseError> {
        let normalized = filebelt_domain::NormalizedName::new(display_name)
            .map_err(|_| DatabaseError::InvalidPersistedValue)?;
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = document_operation_replay::<DocumentConflictCopyRecord>(
            &mut transaction,
            tenant_id,
            operation_digest,
            request_fingerprint,
            "conflict_copy",
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(replay);
        }
        let revision = sqlx::query(
            "SELECT r.id,r.payload_id,r.size_bytes,r.blake3,r.media_type,r.reserved_bytes,\
             s.drive_id,s.node_id FROM filebelt_document.revisions r \
             JOIN filebelt_document.sessions s ON s.tenant_id=r.tenant_id AND s.id=r.document_session_id \
             WHERE r.tenant_id=$1 AND r.document_session_id=$2 AND s.created_by=$3 \
               AND r.state='conflict' AND r.payload_id IS NOT NULL \
               AND r.retained_until>clock_timestamp() ORDER BY r.finished_at DESC,r.id DESC \
             FOR UPDATE OF r,s LIMIT 1",
        ).bind(tenant_id).bind(document_session_id).bind(actor_principal_id)
            .fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?;
        let drive_id: Uuid = revision.get("drive_id");
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            api_session_id,
            drive_id,
            target_parent_id,
            generations.as_array(),
        )
        .await?;
        let parent = sqlx::query("SELECT namespace_generation FROM nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 AND kind='directory' AND trash_root_id IS NULL FOR UPDATE")
            .bind(tenant_id).bind(drive_id).bind(target_parent_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::NotFound)?;
        if parent.get::<i64, _>("namespace_generation") != expected_parent_namespace_generation {
            return Err(DatabaseError::StaleGeneration);
        }
        let payload_id: Uuid = revision.get("payload_id");
        let size_bytes: i64 = revision.get("size_bytes");
        let blake3: Vec<u8> = revision.get("blake3");
        let media_type: String = revision.get("media_type");
        let reserved_bytes: i64 = revision.get("reserved_bytes");
        let node_id = Uuid::new_v4();
        sqlx::query("INSERT INTO nodes (tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) VALUES ($1,$2,$3,$4,'file',$5,$6,$7)")
            .bind(tenant_id).bind(drive_id).bind(node_id).bind(target_parent_id)
            .bind(normalized.display()).bind(normalized.comparison_key()).bind(actor_principal_id)
            .execute(&mut *transaction).await.map_err(map_conflict)?;
        sqlx::query("INSERT INTO node_ancestry (tenant_id,drive_id,ancestor_id,descendant_id,depth) SELECT tenant_id,drive_id,ancestor_id,$4,depth+1 FROM node_ancestry WHERE tenant_id=$1 AND drive_id=$2 AND descendant_id=$3 UNION ALL SELECT $1,$2,$4,$4,0")
            .bind(tenant_id).bind(drive_id).bind(target_parent_id).bind(node_id).execute(&mut *transaction).await?;
        let version_id = Uuid::new_v4();
        sqlx::query("INSERT INTO file_versions (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,created_by,origin_kind) VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,'external_document')")
            .bind(tenant_id).bind(node_id).bind(version_id).bind(payload_id).bind(size_bytes).bind(&blake3).bind(&media_type).bind(actor_principal_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE nodes SET head_version_id=$4,updated_at=clock_timestamp() WHERE tenant_id=$1 AND drive_id=$2 AND id=$3")
            .bind(tenant_id).bind(drive_id).bind(node_id).bind(version_id).execute(&mut *transaction).await?;
        let payload_changed = sqlx::query("UPDATE payload_objects SET state='referenced',referenced_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='finalized'")
            .bind(tenant_id).bind(payload_id).execute(&mut *transaction).await?.rows_affected();
        if payload_changed != 1 {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query("UPDATE drives SET reserved_bytes=reserved_bytes-$3,used_physical_bytes=used_physical_bytes+$4 WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id).bind(drive_id).bind(reserved_bytes).bind(size_bytes).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(node_id),
            "document.conflict_copy.create",
            "allowed",
            "document_conflict_copy_created",
            true,
            json!({"document_session_id":document_session_id,"version_id":version_id}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.file.version.committed",
            "node",
            node_id,
            1,
        )
        .await?;
        let copy = DocumentConflictCopyRecord {
            drive_id,
            node_id,
            version_id,
            display_name: normalized.display().to_owned(),
            media_type,
            size_bytes,
            blake3,
        };
        document_operation_record(
            &mut transaction,
            tenant_id,
            operation_digest,
            request_fingerprint,
            "conflict_copy",
            &copy,
        )
        .await?;
        transaction.commit().await?;
        Ok(copy)
    }

    /// Returns the opaque payload identifiers and authorization projection
    /// needed to mint exact document I/O capabilities. Physical locators stay
    /// in PostgreSQL and are resolved only by the I/O worker.
    pub async fn document_revision_io_context(
        &self,
        tenant_id: Uuid,
        revision_id: Uuid,
    ) -> Result<DocumentIoContext, DatabaseError> {
        let row = sqlx::query(
            "SELECT r.id,r.document_session_id,r.actor_participant_id,r.kind,r.state,\
             r.expected_head_version_id,r.payload_id,r.reserved_bytes,r.size_bytes,r.blake3,\
             r.media_type,r.committed_version_id,r.retained_until::text,\
             s.id AS session_id,s.session_principal_id,s.drive_id,s.node_id,s.base_version_id,\
             s.expected_head_version_id AS session_expected_head_version_id,s.provider_id,\
             s.state AS session_state,s.fencing_token,s.created_at::text AS session_created_at,\
             s.absolute_expires_at::text AS session_absolute_expires_at,\
             s.reconnect_until::text AS session_reconnect_until,s.close_reason AS session_close_reason,\
             p.id AS participant_id,p.document_session_id AS participant_document_session_id,\
             p.user_principal_id,p.api_session_id,p.mode,p.state AS participant_state,\
             p.last_activity_at::text,p.disconnected_until::text,p.membership_generation,\
             p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation,\
             b.payload_id AS base_payload_id,b.size_bytes AS base_size_bytes \
             FROM filebelt_document.revisions r \
             JOIN filebelt_document.sessions s ON s.tenant_id=r.tenant_id AND s.id=r.document_session_id \
             JOIN filebelt_document.participants p ON p.tenant_id=r.tenant_id AND p.id=r.actor_participant_id \
             JOIN file_versions b ON b.tenant_id=s.tenant_id AND b.node_id=s.node_id AND b.id=s.base_version_id \
             WHERE r.tenant_id=$1 AND r.id=$2",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let revision = document_revision_from_row(&row);
        let session = DocumentSessionRecord {
            id: row.get("session_id"),
            session_principal_id: row.get("session_principal_id"),
            drive_id: row.get("drive_id"),
            node_id: row.get("node_id"),
            base_version_id: row.get("base_version_id"),
            expected_head_version_id: row.get("session_expected_head_version_id"),
            provider_id: row.get("provider_id"),
            state: row.get("session_state"),
            fencing_token: row.get("fencing_token"),
            created_at: row.get("session_created_at"),
            created_at_unix_microseconds: 0,
            absolute_expires_at: row.get("session_absolute_expires_at"),
            reconnect_until: row.get("session_reconnect_until"),
            closed_at: None,
            close_reason: row.get("session_close_reason"),
            conflict_head_version_id: None,
        };
        let participant = DocumentParticipantRecord {
            id: row.get("participant_id"),
            document_session_id: row.get("participant_document_session_id"),
            user_principal_id: row.get("user_principal_id"),
            api_session_id: row.get("api_session_id"),
            mode: row.get("mode"),
            state: row.get("participant_state"),
            // This internal I/O projection never leaves the process boundary;
            // omit browser-facing identity data so the worker need not read it.
            display_name: String::new(),
            created_at: String::new(),
            last_activity_at: row.get("last_activity_at"),
            disconnected_until: row.get("disconnected_until"),
            generations: document_generations_from_row(&row),
        };
        Ok(DocumentIoContext {
            session,
            participant,
            revision,
            base_payload_id: row.get("base_payload_id"),
            base_size_bytes: row.get("base_size_bytes"),
        })
    }

    pub async fn document_launch_io_context(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        participant_id: Uuid,
    ) -> Result<DocumentLaunchIoContext, DatabaseError> {
        let row = sqlx::query(
            "SELECT s.id,s.session_principal_id,s.drive_id,s.node_id,s.base_version_id,\
             s.expected_head_version_id,s.provider_id,s.state,s.fencing_token,s.created_at::text,\
             s.absolute_expires_at::text,s.reconnect_until::text,s.close_reason,\
             p.id AS participant_id,p.document_session_id,p.user_principal_id,p.api_session_id,\
             p.mode,p.state AS participant_state,p.last_activity_at::text,p.disconnected_until::text,\
             p.membership_generation,p.drive_acl_generation,p.namespace_generation,\
             p.resource_acl_generation,u.display_name,b.payload_id AS base_payload_id,\
             b.size_bytes AS base_size_bytes,b.media_type AS base_media_type,n.display_name AS source_display_name FROM filebelt_document.sessions s \
             JOIN filebelt_document.participants p ON p.tenant_id=s.tenant_id \
               AND p.document_session_id=s.id \
             JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.user_principal_id \
             JOIN nodes n ON n.tenant_id=s.tenant_id AND n.drive_id=s.drive_id AND n.id=s.node_id \
             JOIN file_versions b ON b.tenant_id=s.tenant_id AND b.node_id=s.node_id \
               AND b.id=s.base_version_id WHERE s.tenant_id=$1 AND s.id=$2 AND p.id=$3 \
               AND s.state='active' AND p.state='active' AND s.absolute_expires_at>clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(participant_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(DocumentLaunchIoContext {
            session: document_session_from_row(&row),
            participant: document_participant_from_row(&row, row.get("display_name")),
            base_payload_id: row.get("base_payload_id"),
            base_size_bytes: row.get("base_size_bytes"),
            base_media_type: row.get("base_media_type"),
            source_display_name: row.get("source_display_name"),
        })
    }

    pub async fn begin_document_revision(
        &self,
        input: &BeginDocumentRevisionInput<'_>,
    ) -> Result<DocumentPayloadAllocation, DatabaseError> {
        if !matches!(input.kind, "checkpoint" | "user_save" | "final_save")
            || !(0..=DOCUMENT_MAX_BYTES).contains(&input.reserved_bytes)
            || !matches!(
                input.media_type,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let participant = sqlx::query(
            "SELECT p.user_principal_id,p.api_session_id,p.mode,p.membership_generation,\
             p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation,s.drive_id,s.node_id,\
             s.expected_head_version_id,s.session_principal_id,s.fencing_token \
             FROM filebelt_document.participants p \
             JOIN filebelt_document.sessions s ON s.tenant_id=p.tenant_id \
               AND s.id=p.document_session_id \
             WHERE p.tenant_id=$1 AND p.id=$2 AND p.document_session_id=$3 \
               AND p.state='active' AND s.state='active' \
               AND s.absolute_expires_at>clock_timestamp() FOR UPDATE OF p,s",
        )
        .bind(input.tenant_id)
        .bind(input.participant_id)
        .bind(input.document_session_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if !document_participant_can_write(&participant.get::<String, _>("mode")) {
            return Err(DatabaseError::Conflict);
        }
        let user_principal_id: Uuid = participant.get("user_principal_id");
        let api_session_id: Uuid = participant.get("api_session_id");
        let drive_id: Uuid = participant.get("drive_id");
        let node_id: Uuid = participant.get("node_id");
        lock_authorization_fence(
            &mut transaction,
            input.tenant_id,
            user_principal_id,
            api_session_id,
            drive_id,
            node_id,
            [
                participant.get("membership_generation"),
                participant.get("drive_acl_generation"),
                participant.get("namespace_generation"),
                participant.get("resource_acl_generation"),
            ],
        )
        .await?;
        let mut received_revision_id = None;
        if let Some(existing) = sqlx::query(
            "SELECT id,document_session_id,actor_participant_id,kind,state,\
             expected_head_version_id,payload_id,reserved_bytes,size_bytes,blake3,media_type,\
             committed_version_id,retained_until::text FROM filebelt_document.revisions \
             WHERE tenant_id=$1 AND document_session_id=$2 AND provider_event_digest=$3",
        )
        .bind(input.tenant_id)
        .bind(input.document_session_id)
        .bind(input.provider_event_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        {
            let revision = document_revision_from_row(&existing);
            if revision.state == "received" {
                received_revision_id = Some(revision.id);
            } else if revision.state == "staging" {
                let payload_id = revision.payload_id.ok_or(DatabaseError::Conflict)?;
                let payload = sqlx::query(
                    "SELECT backend_id,locator FROM payload_objects WHERE tenant_id=$1 AND id=$2",
                )
                .bind(input.tenant_id)
                .bind(payload_id)
                .fetch_one(&mut *transaction)
                .await?;
                transaction.commit().await?;
                return Ok(DocumentPayloadAllocation {
                    payload_id,
                    backend_id: payload.get("backend_id"),
                    locator: payload.get("locator"),
                    fencing_token: participant.get("fencing_token"),
                    revision,
                });
            } else {
                return Err(DatabaseError::Conflict);
            }
        }
        let drive = sqlx::query(
            "SELECT quota_bytes,used_physical_bytes,reserved_bytes FROM drives \
             WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .fetch_one(&mut *transaction)
        .await?;
        let quota: i64 = drive.get("quota_bytes");
        let used: i64 = drive.get("used_physical_bytes");
        let reserved: i64 = drive.get("reserved_bytes");
        if used
            .checked_add(reserved)
            .and_then(|total| total.checked_add(input.reserved_bytes))
            .is_none_or(|total| total > quota)
        {
            return Err(DatabaseError::QuotaExceeded);
        }
        let backend_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM storage_backends WHERE tenant_id=$1 AND kind='posix' \
             AND storage_ready=true AND capacity_checked_at>clock_timestamp()-interval '30 seconds'",
        )
        .bind(input.tenant_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StorageUnavailable)?;
        let revision_id = received_revision_id.unwrap_or_else(Uuid::new_v4);
        let payload_id = Uuid::new_v4();
        let locator = Uuid::new_v4();
        sqlx::query(
            "UPDATE drives SET reserved_bytes=reserved_bytes+$3 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(input.reserved_bytes)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO payload_objects \
             (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes) \
             VALUES ($1,$2,$3,$4,$5,'whole','staging',0)",
        )
        .bind(input.tenant_id)
        .bind(payload_id)
        .bind(drive_id)
        .bind(backend_id)
        .bind(locator)
        .execute(&mut *transaction)
        .await?;
        let row = if received_revision_id.is_some() {
            sqlx::query(
            "UPDATE filebelt_document.revisions SET state='staging',payload_id=$3,reserved_bytes=$4,media_type=$5 WHERE tenant_id=$1 AND id=$2 AND state='received' RETURNING id,document_session_id,actor_participant_id,kind,state,expected_head_version_id,payload_id,reserved_bytes,size_bytes,blake3,media_type,committed_version_id,retained_until::text"
        ).bind(input.tenant_id).bind(revision_id).bind(payload_id).bind(input.reserved_bytes).bind(input.media_type).fetch_one(&mut *transaction).await?
        } else {
            sqlx::query(
                "INSERT INTO filebelt_document.revisions \
             (tenant_id,id,document_session_id,actor_participant_id,provider_event_digest,\
              kind,state,expected_head_version_id,payload_id,reserved_bytes,media_type) \
             VALUES ($1,$2,$3,$4,$5,$6,'staging',$7,$8,$9,$10) \
             RETURNING id,document_session_id,actor_participant_id,kind,state,\
               expected_head_version_id,payload_id,reserved_bytes,size_bytes,blake3,media_type,\
               committed_version_id,retained_until::text",
            )
            .bind(input.tenant_id)
            .bind(revision_id)
            .bind(input.document_session_id)
            .bind(input.participant_id)
            .bind(input.provider_event_digest.as_slice())
            .bind(input.kind)
            .bind(participant.get::<Uuid, _>("expected_head_version_id"))
            .bind(payload_id)
            .bind(input.reserved_bytes)
            .bind(input.media_type)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_conflict)?
        };
        sqlx::query(
            "INSERT INTO filebelt_document.revision_contributors \
             (tenant_id,revision_id,principal_id) VALUES ($1,$2,$3)",
        )
        .bind(input.tenant_id)
        .bind(revision_id)
        .bind(user_principal_id)
        .execute(&mut *transaction)
        .await?;
        let revision = document_revision_from_row(&row);
        transaction.commit().await?;
        Ok(DocumentPayloadAllocation {
            revision,
            payload_id,
            backend_id,
            locator,
            fencing_token: participant.get("fencing_token"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_document_revision(
        &self,
        tenant_id: Uuid,
        revision_id: Uuid,
        fencing_token: i64,
        size_bytes: i64,
        blake3: &[u8; 32],
        media_type: &str,
    ) -> Result<DocumentRevisionRecord, DatabaseError> {
        if !(0..=DOCUMENT_MAX_BYTES).contains(&size_bytes)
            || !matches!(
                media_type,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            )
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT r.id,r.document_session_id,r.actor_participant_id,r.kind,r.state,\
             r.expected_head_version_id,r.payload_id,r.reserved_bytes,r.size_bytes,r.blake3,\
             r.media_type,r.committed_version_id,r.retained_until::text,s.fencing_token,\
             s.state AS session_state,s.absolute_expires_at>clock_timestamp() AS session_unexpired,\
             s.drive_id,s.node_id,p.user_principal_id,p.api_session_id,\
             p.membership_generation,p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation \
             FROM filebelt_document.revisions r JOIN filebelt_document.sessions s \
             ON s.tenant_id=r.tenant_id AND s.id=r.document_session_id \
             JOIN filebelt_document.participants p ON p.tenant_id=r.tenant_id \
               AND p.id=r.actor_participant_id \
             WHERE r.tenant_id=$1 AND r.id=$2 FOR UPDATE OF r,s,p",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if row.get::<i64, _>("fencing_token") != fencing_token
            || row.get::<String, _>("session_state") != "active"
            || !row.get::<bool, _>("session_unexpired")
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let existing = document_revision_from_row(&row);
        if existing.state != "staging" {
            transaction.commit().await?;
            return Ok(existing);
        }
        let authorization_changed = match lock_document_authorization_fence(
            &mut transaction,
            tenant_id,
            row.get("user_principal_id"),
            row.get("api_session_id"),
            row.get("drive_id"),
            row.get("node_id"),
            [
                row.get("membership_generation"),
                row.get("drive_acl_generation"),
                row.get("namespace_generation"),
                row.get("resource_acl_generation"),
            ],
        )
        .await
        {
            Ok(()) => false,
            Err(DatabaseError::StaleGeneration) => true,
            Err(error) => return Err(error),
        };
        if size_bytes > existing.reserved_bytes {
            return Err(DatabaseError::QuotaExceeded);
        }
        let payload_id = existing
            .payload_id
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        sqlx::query(
            "UPDATE payload_objects SET state='finalized',size_bytes=$3,blake3=$4,\
             finalized_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='staging'",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .bind(size_bytes)
        .bind(blake3.as_slice())
        .execute(&mut *transaction)
        .await?;
        let checkpoint = existing.kind == "checkpoint" && !authorization_changed;
        if checkpoint {
            sqlx::query(
                "UPDATE filebelt_document.revisions SET state='failed',\
                 conflict_reason='checkpoint_superseded',retained_until=LEAST(\
                   COALESCE(retained_until,clock_timestamp()+interval '1 day'),\
                   clock_timestamp()+interval '1 day'),finished_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND document_session_id=$2 AND id<>$3 \
                   AND state='checkpoint'",
            )
            .bind(tenant_id)
            .bind(existing.document_session_id)
            .bind(revision_id)
            .execute(&mut *transaction)
            .await?;
        }
        let row = sqlx::query(
            "UPDATE filebelt_document.revisions SET state=$3,size_bytes=$4,blake3=$5,\
             media_type=$6,staged_at=clock_timestamp(),\
             retained_until=CASE WHEN $3='checkpoint' THEN clock_timestamp()+interval '1 day' \
               ELSE NULL END WHERE tenant_id=$1 AND id=$2 \
             RETURNING id,document_session_id,actor_participant_id,kind,state,\
               expected_head_version_id,payload_id,reserved_bytes,size_bytes,blake3,media_type,\
               committed_version_id,retained_until::text",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .bind(if checkpoint { "checkpoint" } else { "staged" })
        .bind(size_bytes)
        .bind(blake3.as_slice())
        .bind(media_type)
        .fetch_one(&mut *transaction)
        .await?;
        if !checkpoint {
            sqlx::query(
                "INSERT INTO filebelt_document.reconciliation_jobs (tenant_id,revision_id) \
                 VALUES ($1,$2) ON CONFLICT (tenant_id,revision_id) DO NOTHING",
            )
            .bind(tenant_id)
            .bind(revision_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        if authorization_changed {
            return Err(DatabaseError::StaleGeneration);
        }
        Ok(document_revision_from_row(&row))
    }

    pub async fn commit_document_revision(
        &self,
        tenant_id: Uuid,
        revision_id: Uuid,
    ) -> Result<DocumentCommitResult, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT r.id,r.document_session_id,r.actor_participant_id,r.kind,r.state,\
             r.expected_head_version_id,r.payload_id,r.reserved_bytes,r.size_bytes,r.blake3,\
             r.media_type,r.committed_version_id,r.retained_until::text,\
             s.session_principal_id,s.drive_id,s.node_id,s.fencing_token,\
             s.state AS session_state,s.absolute_expires_at>clock_timestamp() AS session_unexpired,\
             p.user_principal_id,p.api_session_id,p.mode,p.membership_generation,\
             p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation \
             FROM filebelt_document.revisions r \
             JOIN filebelt_document.sessions s ON s.tenant_id=r.tenant_id \
               AND s.id=r.document_session_id \
             JOIN filebelt_document.participants p ON p.tenant_id=r.tenant_id \
               AND p.id=r.actor_participant_id \
             WHERE r.tenant_id=$1 AND r.id=$2 FOR UPDATE OF r,s,p",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if !document_participant_can_write(&row.get::<String, _>("mode")) {
            return Err(DatabaseError::Conflict);
        }
        let revision = document_revision_from_row(&row);
        match revision.state.as_str() {
            "committed" => {
                return Ok(DocumentCommitResult::Committed {
                    version_id: revision
                        .committed_version_id
                        .ok_or(DatabaseError::InvalidPersistedValue)?,
                });
            }
            "no_op" => {
                return Ok(DocumentCommitResult::NoOp {
                    version_id: revision.expected_head_version_id,
                });
            }
            "conflict" => {
                return Ok(DocumentCommitResult::Conflict {
                    retained_until: revision
                        .retained_until
                        .ok_or(DatabaseError::InvalidPersistedValue)?,
                });
            }
            "staged" | "committing" => {}
            _ => return Err(DatabaseError::Conflict),
        }
        if row.get::<String, _>("session_state") != "active"
            || !row.get::<bool, _>("session_unexpired")
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let actor_principal_id: Uuid = row.get("user_principal_id");
        let api_session_id: Uuid = row.get("api_session_id");
        let drive_id: Uuid = row.get("drive_id");
        let node_id: Uuid = row.get("node_id");
        lock_authorization_fence(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            api_session_id,
            drive_id,
            node_id,
            [
                row.get("membership_generation"),
                row.get("drive_acl_generation"),
                row.get("namespace_generation"),
                row.get("resource_acl_generation"),
            ],
        )
        .await?;
        let current = sqlx::query(
            "SELECT n.head_version_id,v.size_bytes,v.blake3,v.ordinal \
             FROM nodes n LEFT JOIN file_versions v ON v.tenant_id=n.tenant_id \
               AND v.node_id=n.id AND v.id=n.head_version_id \
             WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 FOR UPDATE OF n",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .fetch_one(&mut *transaction)
        .await?;
        let current_head: Option<Uuid> = current.get("head_version_id");
        if current_head != Some(revision.expected_head_version_id) {
            let retained_until = mark_document_conflict(
                &mut transaction,
                tenant_id,
                revision_id,
                revision.document_session_id,
                "document_head_changed",
            )
            .await?;
            insert_audit(
                &mut transaction,
                tenant_id,
                Some(actor_principal_id),
                Some(row.get("session_principal_id")),
                Some(node_id),
                "document.revision.commit",
                "conflict",
                "document_head_changed",
                true,
                json!({"revision_id":revision_id}),
            )
            .await?;
            transaction.commit().await?;
            return Ok(DocumentCommitResult::Conflict { retained_until });
        }
        let size_bytes = revision
            .size_bytes
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let digest = revision
            .blake3
            .as_deref()
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let payload_id = revision
            .payload_id
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let current_size: Option<i64> = current.get("size_bytes");
        let current_digest: Option<Vec<u8>> = current.get("blake3");
        if current_size == Some(size_bytes) && current_digest.as_deref() == Some(digest) {
            let _ = release_document_payload(
                &mut transaction,
                tenant_id,
                drive_id,
                payload_id,
                revision.reserved_bytes,
            )
            .await?;
            sqlx::query(
                "UPDATE filebelt_document.revisions SET state='no_op',finished_at=clock_timestamp(),\
                 retained_until=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant_id)
            .bind(revision_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE filebelt_document.reconciliation_jobs SET state='complete',\
                 updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2",
            )
            .bind(tenant_id)
            .bind(revision_id)
            .execute(&mut *transaction)
            .await?;
            insert_audit(
                &mut transaction,
                tenant_id,
                Some(actor_principal_id),
                Some(row.get("session_principal_id")),
                Some(node_id),
                "document.revision.commit",
                "allowed",
                "document_save_noop",
                true,
                json!({"revision_id":revision_id,"version_id":revision.expected_head_version_id}),
            )
            .await?;
            transaction.commit().await?;
            return Ok(DocumentCommitResult::NoOp {
                version_id: revision.expected_head_version_id,
            });
        }
        let version_id = Uuid::new_v4();
        let ordinal = current.get::<Option<i64>, _>("ordinal").unwrap_or(0) + 1;
        sqlx::query(
            "INSERT INTO file_versions \
             (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,media_type,\
              created_by,origin_kind) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'external_document')",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(version_id)
        .bind(ordinal)
        .bind(payload_id)
        .bind(size_bytes)
        .bind(digest)
        .bind(revision.media_type.as_deref())
        .bind(row.get::<Uuid, _>("session_principal_id"))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE payload_objects SET state='referenced',referenced_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND state='finalized'",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE drives SET reserved_bytes=reserved_bytes-$3,\
             used_physical_bytes=used_physical_bytes+$4 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(revision.reserved_bytes)
        .bind(size_bytes)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE nodes SET head_version_id=$4,updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(version_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_document.revisions SET state='committed',committed_version_id=$3,\
             finished_at=clock_timestamp(),retained_until=NULL WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .bind(version_id)
        .execute(&mut *transaction)
        .await?;
        let final_save = revision.kind == "final_save";
        sqlx::query(
            "UPDATE filebelt_document.sessions SET expected_head_version_id=$3,\
             state=CASE WHEN $4 THEN 'committed' ELSE state END,\
             closed_at=CASE WHEN $4 THEN clock_timestamp() ELSE closed_at END,\
             close_reason=CASE WHEN $4 THEN 'final_save' ELSE close_reason END \
             WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(revision.document_session_id)
        .bind(version_id)
        .bind(final_save)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_document.reconciliation_jobs SET state='complete',\
             updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_document.sessions SET state='conflict',\
             fencing_token=fencing_token+1,closed_at=clock_timestamp(),\
             close_reason='external_head' WHERE tenant_id=$1 AND drive_id=$2 AND node_id=$3 \
             AND id<>$4 AND state IN ('active','draining')",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(revision.document_session_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_collaboration.epochs e SET state='frozen',\
             freeze_reason='external_head',fencing_token=fencing_token+1 \
             FROM filebelt_collaboration.rooms r WHERE r.tenant_id=$1 AND r.drive_id=$2 \
             AND r.node_id=$3 AND e.tenant_id=r.tenant_id AND e.room_id=r.id \
             AND e.epoch=r.current_epoch AND e.state='active'",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            Some(row.get("session_principal_id")),
            Some(node_id),
            "document.revision.commit",
            "allowed",
            "document_version_committed",
            true,
            json!({"revision_id":revision_id,"version_id":version_id}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.file.version.committed",
            "node",
            node_id,
            ordinal,
        )
        .await?;
        transaction.commit().await?;
        Ok(DocumentCommitResult::Committed { version_id })
    }

    /// Reject a durable-but-uncommittable revision after its stored
    /// authorization projection has become stale. This is deliberately
    /// separate from physical I/O: it fences outstanding capabilities,
    /// releases the exact reservation once, and leaves a payload-delete job
    /// as the durable retry record for any promoted final object.
    pub async fn reject_document_revision_for_authorization_change(
        &self,
        tenant_id: Uuid,
        revision_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT r.id,r.document_session_id,r.actor_participant_id,r.state,r.payload_id,\
             r.reserved_bytes,s.drive_id,s.node_id,s.state AS session_state,\
             s.absolute_expires_at>clock_timestamp() AS session_unexpired,p.user_principal_id,p.api_session_id,\
             p.membership_generation,p.drive_acl_generation,p.namespace_generation,p.resource_acl_generation \
             FROM filebelt_document.revisions r \
             JOIN filebelt_document.sessions s ON s.tenant_id=r.tenant_id AND s.id=r.document_session_id \
             JOIN filebelt_document.participants p ON p.tenant_id=r.tenant_id AND p.id=r.actor_participant_id \
             WHERE r.tenant_id=$1 AND r.id=$2 FOR UPDATE OF r,s,p",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let state: String = row.get("state");
        if matches!(
            state.as_str(),
            "checkpoint" | "committed" | "no_op" | "conflict" | "rejected" | "failed"
        ) {
            transaction.commit().await?;
            return Ok(false);
        }
        if !matches!(state.as_str(), "staging" | "staged" | "committing") {
            return Err(DatabaseError::Conflict);
        }
        if row.get::<String, _>("session_state") == "active"
            && row.get::<bool, _>("session_unexpired")
        {
            match lock_authorization_fence(
                &mut transaction,
                tenant_id,
                row.get("user_principal_id"),
                row.get("api_session_id"),
                row.get("drive_id"),
                row.get("node_id"),
                [
                    row.get("membership_generation"),
                    row.get("drive_acl_generation"),
                    row.get("namespace_generation"),
                    row.get("resource_acl_generation"),
                ],
            )
            .await
            {
                Err(DatabaseError::StaleGeneration) => {}
                Ok(()) => return Err(DatabaseError::Conflict),
                Err(error) => return Err(error),
            }
        }
        let payload_id: Uuid = row
            .get::<Option<Uuid>, _>("payload_id")
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let _ = release_document_payload(
            &mut transaction,
            tenant_id,
            row.get("drive_id"),
            payload_id,
            row.get("reserved_bytes"),
        )
        .await?;
        let revision_updated = sqlx::query(
            "UPDATE filebelt_document.revisions SET state='rejected',\
             conflict_reason='authorization_changed',finished_at=clock_timestamp(),\
             retained_until=LEAST(created_at+interval '7 days',clock_timestamp()+interval '1 day') \
             WHERE tenant_id=$1 AND id=$2 AND state IN ('staging','staged','committing')",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if revision_updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "UPDATE filebelt_document.reconciliation_jobs SET state='terminal',\
             last_error_code='authorization_changed',lease_owner=NULL,lease_expires_at=NULL,\
             updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2",
        )
        .bind(tenant_id)
        .bind(revision_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_document.participants SET state='revoked',closed_at=clock_timestamp(),\
             close_reason='authorization_changed' WHERE tenant_id=$1 AND document_session_id=$2 \
             AND state IN ('active','disconnected')",
        )
        .bind(tenant_id)
        .bind(row.get::<Uuid, _>("document_session_id"))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_document.sessions SET state='revoked',fencing_token=fencing_token+1,\
             closed_at=clock_timestamp(),close_reason='authorization_changed' \
             WHERE tenant_id=$1 AND id=$2 AND state IN ('active','draining')",
        )
        .bind(tenant_id)
        .bind(row.get::<Uuid, _>("document_session_id"))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    /// Fence document revisions whose session is no longer usable, release
    /// their reservation exactly once, and enqueue their payload deletion.
    ///
    /// A live session is intentionally never expired here: an adapter may
    /// still be fetching its output. Once the session is closed or its
    /// absolute deadline has passed, neither Begin nor Finalize can accept the
    /// revision, so transitioning a received/staging revision to failed is
    /// safe and makes physical cleanup retryable through the normal job queue.
    pub async fn document_revision_retention_sweep(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<DocumentRevisionRetentionReport, DatabaseError> {
        if !(1..=1_000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let candidates = sqlx::query(
            "SELECT r.id,r.payload_id,r.reserved_bytes,s.drive_id \
             FROM filebelt_document.revisions r \
             JOIN filebelt_document.sessions s ON s.tenant_id=r.tenant_id \
               AND s.id=r.document_session_id \
             WHERE r.tenant_id=$1 AND r.state IN ('received','staging') \
               AND (s.state NOT IN ('active','draining') \
                    OR s.absolute_expires_at<=clock_timestamp()) \
             ORDER BY r.created_at,r.id LIMIT $2 FOR UPDATE OF r,s SKIP LOCKED",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        let mut report = DocumentRevisionRetentionReport::default();
        for candidate in candidates {
            let revision_id: Uuid = candidate.get("id");
            let payload_id: Option<Uuid> = candidate.get("payload_id");
            if let Some(payload_id) = payload_id {
                let reserved_bytes: i64 = candidate.get("reserved_bytes");
                let drive_id: Uuid = candidate.get("drive_id");
                let payload_updated = sqlx::query(
                    "UPDATE payload_objects SET state='delete_intent',\
                     deletion_intent_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 \
                     AND state='staging'",
                )
                .bind(tenant_id)
                .bind(payload_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if payload_updated != 1 {
                    return Err(DatabaseError::StaleGeneration);
                }
                let drive_updated = sqlx::query(
                    "UPDATE drives SET reserved_bytes=reserved_bytes-$3 \
                     WHERE tenant_id=$1 AND id=$2 AND reserved_bytes>=$3",
                )
                .bind(tenant_id)
                .bind(drive_id)
                .bind(reserved_bytes)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if drive_updated != 1 {
                    return Err(DatabaseError::StaleGeneration);
                }
                let revision_updated = sqlx::query(
                    "UPDATE filebelt_document.revisions SET state='failed',\
                     conflict_reason='document_session_expired_before_finalize',\
                     finished_at=clock_timestamp(),retained_until=LEAST(\
                       created_at+interval '7 days',clock_timestamp()+interval '1 day') \
                     WHERE tenant_id=$1 AND id=$2 AND state='staging'",
                )
                .bind(tenant_id)
                .bind(revision_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if revision_updated != 1 {
                    return Err(DatabaseError::StaleGeneration);
                }
                report.staging_abandoned += 1;
                report.payload_deletions_enqueued += sqlx::query(
                    "INSERT INTO public.jobs \
                     (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) \
                     VALUES ($1,$2,'payload_delete','queued',80,$3,$4,$5) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(tenant_id)
                .bind(Uuid::new_v4())
                .bind(payload_id)
                .bind(format!("document-expire:{payload_id}"))
                .bind(json!({"payload_id": payload_id}))
                .execute(&mut *transaction)
                .await?
                .rows_affected();
            } else {
                let revision_updated = sqlx::query(
                    "UPDATE filebelt_document.revisions SET state='failed',\
                     conflict_reason='document_session_expired_before_output',\
                     finished_at=clock_timestamp(),retained_until=LEAST(\
                       created_at+interval '7 days',clock_timestamp()+interval '1 day') \
                     WHERE tenant_id=$1 AND id=$2 AND state='received'",
                )
                .bind(tenant_id)
                .bind(revision_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if revision_updated != 1 {
                    return Err(DatabaseError::StaleGeneration);
                }
                report.received_abandoned += 1;
            }
        }
        // Checkpoints and conflicts retain their finalized, unreferenced
        // payload only for their documented recovery window. Once that window
        // closes, release the reservation in the same transaction that marks
        // the payload delete-intent. Referenced committed and conflict-copy
        // payloads cannot match this state predicate and are never touched.
        let terminal = sqlx::query(
            "SELECT r.id,r.payload_id,r.reserved_bytes,s.drive_id \
             FROM filebelt_document.revisions r \
             JOIN filebelt_document.sessions s ON s.tenant_id=r.tenant_id AND s.id=r.document_session_id \
             JOIN payload_objects p ON p.tenant_id=r.tenant_id AND p.id=r.payload_id \
             WHERE r.tenant_id=$1 AND r.state IN ('checkpoint','conflict','rejected','failed','no_op') \
               AND r.retained_until<=clock_timestamp() AND r.payload_id IS NOT NULL \
               AND p.state='finalized' \
             ORDER BY r.retained_until,r.id LIMIT $2 FOR UPDATE OF r,s,p SKIP LOCKED",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        for candidate in terminal {
            let revision_id: Uuid = candidate.get("id");
            let payload_id: Uuid = candidate.get("payload_id");
            let payload_delete_enqueued = release_document_payload(
                &mut transaction,
                tenant_id,
                candidate.get("drive_id"),
                payload_id,
                candidate.get("reserved_bytes"),
            )
            .await?;
            let updated = sqlx::query(
                "UPDATE filebelt_document.revisions SET state='failed',\
                 conflict_reason=COALESCE(conflict_reason,'document_retention_expired'),\
                 finished_at=COALESCE(finished_at,clock_timestamp()),retained_until=NULL \
                 WHERE tenant_id=$1 AND id=$2 AND state IN ('checkpoint','conflict','rejected','failed','no_op')",
            )
            .bind(tenant_id)
            .bind(revision_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if updated != 1 {
                return Err(DatabaseError::StaleGeneration);
            }
            sqlx::query(
                "UPDATE filebelt_document.reconciliation_jobs SET state='complete',\
                 updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2",
            )
            .bind(tenant_id)
            .bind(revision_id)
            .execute(&mut *transaction)
            .await?;
            report.terminal_revisions_released += 1;
            report.payload_deletions_enqueued += payload_delete_enqueued;
        }
        report.launch_grants_purged = bounded_document_metadata_delete(
            &mut transaction,
            "launch_grants",
            "expires_at<=clock_timestamp() OR consumed_at IS NOT NULL",
            tenant_id,
            limit,
        )
        .await?;
        report.session_events_purged = bounded_document_metadata_delete(
            &mut transaction,
            "session_events",
            "purge_after<=clock_timestamp()",
            tenant_id,
            limit,
        )
        .await?;
        report.operation_receipts_purged = bounded_document_metadata_delete(
            &mut transaction,
            "operation_receipts",
            "expires_at<=clock_timestamp()",
            tenant_id,
            limit,
        )
        .await?;
        transaction.commit().await?;
        Ok(report)
    }

    /// Close disconnected participants only after their bounded reconnect
    /// deadline, then terminalize drained sessions with no remaining live
    /// participant. Both updates are idempotent and release admission slots.
    pub async fn document_reconnect_sweep(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<DocumentReconnectSweepReport, DatabaseError> {
        if !(1..=1_000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let participants_closed = sqlx::query(
            "UPDATE filebelt_document.participants SET state='closed',closed_at=clock_timestamp(),\
             close_reason='reconnect_deadline_elapsed' WHERE (tenant_id,id) IN (\
               SELECT p.tenant_id,p.id FROM filebelt_document.participants p \
               JOIN filebelt_document.sessions s ON s.tenant_id=p.tenant_id AND s.id=p.document_session_id \
               WHERE p.tenant_id=$1 AND p.state='disconnected' \
                 AND (p.disconnected_until<=clock_timestamp() OR s.reconnect_until<=clock_timestamp()) \
               ORDER BY p.disconnected_until,p.id LIMIT $2 FOR UPDATE OF p,s SKIP LOCKED)",
        )
        .bind(tenant_id)
        .bind(limit)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let sessions_expired = sqlx::query(
            "UPDATE filebelt_document.sessions SET state='expired',fencing_token=fencing_token+1,\
             closed_at=clock_timestamp(),close_reason='reconnect_deadline_elapsed' \
             WHERE (tenant_id,id) IN (SELECT s.tenant_id,s.id FROM filebelt_document.sessions s \
               WHERE s.tenant_id=$1 AND s.state='draining' AND s.reconnect_until<=clock_timestamp() \
                 AND NOT EXISTS (SELECT 1 FROM filebelt_document.participants p \
                   WHERE p.tenant_id=s.tenant_id AND p.document_session_id=s.id \
                     AND p.state IN ('active','disconnected')) \
               ORDER BY s.reconnect_until,s.id LIMIT $2 FOR UPDATE OF s SKIP LOCKED)",
        )
        .bind(tenant_id)
        .bind(limit)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        transaction.commit().await?;
        Ok(DocumentReconnectSweepReport {
            participants_closed,
            sessions_expired,
        })
    }

    /// Return stale staging hard-link locators only after the durable payload
    /// state proves that final bytes exist. Removing these locators is
    /// idempotent and never removes the canonical payload path.
    pub async fn document_finalized_staging_locators(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        if !(1..=1_000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar(
            "SELECT DISTINCT p.locator FROM filebelt_document.revisions r \
             JOIN payload_objects p ON p.tenant_id=r.tenant_id AND p.id=r.payload_id \
             WHERE r.tenant_id=$1 AND p.backend_id=$2 \
               AND p.state IN ('finalized','referenced') \
               AND r.state IN ('staged','committing','checkpoint','committed','no_op','conflict','failed','rejected') \
             ORDER BY p.locator LIMIT $3",
        )
        .bind(tenant_id)
        .bind(backend_id)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(DatabaseError::from)
    }

    /// Whether an unlinked public payload belongs to a failed document
    /// revision. This lets maintenance choose the matching durable completion
    /// transition without granting the document service physical I/O access.
    pub async fn document_payload_deletion_pending(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_document.revisions r \
             JOIN payload_objects p ON p.tenant_id=r.tenant_id AND p.id=r.payload_id \
             WHERE r.tenant_id=$1 AND r.payload_id=$2 AND r.state IN ('failed','no_op') \
               AND p.state IN ('delete_intent','deleting','abandoned'))",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .fetch_one(self.pool())
        .await
        .map_err(DatabaseError::from)
    }

    /// Record physical deletion for a stale document output. The reservation
    /// was released in `document_revision_retention_sweep`, so this transition
    /// only makes the payload terminal and is safe to repeat after a crash.
    pub async fn complete_document_payload_deletion(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT p.state FROM payload_objects p WHERE p.tenant_id=$1 AND p.id=$2 \
             AND EXISTS (SELECT 1 FROM filebelt_document.revisions r \
               WHERE r.tenant_id=p.tenant_id AND r.payload_id=p.id \
                 AND r.state IN ('failed','no_op')) \
             FOR UPDATE OF p",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let state: String = row.get("state");
        if state == "deleted" {
            transaction.commit().await?;
            return Ok(());
        }
        if !matches!(state.as_str(), "deleting" | "abandoned") {
            return Err(DatabaseError::StaleGeneration);
        }
        let updated = sqlx::query(
            "UPDATE payload_objects SET state='deleted' WHERE tenant_id=$1 AND id=$2 \
             AND state IN ('deleting','abandoned')",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(())
    }
}

/// Serializes same-operation retries behind a transaction-scoped lock, then
/// returns the originally persisted public result. The operation digest is
/// opaque and already bound by the caller to tenant, actor, route, and its
/// idempotency key; the fingerprint prevents that key from being reused for a
/// different semantic effect.
async fn document_operation_replay<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    operation_digest: &[u8; 32],
    request_fingerprint: &[u8; 32],
    command_kind: &str,
) -> Result<Option<T>, DatabaseError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(\
         hashtextextended(encode($1,'hex') || ':' || $2::text, 0))",
    )
    .bind(operation_digest.as_slice())
    .bind(tenant_id)
    .execute(&mut **transaction)
    .await?;
    let receipt = sqlx::query(
        "SELECT request_fingerprint,command_kind,response \
         FROM filebelt_document.operation_receipts \
         WHERE tenant_id=$1 AND operation_digest=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(operation_digest.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let stored_fingerprint: Vec<u8> = receipt.get("request_fingerprint");
    let stored_kind: String = receipt.get("command_kind");
    if stored_fingerprint.as_slice() != request_fingerprint || stored_kind != command_kind {
        return Err(DatabaseError::Conflict);
    }
    serde_json::from_value(receipt.get("response"))
        .map(Some)
        .map_err(|_| DatabaseError::InvalidPersistedValue)
}

async fn document_operation_record<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    operation_digest: &[u8; 32],
    request_fingerprint: &[u8; 32],
    command_kind: &str,
    response: &T,
) -> Result<(), DatabaseError> {
    let response =
        serde_json::to_value(response).map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let inserted = sqlx::query(
        "INSERT INTO filebelt_document.operation_receipts \
         (tenant_id,operation_digest,request_fingerprint,command_kind,response) \
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(operation_digest.as_slice())
    .bind(request_fingerprint.as_slice())
    .bind(command_kind)
    .bind(response)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(DatabaseError::Conflict);
    }
    Ok(())
}

fn page_limit(limit: u32) -> Result<usize, DatabaseError> {
    match limit {
        1..=200 => Ok(limit as usize),
        _ => Err(DatabaseError::InvalidPersistedValue),
    }
}

fn document_participant_can_write(mode: &str) -> bool {
    matches!(mode, "comment" | "review" | "edit")
}

fn document_session_page_from_rows(
    rows: Vec<sqlx::postgres::PgRow>,
    limit: usize,
) -> Result<DocumentSessionPageRecord, DatabaseError> {
    let mut launches = Vec::with_capacity(rows.len());
    let mut sessions = Vec::new();
    for row in &rows {
        let session = document_session_from_row(row);
        if !sessions.iter().any(|(id, _)| *id == session.id) {
            sessions.push((
                session.id,
                DocumentSessionPageAnchor {
                    created_at_unix_microseconds: session.created_at_unix_microseconds,
                    session_id: session.id,
                },
            ));
        }
        launches.push(DocumentLaunchRecord {
            grant_id: Uuid::nil(),
            expires_at: row.get("grant_expires_at"),
            participant: DocumentParticipantRecord {
                id: row.get("participant_id"),
                document_session_id: row.get("document_session_id"),
                user_principal_id: row.get("user_principal_id"),
                api_session_id: row.get("api_session_id"),
                mode: row.get("mode"),
                state: row.get("participant_state"),
                display_name: row.get("display_name"),
                created_at: row.get("participant_created_at"),
                last_activity_at: row.get("last_activity_at"),
                disconnected_until: row.get("disconnected_until"),
                generations: document_generations_from_row(row),
            },
            session,
        });
    }
    let next_anchor = if sessions.len() > limit {
        let included: Vec<Uuid> = sessions.iter().take(limit).map(|(id, _)| *id).collect();
        launches.retain(|launch| included.contains(&launch.session.id));
        sessions.get(limit - 1).map(|(_, anchor)| anchor.clone())
    } else {
        None
    };
    Ok(DocumentSessionPageRecord {
        launches,
        next_anchor,
    })
}

async fn bounded_document_metadata_delete(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    predicate: &str,
    tenant_id: Uuid,
    limit: i64,
) -> Result<u64, DatabaseError> {
    // Both fragments are selected only from this module's fixed maintenance
    // vocabulary; they are not derived from a request or persisted value.
    let statement = match (table, predicate) {
        ("launch_grants", "expires_at<=clock_timestamp() OR consumed_at IS NOT NULL") => {
            "DELETE FROM filebelt_document.launch_grants WHERE ctid IN (\
             SELECT ctid FROM filebelt_document.launch_grants WHERE tenant_id=$1 \
             AND (expires_at<=clock_timestamp() OR consumed_at IS NOT NULL) \
             ORDER BY expires_at,id LIMIT $2 FOR UPDATE SKIP LOCKED)"
        }
        ("session_events", "purge_after<=clock_timestamp()") => {
            "DELETE FROM filebelt_document.session_events WHERE ctid IN (\
             SELECT ctid FROM filebelt_document.session_events WHERE tenant_id=$1 \
             AND purge_after<=clock_timestamp() ORDER BY purge_after,id LIMIT $2 FOR UPDATE SKIP LOCKED)"
        }
        ("operation_receipts", "expires_at<=clock_timestamp()") => {
            "DELETE FROM filebelt_document.operation_receipts WHERE ctid IN (\
             SELECT ctid FROM filebelt_document.operation_receipts WHERE tenant_id=$1 \
             AND expires_at<=clock_timestamp() ORDER BY expires_at,operation_digest \
             LIMIT $2 FOR UPDATE SKIP LOCKED)"
        }
        _ => return Err(DatabaseError::InvalidPersistedValue),
    };
    Ok(sqlx::query(statement)
        .bind(tenant_id)
        .bind(limit)
        .execute(&mut **transaction)
        .await?
        .rows_affected())
}

async fn mark_document_conflict(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    revision_id: Uuid,
    session_id: Uuid,
    reason: &str,
) -> Result<String, DatabaseError> {
    let retained_until: String = sqlx::query_scalar(
        "UPDATE filebelt_document.revisions SET state='conflict',conflict_reason=$3,\
         retained_until=clock_timestamp()+interval '7 days',finished_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2 RETURNING retained_until::text",
    )
    .bind(tenant_id)
    .bind(revision_id)
    .bind(reason)
    .fetch_one(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE filebelt_document.sessions SET state='conflict',fencing_token=fencing_token+1,\
         closed_at=clock_timestamp(),close_reason=$3 WHERE tenant_id=$1 AND id=$2 \
         AND state IN ('active','draining')",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE filebelt_document.reconciliation_jobs SET state='complete',\
         updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2",
    )
    .bind(tenant_id)
    .bind(revision_id)
    .execute(&mut **transaction)
    .await?;
    Ok(retained_until)
}

/// Lock the exact authorization projection without granting the I/O worker
/// visibility into identity or namespace rows. Authorization-changing triggers
/// delete this projection, and `FOR SHARE` makes that deletion conflict with
/// the final durable transition.
#[allow(clippy::too_many_arguments)]
async fn lock_document_authorization_fence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    resource_id: Uuid,
    expected: [i64; 4],
) -> Result<(), DatabaseError> {
    let _projection = sqlx::query(
        "SELECT 1 FROM authorization_generations WHERE tenant_id=$1 AND session_id=$2 \
         AND principal_id=$3 AND drive_id=$4 AND resource_id=$5 \
         AND membership_generation=$6 AND drive_acl_generation=$7 \
         AND namespace_generation=$8 AND resource_acl_generation=$9 \
         AND session_expires_at>clock_timestamp() FOR SHARE",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(actor_principal_id)
    .bind(drive_id)
    .bind(resource_id)
    .bind(expected[0])
    .bind(expected[1])
    .bind(expected[2])
    .bind(expected[3])
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    Ok(())
}

async fn release_document_payload(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    drive_id: Uuid,
    payload_id: Uuid,
    reserved_bytes: i64,
) -> Result<u64, DatabaseError> {
    let payload_updated = sqlx::query(
        "UPDATE payload_objects SET state='delete_intent',deletion_intent_at=clock_timestamp() \
         WHERE tenant_id=$1 AND id=$2 AND state IN ('staging','finalized')",
    )
    .bind(tenant_id)
    .bind(payload_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if payload_updated != 1 {
        return Err(DatabaseError::StaleGeneration);
    }
    let drive_updated = sqlx::query(
        "UPDATE drives SET reserved_bytes=reserved_bytes-$3 \
         WHERE tenant_id=$1 AND id=$2 AND reserved_bytes>=$3",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(reserved_bytes)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if drive_updated != 1 {
        return Err(DatabaseError::StaleGeneration);
    }
    let payload_delete_enqueued = sqlx::query(
        "INSERT INTO public.jobs \
         (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) \
         VALUES ($1,$2,'payload_delete','queued',80,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(payload_id)
    .bind(format!("document-release:{payload_id}"))
    .bind(json!({"payload_id": payload_id}))
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    Ok(payload_delete_enqueued)
}

fn document_session_from_row(row: &sqlx::postgres::PgRow) -> DocumentSessionRecord {
    DocumentSessionRecord {
        id: row.get("id"),
        session_principal_id: row.get("session_principal_id"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        base_version_id: row.get("base_version_id"),
        expected_head_version_id: row.get("expected_head_version_id"),
        provider_id: row.get("provider_id"),
        state: row.get("state"),
        fencing_token: row.get("fencing_token"),
        created_at: row.get("created_at"),
        created_at_unix_microseconds: row
            .try_get("created_at_unix_microseconds")
            .unwrap_or_default(),
        absolute_expires_at: row.get("absolute_expires_at"),
        reconnect_until: row.get("reconnect_until"),
        closed_at: row.try_get("closed_at").ok().flatten(),
        close_reason: row.get("close_reason"),
        conflict_head_version_id: row.try_get("conflict_head_version_id").ok().flatten(),
    }
}

fn document_participant_from_row(
    row: &sqlx::postgres::PgRow,
    display_name: String,
) -> DocumentParticipantRecord {
    DocumentParticipantRecord {
        id: row.get("id"),
        document_session_id: row.get("document_session_id"),
        user_principal_id: row.get("user_principal_id"),
        api_session_id: row.get("api_session_id"),
        mode: row.get("mode"),
        state: row.get("state"),
        display_name,
        created_at: row.try_get("participant_created_at").unwrap_or_default(),
        last_activity_at: row.get("last_activity_at"),
        disconnected_until: row.get("disconnected_until"),
        generations: document_generations_from_row(row),
    }
}

fn document_generations_from_row(row: &sqlx::postgres::PgRow) -> DocumentAuthorizationGenerations {
    DocumentAuthorizationGenerations {
        membership: row.get("membership_generation"),
        drive_acl: row.get("drive_acl_generation"),
        namespace: row.get("namespace_generation"),
        resource_acl: row.get("resource_acl_generation"),
    }
}

fn document_revision_from_row(row: &sqlx::postgres::PgRow) -> DocumentRevisionRecord {
    DocumentRevisionRecord {
        id: row.get("id"),
        document_session_id: row.get("document_session_id"),
        actor_participant_id: row.get("actor_participant_id"),
        kind: row.get("kind"),
        state: row.get("state"),
        expected_head_version_id: row.get("expected_head_version_id"),
        payload_id: row.get("payload_id"),
        reserved_bytes: row.get("reserved_bytes"),
        size_bytes: row.get("size_bytes"),
        blake3: row.get("blake3"),
        media_type: row.get("media_type"),
        committed_version_id: row.get("committed_version_id"),
        retained_until: row.get("retained_until"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_match_the_reviewed_public_beta_profile() {
        assert_eq!(DOCUMENT_MAX_ACTIVE_PARTICIPANTS, 20);
        assert_eq!(DOCUMENT_MAX_BYTES, 104_857_600);
    }

    #[test]
    fn migration_contains_no_adapter_callback_or_secret_columns() {
        let migration = include_str!("../../../migrations/postgres/000006_phase7_documents.sql");
        for forbidden in ["callback_url", "output_url", "jwt_secret", "onlyoffice"] {
            assert!(!migration.to_ascii_lowercase().contains(forbidden));
        }
        assert!(migration.contains("interval '60 seconds'"));
        assert!(migration.contains("interval '7 days'"));
        assert!(migration.contains("document_operation_receipts_expiry_index"));
        assert!(migration.contains("interval '24 hours'"));
        assert!(migration.contains("document_session"));
    }

    #[test]
    fn origin_isolation_cutover_revokes_only_linked_live_api_sessions() {
        let migration =
            include_str!("../../../migrations/postgres/000010_onlyoffice_origin_isolation.sql");
        assert!(migration.contains("JOIN filebelt_document.participants"));
        assert!(migration.contains("s.revoked_at IS NULL"));
        assert!(migration.contains("s.idle_expires_at>statement_timestamp()"));
        assert!(migration.contains("s.absolute_expires_at>statement_timestamp()"));
        assert!(migration.contains("AND s.revoked_at IS NULL\n  RETURNING"));
        assert!(migration.contains("SET state='closed',disconnected_until=NULL"));
        assert!(migration.contains("SET state='revoked',fencing_token=fencing_token+1"));
        assert!(migration.contains("SET consumed_at=clock_timestamp()"));
        assert!(migration.contains("onlyoffice_origin_isolation_cutover"));
        assert!(migration.contains("onlyoffice_origin_isolation_v1"));
        assert!(!migration.contains("UPDATE filebelt_document.revisions"));
        assert!(!migration.contains("UPDATE filebelt_document.reconciliation_jobs"));
    }

    #[test]
    fn commit_outcomes_are_explicit() {
        let committed = DocumentCommitResult::Committed {
            version_id: Uuid::nil(),
        };
        assert!(matches!(committed, DocumentCommitResult::Committed { .. }));
    }

    #[test]
    fn callback_and_revision_fences_are_derived_from_the_participant_record() {
        let source = include_str!("document.rs");
        let receive = source
            .split_once("pub async fn receive_document_callback")
            .expect("callback receipt exists")
            .1
            .split_once("pub async fn received_document_revision")
            .expect("receipt lookup follows callback receipt")
            .0;
        assert!(receive.contains("p.membership_generation"));
        assert!(receive.contains("participant.get(\"resource_acl_generation\")"));
        assert!(receive.contains("b.media_type"));
        assert!(!receive.contains("input.generations"));
        assert!(!receive.contains("input.media_type"));

        let begin = source
            .split_once("pub async fn begin_document_revision")
            .expect("revision admission exists")
            .1
            .split_once("pub async fn finalize_document_revision")
            .expect("finalization follows admission")
            .0;
        assert!(begin.contains("p.membership_generation"));
        assert!(!begin.contains("input.generations"));

        let commit = source
            .split_once("pub async fn commit_document_revision")
            .expect("commit exists")
            .1
            .split_once("pub async fn document_revision_retention_sweep")
            .expect("retention follows commit")
            .0;
        assert!(commit.contains("p.membership_generation"));
        assert!(!commit.contains("generations.as_array()"));
    }

    #[test]
    fn retention_reclaims_only_unreferenced_expired_document_outputs_and_metadata() {
        let source = include_str!("document.rs");
        let sweep = source
            .split_once("pub async fn document_revision_retention_sweep")
            .expect("retention sweep exists")
            .1
            .split_once("pub async fn document_finalized_staging_locators")
            .expect("staging cleanup follows retention")
            .0;
        assert!(sweep.contains("r.state IN ('received','staging')"));
        assert!(sweep.contains("s.absolute_expires_at<=clock_timestamp()"));
        assert!(sweep.contains("state='delete_intent'"));
        assert!(sweep.contains("document-expire:{payload_id}"));
        assert!(sweep.contains("'checkpoint','conflict','rejected','failed','no_op'"));
        assert!(sweep.contains("p.state='finalized'"));
        assert!(sweep.contains("release_document_payload("));
        assert!(sweep.contains("bounded_document_metadata_delete("));
        assert!(sweep.contains("operation_receipts"));
        assert!(sweep.contains("session_events"));
        assert!(sweep.contains("launch_grants"));
    }

    #[test]
    fn staging_cleanup_requires_durable_final_bytes() {
        let source = include_str!("document.rs");
        let locators = source
            .split_once("pub async fn document_finalized_staging_locators")
            .expect("staging locator query exists")
            .1
            .split_once("pub async fn document_payload_deletion_pending")
            .expect("deletion classification follows locator query")
            .0;
        assert!(locators.contains("p.state IN ('finalized','referenced')"));
        assert!(locators.contains("'checkpoint','committed','no_op','conflict'"));
    }

    #[test]
    fn finalization_holds_the_exact_authorization_projection_and_rejection_releases_once() {
        let source = include_str!("document.rs");
        let finalize = source
            .split_once("pub async fn finalize_document_revision")
            .expect("finalization exists")
            .1
            .split_once("pub async fn commit_document_revision")
            .expect("commit follows finalization")
            .0;
        assert!(finalize.contains("lock_document_authorization_fence"));
        assert!(finalize.contains("authorization_changed"));
        assert!(finalize.contains("reconciliation_jobs"));

        let reject = source
            .split_once("pub async fn reject_document_revision_for_authorization_change")
            .expect("authorization rejection exists")
            .1
            .split_once("pub async fn document_revision_retention_sweep")
            .expect("retention follows rejection")
            .0;
        assert!(reject.contains("release_document_payload"));
        assert!(reject.contains("state='rejected'"));
        assert!(reject.contains("fencing_token=fencing_token+1"));
    }

    #[test]
    fn callback_events_are_digest_idempotent_and_allocate_revisions_only_for_output() {
        let source = include_str!("document.rs");
        let receipt = source
            .split_once("pub async fn receive_document_callback")
            .expect("callback receipt exists")
            .1
            .split_once("pub async fn received_document_revision_by_digest")
            .expect("callback digest lookup follows receipt")
            .0;
        assert!(receipt.contains("session_events"));
        assert!(receipt.contains("provider_event_digest"));
        assert!(receipt.contains("event.get::<Option<Uuid>, _>(\"participant_id\")"));
        assert!(receipt.contains("event.get::<String, _>(\"event_kind\")"));
        assert!(receipt.contains("input.callback_kind != \"output_required\""));
        assert!(receipt.contains("closed_no_changes"));
    }

    #[test]
    fn editing_callbacks_use_a_bounded_reconnect_state_machine() {
        let source = include_str!("document.rs");
        let receipt = source
            .split_once("pub async fn receive_document_callback")
            .expect("callback receipt exists")
            .1
            .split_once("pub async fn received_document_revision_by_digest")
            .expect("digest lookup follows receipt")
            .0;
        assert!(receipt.contains("Some(\"connected\" | \"disconnected\")"));
        assert!(receipt.contains("interval '100 seconds'"));
        assert!(receipt.contains("state='draining'"));
        assert!(receipt.contains("state='active',fencing_token=fencing_token+1"));

        let sweep = source
            .split_once("pub async fn document_reconnect_sweep")
            .expect("reconnect sweep exists")
            .1
            .split_once("pub async fn document_finalized_staging_locators")
            .expect("staging cleanup follows reconnect sweep")
            .0;
        assert!(sweep.contains("reconnect_deadline_elapsed"));
        assert!(sweep.contains("state='draining'"));
        assert!(sweep.contains("fencing_token=fencing_token+1"));
    }

    #[test]
    fn duplicate_editing_connect_reapplies_activity_after_transient_disconnect() {
        let source = include_str!("document.rs");
        let receipt = source
            .split_once("pub async fn receive_document_callback")
            .expect("callback receipt exists")
            .1
            .split_once("async fn received_document_revision_by_digest")
            .expect("output lookup follows callback receipt")
            .0;
        let duplicate = receipt
            .split_once("if let Some(event) = sqlx::query")
            .expect("duplicate event lookup exists")
            .1
            .split_once("let participant = sqlx::query")
            .expect("participant fence follows duplicate lookup")
            .0;
        assert!(duplicate.contains("if input.callback_kind != \"editing\""));
        assert!(duplicate.contains("continue through the participant/session fence"));
        assert!(receipt.contains("state='active',fencing_token=fencing_token+1"));
        assert!(receipt.contains("state IN ('active','draining')"));
    }

    #[test]
    fn create_operations_persist_and_replay_a_bound_response_without_a_launch_token() {
        let source = include_str!("document.rs");
        let create = source
            .split_once("pub async fn create_document_session")
            .expect("create session exists")
            .1
            .split_once("pub async fn issue_document_launch_grant")
            .expect("launch grant issuance follows creation")
            .0;
        assert!(create.contains("document_operation_replay::<DocumentLaunchRecord>"));
        assert!(create.contains("document_operation_record("));
        assert!(create.contains("grant_id: Uuid::nil()"));

        let copy = source
            .split_once("pub async fn create_document_conflict_copy")
            .expect("conflict copy exists")
            .1
            .split_once("pub async fn document_revision_io_context")
            .expect("I/O lookup follows conflict copy")
            .0;
        assert!(copy.contains("document_operation_replay::<DocumentConflictCopyRecord>"));
        assert!(copy.contains("\"conflict_copy\""));
        assert!(copy.contains("name_key,owner_principal_id"));
        assert!(copy.contains("bind(actor_principal_id)"));

        let replay = source
            .split_once("async fn document_operation_replay")
            .expect("replay helper exists")
            .1
            .split_once("async fn document_operation_record")
            .expect("record helper follows replay")
            .0;
        assert!(replay.contains("pg_advisory_xact_lock"));
        assert!(replay.contains("stored_fingerprint.as_slice() != request_fingerprint"));
        assert!(replay.contains("stored_kind != command_kind"));
    }

    #[test]
    fn a_participant_has_one_consumable_provider_launch_lifetime() {
        let source = include_str!("document.rs");
        let issuance = source
            .split_once("pub async fn issue_document_launch_grant")
            .expect("handoff issuance exists")
            .1
            .split_once("pub async fn consume_document_launch_grant")
            .expect("handoff redemption follows issuance")
            .0;
        assert!(issuance.contains("consumed_at IS NOT NULL"));
        assert!(issuance.contains("return Err(DatabaseError::Conflict)"));
        assert!(issuance.contains("AND consumed_at IS NULL"));
        assert!(issuance.contains("FOR UPDATE OF p,s"));
    }

    #[test]
    fn view_participants_are_rejected_at_every_durable_write_boundary() {
        let source = include_str!("document.rs");
        let receipt = source
            .split_once("pub async fn receive_document_callback")
            .expect("callback receipt exists")
            .1
            .split_once("async fn received_document_revision_by_digest")
            .expect("revision lookup follows receipt")
            .0;
        assert!(receipt.contains("input.callback_kind == \"output_required\""));
        assert!(receipt.contains("document_participant_can_write"));

        let begin = source
            .split_once("pub async fn begin_document_revision")
            .expect("begin exists")
            .1
            .split_once("pub async fn finalize_document_revision")
            .expect("finalize follows begin")
            .0;
        assert!(begin.contains("p.mode"));
        assert!(begin.contains("document_participant_can_write"));

        let commit = source
            .split_once("pub async fn commit_document_revision")
            .expect("commit exists")
            .1
            .split_once("pub async fn reject_document_revision_for_authorization_change")
            .expect("authorization rejection follows commit")
            .0;
        assert!(commit.contains("p.mode"));
        assert!(commit.contains("document_participant_can_write"));
        assert!(!document_participant_can_write("view"));
        assert!(!document_participant_can_write("unknown"));
        for mode in ["comment", "review", "edit"] {
            assert!(document_participant_can_write(mode));
        }
    }

    #[test]
    fn node_manager_list_holds_the_exact_authorization_generation_fence() {
        let source = include_str!("document.rs");
        let list = source
            .split_once("pub async fn list_document_sessions_for_node")
            .expect("node list exists")
            .1
            .split_once("pub async fn document_session_for_principal")
            .expect("exact owner lookup follows node list")
            .0;
        assert!(list.contains("actor_principal_id"));
        assert!(list.contains("api_session_id"));
        assert!(list.contains("generations.as_array()"));
        assert!(list.contains("lock_authorization_fence("));
        assert!(list.contains("fetch_all(&mut *transaction)"));
    }
}

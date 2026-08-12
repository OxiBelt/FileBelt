// SPDX-License-Identifier: Apache-2.0

//! Authoritative PostgreSQL state for Markdown collaboration.

use sqlx::Row;
use uuid::Uuid;

use crate::{Database, DatabaseError, lock_collaboration_authorization_fence};

#[derive(Clone, Debug)]
pub struct CollaborationSummaryRecord {
    pub room_id: Uuid,
    pub epoch: i64,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub base_version_id: Uuid,
    pub state: String,
    pub durable_sequence: i64,
    pub fencing_token: i64,
    pub expires_at: String,
    pub warning_at: String,
}

#[derive(Clone, Debug)]
pub struct CollaborationObjectRecord {
    pub id: Uuid,
    pub room_id: Uuid,
    pub epoch: i64,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub fencing_token: i64,
    pub payload_id: Uuid,
    pub backend_id: Uuid,
    pub payload_locator: Uuid,
    pub purpose: String,
    pub state: String,
    pub reserved_bytes: i64,
    pub size_bytes: Option<i64>,
    pub blake3: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct CollaborationJoinGrantRecord {
    pub id: Uuid,
    pub room_id: Uuid,
    pub epoch: i64,
    pub principal_id: Uuid,
    pub session_id: Uuid,
    pub client_id: Uuid,
    pub presence_mode: String,
    pub presence_label: String,
    pub can_checkpoint: bool,
    pub expires_at: String,
}

#[derive(Clone, Debug)]
pub struct CollaborationUpdateChunkInput {
    pub chunk_index: i32,
    pub object_offset: i64,
    pub size_bytes: i32,
    pub blake3: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CollaborationReplayGroupRecord {
    pub object: CollaborationObjectRecord,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub chunks: Vec<CollaborationUpdateChunkInput>,
}

/// A durable full-state CRDT snapshot used as a bounded replay anchor.
#[derive(Clone, Debug)]
pub struct CollaborationSnapshotRecord {
    pub object: CollaborationObjectRecord,
    pub covered_sequence: i64,
    pub state_vector: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CollaborationRetentionReport {
    pub warnings_emitted: u64,
    pub epochs_expired: u64,
    pub payload_deletions_enqueued: u64,
    pub objects_abandoned: u64,
}

#[derive(Clone, Debug)]
pub struct CollaborationImportIntentRecord {
    pub id: Uuid,
    pub drive_id: Uuid,
    pub source_node_id: Uuid,
    pub source_version_id: Uuid,
    pub target_parent_id: Uuid,
    pub target_display_name: String,
    pub target_name_key: String,
    pub expires_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollaborationAuthorizationGenerations {
    pub membership: i64,
    pub drive_acl: i64,
    pub namespace: i64,
    pub resource_acl: i64,
}

/// The current Virtual ACL projection that must remain valid when a
/// collaboration object becomes durable or is made authoritative in a room
/// manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollaborationAuthorizationContext {
    pub principal_id: Uuid,
    pub session_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub generations: CollaborationAuthorizationGenerations,
}

impl CollaborationAuthorizationContext {
    const fn expected_generations(self) -> [i64; 4] {
        [
            self.generations.membership,
            self.generations.drive_acl,
            self.generations.namespace,
            self.generations.resource_acl,
        ]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CollaborationImportIntentInput<'a> {
    pub tenant_id: Uuid,
    pub drive_id: Uuid,
    pub source_node_id: Uuid,
    pub source_version_id: Uuid,
    pub principal_id: Uuid,
    pub session_id: Uuid,
    pub source_generations: CollaborationAuthorizationGenerations,
    pub target_generations: CollaborationAuthorizationGenerations,
    pub target_display_name: &'a str,
    pub target_name_key: &'a str,
}

impl Database {
    #[allow(clippy::too_many_arguments)]
    pub async fn collaboration_prepare_checkpoint(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        expected_fencing_token: i64,
        authorization: CollaborationAuthorizationContext,
        durable_sequence: i64,
        state_vector: &[u8],
        source_size_bytes: i64,
        source_blake3: &[u8],
    ) -> Result<Uuid, DatabaseError> {
        if durable_sequence < 0
            || state_vector.len() > 1_048_576
            || !(0..=16_777_216).contains(&source_size_bytes)
            || source_blake3.len() != 32
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        lock_collaboration_authorization_fence(
            &mut transaction,
            tenant_id,
            authorization.principal_id,
            authorization.session_id,
            authorization.drive_id,
            authorization.node_id,
            authorization.expected_generations(),
        )
        .await?;
        let room = sqlx::query(
            "SELECT node_id,base_version_id,durable_sequence,fencing_token \
             FROM filebelt_collaboration.epochs WHERE tenant_id=$1 AND room_id=$2 \
               AND epoch=$3 AND state='active' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        if room.get::<Uuid, _>("node_id") != authorization.node_id
            || room.get::<i64, _>("durable_sequence") != durable_sequence
            || room.get::<i64, _>("fencing_token") != expected_fencing_token
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let mcp_assisted: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_collaboration.update_groups g \
             JOIN filebelt_mcp.invocations i ON i.tenant_id=g.tenant_id \
               AND i.id=g.mcp_invocation_id \
             WHERE g.tenant_id=$1 AND g.room_id=$2 AND g.epoch=$3 \
               AND g.origin_kind='mcp' AND g.last_sequence<=$4 \
               AND i.principal_id=g.actor_principal_id \
               AND i.application_id='filebelt-web-markdown-proposal' \
               AND i.state='succeeded' AND i.semantic_node_id=$5 \
               AND i.semantic_base_version_id=$6 \
               AND i.semantic_input_digest=g.source_before_digest \
               AND i.semantic_output_digest=g.source_after_digest)",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(durable_sequence)
        .bind(authorization.node_id)
        .bind(room.get::<Uuid, _>("base_version_id"))
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_collaboration.checkpoints SET state='expired' \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND state='prepared'",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .execute(&mut *transaction)
        .await?;
        let checkpoint_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO filebelt_collaboration.checkpoints \
             (tenant_id,id,room_id,epoch,node_id,base_version_id,durable_sequence, \
              state_vector,source_size_bytes,source_blake3,created_by,mcp_assisted,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, \
                     clock_timestamp()+interval '5 minutes')",
        )
        .bind(tenant_id)
        .bind(checkpoint_id)
        .bind(room_id)
        .bind(epoch)
        .bind(room.get::<Uuid, _>("node_id"))
        .bind(room.get::<Uuid, _>("base_version_id"))
        .bind(durable_sequence)
        .bind(state_vector)
        .bind(source_size_bytes)
        .bind(source_blake3)
        .bind(authorization.principal_id)
        .bind(mcp_assisted)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(checkpoint_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn collaboration_join_participant(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        client_id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
        max_participants: i64,
    ) -> Result<Uuid, DatabaseError> {
        if !(1..=32).contains(&max_participants) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "SELECT 1 FROM filebelt_collaboration.epochs \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND state='active' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        sqlx::query(
            "DELETE FROM filebelt_collaboration.participants \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND expires_at<=clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .execute(&mut *transaction)
        .await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM filebelt_collaboration.participants \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_one(&mut *transaction)
        .await?;
        if count >= max_participants {
            return Err(DatabaseError::AdmissionLimited);
        }
        let connection_id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO filebelt_collaboration.participants \
             (tenant_id,room_id,epoch,client_id,connection_id,principal_id,session_id,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '90 seconds') \
             ON CONFLICT (tenant_id,room_id,epoch,client_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(client_id)
        .bind(connection_id)
        .bind(principal_id)
        .bind(session_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit().await?;
        Ok(connection_id)
    }

    pub async fn collaboration_heartbeat_participant(
        &self,
        tenant_id: Uuid,
        connection_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let affected = sqlx::query(
            "UPDATE filebelt_collaboration.participants SET \
               last_seen_at=clock_timestamp(),expires_at=clock_timestamp()+interval '90 seconds' \
             WHERE tenant_id=$1 AND connection_id=$2 AND expires_at>clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(DatabaseError::StaleGeneration)
        }
    }

    pub async fn collaboration_leave_participant(
        &self,
        tenant_id: Uuid,
        connection_id: Uuid,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            "DELETE FROM filebelt_collaboration.participants \
             WHERE tenant_id=$1 AND connection_id=$2",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn collaboration_epoch_is_current(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        expected_fencing_token: i64,
        base_version_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        let current: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM filebelt_collaboration.epochs e \
             JOIN public.nodes n ON n.tenant_id=e.tenant_id AND n.drive_id=e.drive_id AND n.id=e.node_id \
             WHERE e.tenant_id=$1 AND e.room_id=$2 AND e.epoch=$3 AND e.state='active' \
               AND e.fencing_token=$4 AND e.base_version_id=$5 AND n.head_version_id=$5 \
               AND n.trash_root_id IS NULL)",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(expected_fencing_token)
        .bind(base_version_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(current)
    }

    pub async fn collaboration_room(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
    ) -> Result<Option<CollaborationSummaryRecord>, DatabaseError> {
        let row = sqlx::query("SELECT e.room_id,e.epoch,e.drive_id,e.node_id,e.base_version_id,e.state,e.durable_sequence,e.fencing_token,e.expires_at::text AS expires_at,e.warning_at::text AS warning_at FROM filebelt_collaboration.rooms r JOIN filebelt_collaboration.epochs e ON e.tenant_id=r.tenant_id AND e.room_id=r.id AND e.epoch=r.current_epoch WHERE r.tenant_id=$1 AND r.drive_id=$2 AND r.node_id=$3")
            .bind(tenant_id).bind(drive_id).bind(node_id).fetch_optional(&self.pool).await?;
        Ok(row.as_ref().map(summary_from_row))
    }

    pub async fn collaboration_get_or_create_room(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
        base_version_id: Uuid,
        created_by: Uuid,
    ) -> Result<CollaborationSummaryRecord, DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        if let Some(row) = sqlx::query("SELECT e.room_id,e.epoch,e.drive_id,e.node_id,e.base_version_id,e.state,e.durable_sequence,e.fencing_token,e.expires_at::text AS expires_at,e.warning_at::text AS warning_at FROM filebelt_collaboration.rooms r JOIN filebelt_collaboration.epochs e ON e.tenant_id=r.tenant_id AND e.room_id=r.id AND e.epoch=r.current_epoch WHERE r.tenant_id=$1 AND r.drive_id=$2 AND r.node_id=$3 FOR UPDATE OF r,e")
            .bind(tenant_id).bind(drive_id).bind(node_id).fetch_optional(&mut *transaction).await? {
            let state: String = row.get("state");
            if state == "active" && row.get::<Uuid, _>("base_version_id") != base_version_id {
                sqlx::query("UPDATE filebelt_collaboration.epochs SET state='frozen',freeze_reason='external_head',fencing_token=fencing_token+1 WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND state='active'")
                    .bind(tenant_id).bind(row.get::<Uuid,_>("room_id")).bind(row.get::<i64,_>("epoch")).execute(&mut *transaction).await?;
                transaction.commit().await?;
                return Err(DatabaseError::Conflict);
            }
            if state == "active" {
                transaction.commit().await?;
                return Ok(summary_from_row(&row));
            }
            if state == "frozen" {
                transaction.commit().await?;
                return Err(DatabaseError::Conflict);
            }
            let room_id: Uuid = row.get("room_id");
            let epoch = row
                .get::<i64, _>("epoch")
                .checked_add(1)
                .ok_or(DatabaseError::InvalidPersistedValue)?;
            let next = sqlx::query("INSERT INTO filebelt_collaboration.epochs (tenant_id,room_id,epoch,drive_id,node_id,base_version_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING room_id,epoch,drive_id,node_id,base_version_id,state,durable_sequence,fencing_token,expires_at::text AS expires_at,warning_at::text AS warning_at")
                .bind(tenant_id).bind(room_id).bind(epoch).bind(drive_id).bind(node_id).bind(base_version_id).fetch_one(&mut *transaction).await?;
            sqlx::query("UPDATE filebelt_collaboration.rooms SET current_epoch=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(tenant_id).bind(room_id).bind(epoch).execute(&mut *transaction).await?;
            transaction.commit().await?;
            return Ok(summary_from_row(&next));
        }
        let room_id = Uuid::new_v4();
        sqlx::query("INSERT INTO filebelt_collaboration.rooms (tenant_id,id,drive_id,node_id,created_by) VALUES ($1,$2,$3,$4,$5)")
            .bind(tenant_id).bind(room_id).bind(drive_id).bind(node_id).bind(created_by).execute(&mut *transaction).await?;
        let row = sqlx::query("INSERT INTO filebelt_collaboration.epochs (tenant_id,room_id,epoch,drive_id,node_id,base_version_id) VALUES ($1,$2,1,$3,$4,$5) RETURNING room_id,epoch,drive_id,node_id,base_version_id,state,durable_sequence,fencing_token,expires_at::text AS expires_at,warning_at::text AS warning_at")
            .bind(tenant_id).bind(room_id).bind(drive_id).bind(node_id).bind(base_version_id).fetch_one(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(summary_from_row(&row))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn collaboration_create_join_grant(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        room_id: Uuid,
        epoch: i64,
        token_digest: &[u8],
        principal_id: Uuid,
        session_id: Uuid,
        client_id: Uuid,
        presence_mode: &str,
        presence_label: &str,
        resource_acl_generation: i64,
        drive_acl_generation: i64,
        membership_generation: i64,
        namespace_generation: i64,
        can_checkpoint: bool,
    ) -> Result<CollaborationJoinGrantRecord, DatabaseError> {
        let row = sqlx::query("INSERT INTO filebelt_collaboration.join_grants (tenant_id,id,token_digest,room_id,epoch,principal_id,session_id,client_id,presence_mode,presence_label,resource_acl_generation,drive_acl_generation,membership_generation,namespace_generation,can_checkpoint,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp()+interval '60 seconds' FROM filebelt_collaboration.epochs WHERE tenant_id=$1 AND room_id=$4 AND epoch=$5 AND state='active' RETURNING id,room_id,epoch,principal_id,session_id,client_id,presence_mode,presence_label,can_checkpoint,expires_at::text AS expires_at")
            .bind(tenant_id).bind(id).bind(token_digest).bind(room_id).bind(epoch).bind(principal_id).bind(session_id).bind(client_id).bind(presence_mode).bind(presence_label).bind(resource_acl_generation).bind(drive_acl_generation).bind(membership_generation).bind(namespace_generation).bind(can_checkpoint)
            .fetch_optional(&self.pool).await?.ok_or(DatabaseError::Conflict)?;
        Ok(join_grant_from_row(&row))
    }

    pub async fn collaboration_consume_join_grant(
        &self,
        tenant_id: Uuid,
        token_digest: &[u8],
    ) -> Result<CollaborationJoinGrantRecord, DatabaseError> {
        let row = sqlx::query("UPDATE filebelt_collaboration.join_grants g SET consumed_at=clock_timestamp() FROM filebelt_collaboration.epochs e WHERE g.tenant_id=$1 AND g.token_digest=$2 AND g.consumed_at IS NULL AND g.expires_at>clock_timestamp() AND e.tenant_id=g.tenant_id AND e.room_id=g.room_id AND e.epoch=g.epoch AND e.state='active' RETURNING g.id,g.room_id,g.epoch,g.principal_id,g.session_id,g.client_id,g.presence_mode,g.presence_label,g.can_checkpoint,g.expires_at::text AS expires_at")
            .bind(tenant_id).bind(token_digest).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(join_grant_from_row(&row))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn collaboration_reserve_object(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        drive_id: Uuid,
        purpose: &str,
        reserved_bytes: i64,
        expected_fencing_token: i64,
    ) -> Result<CollaborationObjectRecord, DatabaseError> {
        if !matches!(purpose, "update_group" | "snapshot") || reserved_bytes < 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        let epoch_row = sqlx::query("SELECT node_id,fencing_token FROM filebelt_collaboration.epochs WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND drive_id=$4 AND state='active' FOR UPDATE")
            .bind(tenant_id).bind(room_id).bind(epoch).bind(drive_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StaleGeneration)?;
        if epoch_row.get::<i64, _>("fencing_token") != expected_fencing_token {
            return Err(DatabaseError::StaleGeneration);
        }
        if sqlx::query("UPDATE public.drives SET reserved_bytes=reserved_bytes+$3 WHERE tenant_id=$1 AND id=$2 AND used_physical_bytes+reserved_bytes+$3<=quota_bytes RETURNING id")
            .bind(tenant_id).bind(drive_id).bind(reserved_bytes).fetch_optional(&mut *transaction).await?.is_none() { return Err(DatabaseError::QuotaExceeded); }
        let backend_id: Uuid = sqlx::query("SELECT id FROM public.storage_backends WHERE tenant_id=$1 AND kind='posix' AND storage_ready AND capacity_checked_at>clock_timestamp()-interval '2 minutes' AND capacity_free_bytes-(SELECT COALESCE(sum(reserved_bytes),0) FROM public.drives WHERE tenant_id=$1)>=10737418240 AND (capacity_free_bytes-(SELECT COALESCE(sum(reserved_bytes),0) FROM public.drives WHERE tenant_id=$1))::numeric>=capacity_total_bytes::numeric*0.05 FOR SHARE")
            .bind(tenant_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::StorageUnavailable)?.get(0);
        let object_id = Uuid::new_v4();
        let payload_id = Uuid::new_v4();
        let locator = Uuid::new_v4();
        sqlx::query("INSERT INTO filebelt_collaboration.payload_objects (tenant_id,id,drive_id,backend_id,locator,layout,state,size_bytes,authority_kind) VALUES ($1,$2,$3,$4,$5,'whole','staging',$6,'collaboration')")
            .bind(tenant_id).bind(payload_id).bind(drive_id).bind(backend_id).bind(locator).bind(reserved_bytes).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO filebelt_collaboration.objects (tenant_id,id,room_id,epoch,drive_id,payload_id,purpose,reserved_bytes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(tenant_id).bind(object_id).bind(room_id).bind(epoch).bind(drive_id).bind(payload_id).bind(purpose).bind(reserved_bytes).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO filebelt_collaboration.object_reservations (tenant_id,object_id,drive_id,bytes,expires_at) VALUES ($1,$2,$3,$4,clock_timestamp()+interval '5 minutes')")
            .bind(tenant_id).bind(object_id).bind(drive_id).bind(reserved_bytes).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(CollaborationObjectRecord {
            id: object_id,
            room_id,
            epoch,
            drive_id,
            node_id: epoch_row.get("node_id"),
            fencing_token: expected_fencing_token,
            payload_id,
            backend_id,
            payload_locator: locator,
            purpose: purpose.into(),
            state: "staging".into(),
            reserved_bytes,
            size_bytes: None,
            blake3: None,
        })
    }

    pub async fn collaboration_object(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
    ) -> Result<CollaborationObjectRecord, DatabaseError> {
        let row=sqlx::query("SELECT o.id,o.room_id,o.epoch,o.drive_id,e.node_id,e.fencing_token,o.payload_id,p.backend_id,p.locator AS payload_locator,o.purpose,o.state,o.reserved_bytes,o.size_bytes,o.blake3 FROM filebelt_collaboration.objects o JOIN filebelt_collaboration.epochs e ON e.tenant_id=o.tenant_id AND e.room_id=o.room_id AND e.epoch=o.epoch JOIN filebelt_collaboration.payload_objects p ON p.tenant_id=o.tenant_id AND p.id=o.payload_id WHERE o.tenant_id=$1 AND o.id=$2")
            .bind(tenant_id).bind(object_id).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(object_from_row(&row))
    }

    /// Make a physically published whole collaboration object authoritative
    /// and convert its drive reservation into used bytes in one transaction.
    pub async fn collaboration_finalize_object(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
        expected_fencing_token: i64,
        authorization: CollaborationAuthorizationContext,
        size_bytes: i64,
        blake3: &[u8],
    ) -> Result<CollaborationObjectRecord, DatabaseError> {
        if size_bytes < 0 || blake3.len() != 32 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        lock_collaboration_authorization_fence(
            &mut transaction,
            tenant_id,
            authorization.principal_id,
            authorization.session_id,
            authorization.drive_id,
            authorization.node_id,
            authorization.expected_generations(),
        )
        .await?;
        let current = sqlx::query(
            "SELECT o.state,o.reserved_bytes,o.size_bytes,o.blake3, \
                    e.node_id,e.drive_id,e.state AS epoch_state,e.fencing_token, \
                    r.state AS reservation_state \
             FROM filebelt_collaboration.objects o \
             JOIN filebelt_collaboration.epochs e \
               ON e.tenant_id=o.tenant_id AND e.room_id=o.room_id AND e.epoch=o.epoch \
             JOIN filebelt_collaboration.object_reservations r \
               ON r.tenant_id=o.tenant_id AND r.object_id=o.id \
             JOIN filebelt_collaboration.payload_objects p \
               ON p.tenant_id=o.tenant_id AND p.id=o.payload_id \
             WHERE o.tenant_id=$1 AND o.id=$2 FOR UPDATE OF o,e,r,p",
        )
        .bind(tenant_id)
        .bind(object_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let object_state: String = current.get("state");
        if object_state == "durable" {
            let same = current.get::<Option<i64>, _>("size_bytes") == Some(size_bytes)
                && current.get::<Option<Vec<u8>>, _>("blake3").as_deref() == Some(blake3);
            transaction.commit().await?;
            return if same {
                self.collaboration_object(tenant_id, object_id).await
            } else {
                Err(DatabaseError::Conflict)
            };
        }
        let reserved_bytes: i64 = current.get("reserved_bytes");
        if current.get::<Uuid, _>("node_id") != authorization.node_id
            || current.get::<Uuid, _>("drive_id") != authorization.drive_id
            || object_state != "staging"
            || current.get::<String, _>("epoch_state") != "active"
            || current.get::<i64, _>("fencing_token") != expected_fencing_token
            || current.get::<String, _>("reservation_state") != "active"
            || size_bytes > reserved_bytes
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let payload_update = sqlx::query(
            "UPDATE filebelt_collaboration.payload_objects p \
             SET state='finalized',size_bytes=$3,blake3=$4,finalized_at=clock_timestamp() \
             FROM filebelt_collaboration.objects o \
             WHERE o.tenant_id=$1 AND o.id=$2 AND p.tenant_id=o.tenant_id \
               AND p.id=o.payload_id AND p.state='staging'",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(size_bytes)
        .bind(blake3)
        .execute(&mut *transaction)
        .await?;
        if payload_update.rows_affected() != 1 {
            return Err(DatabaseError::Conflict);
        }
        sqlx::query(
            "UPDATE filebelt_collaboration.objects \
             SET state='durable',size_bytes=$3,blake3=$4,durable_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND state='staging'",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(size_bytes)
        .bind(blake3)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_collaboration.object_reservations SET state='committed' \
             WHERE tenant_id=$1 AND object_id=$2 AND state='active'",
        )
        .bind(tenant_id)
        .bind(object_id)
        .execute(&mut *transaction)
        .await?;
        let drive_update = sqlx::query(
            "UPDATE public.drives d \
             SET reserved_bytes=reserved_bytes-$3,used_physical_bytes=used_physical_bytes+$4 \
             FROM filebelt_collaboration.objects o \
             WHERE o.tenant_id=$1 AND o.id=$2 AND d.tenant_id=o.tenant_id \
               AND d.id=o.drive_id AND d.reserved_bytes >= $3",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(reserved_bytes)
        .bind(size_bytes)
        .execute(&mut *transaction)
        .await?;
        if drive_update.rows_affected() != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit().await?;
        self.collaboration_object(tenant_id, object_id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn collaboration_persist_update_group(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        expected_fencing_token: i64,
        expected_base_sequence: i64,
        client_id: Uuid,
        client_update_id: Uuid,
        authorization: CollaborationAuthorizationContext,
        mcp_invocation_id: Option<Uuid>,
        source_before_digest: &[u8],
        source_after_digest: &[u8],
        object_id: Uuid,
        chunks: &[CollaborationUpdateChunkInput],
        state_vector: &[u8],
        state_digest: &[u8],
    ) -> Result<(Uuid, i64, i64), DatabaseError> {
        if chunks.is_empty()
            || chunks.len() > 16
            || expected_base_sequence < 0
            || state_vector.len() > 1_048_576
            || state_digest.len() != 32
            || source_before_digest.len() != 32
            || source_after_digest.len() != 32
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let total: i64 = chunks
            .iter()
            .try_fold(0_i64, |sum, c| sum.checked_add(i64::from(c.size_bytes)))
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        if total <= 0
            || total > 2_097_152
            || chunks.iter().enumerate().any(|(index, c)| {
                c.chunk_index < 0
                    || usize::try_from(c.chunk_index).ok() != Some(index)
                    || c.object_offset
                        != chunks[..index]
                            .iter()
                            .map(|previous| i64::from(previous.size_bytes))
                            .sum::<i64>()
                    || c.size_bytes <= 0
                    || c.size_bytes > 262_144
                    || c.blake3.len() != 32
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        lock_collaboration_authorization_fence(
            &mut transaction,
            tenant_id,
            authorization.principal_id,
            authorization.session_id,
            authorization.drive_id,
            authorization.node_id,
            authorization.expected_generations(),
        )
        .await?;
        let epoch_row=sqlx::query("SELECT durable_sequence,fencing_token,base_version_id FROM filebelt_collaboration.epochs WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND drive_id=$4 AND node_id=$5 AND state='active' FOR UPDATE")
            .bind(tenant_id).bind(room_id).bind(epoch).bind(authorization.drive_id).bind(authorization.node_id).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        if epoch_row.get::<i64, _>("fencing_token") != expected_fencing_token {
            return Err(DatabaseError::StaleGeneration);
        }
        if let Some(invocation_id) = mcp_invocation_id {
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM filebelt_mcp.invocations WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND application_id='filebelt-web-markdown-proposal' AND state='succeeded' AND semantic_node_id=$4 AND semantic_base_version_id=$5 AND semantic_input_digest=$6 AND semantic_output_digest=$7)",
            )
            .bind(tenant_id)
            .bind(invocation_id)
            .bind(authorization.principal_id)
            .bind(authorization.node_id)
            .bind(epoch_row.get::<Uuid, _>("base_version_id"))
            .bind(source_before_digest)
            .bind(source_after_digest)
            .fetch_one(&mut *transaction)
            .await?;
            if !valid {
                return Err(DatabaseError::Conflict);
            }
        }
        let incoming_digest: Vec<u8> = sqlx::query_scalar(
            "SELECT blake3 FROM filebelt_collaboration.objects WHERE tenant_id=$1 AND id=$2 \
             AND room_id=$3 AND epoch=$4 AND state='durable' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        if let Some(existing) = sqlx::query(
            "SELECT g.object_id,g.first_sequence,g.last_sequence,g.state_digest,g.mcp_invocation_id,g.source_before_digest,g.source_after_digest,o.blake3 \
             FROM filebelt_collaboration.update_groups g \
             JOIN filebelt_collaboration.objects o ON o.tenant_id=g.tenant_id AND o.id=g.object_id \
             WHERE g.tenant_id=$1 AND g.room_id=$2 AND g.epoch=$3 \
               AND g.client_id=$4 AND g.client_update_id=$5",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(client_id)
        .bind(client_update_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if existing.get::<Vec<u8>, _>("state_digest") != state_digest
                || existing.get::<Vec<u8>, _>("blake3") != incoming_digest
                || existing.get::<Option<Uuid>, _>("mcp_invocation_id") != mcp_invocation_id
                || existing.get::<Vec<u8>, _>("source_before_digest") != source_before_digest
                || existing.get::<Vec<u8>, _>("source_after_digest") != source_after_digest
            {
                return Err(DatabaseError::Conflict);
            }
            let durable_object: Uuid = existing.get("object_id");
            if durable_object != object_id {
                sqlx::query("UPDATE filebelt_collaboration.objects SET state='superseded',delete_after=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND id=$2 AND state='durable'")
                    .bind(tenant_id).bind(object_id).execute(&mut *transaction).await?;
            }
            let first = existing.get("first_sequence");
            let last = existing.get("last_sequence");
            transaction.commit().await?;
            return Ok((durable_object, first, last));
        }
        if epoch_row.get::<i64, _>("durable_sequence") != expected_base_sequence {
            sqlx::query("UPDATE filebelt_collaboration.objects SET state='superseded',delete_after=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND id=$2 AND state='durable'")
                .bind(tenant_id).bind(object_id).execute(&mut *transaction).await?;
            transaction.commit().await?;
            return Err(DatabaseError::StaleGeneration);
        }
        let first = epoch_row
            .get::<i64, _>("durable_sequence")
            .checked_add(1)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let last = first;
        let origin_kind = if mcp_invocation_id.is_some() {
            "mcp"
        } else {
            "user"
        };
        let inserted=sqlx::query("INSERT INTO filebelt_collaboration.update_groups (tenant_id,room_id,epoch,id,client_id,client_update_id,actor_principal_id,origin_kind,mcp_invocation_id,source_before_digest,source_after_digest,object_id,chunk_count,total_bytes,first_sequence,last_sequence,state_vector,state_digest) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18 WHERE EXISTS (SELECT 1 FROM filebelt_collaboration.objects WHERE tenant_id=$1 AND id=$12 AND room_id=$2 AND epoch=$3 AND state='durable')")
            .bind(tenant_id).bind(room_id).bind(epoch).bind(Uuid::new_v4()).bind(client_id).bind(client_update_id).bind(authorization.principal_id).bind(origin_kind).bind(mcp_invocation_id).bind(source_before_digest).bind(source_after_digest).bind(object_id).bind(i32::try_from(chunks.len()).map_err(|_|DatabaseError::InvalidPersistedValue)?).bind(total).bind(first).bind(last).bind(state_vector).bind(state_digest).execute(&mut *transaction).await?.rows_affected();
        if inserted != 1 {
            return Err(DatabaseError::Conflict);
        }
        let group_id:Uuid=sqlx::query_scalar("SELECT id FROM filebelt_collaboration.update_groups WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND client_id=$4 AND client_update_id=$5").bind(tenant_id).bind(room_id).bind(epoch).bind(client_id).bind(client_update_id).fetch_one(&mut *transaction).await?;
        for chunk in chunks {
            sqlx::query("INSERT INTO filebelt_collaboration.update_chunks (tenant_id,group_id,chunk_index,object_offset,size_bytes,blake3) VALUES ($1,$2,$3,$4,$5,$6)").bind(tenant_id).bind(group_id).bind(chunk.chunk_index).bind(chunk.object_offset).bind(chunk.size_bytes).bind(&chunk.blake3).execute(&mut *transaction).await?;
        }
        sqlx::query("UPDATE filebelt_collaboration.epochs SET durable_sequence=$4,dirty=true,last_content_activity_at=clock_timestamp(),expires_at=clock_timestamp()+interval '30 days',warning_at=clock_timestamp()+interval '23 days' WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3").bind(tenant_id).bind(room_id).bind(epoch).bind(last).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok((object_id, first, last))
    }

    pub async fn collaboration_replay_groups(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        after_sequence: i64,
    ) -> Result<Vec<CollaborationReplayGroupRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT o.id,o.room_id,o.epoch,o.drive_id,e.node_id,e.fencing_token, \
                    o.payload_id,p.backend_id,p.locator AS payload_locator,o.purpose,o.state, \
                    o.reserved_bytes,o.size_bytes,o.blake3,g.first_sequence,g.last_sequence \
             FROM filebelt_collaboration.update_groups g \
             JOIN filebelt_collaboration.objects o \
               ON o.tenant_id=g.tenant_id AND o.id=g.object_id \
             JOIN filebelt_collaboration.epochs e \
               ON e.tenant_id=o.tenant_id AND e.room_id=o.room_id AND e.epoch=o.epoch \
             JOIN filebelt_collaboration.payload_objects p \
               ON p.tenant_id=o.tenant_id AND p.id=o.payload_id \
             WHERE g.tenant_id=$1 AND g.room_id=$2 AND g.epoch=$3 \
               AND g.last_sequence>$4 AND o.state='durable' \
             ORDER BY g.first_sequence",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(after_sequence)
        .fetch_all(&self.pool)
        .await?;
        let mut groups = Vec::with_capacity(rows.len());
        for row in rows {
            let object = object_from_row(&row);
            let chunk_rows = sqlx::query(
                "SELECT c.chunk_index,c.object_offset,c.size_bytes,c.blake3 \
                 FROM filebelt_collaboration.update_groups g \
                 JOIN filebelt_collaboration.update_chunks c \
                   ON c.tenant_id=g.tenant_id AND c.group_id=g.id \
                 WHERE g.tenant_id=$1 AND g.room_id=$2 AND g.epoch=$3 \
                   AND g.object_id=$4 ORDER BY c.chunk_index",
            )
            .bind(tenant_id)
            .bind(room_id)
            .bind(epoch)
            .bind(object.id)
            .fetch_all(&self.pool)
            .await?;
            groups.push(CollaborationReplayGroupRecord {
                object,
                first_sequence: row.get("first_sequence"),
                last_sequence: row.get("last_sequence"),
                chunks: chunk_rows
                    .into_iter()
                    .map(|chunk| CollaborationUpdateChunkInput {
                        chunk_index: chunk.get("chunk_index"),
                        object_offset: chunk.get("object_offset"),
                        size_bytes: chunk.get("size_bytes"),
                        blake3: chunk.get("blake3"),
                    })
                    .collect(),
            });
        }
        Ok(groups)
    }

    /// Return the newest verified full-state snapshot, if compaction has made
    /// one authoritative for the epoch.
    pub async fn collaboration_current_snapshot(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
    ) -> Result<Option<CollaborationSnapshotRecord>, DatabaseError> {
        let row = sqlx::query(
            "SELECT o.id,o.room_id,o.epoch,o.drive_id,e.node_id,e.fencing_token, \
                    o.payload_id,p.backend_id,p.locator AS payload_locator,o.purpose,o.state, \
                    o.reserved_bytes,o.size_bytes,o.blake3,s.covered_sequence,s.state_vector \
             FROM filebelt_collaboration.snapshots s \
             JOIN filebelt_collaboration.objects o ON o.tenant_id=s.tenant_id AND o.id=s.object_id \
             JOIN filebelt_collaboration.epochs e ON e.tenant_id=o.tenant_id \
               AND e.room_id=o.room_id AND e.epoch=o.epoch \
             JOIN filebelt_collaboration.payload_objects p ON p.tenant_id=o.tenant_id AND p.id=o.payload_id \
             WHERE s.tenant_id=$1 AND s.room_id=$2 AND s.epoch=$3 \
               AND s.superseded_at IS NULL AND o.state='durable' AND p.state='finalized'",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| CollaborationSnapshotRecord {
            object: object_from_row(&row),
            covered_sequence: row.get("covered_sequence"),
            state_vector: row.get("state_vector"),
        }))
    }

    /// Make a finalized snapshot the replay anchor and supersede manifests it
    /// covers. The snapshot payload remains retained until the epoch cleanup
    /// transition, so PostgreSQL can always prove the recovery anchor.
    #[allow(clippy::too_many_arguments)]
    pub async fn collaboration_commit_snapshot(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        expected_fencing_token: i64,
        authorization: CollaborationAuthorizationContext,
        object_id: Uuid,
        covered_sequence: i64,
        state_vector: &[u8],
    ) -> Result<Uuid, DatabaseError> {
        if covered_sequence < 0 || state_vector.len() > 1_048_576 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool.begin().await?;
        lock_collaboration_authorization_fence(
            &mut transaction,
            tenant_id,
            authorization.principal_id,
            authorization.session_id,
            authorization.drive_id,
            authorization.node_id,
            authorization.expected_generations(),
        )
        .await?;
        let epoch_row = sqlx::query(
            "SELECT durable_sequence,fencing_token FROM filebelt_collaboration.epochs \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND drive_id=$4 AND node_id=$5 \
               AND state='active' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(authorization.drive_id)
        .bind(authorization.node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        if epoch_row.get::<i64, _>("fencing_token") != expected_fencing_token
            || covered_sequence > epoch_row.get::<i64, _>("durable_sequence")
        {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "SELECT 1 FROM filebelt_collaboration.objects WHERE tenant_id=$1 AND id=$2 \
             AND room_id=$3 AND epoch=$4 AND purpose='snapshot' AND state='durable' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        if let Some(current) = sqlx::query(
            "SELECT id,object_id,covered_sequence FROM filebelt_collaboration.snapshots \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND superseded_at IS NULL FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let current_sequence: i64 = current.get("covered_sequence");
            if current_sequence > covered_sequence {
                return Err(DatabaseError::StaleGeneration);
            }
            if current_sequence == covered_sequence {
                let current_object: Uuid = current.get("object_id");
                transaction.commit().await?;
                return if current_object == object_id {
                    Ok(current.get("id"))
                } else {
                    Err(DatabaseError::Conflict)
                };
            }
            sqlx::query(
                "UPDATE filebelt_collaboration.snapshots SET superseded_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND id=$2 AND superseded_at IS NULL",
            )
            .bind(tenant_id)
            .bind(current.get::<Uuid, _>("id"))
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE filebelt_collaboration.objects SET state='superseded', \
                   delete_after=clock_timestamp()+interval '1 day' \
                 WHERE tenant_id=$1 AND id=$2 AND state='durable'",
            )
            .bind(tenant_id)
            .bind(current.get::<Uuid, _>("object_id"))
            .execute(&mut *transaction)
            .await?;
        }
        let snapshot_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO filebelt_collaboration.snapshots \
             (tenant_id,room_id,epoch,id,object_id,covered_sequence,state_vector) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(snapshot_id)
        .bind(object_id)
        .bind(covered_sequence)
        .bind(state_vector)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE filebelt_collaboration.objects o SET state='superseded', \
               delete_after=clock_timestamp()+interval '1 day' \
             FROM filebelt_collaboration.update_groups g \
             WHERE o.tenant_id=$1 AND o.tenant_id=g.tenant_id AND o.id=g.object_id \
               AND g.room_id=$2 AND g.epoch=$3 AND g.last_sequence<=$4 AND o.state='durable'",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(covered_sequence)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(snapshot_id)
    }

    /// Make an object that never reached a durable room manifest reclaimable.
    ///
    /// Staging objects release their reservation immediately. Finalized objects
    /// retain their used-byte accounting until maintenance confirms physical
    /// deletion. Manifest-referenced objects are deliberately never abandoned.
    pub async fn collaboration_abandon_object(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT o.id,o.payload_id,o.drive_id,o.state,o.reserved_bytes,o.size_bytes, \
                    r.state AS reservation_state \
             FROM filebelt_collaboration.objects o \
             JOIN filebelt_collaboration.object_reservations r \
               ON r.tenant_id=o.tenant_id AND r.object_id=o.id \
             JOIN filebelt_collaboration.payload_objects p \
               ON p.tenant_id=o.tenant_id AND p.id=o.payload_id \
             WHERE o.tenant_id=$1 AND o.id=$2 FOR UPDATE OF o,r,p",
        )
        .bind(tenant_id)
        .bind(object_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let state: String = row.get("state");
        if matches!(
            state.as_str(),
            "quarantined" | "delete_intent" | "tombstoned" | "abandoned"
        ) {
            transaction.commit().await?;
            return Ok(());
        }
        let referenced: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_collaboration.update_groups \
             WHERE tenant_id=$1 AND object_id=$2) OR EXISTS ( \
               SELECT 1 FROM filebelt_collaboration.snapshots WHERE tenant_id=$1 AND object_id=$2)",
        )
        .bind(tenant_id)
        .bind(object_id)
        .fetch_one(&mut *transaction)
        .await?;
        if referenced {
            return Err(DatabaseError::Conflict);
        }
        let payload_id: Uuid = row.get("payload_id");
        let drive_id: Uuid = row.get("drive_id");
        let payload_state = match state.as_str() {
            "staging" => {
                let released = sqlx::query(
                    "UPDATE filebelt_collaboration.object_reservations SET state='released' \
                     WHERE tenant_id=$1 AND object_id=$2 AND state='active'",
                )
                .bind(tenant_id)
                .bind(object_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if released != 1 || row.get::<String, _>("reservation_state") != "active" {
                    return Err(DatabaseError::StaleGeneration);
                }
                let drive = sqlx::query(
                    "UPDATE public.drives SET reserved_bytes=reserved_bytes-$3 \
                     WHERE tenant_id=$1 AND id=$2 AND reserved_bytes>=$3",
                )
                .bind(tenant_id)
                .bind(drive_id)
                .bind(row.get::<i64, _>("reserved_bytes"))
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                let object = sqlx::query(
                    "UPDATE filebelt_collaboration.objects SET state='quarantined' \
                     WHERE tenant_id=$1 AND id=$2 AND state='staging'",
                )
                .bind(tenant_id)
                .bind(object_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if drive != 1 || object != 1 {
                    return Err(DatabaseError::StaleGeneration);
                }
                // Phase-2 payload integrity requires delete-intent objects to
                // have a final digest. A collaboration object abandoned before
                // finalization instead remains explicitly abandoned while the
                // maintenance worker removes any partial staging bytes.
                "abandoned"
            }
            "durable" | "superseded" => {
                if row.get::<String, _>("reservation_state") != "committed"
                    || row.get::<Option<i64>, _>("size_bytes").is_none()
                {
                    return Err(DatabaseError::StaleGeneration);
                }
                let object = sqlx::query(
                    "UPDATE filebelt_collaboration.objects SET state='delete_intent',delete_after=clock_timestamp() \
                     WHERE tenant_id=$1 AND id=$2 AND state IN ('durable','superseded')",
                )
                .bind(tenant_id)
                .bind(object_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if object != 1 {
                    return Err(DatabaseError::StaleGeneration);
                }
                "delete_intent"
            }
            _ => return Err(DatabaseError::Conflict),
        };
        let payload = sqlx::query(
            "UPDATE filebelt_collaboration.payload_objects SET state=$3, \
               deletion_intent_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 \
               AND state IN ('staging','finalized')",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .bind(payload_state)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if payload != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "INSERT INTO public.jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) \
             VALUES ($1,$2,'payload_delete','queued',80,$3,$4,$5) ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(payload_id)
        .bind(format!("collaboration-abandon:{payload_id}"))
        .bind(serde_json::json!({"payload_id": payload_id}))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Fence expired dirty epochs and enqueue payload deletion only after their
    /// durable manifests have been retained through the configured deadline.
    pub async fn collaboration_retention_sweep(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<CollaborationRetentionReport, DatabaseError> {
        if !(1..=1_000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let abandoned_candidates: Vec<Uuid> = sqlx::query_scalar(
            "SELECT o.id FROM filebelt_collaboration.objects o \
             JOIN filebelt_collaboration.object_reservations r \
               ON r.tenant_id=o.tenant_id AND r.object_id=o.id \
             WHERE o.tenant_id=$1 AND ( \
               (o.state='staging' AND r.state='active' AND r.expires_at<=clock_timestamp()) OR \
               (o.state='durable' AND o.durable_at<=clock_timestamp()-interval '5 minutes' \
                AND NOT EXISTS (SELECT 1 FROM filebelt_collaboration.update_groups g \
                  WHERE g.tenant_id=o.tenant_id AND g.object_id=o.id) \
                AND NOT EXISTS (SELECT 1 FROM filebelt_collaboration.snapshots s \
                  WHERE s.tenant_id=o.tenant_id AND s.object_id=o.id)) \
             ) ORDER BY o.created_at LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut objects_abandoned = 0_u64;
        for object_id in abandoned_candidates {
            match self
                .collaboration_abandon_object(tenant_id, object_id)
                .await
            {
                Ok(()) => objects_abandoned += 1,
                Err(
                    DatabaseError::Conflict
                    | DatabaseError::StaleGeneration
                    | DatabaseError::NotFound,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        let mut transaction = self.pool.begin().await?;
        let warnings = sqlx::query(
            "UPDATE filebelt_collaboration.epochs SET warning_emitted_at=clock_timestamp() \
             WHERE (tenant_id,room_id,epoch) IN ( \
               SELECT tenant_id,room_id,epoch FROM filebelt_collaboration.epochs \
               WHERE tenant_id=$1 AND dirty AND state IN ('active','frozen') \
                 AND warning_at<=clock_timestamp() AND expires_at>clock_timestamp() \
                 AND warning_emitted_at IS NULL ORDER BY warning_at LIMIT $2 FOR UPDATE SKIP LOCKED \
             )",
        )
        .bind(tenant_id)
        .bind(limit)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let expired = sqlx::query(
            "UPDATE filebelt_collaboration.epochs SET state='tombstoned',dirty=false, \
               freeze_reason=NULL,closed_at=clock_timestamp(),fencing_token=fencing_token+1 \
             WHERE (tenant_id,room_id,epoch) IN ( \
               SELECT tenant_id,room_id,epoch FROM filebelt_collaboration.epochs \
               WHERE tenant_id=$1 AND dirty AND state IN ('active','frozen') \
                 AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED \
             ) RETURNING room_id,epoch",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        let mut enqueued = 0_u64;
        for row in &expired {
            let room_id: Uuid = row.get("room_id");
            let epoch: i64 = row.get("epoch");
            let payloads = sqlx::query(
                "UPDATE filebelt_collaboration.payload_objects p SET state='delete_intent',deletion_intent_at=clock_timestamp() \
                 FROM filebelt_collaboration.objects o \
                 WHERE p.tenant_id=$1 AND p.tenant_id=o.tenant_id AND p.id=o.payload_id \
                   AND o.room_id=$2 AND o.epoch=$3 \
                   AND o.state IN ('durable','superseded') AND p.state='finalized' \
                 RETURNING p.id",
            )
            .bind(tenant_id)
            .bind(room_id)
            .bind(epoch)
            .fetch_all(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE filebelt_collaboration.objects SET state='delete_intent',delete_after=clock_timestamp() \
                 WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND state IN ('durable','superseded')",
            )
            .bind(tenant_id)
            .bind(room_id)
            .bind(epoch)
            .execute(&mut *transaction)
            .await?;
            for payload in payloads {
                let payload_id: Uuid = payload.get("id");
                enqueued += sqlx::query(
                    "INSERT INTO public.jobs (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) \
                     VALUES ($1,$2,'payload_delete','queued',80,$3,$4,$5) ON CONFLICT DO NOTHING",
                )
                .bind(tenant_id)
                .bind(Uuid::new_v4())
                .bind(payload_id)
                .bind(format!("collaboration-expire:{payload_id}"))
                .bind(serde_json::json!({"payload_id": payload_id}))
                .execute(&mut *transaction)
                .await?
                .rows_affected();
            }
        }
        let superseded = sqlx::query(
            "SELECT id,payload_id FROM filebelt_collaboration.objects \
             WHERE tenant_id=$1 AND state='superseded' AND delete_after<=clock_timestamp() \
             ORDER BY delete_after LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        for row in superseded {
            let object_id: Uuid = row.get("id");
            let payload_id: Uuid = row.get("payload_id");
            let payload = sqlx::query(
                "UPDATE filebelt_collaboration.payload_objects SET state='delete_intent', \
                   deletion_intent_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND id=$2 AND state='finalized'",
            )
            .bind(tenant_id)
            .bind(payload_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if payload != 1 {
                continue;
            }
            sqlx::query(
                "UPDATE filebelt_collaboration.objects SET state='delete_intent' \
                 WHERE tenant_id=$1 AND id=$2 AND state='superseded'",
            )
            .bind(tenant_id)
            .bind(object_id)
            .execute(&mut *transaction)
            .await?;
            enqueued += sqlx::query(
                "INSERT INTO public.jobs \
                   (tenant_id,id,kind,state,priority,aggregate_id,idempotency_key,payload) \
                 VALUES ($1,$2,'payload_delete','queued',80,$3,$4,$5) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(tenant_id)
            .bind(Uuid::new_v4())
            .bind(payload_id)
            .bind(format!("collaboration-superseded:{payload_id}"))
            .bind(serde_json::json!({"payload_id": payload_id}))
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        }
        transaction.commit().await?;
        Ok(CollaborationRetentionReport {
            warnings_emitted: warnings,
            epochs_expired: expired.len() as u64,
            payload_deletions_enqueued: enqueued,
            objects_abandoned,
        })
    }

    /// Record physical deletion of an abandoned collaboration payload and
    /// return committed bytes to the drive quota exactly once. Staging
    /// reservations were released before their delete job was queued.
    pub async fn complete_collaboration_payload_deletion(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT o.id,o.drive_id,o.size_bytes,o.state,p.state AS payload_state, \
                    r.state AS reservation_state \
             FROM filebelt_collaboration.objects o \
             JOIN filebelt_collaboration.payload_objects p ON p.tenant_id=o.tenant_id AND p.id=o.payload_id \
             JOIN filebelt_collaboration.object_reservations r \
               ON r.tenant_id=o.tenant_id AND r.object_id=o.id \
             WHERE o.tenant_id=$1 AND o.payload_id=$2 \
               AND o.state IN ('delete_intent','quarantined','tombstoned','abandoned') \
               AND p.state IN ('deleting','deleted','abandoned') \
             FOR UPDATE OF o,p,r",
        )
        .bind(tenant_id)
        .bind(payload_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        if matches!(
            row.get::<String, _>("state").as_str(),
            "tombstoned" | "abandoned"
        ) {
            transaction.commit().await?;
            return Ok(());
        }
        let object_id: Uuid = row.get("id");
        let drive_id: Uuid = row.get("drive_id");
        let size: Option<i64> = row.get("size_bytes");
        let reservation_state: String = row.get("reservation_state");
        let payload_state: String = row.get("payload_state");
        let payload = if payload_state == "deleting" {
            sqlx::query(
                "UPDATE filebelt_collaboration.payload_objects SET state='deleted' \
                 WHERE tenant_id=$1 AND id=$2 AND state='deleting'",
            )
            .bind(tenant_id)
            .bind(payload_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        } else if payload_state == "abandoned" {
            1
        } else {
            return Err(DatabaseError::StaleGeneration);
        };
        let final_object_state = if size.is_some() {
            "tombstoned"
        } else {
            "abandoned"
        };
        let object = sqlx::query(
            "UPDATE filebelt_collaboration.objects SET state=$3 \
             WHERE tenant_id=$1 AND id=$2 AND state IN ('delete_intent','quarantined')",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(final_object_state)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let drive = if let Some(size) = size {
            if reservation_state != "committed" {
                return Err(DatabaseError::StaleGeneration);
            }
            sqlx::query(
                "UPDATE public.drives SET used_physical_bytes=used_physical_bytes-$3 \
                 WHERE tenant_id=$1 AND id=$2 AND used_physical_bytes>=$3",
            )
            .bind(tenant_id)
            .bind(drive_id)
            .bind(size)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        } else {
            if reservation_state != "released" {
                return Err(DatabaseError::StaleGeneration);
            }
            1
        };
        if payload != 1 || object != 1 || drive != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn collaboration_freeze(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        reason: &str,
    ) -> Result<(), DatabaseError> {
        let affected=sqlx::query("UPDATE filebelt_collaboration.epochs SET state='frozen',freeze_reason=$4,fencing_token=fencing_token+1 WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND state='active'").bind(tenant_id).bind(room_id).bind(epoch).bind(reason).execute(&self.pool).await?.rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(DatabaseError::Conflict)
        }
    }
    pub async fn collaboration_discard(
        &self,
        tenant_id: Uuid,
        room_id: Uuid,
        epoch: i64,
        authorization: CollaborationAuthorizationContext,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool.begin().await?;
        lock_collaboration_authorization_fence(
            &mut transaction,
            tenant_id,
            authorization.principal_id,
            authorization.session_id,
            authorization.drive_id,
            authorization.node_id,
            authorization.expected_generations(),
        )
        .await?;
        let affected = sqlx::query(
            "UPDATE filebelt_collaboration.epochs SET \
               state=CASE WHEN dirty THEN 'frozen' ELSE 'closed' END, \
               freeze_reason=CASE WHEN dirty THEN 'discarded' ELSE NULL END, \
               closed_at=CASE WHEN dirty THEN NULL ELSE clock_timestamp() END, \
               warning_at=CASE WHEN dirty THEN clock_timestamp()-interval '1 microsecond' ELSE warning_at END, \
               expires_at=CASE WHEN dirty THEN clock_timestamp() ELSE expires_at END, \
               fencing_token=fencing_token+1 \
             WHERE tenant_id=$1 AND room_id=$2 AND epoch=$3 AND drive_id=$4 AND node_id=$5 \
               AND state IN ('active','frozen')",
        )
        .bind(tenant_id)
        .bind(room_id)
        .bind(epoch)
        .bind(authorization.drive_id)
        .bind(authorization.node_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if affected == 1 {
            transaction.commit().await?;
            Ok(())
        } else {
            Err(DatabaseError::Conflict)
        }
    }

    pub async fn collaboration_create_import_intent(
        &self,
        input: CollaborationImportIntentInput<'_>,
    ) -> Result<CollaborationImportIntentRecord, DatabaseError> {
        let id = Uuid::new_v4();
        let row=sqlx::query("INSERT INTO filebelt_collaboration.import_intents (tenant_id,id,drive_id,source_node_id,source_version_id,target_parent_id,target_display_name,target_name_key,principal_id,session_id,source_membership_generation,source_drive_acl_generation,source_namespace_generation,source_resource_acl_generation,target_membership_generation,target_drive_acl_generation,target_namespace_generation,target_resource_acl_generation,expires_at) SELECT $1,$2,$3,$4,$5,n.parent_id,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,clock_timestamp()+interval '15 minutes' FROM public.nodes n JOIN public.file_versions v ON v.tenant_id=n.tenant_id AND v.node_id=n.id AND v.id=$5 WHERE n.tenant_id=$1 AND n.drive_id=$3 AND n.id=$4 AND n.kind='file' AND n.parent_id IS NOT NULL AND n.trash_root_id IS NULL RETURNING id,drive_id,source_node_id,source_version_id,target_parent_id,target_display_name,target_name_key,expires_at::text AS expires_at").bind(input.tenant_id).bind(id).bind(input.drive_id).bind(input.source_node_id).bind(input.source_version_id).bind(input.target_display_name).bind(input.target_name_key).bind(input.principal_id).bind(input.session_id).bind(input.source_generations.membership).bind(input.source_generations.drive_acl).bind(input.source_generations.namespace).bind(input.source_generations.resource_acl).bind(input.target_generations.membership).bind(input.target_generations.drive_acl).bind(input.target_generations.namespace).bind(input.target_generations.resource_acl).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(import_from_row(&row))
    }
    pub async fn collaboration_consume_import_intent(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
    ) -> Result<CollaborationImportIntentRecord, DatabaseError> {
        let row=sqlx::query("UPDATE filebelt_collaboration.import_intents SET state='consumed',consumed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND session_id=$4 AND state='active' AND expires_at>clock_timestamp() RETURNING id,drive_id,source_node_id,source_version_id,target_parent_id,target_display_name,target_name_key,expires_at::text AS expires_at").bind(tenant_id).bind(id).bind(principal_id).bind(session_id).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)?;
        Ok(import_from_row(&row))
    }
}

fn summary_from_row(row: &sqlx::postgres::PgRow) -> CollaborationSummaryRecord {
    CollaborationSummaryRecord {
        room_id: row.get("room_id"),
        epoch: row.get("epoch"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        base_version_id: row.get("base_version_id"),
        state: row.get("state"),
        durable_sequence: row.get("durable_sequence"),
        fencing_token: row.get("fencing_token"),
        expires_at: row.get("expires_at"),
        warning_at: row.get("warning_at"),
    }
}
fn object_from_row(row: &sqlx::postgres::PgRow) -> CollaborationObjectRecord {
    CollaborationObjectRecord {
        id: row.get("id"),
        room_id: row.get("room_id"),
        epoch: row.get("epoch"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        fencing_token: row.get("fencing_token"),
        payload_id: row.get("payload_id"),
        backend_id: row.get("backend_id"),
        payload_locator: row.get("payload_locator"),
        purpose: row.get("purpose"),
        state: row.get("state"),
        reserved_bytes: row.get("reserved_bytes"),
        size_bytes: row.get("size_bytes"),
        blake3: row.get("blake3"),
    }
}
fn join_grant_from_row(row: &sqlx::postgres::PgRow) -> CollaborationJoinGrantRecord {
    CollaborationJoinGrantRecord {
        id: row.get("id"),
        room_id: row.get("room_id"),
        epoch: row.get("epoch"),
        principal_id: row.get("principal_id"),
        session_id: row.get("session_id"),
        client_id: row.get("client_id"),
        presence_mode: row.get("presence_mode"),
        presence_label: row.get("presence_label"),
        can_checkpoint: row.get("can_checkpoint"),
        expires_at: row.get("expires_at"),
    }
}
fn import_from_row(row: &sqlx::postgres::PgRow) -> CollaborationImportIntentRecord {
    CollaborationImportIntentRecord {
        id: row.get("id"),
        drive_id: row.get("drive_id"),
        source_node_id: row.get("source_node_id"),
        source_version_id: row.get("source_version_id"),
        target_parent_id: row.get("target_parent_id"),
        target_display_name: row.get("target_display_name"),
        target_name_key: row.get("target_name_key"),
        expires_at: row.get("expires_at"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshots_are_manifest_anchors_and_not_event_state() {
        let source = include_str!("collaboration.rs");
        let snapshot = source
            .split_once("pub async fn collaboration_current_snapshot")
            .expect("snapshot lookup exists")
            .1
            .split_once("pub async fn collaboration_commit_snapshot")
            .expect("snapshot commit follows lookup")
            .0;
        assert!(snapshot.contains("filebelt_collaboration.snapshots"));
        assert!(snapshot.contains("p.state='finalized'"));

        let commit = source
            .split_once("pub async fn collaboration_commit_snapshot")
            .expect("snapshot commit exists")
            .1
            .split_once("pub async fn collaboration_retention_sweep")
            .expect("retention follows snapshot commit")
            .0;
        assert!(commit.contains("covered_sequence >"));
        assert!(commit.contains("state='superseded'"));
        assert!(commit.contains("UPDATE filebelt_collaboration.snapshots SET superseded_at"));
    }

    #[test]
    fn retention_fences_epochs_before_enqueueing_object_cleanup() {
        let source = include_str!("collaboration.rs");
        let retention = source
            .split_once("pub async fn collaboration_retention_sweep")
            .expect("retention sweep exists")
            .1
            .split_once("pub async fn complete_collaboration_payload_deletion")
            .expect("deletion completion follows sweep")
            .0;
        assert!(retention.contains("state='tombstoned'"));
        assert!(retention.contains("fencing_token=fencing_token+1"));
        assert!(retention.contains("state='delete_intent'"));
        assert!(retention.contains("'payload_delete'"));
    }

    #[test]
    fn abandoned_objects_release_reservations_or_delete_committed_bytes_once() {
        let source = include_str!("collaboration.rs");
        let abandon = source
            .split_once("pub async fn collaboration_abandon_object")
            .expect("abandon exists")
            .1
            .split_once("pub async fn collaboration_retention_sweep")
            .expect("retention follows abandon")
            .0;
        assert!(abandon.contains("state='released'"));
        assert!(abandon.contains("state='quarantined'"));
        assert!(abandon.contains("state='delete_intent'"));
        assert!(
            abandon.contains("SELECT EXISTS (SELECT 1 FROM filebelt_collaboration.update_groups")
        );
        assert!(abandon.contains("'payload_delete'"));

        let completion = source
            .split_once("pub async fn complete_collaboration_payload_deletion")
            .expect("deletion completion exists")
            .1
            .split_once("pub async fn collaboration_freeze")
            .expect("freeze follows deletion completion")
            .0;
        assert!(completion.contains("\"tombstoned\" | \"abandoned\""));
        assert!(completion.contains("let final_object_state = if size.is_some()"));

        let retention = source
            .split_once("pub async fn collaboration_retention_sweep")
            .expect("retention exists")
            .1
            .split_once("pub async fn complete_collaboration_payload_deletion")
            .expect("deletion completion follows retention")
            .0;
        assert!(retention.contains("r.expires_at<=clock_timestamp()"));
        assert!(retention.contains("o.durable_at<=clock_timestamp()-interval '5 minutes'"));
        assert!(retention.contains("collaboration_abandon_object"));
    }

    #[test]
    fn collaboration_durability_paths_lock_the_current_authorization_fence() {
        let source = include_str!("collaboration.rs");
        for function in [
            "pub async fn collaboration_prepare_checkpoint",
            "pub async fn collaboration_finalize_object",
            "pub async fn collaboration_persist_update_group",
            "pub async fn collaboration_commit_snapshot",
        ] {
            let implementation = source
                .split_once(function)
                .expect("durability function exists")
                .1;
            assert!(implementation.contains("lock_collaboration_authorization_fence("));
        }
    }

    #[test]
    fn discard_locks_the_current_authorization_fence_before_expiring_the_room() {
        let source = include_str!("collaboration.rs");
        let discard = source
            .split_once("pub async fn collaboration_discard")
            .expect("discard exists")
            .1
            .split_once("pub async fn collaboration_create_import_intent")
            .expect("import intent follows discard")
            .0;
        for required in [
            "authorization: CollaborationAuthorizationContext",
            "lock_collaboration_authorization_fence(",
            "authorization.expected_generations()",
            "drive_id=$4 AND node_id=$5",
            "fencing_token=fencing_token+1",
        ] {
            assert!(discard.contains(required), "missing {required}");
        }
    }

    #[test]
    fn mcp_provenance_is_bound_to_the_fenced_source_transition() {
        let source = include_str!("collaboration.rs");
        let checkpoint = source
            .split_once("pub async fn collaboration_prepare_checkpoint")
            .expect("checkpoint exists")
            .1
            .split_once("pub async fn collaboration_finalize_object")
            .expect("finalize follows checkpoint")
            .0;
        for required in [
            "JOIN filebelt_mcp.invocations i",
            "i.principal_id=g.actor_principal_id",
            "i.semantic_input_digest=g.source_before_digest",
            "i.semantic_output_digest=g.source_after_digest",
        ] {
            assert!(checkpoint.contains(required), "missing {required}");
        }

        let persist = source
            .split_once("pub async fn collaboration_persist_update_group")
            .expect("persist exists")
            .1
            .split_once("pub async fn collaboration_replay_groups")
            .expect("replay follows persist")
            .0;
        for required in [
            "lock_collaboration_authorization_fence(",
            "base_version_id",
            "semantic_node_id=$4",
            "semantic_base_version_id=$5",
            "semantic_input_digest=$6",
            "semantic_output_digest=$7",
            "source_before_digest",
            "source_after_digest",
        ] {
            assert!(persist.contains(required), "missing {required}");
        }
    }

    #[test]
    fn discard_immediately_fences_dirty_state_for_retention() {
        let source = include_str!("collaboration.rs");
        let discard = source
            .split_once("pub async fn collaboration_discard")
            .expect("discard exists")
            .1
            .split_once("pub async fn collaboration_create_import_intent")
            .expect("import follows discard")
            .0;
        assert!(discard.contains("freeze_reason=CASE WHEN dirty THEN 'discarded'"));
        assert!(discard.contains("expires_at=CASE WHEN dirty THEN clock_timestamp()"));
        assert!(discard.contains("fencing_token=fencing_token+1"));
    }

    #[test]
    fn collaboration_payload_authority_is_structurally_isolated() {
        let migration = include_str!("../../../migrations/postgres/000003_phase5_markdown.sql");
        assert!(migration.contains("payload_objects_authority_immutable"));
        assert!(migration.contains("WITH (security_barrier = true)"));
        assert!(migration.contains("payload_authority_kind text NOT NULL DEFAULT 'collaboration'"));
        assert!(
            migration.contains("REFERENCES public.payload_objects(tenant_id,id,authority_kind)")
        );

        let grants = include_str!("../../../migrations/postgres/grants.sql");
        assert!(!grants.contains("ON payload_objects TO filebelt_collaboration"));
        assert!(grants.contains("ON filebelt_collaboration.payload_objects"));

        let source = include_str!("collaboration.rs")
            .split_once("#[cfg(test)]")
            .expect("test module follows implementation")
            .0;
        assert!(!source.contains("public.payload_objects"));
    }

    #[test]
    fn participant_identity_cannot_replace_an_active_connection() {
        let source = include_str!("collaboration.rs");
        let join = source
            .split_once("pub async fn collaboration_join_participant")
            .expect("participant join exists")
            .1
            .split_once("pub async fn collaboration_heartbeat_participant")
            .expect("participant heartbeat follows join")
            .0;
        assert!(join.contains("ON CONFLICT (tenant_id,room_id,epoch,client_id) DO NOTHING"));
        assert!(!join.contains("DO UPDATE SET"));
        assert!(join.contains("inserted != 1"));
    }
}

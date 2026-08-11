// SPDX-License-Identifier: Apache-2.0

//! Authoritative mount credential, device, gateway, and session mechanics.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use super::{Database, DatabaseError, insert_audit, insert_outbox, map_conflict};

#[derive(Clone, Debug)]
pub struct MountSecretEnvelopeInput<'a> {
    pub ciphertext: &'a [u8],
    pub nonce: &'a [u8; 12],
    pub wrapped_dek: &'a [u8],
    pub wrap_nonce: &'a [u8; 12],
    pub kek_generation: i32,
    pub aad_digest: &'a [u8; 32],
    pub aad_version: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountCredentialRecord {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub protocol: String,
    pub username: String,
    pub verifier_kind: String,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub read_only: bool,
    pub allowed_drive_ids: Vec<Uuid>,
    pub bound_device_id: Option<Uuid>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountAuthenticationMaterial {
    pub credential: MountCredentialRecord,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub kek_generation: i32,
    pub aad_digest: [u8; 32],
    pub aad_version: i32,
}

#[derive(Clone, Debug)]
pub struct MountSessionFence {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub user_principal_id: Uuid,
    pub credential_id: Uuid,
    pub protocol: String,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub gateway_epoch: i64,
    pub read_only: bool,
    pub allowed_drive_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountDeviceRecord {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub headscale_node_id: String,
    pub display_name: String,
    pub tailnet_addresses: Vec<String>,
    pub node_tags: Vec<String>,
    pub capability_version: String,
    pub ownership_generation: i64,
    pub observed_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountDeviceObservation {
    pub principal_id: Uuid,
    pub headscale_node_id: String,
    pub issuer: String,
    pub subject: String,
    pub display_name: String,
    pub addresses: Vec<String>,
    pub tags: Vec<String>,
    pub capability_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountSessionSummary {
    pub id: Uuid,
    pub protocol: String,
    pub gateway_id: String,
    pub source_address: String,
    pub state: String,
    pub created_at: String,
    pub last_activity_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub close_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountHandleRecord {
    pub id: Uuid,
    pub session_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Option<Uuid>,
    pub access_actions: Vec<String>,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub namespace_generation: i64,
    pub resource_acl_generation: i64,
    pub gateway_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct MountReadCapabilityFence {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub mount_session_id: Uuid,
    pub credential_id: Uuid,
    pub handle_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Uuid,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub namespace_generation: i64,
    pub resource_acl_generation: i64,
    pub gateway_epoch: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountPolicyRecord {
    pub protocol: String,
    pub enabled: bool,
    pub read_only: bool,
    pub allowed_drive_ids: Vec<Uuid>,
    pub authorization_generation: i64,
    pub revision: i64,
    pub updated_at: String,
}

const NFS_MAX_PROJECTED_ID: i64 = 4_294_967_294;
const NFS_NOBODY_PROJECTED_ID: i64 = 65_534;
const NFS_MAX_REPLAY_RESPONSE_BYTES: usize = 1_114_112;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfsFeatureState {
    Disabled,
    Preflight,
    Active,
    Draining,
}

impl NfsFeatureState {
    fn parse(value: &str) -> Result<Self, DatabaseError> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "preflight" => Ok(Self::Preflight),
            "active" => Ok(Self::Active),
            "draining" => Ok(Self::Draining),
            _ => Err(DatabaseError::InvalidPersistedValue),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Preflight => "preflight",
            Self::Active => "active",
            Self::Draining => "draining",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsFeatureStateRecord {
    pub state: NfsFeatureState,
    pub generation: i64,
    pub manifest_generation: i64,
    pub applied_manifest_generation: i64,
    pub applied_manifest_digest: Option<[u8; 32]>,
    pub applied_gateway_id: Option<String>,
    pub applied_gateway_epoch: Option<i64>,
    pub restore_generation: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfsExportState {
    Disabled,
    Active,
    Draining,
}

impl NfsExportState {
    fn parse(value: &str) -> Result<Self, DatabaseError> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "active" => Ok(Self::Active),
            "draining" => Ok(Self::Draining),
            _ => Err(DatabaseError::InvalidPersistedValue),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Active => "active",
            Self::Draining => "draining",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsExportRecord {
    pub drive_id: Uuid,
    pub export_id: i64,
    pub export_path: String,
    pub desired_state: NfsExportState,
    pub applied_state: NfsExportState,
    pub desired_generation: i64,
    pub applied_generation: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsExportManifest {
    pub feature_generation: i64,
    pub manifest_generation: i64,
    pub applied_manifest_generation: i64,
    pub applied_manifest_digest: Option<[u8; 32]>,
    pub restore_generation: i64,
    pub exports: Vec<NfsExportManifestEntry>,
}

#[derive(Clone, Debug)]
pub struct ReconcileNfsExportManifestInput<'a> {
    pub tenant_id: Uuid,
    pub gateway_id: &'a str,
    pub gateway_epoch: i64,
    pub feature_generation: i64,
    pub manifest_generation: i64,
    pub manifest_digest: &'a [u8; 32],
    pub export_ids: &'a [i64],
    pub export_generations: &'a [i64],
    pub root_handle_digests: &'a [[u8; 32]],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsAppliedManifestRecord {
    pub manifest_generation: i64,
    pub manifest_digest: [u8; 32],
    pub gateway_id: String,
    pub gateway_epoch: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsExportManifestEntry {
    pub drive_id: Uuid,
    pub export_id: i64,
    pub export_path: String,
    pub export_generation: i64,
    pub root_node_id: Uuid,
    pub root_node_generation: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsPosixGroupRecord {
    pub group_id: Uuid,
    pub posix_name: String,
    pub projected_gid: i64,
}

#[derive(Clone, Debug)]
pub struct NfsMountSessionProjection {
    pub session: MountSessionFence,
    pub posix_name: String,
    pub posix_group_id: Uuid,
    pub primary_group_name: String,
    pub projected_uid: i64,
    pub projected_gid: i64,
    pub mapping_generation: i64,
    pub feature_generation: i64,
    pub manifest_generation: i64,
    pub restore_generation: i64,
    pub absolute_expires_at_unix_seconds: i64,
    pub allowed_export_ids: Vec<i64>,
}

#[derive(Clone, Debug)]
pub struct CreateNfsMountSessionInput<'a> {
    pub tenant_id: Uuid,
    pub kerberos_principal: &'a str,
    pub gss_binding_digest: &'a [u8; 32],
    pub gateway_id: &'a str,
    pub gateway_epoch: i64,
    pub source_address: &'a str,
    pub gss_expires_at_unix_seconds: i64,
}

#[derive(Clone, Debug)]
pub struct NfsReplayContext<'a> {
    pub tenant_id: Uuid,
    pub mount_session_id: Uuid,
    pub client_id: &'a str,
    pub nfs_session_id: &'a str,
    pub slot_id: i32,
    pub sequence_id: i64,
    pub operation_index: i32,
    pub operation: &'a str,
    pub request_digest: &'a [u8; 32],
    pub gateway_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct RecordNfsReplayReceiptInput<'a> {
    pub context: NfsReplayContext<'a>,
    pub response_bytes: &'a [u8],
    pub response_digest: &'a [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsReplayReceipt {
    pub response_bytes: Vec<u8>,
    pub response_digest: [u8; 32],
    pub gateway_epoch: i64,
    pub expires_at_unix_seconds: i64,
}

/// One explicit Kerberos-to-FileBelt projection used by the NFS gateway.
/// Numeric POSIX projections remain compatibility metadata; callers must still
/// evaluate the current Virtual ACL before every filesystem operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NfsPrincipalMapping {
    pub kerberos_principal: String,
    pub principal_id: Uuid,
    pub credential_id: Uuid,
    pub projected_uid: i64,
    pub projected_gid: i64,
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct UpsertNfsPrincipalMappingInput<'a> {
    pub tenant_id: Uuid,
    pub actor_principal_id: Uuid,
    pub principal_id: Uuid,
    pub kerberos_principal: &'a str,
    pub projected_uid: i64,
    pub projected_gid: i64,
    pub allowed_drive_ids: &'a [Uuid],
    pub expected_generation: Option<i64>,
}

impl Database {
    pub async fn nfs_feature_state(
        &self,
        tenant_id: Uuid,
    ) -> Result<NfsFeatureStateRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT state,generation,manifest_generation,applied_manifest_generation,\
             applied_manifest_digest,applied_gateway_id,applied_gateway_epoch,restore_generation \
             FROM filebelt_mount.nfs_feature_state WHERE tenant_id=$1",
        )
        .bind(tenant_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        nfs_feature_state_from_row(&row)
    }

    pub async fn transition_nfs_feature_state(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        expected_generation: i64,
        target: NfsFeatureState,
    ) -> Result<NfsFeatureStateRecord, DatabaseError> {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_mount.nfs_feature_state SET state=$3,generation=generation+1 \
             WHERE tenant_id=$1 AND generation=$2 AND (\
               (state='disabled' AND $3='preflight') OR \
               (state='preflight' AND $3 IN ('disabled','active')) OR \
               (state='active' AND $3='draining') OR \
               (state='draining' AND $3='disabled')) \
             RETURNING state,generation,manifest_generation,applied_manifest_generation,\
             applied_manifest_digest,applied_gateway_id,applied_gateway_epoch,restore_generation",
        )
        .bind(tenant_id)
        .bind(expected_generation)
        .bind(target.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        let record = nfs_feature_state_from_row(&row)?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(tenant_id),
            "mount.nfs.feature.transition",
            "allowed",
            target.as_str(),
            false,
            json!({"generation":record.generation}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.nfs.feature.changed",
            "nfs_feature",
            tenant_id,
            record.generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn list_nfs_exports(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<NfsExportRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT drive_id,export_id,export_path,desired_state,applied_state,\
             desired_generation,applied_generation FROM filebelt_mount.nfs_exports \
             WHERE tenant_id=$1 ORDER BY export_id,drive_id",
        )
        .bind(tenant_id)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(nfs_export_from_row).collect()
    }

    /// Returns one transactionally consistent desired export manifest for an
    /// admitted Hello or the already-fenced boot's drain reconciliation. A new
    /// or renewed Hello is separately denied while the feature is draining.
    /// The tenant-wide desired generation changes whenever any registry row or
    /// desired projection changes.
    pub async fn nfs_export_manifest(
        &self,
        tenant_id: Uuid,
    ) -> Result<NfsExportManifest, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let feature = sqlx::query(
            "SELECT state,generation,manifest_generation,applied_manifest_generation,\
             applied_manifest_digest,restore_generation \
             FROM filebelt_mount.nfs_feature_state WHERE tenant_id=$1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if !matches!(
            NfsFeatureState::parse(feature.get::<String, _>("state").as_str())?,
            NfsFeatureState::Preflight | NfsFeatureState::Active | NfsFeatureState::Draining
        ) {
            return Err(DatabaseError::AdmissionLimited);
        }
        let rows = sqlx::query(
            "SELECT export.drive_id,export.export_id,export.export_path,\
             export.desired_generation AS export_generation,root.id AS root_node_id,\
             root.namespace_generation AS root_node_generation \
             FROM filebelt_mount.nfs_exports export JOIN nodes root \
               ON root.tenant_id=export.tenant_id AND root.drive_id=export.drive_id \
                 AND root.parent_id IS NULL AND root.trash_root_id IS NULL \
                 AND root.kind='directory' \
             WHERE export.tenant_id=$1 AND export.desired_state='active' \
             ORDER BY export.export_id,export.drive_id",
        )
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await?;
        let exports = rows
            .iter()
            .map(nfs_export_manifest_entry_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = NfsExportManifest {
            feature_generation: feature.get("generation"),
            manifest_generation: feature.get("manifest_generation"),
            applied_manifest_generation: feature.get("applied_manifest_generation"),
            applied_manifest_digest: optional_digest_32(
                feature.get::<Option<Vec<u8>>, _>("applied_manifest_digest"),
            )?,
            restore_generation: feature.get("restore_generation"),
            exports,
        };
        transaction.commit().await?;
        Ok(manifest)
    }

    /// Advances the never-decreasing restore fence through the recovery-only
    /// database function. PostgreSQL also requires NFS to be fully disabled.
    pub async fn advance_nfs_restore_generation(
        &self,
        tenant_id: Uuid,
        expected_generation: i64,
    ) -> Result<i64, DatabaseError> {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar("SELECT filebelt_mount.advance_nfs_restore_generation($1,$2)")
            .bind(tenant_id)
            .bind(expected_generation)
            .fetch_one(self.pool())
            .await
            .map_err(map_conflict)
    }

    pub async fn register_nfs_export(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        drive_id: Uuid,
        export_id: i64,
    ) -> Result<NfsExportRecord, DatabaseError> {
        if export_id <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "INSERT INTO filebelt_mount.nfs_exports (tenant_id,drive_id,export_id) \
             VALUES ($1,$2,$3) RETURNING drive_id,export_id,export_path,desired_state,\
             applied_state,desired_generation,applied_generation",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(export_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        let record = nfs_export_from_row(&row)?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(drive_id),
            "mount.nfs.export.register",
            "allowed",
            "tenant_admin_export",
            false,
            json!({"export_id":export_id,"export_path":record.export_path}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.nfs.export.changed",
            "nfs_export",
            drive_id,
            record.desired_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn stage_nfs_export(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        drive_id: Uuid,
        expected_generation: i64,
        target: NfsExportState,
    ) -> Result<NfsExportRecord, DatabaseError> {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_mount.nfs_exports \
             SET desired_state=$4,desired_generation=desired_generation+1 \
             WHERE tenant_id=$1 AND drive_id=$2 AND desired_generation=$3 \
               AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_feature_state feature \
                 WHERE feature.tenant_id=$1 AND feature.state IN ('preflight','draining')) AND (\
               (desired_state='disabled' AND $4='active') OR \
               (desired_state='active' AND $4='draining') OR \
               (desired_state='draining' AND $4='active') OR \
               (desired_state='draining' AND $4='disabled' \
                 AND applied_state='draining' AND applied_generation=desired_generation)) \
             RETURNING drive_id,export_id,export_path,desired_state,applied_state,\
             desired_generation,applied_generation",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(expected_generation)
        .bind(target.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::Conflict)?;
        let record = nfs_export_from_row(&row)?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(drive_id),
            "mount.nfs.export.stage",
            "allowed",
            target.as_str(),
            false,
            json!({"export_id":record.export_id,"generation":record.desired_generation}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.nfs.export.changed",
            "nfs_export",
            drive_id,
            record.desired_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn reconcile_nfs_export_manifest(
        &self,
        input: &ReconcileNfsExportManifestInput<'_>,
    ) -> Result<NfsAppliedManifestRecord, DatabaseError> {
        if input.gateway_id.is_empty()
            || input.gateway_id.len() > 255
            || input.gateway_epoch <= 0
            || input.feature_generation <= 0
            || input.manifest_generation <= 0
            || input.export_ids.len() != input.export_generations.len()
            || input.export_ids.len() != input.root_handle_digests.len()
            || input.export_ids.iter().any(|value| *value <= 0)
            || input.export_generations.iter().any(|value| *value <= 0)
            || input.export_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let root_handle_digests = input
            .root_handle_digests
            .iter()
            .map(|digest| digest.to_vec())
            .collect::<Vec<_>>();
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT * FROM filebelt_mount.reconcile_nfs_export_manifest(\
             $1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(input.tenant_id)
        .bind(input.gateway_id)
        .bind(input.gateway_epoch)
        .bind(input.feature_generation)
        .bind(input.manifest_generation)
        .bind(input.manifest_digest.as_slice())
        .bind(input.export_ids)
        .bind(input.export_generations)
        .bind(&root_handle_digests)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        let record = NfsAppliedManifestRecord {
            manifest_generation: row.get("applied_manifest_generation"),
            manifest_digest: row
                .get::<Vec<u8>, _>("applied_manifest_digest")
                .try_into()
                .map_err(|_| DatabaseError::InvalidPersistedValue)?,
            gateway_id: row.get("applied_gateway_id"),
            gateway_epoch: row.get("applied_gateway_epoch"),
        };
        insert_audit(
            &mut transaction,
            input.tenant_id,
            None,
            None,
            Some(input.tenant_id),
            "mount.nfs.manifest.reconcile",
            "allowed",
            "gateway_manifest_readback",
            false,
            json!({
                "feature_generation":input.feature_generation,
                "manifest_generation":input.manifest_generation,
                "gateway_id":input.gateway_id,
                "gateway_epoch":input.gateway_epoch,
                "export_count":input.export_ids.len()
            }),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            input.tenant_id,
            "filebelt.v1.mount.nfs.manifest.applied",
            "nfs_manifest",
            input.tenant_id,
            input.manifest_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn list_nfs_posix_groups(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<NfsPosixGroupRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT group_id,posix_name,projected_gid FROM filebelt_mount.nfs_posix_groups \
             WHERE tenant_id=$1 ORDER BY posix_name,group_id",
        )
        .bind(tenant_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(nfs_posix_group_from_row).collect())
    }

    pub async fn register_nfs_posix_group(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        group_id: Uuid,
        posix_name: &str,
        projected_gid: i64,
    ) -> Result<NfsPosixGroupRecord, DatabaseError> {
        if !valid_nfs_posix_name(posix_name) || !valid_nfs_projected_id(projected_gid) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "INSERT INTO filebelt_mount.nfs_posix_groups \
             (tenant_id,group_id,posix_name,projected_gid) VALUES ($1,$2,$3,$4) \
             RETURNING group_id,posix_name,projected_gid",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(posix_name)
        .bind(projected_gid)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        let record = nfs_posix_group_from_row(&row);
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(group_id),
            "mount.nfs.posix_group.register",
            "allowed",
            "tenant_admin_group_projection",
            false,
            json!({"posix_name":posix_name,"projected_gid":projected_gid}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.nfs.posix_group.changed",
            "nfs_posix_group",
            group_id,
            1,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    /// Lists active NFS identity projections for tenant-administrator review.
    pub async fn list_nfs_principal_mappings(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<NfsPrincipalMapping>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT kerberos_principal,principal_id,credential_id,projected_uid,projected_gid,generation \
             FROM filebelt_mount.nfs_principal_mappings WHERE tenant_id=$1 AND revoked_at IS NULL \
             ORDER BY kerberos_principal,principal_id",
        )
        .bind(tenant_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .iter()
            .map(|row| NfsPrincipalMapping {
                kerberos_principal: row.get("kerberos_principal"),
                principal_id: row.get("principal_id"),
                credential_id: row.get("credential_id"),
                projected_uid: row.get("projected_uid"),
                projected_gid: row.get("projected_gid"),
                generation: row.get("generation"),
            })
            .collect())
    }

    /// Creates or generation-fences an explicit Kerberos identity projection.
    /// No keytab, password verifier, or AUTH_SYS identity is persisted here.
    pub async fn upsert_nfs_principal_mapping(
        &self,
        input: &UpsertNfsPrincipalMappingInput<'_>,
    ) -> Result<NfsPrincipalMapping, DatabaseError> {
        let posix_name = nfs_posix_user_name(input.kerberos_principal)?;
        if !valid_nfs_projected_id(input.projected_uid)
            || !valid_nfs_projected_id(input.projected_gid)
            || input.allowed_drive_ids.is_empty()
            || input.allowed_drive_ids.len() > 256
            || input.expected_generation.is_some_and(|value| value <= 0)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let target_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM principals p JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
             WHERE p.tenant_id=$1 AND p.id=$2 AND p.kind='user' AND p.disabled_at IS NULL AND u.status='active')",
        )
        .bind(input.tenant_id)
        .bind(input.principal_id)
        .fetch_one(&mut *transaction)
        .await?;
        let drive_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM drives WHERE tenant_id=$1 AND id=ANY($2)")
                .bind(input.tenant_id)
                .bind(input.allowed_drive_ids)
                .fetch_one(&mut *transaction)
                .await?;
        if !target_exists || drive_count != input.allowed_drive_ids.len() as i64 {
            return Err(DatabaseError::NotFound);
        }
        let posix_group_id: Uuid = sqlx::query_scalar(
            "SELECT posix_group.group_id FROM filebelt_mount.nfs_posix_groups posix_group \
             JOIN group_memberships membership ON membership.tenant_id=posix_group.tenant_id \
               AND membership.group_id=posix_group.group_id \
             WHERE posix_group.tenant_id=$1 AND posix_group.projected_gid=$2 \
               AND membership.user_principal_id=$3",
        )
        .bind(input.tenant_id)
        .bind(input.projected_gid)
        .bind(input.principal_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;

        let existing = sqlx::query(
            "SELECT principal_id,credential_id,projected_uid,posix_name,generation \
             FROM filebelt_mount.nfs_principal_mappings \
             WHERE tenant_id=$1 AND kerberos_principal=$2 FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(input.kerberos_principal)
        .fetch_optional(&mut *transaction)
        .await?;
        let credential_id;
        let generation;
        if let Some(row) = existing {
            if row.get::<Uuid, _>("principal_id") != input.principal_id
                || row.get::<i64, _>("projected_uid") != input.projected_uid
                || row
                    .get::<Option<String>, _>("posix_name")
                    .is_some_and(|existing_name| existing_name != posix_name)
                || input.expected_generation != Some(row.get::<i64, _>("generation"))
            {
                return Err(DatabaseError::Conflict);
            }
            credential_id = row.get("credential_id");
            generation = sqlx::query_scalar(
                "UPDATE filebelt_mount.nfs_principal_mappings SET projected_gid=$3,\
                 posix_group_id=$4,posix_name=COALESCE(posix_name,$5),generation=generation+1,\
                 revoked_at=NULL,updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND kerberos_principal=$2 RETURNING generation",
            )
            .bind(input.tenant_id)
            .bind(input.kerberos_principal)
            .bind(input.projected_gid)
            .bind(posix_group_id)
            .bind(&posix_name)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_conflict)?;
            sqlx::query(
                "UPDATE filebelt_mount.credentials SET allowed_drive_ids=$3,\
                 credential_generation=credential_generation+1,\
                 authorization_generation=authorization_generation+1,revoked_at=NULL,\
                 expires_at='infinity'::timestamptz \
                 WHERE tenant_id=$1 AND id=$2 AND principal_id=$4 AND protocol='nfs'",
            )
            .bind(input.tenant_id)
            .bind(credential_id)
            .bind(input.allowed_drive_ids)
            .bind(input.principal_id)
            .execute(&mut *transaction)
            .await?;
        } else {
            if input.expected_generation.is_some() {
                return Err(DatabaseError::Conflict);
            }
            credential_id = Uuid::new_v4();
            generation = 1;
            sqlx::query(
                "INSERT INTO filebelt_mount.credentials (tenant_id,id,principal_id,protocol,username,verifier_kind,read_only,allowed_drive_ids,expires_at) \
                 VALUES ($1,$2,$3,'nfs',$4,'kerberos_principal',false,$5,'infinity'::timestamptz)",
            )
            .bind(input.tenant_id)
            .bind(credential_id)
            .bind(input.principal_id)
            .bind(credential_id.to_string())
            .bind(input.allowed_drive_ids)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
            sqlx::query(
                "INSERT INTO filebelt_mount.nfs_principal_mappings \
                 (tenant_id,kerberos_principal,principal_id,credential_id,posix_name,\
                  posix_group_id,projected_uid,projected_gid) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(input.tenant_id)
            .bind(input.kerberos_principal)
            .bind(input.principal_id)
            .bind(credential_id)
            .bind(&posix_name)
            .bind(posix_group_id)
            .bind(input.projected_uid)
            .bind(input.projected_gid)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
        }
        sqlx::query(
            "INSERT INTO filebelt_mount.policies (tenant_id,principal_id,protocol,enabled,read_only,allowed_drive_ids) \
             VALUES ($1,$2,'nfs',true,false,$3) ON CONFLICT (tenant_id,principal_id,protocol) DO UPDATE SET \
             enabled=true,read_only=false,allowed_drive_ids=EXCLUDED.allowed_drive_ids,authorization_generation=filebelt_mount.policies.authorization_generation+1,revision=filebelt_mount.policies.revision+1,updated_at=clock_timestamp()",
        )
        .bind(input.tenant_id)
        .bind(input.principal_id)
        .bind(input.allowed_drive_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE filebelt_mount.sessions SET state='closed',closed_at=clock_timestamp(),close_reason='nfs_mapping_changed',last_activity_at=clock_timestamp() WHERE tenant_id=$1 AND user_principal_id=$2 AND protocol='nfs' AND state IN ('active','draining')")
            .bind(input.tenant_id).bind(input.principal_id).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            input.tenant_id,
            Some(input.actor_principal_id),
            Some(input.principal_id),
            Some(credential_id),
            "mount.nfs.mapping.update",
            "allowed",
            "tenant_admin_mapping",
            false,
            json!({"kerberos_principal":input.kerberos_principal,"projected_uid":input.projected_uid,"projected_gid":input.projected_gid,"generation":generation}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            input.tenant_id,
            "filebelt.v1.mount.nfs.mapping.changed",
            "nfs_mapping",
            credential_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsPrincipalMapping {
            kerberos_principal: input.kerberos_principal.to_owned(),
            principal_id: input.principal_id,
            credential_id,
            projected_uid: input.projected_uid,
            projected_gid: input.projected_gid,
            generation,
        })
    }

    pub async fn revoke_nfs_principal_mapping(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        credential_id: Uuid,
        expected_generation: i64,
    ) -> Result<(), DatabaseError> {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query("UPDATE filebelt_mount.nfs_principal_mappings SET revoked_at=clock_timestamp(),generation=generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND credential_id=$2 AND generation=$3 AND revoked_at IS NULL RETURNING principal_id,credential_id,kerberos_principal,generation")
            .bind(tenant_id).bind(credential_id).bind(expected_generation).fetch_optional(&mut *transaction).await?.ok_or(DatabaseError::Conflict)?;
        let principal_id: Uuid = row.get("principal_id");
        let credential_id: Uuid = row.get("credential_id");
        let kerberos_principal: String = row.get("kerberos_principal");
        let generation: i64 = row.get("generation");
        sqlx::query("UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),credential_generation=credential_generation+1,authorization_generation=authorization_generation+1 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL")
            .bind(tenant_id).bind(credential_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE filebelt_mount.policies SET enabled=false,authorization_generation=authorization_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs'")
            .bind(tenant_id).bind(principal_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE filebelt_mount.sessions SET state='closed',closed_at=clock_timestamp(),close_reason='nfs_mapping_revoked',last_activity_at=clock_timestamp() WHERE tenant_id=$1 AND user_principal_id=$2 AND protocol='nfs' AND state IN ('active','draining')")
            .bind(tenant_id).bind(principal_id).execute(&mut *transaction).await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(actor_principal_id),
            Some(principal_id),
            Some(credential_id),
            "mount.nfs.mapping.revoke",
            "allowed",
            "tenant_admin_mapping",
            false,
            json!({"kerberos_principal":kerberos_principal,"generation":generation}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.nfs.mapping.changed",
            "nfs_mapping",
            credential_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mount_authentication_throttled(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        principal_key: &[u8; 32],
        source_key: &[u8; 32],
    ) -> Result<bool, DatabaseError> {
        if !matches!(protocol, "smb" | "ftps") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.authentication_throttles \
             WHERE tenant_id=$1 AND protocol=$2 AND principal_key=$3 AND source_key=$4 \
               AND expires_at>clock_timestamp() AND delay_until>clock_timestamp())",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(principal_key.as_slice())
        .bind(source_key.as_slice())
        .fetch_one(self.pool())
        .await
        .map_err(DatabaseError::from)
    }

    pub async fn record_mount_authentication_failure(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        principal_key: &[u8; 32],
        source_key: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        if !matches!(protocol, "smb" | "ftps") {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query(
            "INSERT INTO filebelt_mount.authentication_throttles \
             (tenant_id,protocol,principal_key,source_key,failures,delay_until,expires_at) \
             VALUES ($1,$2,$3,$4,1,clock_timestamp()+interval '2 seconds',\
               clock_timestamp()+interval '1 hour') \
             ON CONFLICT (tenant_id,protocol,principal_key,source_key) DO UPDATE SET \
               failures=LEAST(filebelt_mount.authentication_throttles.failures+1,1024),\
               delay_until=clock_timestamp()+make_interval(secs=>LEAST(300,\
                 power(2,LEAST(filebelt_mount.authentication_throttles.failures+1,8))::integer)),\
               expires_at=clock_timestamp()+interval '1 hour',updated_at=clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(principal_key.as_slice())
        .bind(source_key.as_slice())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn clear_mount_authentication_failures(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        principal_key: &[u8; 32],
        source_key: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            "DELETE FROM filebelt_mount.authentication_throttles \
             WHERE tenant_id=$1 AND protocol=$2 AND principal_key=$3 AND source_key=$4",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(principal_key.as_slice())
        .bind(source_key.as_slice())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn list_mount_policies(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountPolicyRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT protocol,enabled,read_only,allowed_drive_ids,authorization_generation,\
             revision,updated_at::text FROM filebelt_mount.policies \
             WHERE tenant_id=$1 AND principal_id=$2 ORDER BY protocol",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(mount_policy_from_row).collect())
    }

    pub async fn upsert_mount_policy(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        protocol: &str,
        enabled: bool,
        read_only: bool,
        allowed_drive_ids: &[Uuid],
    ) -> Result<MountPolicyRecord, DatabaseError> {
        if !matches!(protocol, "smb" | "ftps" | "nfs") || allowed_drive_ids.len() > 256 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "INSERT INTO filebelt_mount.policies \
             (tenant_id,principal_id,protocol,enabled,read_only,allowed_drive_ids) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,principal_id,protocol) \
             DO UPDATE SET enabled=EXCLUDED.enabled,read_only=EXCLUDED.read_only,\
               allowed_drive_ids=EXCLUDED.allowed_drive_ids,\
               authorization_generation=filebelt_mount.policies.authorization_generation+1,\
               revision=filebelt_mount.policies.revision+1,updated_at=clock_timestamp() \
             RETURNING protocol,enabled,read_only,allowed_drive_ids,authorization_generation,\
               revision,updated_at::text",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .bind(enabled)
        .bind(read_only)
        .bind(allowed_drive_ids)
        .fetch_one(&mut *transaction)
        .await?;
        let policy = mount_policy_from_row(&row);
        let revoked = sqlx::query(
            "UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),\
             credential_generation=credential_generation+1,\
             authorization_generation=authorization_generation+1 \
             WHERE tenant_id=$1 AND principal_id=$2 AND protocol=$3 AND revoked_at IS NULL \
             RETURNING id,credential_generation",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .fetch_all(&mut *transaction)
        .await?;
        for credential in &revoked {
            sqlx::query(
                "INSERT INTO filebelt_mount.deletion_tombstones \
                 (tenant_id,id,object_kind,object_id,principal_id,protocol,reason_code,generation) \
                 VALUES ($1,$2,'credential',$3,$4,$5,'policy_changed',$6)",
            )
            .bind(tenant_id)
            .bind(Uuid::new_v4())
            .bind(credential.get::<Uuid, _>("id"))
            .bind(principal_id)
            .bind(protocol)
            .bind(credential.get::<i64, _>("credential_generation"))
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE filebelt_mount.sessions SET state='revoked',closed_at=clock_timestamp(),\
             close_reason='policy_changed' WHERE tenant_id=$1 AND user_principal_id=$2 \
             AND protocol=$3 AND state IN ('active','draining')",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            None,
            "mount.policy.update",
            "allowed",
            "self_service_policy",
            false,
            json!({"protocol":protocol,"enabled":enabled,"read_only":read_only,"revoked_credentials":revoked.len()}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.policy.changed",
            "mount_policy",
            principal_id,
            policy.authorization_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(policy)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_mount_credential(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
        protocol: &str,
        username: &str,
        verifier_kind: &str,
        read_only: bool,
        allowed_drive_ids: &[Uuid],
        bound_device_id: Option<Uuid>,
        expires_at: &str,
        envelope: &MountSecretEnvelopeInput<'_>,
    ) -> Result<MountCredentialRecord, DatabaseError> {
        if !matches!(
            (protocol, verifier_kind),
            ("smb", "ntlm_verifier") | ("ftps", "hmac_sha256")
        ) || !(16..=96).contains(&username.len())
            || allowed_drive_ids.len() > 256
            || envelope.kek_generation <= 0
            || envelope.aad_version != 1
            || envelope.wrapped_dek.len() != 48
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let policy = sqlx::query(
            "SELECT enabled,read_only,allowed_drive_ids FROM filebelt_mount.policies \
             WHERE tenant_id=$1 AND principal_id=$2 AND protocol=$3 FOR SHARE",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(protocol)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if !policy.get::<bool, _>("enabled")
            || !read_only && policy.get::<bool, _>("read_only")
            || !allowed_drive_ids.iter().all(|drive| {
                policy
                    .get::<Vec<Uuid>, _>("allowed_drive_ids")
                    .contains(drive)
            })
        {
            return Err(DatabaseError::Conflict);
        }
        if let Some(device_id) = bound_device_id {
            let current: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM filebelt_mount.headscale_devices \
                 WHERE tenant_id=$1 AND id=$2 AND principal_id=$3 AND revoked_at IS NULL \
                 AND observed_at>clock_timestamp()-interval '5 minutes')",
            )
            .bind(tenant_id)
            .bind(device_id)
            .bind(principal_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !current {
                return Err(DatabaseError::Conflict);
            }
        }
        let id = credential_id;
        sqlx::query(
            "INSERT INTO filebelt_mount.credentials \
             (tenant_id,id,principal_id,protocol,username,verifier_kind,read_only,allowed_drive_ids,bound_device_id,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz)",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(principal_id)
        .bind(protocol)
        .bind(username)
        .bind(verifier_kind)
        .bind(read_only)
        .bind(allowed_drive_ids)
        .bind(bound_device_id)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        sqlx::query(
            "INSERT INTO filebelt_mount_vault.secret_envelopes \
             (tenant_id,credential_id,owner_principal_id,credential_generation,namespace,secret_kind,\
              ciphertext,nonce,wrapped_dek,wrap_nonce,kek_generation,aad_digest,aad_version) \
             VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(principal_id)
        .bind(protocol)
        .bind(verifier_kind)
        .bind(envelope.ciphertext)
        .bind(envelope.nonce.as_slice())
        .bind(envelope.wrapped_dek)
        .bind(envelope.wrap_nonce.as_slice())
        .bind(envelope.kek_generation)
        .bind(envelope.aad_digest.as_slice())
        .bind(envelope.aad_version)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            Some(id),
            "mount.credential.create",
            "allowed",
            "mount_policy_allowed",
            false,
            json!({"protocol":protocol,"read_only":read_only,"device_bound":bound_device_id.is_some()}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.credential.changed",
            "mount_credential",
            id,
            1,
        )
        .await?;
        transaction.commit().await?;
        self.mount_credential(tenant_id, principal_id, id).await
    }

    pub async fn mount_credential(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
    ) -> Result<MountCredentialRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT id,principal_id,protocol,username,verifier_kind,credential_generation,\
             authorization_generation,read_only,allowed_drive_ids,bound_device_id,\
             created_at::text,last_used_at::text,expires_at::text,revoked_at::text \
             FROM filebelt_mount.credentials WHERE tenant_id=$1 AND principal_id=$2 AND id=$3",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(credential_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(mount_credential_from_row(&row))
    }

    pub async fn list_mount_credentials(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountCredentialRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT id,principal_id,protocol,username,verifier_kind,credential_generation,\
             authorization_generation,read_only,allowed_drive_ids,bound_device_id,\
             created_at::text,last_used_at::text,expires_at::text,revoked_at::text \
             FROM filebelt_mount.credentials WHERE tenant_id=$1 AND principal_id=$2 \
             ORDER BY created_at DESC,id",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(mount_credential_from_row).collect())
    }

    pub async fn revoke_mount_credential(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
        reason_code: &str,
    ) -> Result<(), DatabaseError> {
        if reason_code.is_empty() || reason_code.len() > 128 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),\
             credential_generation=credential_generation+1,authorization_generation=authorization_generation+1 \
             WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND revoked_at IS NULL \
             RETURNING protocol,credential_generation",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let generation: i64 = row.get("credential_generation");
        sqlx::query(
            "UPDATE filebelt_mount.sessions SET state='revoked',closed_at=clock_timestamp(),\
             close_reason=$4 WHERE tenant_id=$1 AND credential_id=$2 AND user_principal_id=$3 \
             AND state IN ('active','draining')",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .bind(principal_id)
        .bind(reason_code)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO filebelt_mount.deletion_tombstones \
             (tenant_id,id,object_kind,object_id,principal_id,protocol,reason_code,generation) \
             VALUES ($1,$2,'credential',$3,$4,$5,$6,$7)",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind(credential_id)
        .bind(principal_id)
        .bind(row.get::<String, _>("protocol"))
        .bind(reason_code)
        .bind(generation)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(principal_id),
            Some(principal_id),
            Some(credential_id),
            "mount.credential.revoke",
            "allowed",
            reason_code,
            false,
            json!({}),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.credential.changed",
            "mount_credential",
            credential_id,
            generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mount_authentication_material(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        username: &str,
        device_id: Option<Uuid>,
    ) -> Result<MountAuthenticationMaterial, DatabaseError> {
        let row = sqlx::query(
            "SELECT c.id,c.principal_id,c.protocol,c.username,c.verifier_kind,c.credential_generation,\
             c.authorization_generation,c.read_only,c.allowed_drive_ids,c.bound_device_id,\
             c.created_at::text,c.last_used_at::text,c.expires_at::text,c.revoked_at::text,\
             e.ciphertext,e.nonce,e.wrapped_dek,e.wrap_nonce,e.kek_generation,e.aad_digest,e.aad_version \
             FROM filebelt_mount.credentials c \
             JOIN filebelt_mount.policies policy ON policy.tenant_id=c.tenant_id \
               AND policy.principal_id=c.principal_id AND policy.protocol=c.protocol \
             JOIN principals p ON p.tenant_id=c.tenant_id AND p.id=c.principal_id \
             JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
             JOIN filebelt_mount_vault.secret_envelopes e \
               ON e.tenant_id=c.tenant_id AND e.credential_id=c.id \
             WHERE c.tenant_id=$1 AND c.protocol=$2 AND c.username=$3 \
               AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() \
               AND policy.enabled AND p.disabled_at IS NULL AND u.status='active' \
               AND (c.bound_device_id IS NULL OR c.bound_device_id=$4) \
               AND (c.bound_device_id IS NULL OR EXISTS (SELECT 1 FROM filebelt_mount.headscale_devices d \
                 WHERE d.tenant_id=c.tenant_id AND d.id=c.bound_device_id AND d.principal_id=c.principal_id \
                   AND d.revoked_at IS NULL AND d.observed_at>clock_timestamp()-interval '5 minutes'))",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(username)
        .bind(device_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(MountAuthenticationMaterial {
            credential: mount_credential_from_row(&row),
            ciphertext: row.get("ciphertext"),
            nonce: array_12(row.get::<Vec<u8>, _>("nonce"))?,
            wrapped_dek: row.get("wrapped_dek"),
            wrap_nonce: array_12(row.get::<Vec<u8>, _>("wrap_nonce"))?,
            kek_generation: row.get("kek_generation"),
            aad_digest: array_32(row.get::<Vec<u8>, _>("aad_digest"))?,
            aad_version: row.get("aad_version"),
        })
    }

    /// Resolves only an already-provisioned RPCSEC_GSS identity. This method
    /// never accepts AUTH_SYS values, reads a vault envelope, or turns a UID,
    /// GID, or host identity into authority.
    pub async fn nfs_principal_mapping(
        &self,
        tenant_id: Uuid,
        kerberos_principal: &str,
    ) -> Result<NfsPrincipalMapping, DatabaseError> {
        if nfs_posix_user_name(kerberos_principal).is_err() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "SELECT mapping.kerberos_principal,mapping.principal_id,mapping.credential_id,\
             mapping.projected_uid,mapping.projected_gid,mapping.generation \
             FROM filebelt_mount.nfs_principal_mappings mapping \
             JOIN filebelt_mount.credentials credential \
               ON credential.tenant_id=mapping.tenant_id AND credential.id=mapping.credential_id \
             JOIN filebelt_mount.policies policy \
               ON policy.tenant_id=credential.tenant_id AND policy.principal_id=credential.principal_id \
                 AND policy.protocol='nfs' \
             JOIN principals principal \
               ON principal.tenant_id=mapping.tenant_id AND principal.id=mapping.principal_id \
             JOIN users user_account \
               ON user_account.tenant_id=principal.tenant_id \
                 AND user_account.principal_id=principal.id \
             JOIN filebelt_mount.nfs_posix_groups posix_group \
               ON posix_group.tenant_id=mapping.tenant_id \
                 AND posix_group.group_id=mapping.posix_group_id \
                 AND posix_group.projected_gid=mapping.projected_gid \
             JOIN group_memberships membership \
               ON membership.tenant_id=mapping.tenant_id \
                 AND membership.group_id=posix_group.group_id \
                 AND membership.user_principal_id=mapping.principal_id \
             JOIN filebelt_mount.nfs_feature_state feature \
               ON feature.tenant_id=mapping.tenant_id AND feature.state='active' \
                 AND feature.applied_manifest_generation=feature.manifest_generation \
                 AND feature.applied_manifest_digest IS NOT NULL \
             WHERE mapping.tenant_id=$1 AND mapping.kerberos_principal=$2 \
               AND mapping.revoked_at IS NULL AND credential.protocol='nfs' \
               AND credential.verifier_kind='kerberos_principal' AND credential.revoked_at IS NULL \
               AND credential.expires_at='infinity'::timestamptz AND policy.enabled \
               AND principal.disabled_at IS NULL AND user_account.status='active' \
               AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_exports export \
                 JOIN nodes root ON root.tenant_id=export.tenant_id \
                   AND root.drive_id=export.drive_id AND root.parent_id IS NULL \
                   AND root.trash_root_id IS NULL AND root.kind='directory' \
                 WHERE export.tenant_id=mapping.tenant_id \
                   AND export.drive_id=ANY(credential.allowed_drive_ids) \
                   AND export.desired_state='active' AND export.applied_state='active' \
                   AND export.desired_generation=export.applied_generation)",
        )
        .bind(tenant_id)
        .bind(kerberos_principal)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(NfsPrincipalMapping {
            kerberos_principal: row.get("kerberos_principal"),
            principal_id: row.get("principal_id"),
            credential_id: row.get("credential_id"),
            projected_uid: row.get("projected_uid"),
            projected_gid: row.get("projected_gid"),
            generation: row.get("generation"),
        })
    }

    /// Creates or reuses one context-bound NFS session. PostgreSQL resolves
    /// the exact Kerberos mapping, gateway lease, feature fence, primary group,
    /// and applied export intersection in the same privileged operation that
    /// creates the mount-session principal.
    pub async fn create_nfs_mount_session(
        &self,
        input: &CreateNfsMountSessionInput<'_>,
    ) -> Result<NfsMountSessionProjection, DatabaseError> {
        if nfs_posix_user_name(input.kerberos_principal).is_err()
            || input.gateway_id.is_empty()
            || input.gateway_id.len() > 255
            || input.gateway_epoch <= 0
            || input.source_address.parse::<std::net::IpAddr>().is_err()
            || input.gss_expires_at_unix_seconds <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let requested_session_id = Uuid::new_v4();
        let session_principal_id = Uuid::new_v4();
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT * FROM filebelt_mount.create_nfs_session(\
             $1,$2,$3,$4,$5,$6::inet,to_timestamp($7),$8,$9)",
        )
        .bind(input.tenant_id)
        .bind(input.kerberos_principal)
        .bind(input.gss_binding_digest.as_slice())
        .bind(input.gateway_id)
        .bind(input.gateway_epoch)
        .bind(input.source_address)
        .bind(input.gss_expires_at_unix_seconds)
        .bind(requested_session_id)
        .bind(session_principal_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_conflict)?
        .ok_or(DatabaseError::NotFound)?;
        let session_id: Uuid = row.get("session_id");
        let user_principal_id: Uuid = row.get("user_principal_id");
        let credential_id: Uuid = row.get("credential_id");
        let mapping_generation: i64 = row.get("mapping_generation");
        let feature_generation: i64 = row.get("feature_generation");
        if session_id == requested_session_id {
            insert_audit(
                &mut transaction,
                input.tenant_id,
                Some(user_principal_id),
                Some(session_principal_id),
                Some(session_id),
                "mount.session.start",
                "allowed",
                "rpcsec_gss_verified",
                false,
                json!({
                    "protocol":"nfs",
                    "mapping_generation":mapping_generation,
                    "feature_generation":feature_generation
                }),
            )
            .await?;
        }
        let projection = NfsMountSessionProjection {
            session: MountSessionFence {
                tenant_id: input.tenant_id,
                session_id,
                user_principal_id,
                credential_id,
                protocol: "nfs".to_owned(),
                credential_generation: row.get("credential_generation"),
                authorization_generation: row.get("authorization_generation"),
                membership_generation: row.get("membership_generation"),
                gateway_epoch: input.gateway_epoch,
                read_only: row.get("read_only"),
                allowed_drive_ids: row.get("allowed_drive_ids"),
            },
            posix_name: row.get("posix_name"),
            posix_group_id: row.get("posix_group_id"),
            primary_group_name: row.get("primary_group_name"),
            projected_uid: row.get("projected_uid"),
            projected_gid: row.get("projected_gid"),
            mapping_generation,
            feature_generation,
            manifest_generation: row.get("manifest_generation"),
            restore_generation: row.get("restore_generation"),
            absolute_expires_at_unix_seconds: row.get("absolute_expires_at_unix_seconds"),
            allowed_export_ids: row.get("allowed_export_ids"),
        };
        transaction.commit().await?;
        Ok(projection)
    }

    /// Looks up the exact persisted protobuf for one NFS compound operation.
    /// A reused slot identity with different context is rejected rather than
    /// treated as a cache miss.
    pub async fn lookup_nfs_replay_receipt(
        &self,
        context: &NfsReplayContext<'_>,
    ) -> Result<Option<NfsReplayReceipt>, DatabaseError> {
        if !valid_nfs_replay_context(context) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "SELECT client_id,operation,request_digest,response_bytes,response_digest,\
             gateway_epoch,expires_at>statement_timestamp() AS current,\
             floor(extract(epoch FROM expires_at))::bigint AS expires_at_unix_seconds \
             FROM filebelt_mount.nfs_replay_receipts \
             WHERE tenant_id=$1 AND mount_session_id=$2 AND nfs_session_id=$3 \
               AND slot_id=$4 AND sequence_id=$5 AND operation_index=$6",
        )
        .bind(context.tenant_id)
        .bind(context.mount_session_id)
        .bind(context.nfs_session_id)
        .bind(context.slot_id)
        .bind(context.sequence_id)
        .bind(context.operation_index)
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if !row.get::<bool, _>("current") {
            return Err(DatabaseError::StaleGeneration);
        }
        if row.get::<String, _>("client_id") != context.client_id
            || row.get::<String, _>("operation") != context.operation
            || row.get::<Vec<u8>, _>("request_digest") != context.request_digest
            || row.get::<i64, _>("gateway_epoch") != context.gateway_epoch
        {
            return Err(DatabaseError::Conflict);
        }
        let response_digest = row
            .get::<Vec<u8>, _>("response_digest")
            .try_into()
            .map_err(|_| DatabaseError::InvalidPersistedValue)?;
        Ok(Some(NfsReplayReceipt {
            response_bytes: row.get("response_bytes"),
            response_digest,
            gateway_epoch: context.gateway_epoch,
            expires_at_unix_seconds: row.get("expires_at_unix_seconds"),
        }))
    }

    /// Persists one replay response in its own database operation. This is a
    /// restart-safe primitive, but it is not yet atomic with the represented
    /// filesystem mutation; mutation methods must compose the same INSERT in
    /// their transaction in the next storage slice.
    pub async fn record_nfs_replay_receipt(
        &self,
        input: &RecordNfsReplayReceiptInput<'_>,
    ) -> Result<NfsReplayReceipt, DatabaseError> {
        if !valid_nfs_replay_context(&input.context)
            || input.response_bytes.is_empty()
            || input.response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let inserted = sqlx::query(
            "INSERT INTO filebelt_mount.nfs_replay_receipts \
             (tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,\
              operation_index,operation,request_digest,response_bytes,response_digest,\
              gateway_epoch,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,\
               statement_timestamp()+interval '90 seconds') \
             ON CONFLICT (tenant_id,mount_session_id,nfs_session_id,slot_id,sequence_id,\
               operation_index) DO NOTHING",
        )
        .bind(input.context.tenant_id)
        .bind(input.context.mount_session_id)
        .bind(input.context.client_id)
        .bind(input.context.nfs_session_id)
        .bind(input.context.slot_id)
        .bind(input.context.sequence_id)
        .bind(input.context.operation_index)
        .bind(input.context.operation)
        .bind(input.context.request_digest.as_slice())
        .bind(input.response_bytes)
        .bind(input.response_digest.as_slice())
        .bind(input.context.gateway_epoch)
        .execute(self.pool())
        .await?;
        let receipt = self
            .lookup_nfs_replay_receipt(&input.context)
            .await?
            .ok_or(DatabaseError::StaleGeneration)?;
        if inserted.rows_affected() == 0
            && (receipt.response_bytes != input.response_bytes
                || receipt.response_digest != *input.response_digest)
        {
            return Err(DatabaseError::Conflict);
        }
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_mount_session(
        &self,
        tenant_id: Uuid,
        credential_id: Uuid,
        device_id: Option<Uuid>,
        protocol: &str,
        gateway_id: &str,
        gateway_epoch: i64,
        source_address: &str,
    ) -> Result<MountSessionFence, DatabaseError> {
        if !matches!(protocol, "smb" | "ftps")
            || gateway_id.is_empty()
            || gateway_id.len() > 255
            || gateway_epoch <= 0
            || source_address.parse::<std::net::IpAddr>().is_err()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let credential = sqlx::query(
            "SELECT c.principal_id,c.credential_generation,c.authorization_generation,\
             c.read_only,c.allowed_drive_ids,p.generation AS membership_generation \
             FROM filebelt_mount.credentials c JOIN principals p \
               ON p.tenant_id=c.tenant_id AND p.id=c.principal_id \
             JOIN filebelt_mount.policies policy ON policy.tenant_id=c.tenant_id \
               AND policy.principal_id=c.principal_id AND policy.protocol=c.protocol \
             WHERE c.tenant_id=$1 AND c.id=$2 AND c.protocol=$3 AND c.revoked_at IS NULL \
               AND c.expires_at>clock_timestamp() AND policy.enabled AND p.disabled_at IS NULL \
               AND (c.bound_device_id IS NULL OR c.bound_device_id=$4) FOR SHARE OF c,p,policy",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .bind(protocol)
        .bind(device_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let gateway: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.gateway_epochs \
             WHERE tenant_id=$1 AND protocol=$2 AND gateway_id=$3 AND epoch=$4 \
               AND NOT draining AND lease_expires_at>clock_timestamp())",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .fetch_one(&mut *transaction)
        .await?;
        if !gateway {
            return Err(DatabaseError::StaleGeneration);
        }
        let session_id = Uuid::new_v4();
        let session_principal_id = Uuid::new_v4();
        let user_principal_id: Uuid = credential.get("principal_id");
        sqlx::query("SELECT filebelt_mount.create_session_principal($1,$2)")
            .bind(tenant_id)
            .bind(session_principal_id)
            .execute(&mut *transaction)
            .await?;
        let absolute_hours = if protocol == "smb" { 12 } else { 4 };
        sqlx::query(
            "INSERT INTO filebelt_mount.sessions \
             (tenant_id,id,session_principal_id,user_principal_id,credential_id,device_id,protocol,\
              gateway_id,gateway_epoch,source_address,credential_generation,authorization_generation,\
              membership_generation,idle_expires_at,absolute_expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::inet,$11,$12,$13,\
              clock_timestamp()+interval '15 minutes',clock_timestamp()+make_interval(hours=>$14))",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(session_principal_id)
        .bind(user_principal_id)
        .bind(credential_id)
        .bind(device_id)
        .bind(protocol)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .bind(source_address)
        .bind(credential.get::<i64, _>("credential_generation"))
        .bind(credential.get::<i64, _>("authorization_generation"))
        .bind(credential.get::<i64, _>("membership_generation"))
        .bind(absolute_hours)
        .execute(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        sqlx::query(
            "UPDATE filebelt_mount.credentials SET last_used_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            Some(user_principal_id),
            Some(session_principal_id),
            Some(session_id),
            "mount.session.start",
            "allowed",
            "credential_verified",
            false,
            json!({"protocol":protocol,"device_bound":device_id.is_some()}),
        )
        .await?;
        transaction.commit().await?;
        Ok(MountSessionFence {
            tenant_id,
            session_id,
            user_principal_id,
            credential_id,
            protocol: protocol.to_owned(),
            credential_generation: credential.get("credential_generation"),
            authorization_generation: credential.get("authorization_generation"),
            membership_generation: credential.get("membership_generation"),
            gateway_epoch,
            read_only: credential.get("read_only"),
            allowed_drive_ids: credential.get("allowed_drive_ids"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn admit_mount_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        protocol: &str,
        gateway_id: &str,
        gateway_epoch: i64,
        credential_generation: i64,
        authorization_generation: i64,
        nfs_gss_binding_digest: Option<&[u8; 32]>,
    ) -> Result<MountSessionFence, DatabaseError> {
        if (protocol == "nfs") != nfs_gss_binding_digest.is_some()
            || !matches!(protocol, "smb" | "ftps" | "nfs")
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let nfs_gss_binding_digest = nfs_gss_binding_digest.map(<[u8; 32]>::as_slice);
        let row = sqlx::query(
            "UPDATE filebelt_mount.sessions s SET last_activity_at=clock_timestamp(),\
             idle_expires_at=LEAST(s.absolute_expires_at,clock_timestamp()+interval '15 minutes') \
             FROM filebelt_mount.credentials c,principals p,filebelt_mount.gateway_epochs gateway,\
                  filebelt_mount.policies policy \
             WHERE s.tenant_id=$1 AND s.id=$2 AND s.protocol=$3 AND s.gateway_id=$4 \
               AND s.gateway_epoch=$5 AND s.credential_generation=$6 \
               AND s.authorization_generation=$7 AND s.state IN ('active','draining') \
               AND (($3='nfs' AND s.nfs_gss_binding_digest=$8) \
                 OR ($3<>'nfs' AND $8::bytea IS NULL)) \
               AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() \
               AND c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.revoked_at IS NULL \
               AND c.expires_at>clock_timestamp() AND c.credential_generation=$6 \
               AND c.authorization_generation=$7 \
               AND (c.bound_device_id IS NULL OR EXISTS (SELECT 1 \
                 FROM filebelt_mount.headscale_devices device \
                 WHERE device.tenant_id=c.tenant_id AND device.id=c.bound_device_id \
                   AND device.principal_id=s.user_principal_id AND device.revoked_at IS NULL \
                   AND device.observed_at>clock_timestamp()-interval '5 minutes')) \
               AND p.tenant_id=s.tenant_id AND p.id=s.user_principal_id \
               AND p.disabled_at IS NULL AND p.generation=s.membership_generation \
               AND policy.tenant_id=s.tenant_id AND policy.principal_id=s.user_principal_id \
               AND policy.protocol=s.protocol AND policy.enabled \
               AND gateway.tenant_id=s.tenant_id AND gateway.protocol=s.protocol \
               AND gateway.gateway_id=s.gateway_id AND gateway.epoch=s.gateway_epoch \
               AND ((s.state='active' AND NOT gateway.draining \
                     AND gateway.lease_expires_at>clock_timestamp()) \
                 OR (s.state='draining' AND gateway.draining \
                     AND gateway.drain_deadline>clock_timestamp())) \
               AND (s.protocol<>'nfs' OR (\
                 s.nfs_gss_binding_digest IS NOT NULL \
                 AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_feature_state feature \
                   WHERE feature.tenant_id=s.tenant_id \
                     AND ((s.state='active' AND feature.state='active') \
                       OR (s.state='draining' AND feature.state IN ('active','draining'))) \
                     AND feature.generation=s.nfs_feature_generation \
                     AND feature.applied_manifest_generation=feature.manifest_generation \
                     AND feature.applied_manifest_digest IS NOT NULL \
                     AND feature.applied_gateway_id=s.gateway_id \
                     AND feature.applied_gateway_epoch=s.gateway_epoch \
                     AND feature.restore_generation=s.nfs_restore_generation) \
                 AND EXISTS (SELECT 1 \
                   FROM filebelt_mount.nfs_principal_mappings mapping \
                   JOIN filebelt_mount.nfs_posix_groups posix_group \
                     ON posix_group.tenant_id=mapping.tenant_id \
                       AND posix_group.group_id=mapping.posix_group_id \
                       AND posix_group.projected_gid=mapping.projected_gid \
                   JOIN group_memberships membership \
                     ON membership.tenant_id=mapping.tenant_id \
                       AND membership.group_id=posix_group.group_id \
                       AND membership.user_principal_id=mapping.principal_id \
                   WHERE mapping.tenant_id=s.tenant_id \
                     AND mapping.credential_id=s.credential_id \
                     AND mapping.principal_id=s.user_principal_id \
                     AND mapping.generation=s.nfs_mapping_generation \
                     AND mapping.revoked_at IS NULL) \
                 AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_exports export \
                   JOIN nodes root ON root.tenant_id=export.tenant_id \
                     AND root.drive_id=export.drive_id AND root.parent_id IS NULL \
                     AND root.trash_root_id IS NULL AND root.kind='directory' \
                   WHERE export.tenant_id=s.tenant_id \
                     AND export.drive_id=ANY(c.allowed_drive_ids) \
                     AND export.desired_state='active' AND export.applied_state='active' \
                     AND export.desired_generation=export.applied_generation))) \
             RETURNING s.user_principal_id,s.credential_id,s.protocol,s.credential_generation,\
               s.authorization_generation,s.membership_generation,s.gateway_epoch,\
               c.read_only,CASE WHEN s.protocol='nfs' THEN ARRAY(\
                 SELECT export.drive_id FROM filebelt_mount.nfs_exports export \
                 JOIN nodes root ON root.tenant_id=export.tenant_id \
                   AND root.drive_id=export.drive_id AND root.parent_id IS NULL \
                   AND root.trash_root_id IS NULL AND root.kind='directory' \
                 WHERE export.tenant_id=s.tenant_id \
                   AND export.drive_id=ANY(c.allowed_drive_ids) \
                   AND export.desired_state='active' AND export.applied_state='active' \
                   AND export.desired_generation=export.applied_generation \
                 ORDER BY export.drive_id) ELSE c.allowed_drive_ids END AS allowed_drive_ids",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(protocol)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .bind(credential_generation)
        .bind(authorization_generation)
        .bind(nfs_gss_binding_digest)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(MountSessionFence {
            tenant_id,
            session_id,
            user_principal_id: row.get("user_principal_id"),
            credential_id: row.get("credential_id"),
            protocol: row.get("protocol"),
            credential_generation: row.get("credential_generation"),
            authorization_generation: row.get("authorization_generation"),
            membership_generation: row.get("membership_generation"),
            gateway_epoch: row.get("gateway_epoch"),
            read_only: row.get("read_only"),
            allowed_drive_ids: row.get("allowed_drive_ids"),
        })
    }

    pub async fn end_mount_session(
        &self,
        fence: &MountSessionFence,
        reason_code: &str,
    ) -> Result<(), DatabaseError> {
        if reason_code.is_empty() || reason_code.len() > 64 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.sessions SET state='closed',closed_at=clock_timestamp(),close_reason=$3 \
             WHERE tenant_id=$1 AND id=$2 AND state='active'",
        )
        .bind(fence.tenant_id)
        .bind(fence.session_id)
        .bind(reason_code)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        insert_audit(
            &mut transaction,
            fence.tenant_id,
            Some(fence.user_principal_id),
            None,
            Some(fence.session_id),
            "mount.session.end",
            "allowed",
            reason_code,
            false,
            json!({"protocol":fence.protocol}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_mount_handle(
        &self,
        fence: &MountSessionFence,
        drive_id: Uuid,
        node_id: Uuid,
        expected_version_id: Option<Uuid>,
        access_actions: &[String],
        share_read: bool,
        share_write: bool,
        share_delete: bool,
        drive_acl_generation: i64,
        namespace_generation: i64,
        resource_acl_generation: i64,
    ) -> Result<MountHandleRecord, DatabaseError> {
        if access_actions.is_empty()
            || access_actions.len() > 19
            || !access_actions.iter().all(|action| {
                matches!(
                    action.as_str(),
                    "READ_METADATA" | "READ_CONTENT" | "MANAGE_LOCK"
                )
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let node = sqlx::query(
            "SELECT n.head_version_id,n.kind,n.namespace_generation,n.acl_generation,\
             d.acl_generation AS drive_acl_generation FROM nodes n JOIN drives d \
             ON d.tenant_id=n.tenant_id AND d.id=n.drive_id \
             WHERE n.tenant_id=$1 AND n.drive_id=$2 AND n.id=$3 \
               AND n.kind='file' AND n.trash_root_id IS NULL FOR SHARE OF n,d",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let version_id: Option<Uuid> = node.get("head_version_id");
        if version_id.is_none()
            || expected_version_id.is_some_and(|expected| Some(expected) != version_id)
            || node.get::<i64, _>("drive_acl_generation") != drive_acl_generation
            || node.get::<i64, _>("namespace_generation") != namespace_generation
            || node.get::<i64, _>("acl_generation") != resource_acl_generation
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let wants_read = access_actions.iter().any(|action| action == "READ_CONTENT");
        let wants_write = access_actions
            .iter()
            .any(|action| action == "WRITE_CONTENT");
        let wants_delete = access_actions.iter().any(|action| action == "DELETE");
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.handles h \
             WHERE h.tenant_id=$1 AND h.drive_id=$2 AND h.node_id=$3 \
               AND h.closed_at IS NULL AND h.expires_at>clock_timestamp() AND (\
                 ($4 AND NOT h.share_read) OR ('READ_CONTENT'=ANY(h.access_actions) AND NOT $5) OR \
                 ($6 AND NOT h.share_write) OR ('WRITE_CONTENT'=ANY(h.access_actions) AND NOT $7) OR \
                 ($8 AND NOT h.share_delete) OR ('DELETE'=ANY(h.access_actions) AND NOT $9)))",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(wants_read)
        .bind(share_read)
        .bind(wants_write)
        .bind(share_write)
        .bind(wants_delete)
        .bind(share_delete)
        .fetch_one(&mut *transaction)
        .await?;
        if conflict {
            return Err(DatabaseError::Conflict);
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO filebelt_mount.handles \
             (tenant_id,id,session_id,drive_id,node_id,version_id,access_actions,\
              share_read,share_write,share_delete,credential_generation,authorization_generation,\
              membership_generation,drive_acl_generation,namespace_generation,\
              resource_acl_generation,gateway_epoch,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
               clock_timestamp()+interval '15 minutes')",
        )
        .bind(fence.tenant_id)
        .bind(id)
        .bind(fence.session_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(version_id)
        .bind(access_actions)
        .bind(share_read)
        .bind(share_write)
        .bind(share_delete)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(drive_acl_generation)
        .bind(namespace_generation)
        .bind(resource_acl_generation)
        .bind(fence.gateway_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(map_conflict)?;
        insert_audit(
            &mut transaction,
            fence.tenant_id,
            Some(fence.user_principal_id),
            None,
            Some(node_id),
            "mount.handle.open",
            "allowed",
            "virtual_acl_allowed",
            false,
            json!({"handle_id":id,"protocol":fence.protocol,"write":wants_write}),
        )
        .await?;
        transaction.commit().await?;
        Ok(MountHandleRecord {
            id,
            session_id: fence.session_id,
            drive_id,
            node_id,
            version_id,
            access_actions: access_actions.to_vec(),
            credential_generation: fence.credential_generation,
            authorization_generation: fence.authorization_generation,
            membership_generation: fence.membership_generation,
            drive_acl_generation,
            namespace_generation,
            resource_acl_generation,
            gateway_epoch: fence.gateway_epoch,
        })
    }

    pub async fn admit_mount_handle(
        &self,
        fence: &MountSessionFence,
        handle_id: Uuid,
        required_action: &str,
    ) -> Result<MountHandleRecord, DatabaseError> {
        if !matches!(
            required_action,
            "READ_METADATA" | "READ_CONTENT" | "MANAGE_LOCK"
        ) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "UPDATE filebelt_mount.handles h SET expires_at=clock_timestamp()+interval '15 minutes' \
             FROM filebelt_mount.sessions s,filebelt_mount.credentials c,principals p,drives d,nodes n,\
                  filebelt_mount.policies policy,filebelt_mount.gateway_epochs gateway \
             WHERE h.tenant_id=$1 AND h.id=$2 AND h.session_id=$3 AND h.closed_at IS NULL \
               AND h.expires_at>clock_timestamp() AND $4=ANY(h.access_actions) \
               AND h.credential_generation=$5 AND h.authorization_generation=$6 \
               AND h.membership_generation=$7 AND h.gateway_epoch=$8 \
               AND s.tenant_id=h.tenant_id AND s.id=h.session_id AND s.state='active' \
               AND s.credential_generation=h.credential_generation \
               AND s.authorization_generation=h.authorization_generation \
               AND s.membership_generation=h.membership_generation AND s.gateway_epoch=h.gateway_epoch \
               AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() \
               AND c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.revoked_at IS NULL \
               AND c.expires_at>clock_timestamp() AND c.credential_generation=h.credential_generation \
               AND c.authorization_generation=h.authorization_generation \
               AND p.tenant_id=s.tenant_id AND p.id=s.user_principal_id AND p.disabled_at IS NULL \
               AND p.generation=h.membership_generation \
               AND d.tenant_id=h.tenant_id AND d.id=h.drive_id AND d.acl_generation=h.drive_acl_generation \
               AND n.tenant_id=h.tenant_id AND n.drive_id=h.drive_id AND n.id=h.node_id \
               AND n.namespace_generation=h.namespace_generation AND n.acl_generation=h.resource_acl_generation \
               AND policy.tenant_id=s.tenant_id AND policy.principal_id=s.user_principal_id \
               AND policy.protocol=s.protocol AND policy.enabled \
               AND gateway.tenant_id=s.tenant_id AND gateway.protocol=s.protocol \
               AND gateway.gateway_id=s.gateway_id AND gateway.epoch=h.gateway_epoch \
               AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp() \
             RETURNING h.id,h.session_id,h.drive_id,h.node_id,h.version_id,h.access_actions,\
               h.credential_generation,h.authorization_generation,h.membership_generation,\
               h.drive_acl_generation,h.namespace_generation,h.resource_acl_generation,h.gateway_epoch",
        )
        .bind(fence.tenant_id)
        .bind(handle_id)
        .bind(fence.session_id)
        .bind(required_action)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(fence.gateway_epoch)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(mount_handle_from_row(&row))
    }

    pub async fn admit_mount_read_capability(
        &self,
        capability: &MountReadCapabilityFence,
    ) -> Result<MountHandleRecord, DatabaseError> {
        let row = sqlx::query(
            "SELECT h.id,h.session_id,h.drive_id,h.node_id,h.version_id,h.access_actions,\
               h.credential_generation,h.authorization_generation,h.membership_generation,\
               h.drive_acl_generation,h.namespace_generation,h.resource_acl_generation,h.gateway_epoch \
             FROM filebelt_mount.handles h \
             JOIN filebelt_mount.sessions s ON s.tenant_id=h.tenant_id AND s.id=h.session_id \
             JOIN filebelt_mount.credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id \
             JOIN principals p ON p.tenant_id=s.tenant_id AND p.id=s.user_principal_id \
             JOIN drives d ON d.tenant_id=h.tenant_id AND d.id=h.drive_id \
             JOIN nodes n ON n.tenant_id=h.tenant_id AND n.drive_id=h.drive_id AND n.id=h.node_id \
             JOIN filebelt_mount.policies policy ON policy.tenant_id=s.tenant_id \
               AND policy.principal_id=s.user_principal_id AND policy.protocol=s.protocol \
             JOIN filebelt_mount.gateway_epochs gateway ON gateway.tenant_id=s.tenant_id \
               AND gateway.protocol=s.protocol AND gateway.gateway_id=s.gateway_id \
             WHERE h.tenant_id=$1 AND h.id=$2 AND h.session_id=$3 AND s.credential_id=$4 \
               AND s.user_principal_id=$5 AND h.drive_id=$6 AND h.node_id=$7 AND h.version_id=$8 \
               AND h.closed_at IS NULL AND h.expires_at>clock_timestamp() \
               AND 'READ_CONTENT'=ANY(h.access_actions) AND s.state='active' \
               AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() \
               AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() \
               AND h.drive_id=ANY(c.allowed_drive_ids) \
               AND (c.bound_device_id IS NULL OR EXISTS (SELECT 1 \
                 FROM filebelt_mount.headscale_devices device \
                 WHERE device.tenant_id=c.tenant_id AND device.id=c.bound_device_id \
                   AND device.principal_id=s.user_principal_id AND device.revoked_at IS NULL \
                   AND device.observed_at>clock_timestamp()-interval '5 minutes')) \
               AND p.disabled_at IS NULL AND policy.enabled AND h.drive_id=ANY(policy.allowed_drive_ids) \
               AND gateway.epoch=$15 AND NOT gateway.draining \
               AND gateway.lease_expires_at>clock_timestamp() \
               AND h.credential_generation=$9 AND c.credential_generation=$9 \
               AND s.credential_generation=$9 AND h.authorization_generation=$10 \
               AND c.authorization_generation=$10 AND s.authorization_generation=$10 \
               AND h.membership_generation=$11 AND s.membership_generation=$11 AND p.generation=$11 \
               AND h.drive_acl_generation=$12 AND d.acl_generation=$12 \
               AND h.namespace_generation=$13 AND n.namespace_generation=$13 \
               AND h.resource_acl_generation=$14 AND n.acl_generation=$14 \
               AND h.gateway_epoch=$15 AND s.gateway_epoch=$15",
        )
        .bind(capability.tenant_id)
        .bind(capability.handle_id)
        .bind(capability.mount_session_id)
        .bind(capability.credential_id)
        .bind(capability.principal_id)
        .bind(capability.drive_id)
        .bind(capability.node_id)
        .bind(capability.version_id)
        .bind(capability.credential_generation)
        .bind(capability.authorization_generation)
        .bind(capability.membership_generation)
        .bind(capability.drive_acl_generation)
        .bind(capability.namespace_generation)
        .bind(capability.resource_acl_generation)
        .bind(capability.gateway_epoch)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        Ok(mount_handle_from_row(&row))
    }

    pub async fn close_mount_handle(
        &self,
        fence: &MountSessionFence,
        handle_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let closed = sqlx::query(
            "UPDATE filebelt_mount.handles SET closed_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND session_id=$3 AND closed_at IS NULL",
        )
        .bind(fence.tenant_id)
        .bind(handle_id)
        .bind(fence.session_id)
        .execute(&mut *transaction)
        .await?;
        if closed.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "UPDATE filebelt_mount.byte_locks SET released_at=clock_timestamp() \
             WHERE tenant_id=$1 AND handle_id=$2 AND released_at IS NULL",
        )
        .bind(fence.tenant_id)
        .bind(handle_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn acquire_mount_byte_lock(
        &self,
        fence: &MountSessionFence,
        handle: &MountHandleRecord,
        owner_key: &str,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<Uuid, DatabaseError> {
        if owner_key.is_empty() || owner_key.len() > 255 || length == 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let offset = i64::try_from(offset).map_err(|_| DatabaseError::InvalidPersistedValue)?;
        let length = i64::try_from(length).map_err(|_| DatabaseError::InvalidPersistedValue)?;
        let end = offset
            .checked_add(length)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let mut transaction = self.pool().begin().await?;
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.byte_locks \
             WHERE tenant_id=$1 AND drive_id=$2 AND node_id=$3 AND released_at IS NULL \
               AND expires_at>clock_timestamp() AND offset_bytes<$4 \
               AND offset_bytes+length_bytes>$5 AND (exclusive OR $6))",
        )
        .bind(fence.tenant_id)
        .bind(handle.drive_id)
        .bind(handle.node_id)
        .bind(end)
        .bind(offset)
        .bind(exclusive)
        .fetch_one(&mut *transaction)
        .await?;
        if conflict {
            return Err(DatabaseError::Conflict);
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO filebelt_mount.byte_locks \
             (tenant_id,id,handle_id,drive_id,node_id,owner_key,offset_bytes,length_bytes,\
              exclusive,gateway_epoch,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()+interval '30 seconds')",
        )
        .bind(fence.tenant_id)
        .bind(id)
        .bind(handle.id)
        .bind(handle.drive_id)
        .bind(handle.node_id)
        .bind(owner_key)
        .bind(offset)
        .bind(length)
        .bind(exclusive)
        .bind(fence.gateway_epoch)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(id)
    }

    pub async fn release_mount_byte_lock(
        &self,
        fence: &MountSessionFence,
        handle_id: Uuid,
        lock_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let changed = sqlx::query(
            "UPDATE filebelt_mount.byte_locks SET released_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND handle_id=$3 AND gateway_epoch=$4 \
               AND released_at IS NULL",
        )
        .bind(fence.tenant_id)
        .bind(lock_id)
        .bind(handle_id)
        .bind(fence.gateway_epoch)
        .execute(self.pool())
        .await?;
        if changed.rows_affected() != 1 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    pub async fn claim_mount_gateway_epoch(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        shard_key: &str,
        gateway_id: &str,
    ) -> Result<i64, DatabaseError> {
        if !matches!(protocol, "smb" | "ftps" | "nfs")
            || shard_key.is_empty()
            || shard_key.len() > 255
            || gateway_id.is_empty()
            || gateway_id.len() > 255
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "INSERT INTO filebelt_mount.gateway_epochs \
             (tenant_id,protocol,shard_key,gateway_id,epoch,lease_expires_at) \
             SELECT $1,$2,$3,$4,1,statement_timestamp()+CASE $2 \
               WHEN 'nfs' THEN interval '30 seconds' ELSE interval '20 seconds' END \
             WHERE $2<>'nfs' OR EXISTS (SELECT 1 FROM filebelt_mount.nfs_feature_state feature \
               WHERE feature.tenant_id=$1 AND feature.state IN ('preflight','active')) \
             ON CONFLICT (tenant_id,protocol,shard_key) DO UPDATE SET \
               gateway_id=EXCLUDED.gateway_id,\
               epoch=CASE WHEN NOT filebelt_mount.gateway_epochs.draining \
                 AND filebelt_mount.gateway_epochs.gateway_id=EXCLUDED.gateway_id \
                 AND filebelt_mount.gateway_epochs.lease_expires_at>statement_timestamp() \
                 THEN filebelt_mount.gateway_epochs.epoch \
                 ELSE filebelt_mount.gateway_epochs.epoch+1 END,\
               draining=false,drain_deadline=NULL,drain_reason=NULL,\
               lease_expires_at=EXCLUDED.lease_expires_at,updated_at=statement_timestamp() \
             WHERE (NOT filebelt_mount.gateway_epochs.draining AND (\
                 filebelt_mount.gateway_epochs.gateway_id=EXCLUDED.gateway_id \
                 OR filebelt_mount.gateway_epochs.lease_expires_at<=statement_timestamp())) \
                OR (filebelt_mount.gateway_epochs.draining \
                  AND filebelt_mount.gateway_epochs.drain_deadline<=statement_timestamp()) \
             RETURNING epoch",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(shard_key)
        .bind(gateway_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::AdmissionLimited)?;
        Ok(row.get("epoch"))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn drain_mount_gateway_epoch(
        &self,
        tenant_id: Uuid,
        protocol: &str,
        shard_key: &str,
        gateway_id: &str,
        gateway_epoch: i64,
        reason: &str,
    ) -> Result<(), DatabaseError> {
        if !matches!(protocol, "smb" | "ftps" | "nfs")
            || shard_key.is_empty()
            || shard_key.len() > 255
            || gateway_id.is_empty()
            || gateway_id.len() > 255
            || gateway_epoch <= 0
            || reason.is_empty()
            || reason.len() > 64
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.gateway_epochs \
             SET draining=true,drain_deadline=statement_timestamp()+interval '5 minutes',\
                 drain_reason=$6,updated_at=statement_timestamp() \
             WHERE tenant_id=$1 AND protocol=$2 AND shard_key=$3 AND gateway_id=$4 \
               AND epoch=$5 AND NOT draining AND lease_expires_at>statement_timestamp()",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(shard_key)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .bind(reason)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "UPDATE filebelt_mount.sessions AS session \
             SET state='draining',\
                 idle_expires_at=LEAST(session.idle_expires_at,gateway.drain_deadline),\
                 absolute_expires_at=LEAST(session.absolute_expires_at,gateway.drain_deadline),\
                 last_activity_at=statement_timestamp() \
             FROM filebelt_mount.gateway_epochs AS gateway \
             WHERE session.tenant_id=$1 AND session.protocol=$2 \
               AND session.gateway_id=$4 AND session.gateway_epoch=$5 \
               AND session.state='active' AND gateway.tenant_id=session.tenant_id \
               AND gateway.protocol=session.protocol AND gateway.shard_key=$3 \
               AND gateway.gateway_id=session.gateway_id AND gateway.epoch=session.gateway_epoch \
               AND gateway.draining",
        )
        .bind(tenant_id)
        .bind(protocol)
        .bind(shard_key)
        .bind(gateway_id)
        .bind(gateway_epoch)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            tenant_id,
            None,
            None,
            Some(tenant_id),
            "mount.gateway.drain",
            "allowed",
            "gateway_drain_requested",
            false,
            json!({
                "protocol":protocol,
                "shard_key":shard_key,
                "gateway_id":gateway_id,
                "gateway_epoch":gateway_epoch,
                "reason":reason
            }),
        )
        .await?;
        insert_outbox(
            &mut transaction,
            tenant_id,
            "filebelt.v1.mount.gateway.draining",
            "mount_gateway",
            tenant_id,
            gateway_epoch,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn list_mount_devices(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountDeviceRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT id,principal_id,headscale_node_id,display_name,\
             ARRAY(SELECT value::text FROM unnest(tailnet_addresses) value) AS tailnet_addresses,\
             node_tags,capability_version,ownership_generation,observed_at::text,revoked_at::text \
             FROM filebelt_mount.headscale_devices WHERE tenant_id=$1 AND principal_id=$2 \
             ORDER BY revoked_at NULLS FIRST,display_name,id",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(mount_device_from_row).collect())
    }

    pub async fn list_mount_sessions(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
    ) -> Result<Vec<MountSessionSummary>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT id,protocol,gateway_id,host(source_address) AS source_address,state,\
             created_at::text,last_activity_at::text,idle_expires_at::text,\
             absolute_expires_at::text,close_reason FROM filebelt_mount.sessions \
             WHERE tenant_id=$1 AND user_principal_id=$2 ORDER BY created_at DESC,id LIMIT 200",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .iter()
            .map(|row| MountSessionSummary {
                id: row.get("id"),
                protocol: row.get("protocol"),
                gateway_id: row.get("gateway_id"),
                source_address: row.get("source_address"),
                state: row.get("state"),
                created_at: row.get("created_at"),
                last_activity_at: row.get("last_activity_at"),
                idle_expires_at: row.get("idle_expires_at"),
                absolute_expires_at: row.get("absolute_expires_at"),
                close_reason: row.get("close_reason"),
            })
            .collect())
    }

    pub async fn mount_principal_for_external_identity(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<Uuid>, DatabaseError> {
        sqlx::query_scalar(
            "SELECT u.principal_id FROM external_identities identity JOIN users u \
             ON u.tenant_id=identity.tenant_id AND u.id=identity.user_id JOIN principals p \
             ON p.tenant_id=u.tenant_id AND p.id=u.principal_id \
             WHERE identity.tenant_id=$1 AND identity.issuer=$2 AND identity.subject=$3 \
               AND identity.disabled_at IS NULL AND u.status='active' AND p.disabled_at IS NULL",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .fetch_optional(self.pool())
        .await
        .map_err(DatabaseError::from)
    }

    pub async fn replace_mount_devices(
        &self,
        tenant_id: Uuid,
        observations: &[MountDeviceObservation],
    ) -> Result<(), DatabaseError> {
        if observations.len() > 10_000
            || observations.iter().any(|observation| {
                observation.headscale_node_id.is_empty()
                    || observation.headscale_node_id.len() > 255
                    || observation.addresses.is_empty()
                    || observation.addresses.len() > 16
                    || observation.tags.len() > 32
                    || observation.capability_version.is_empty()
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        for observation in observations {
            sqlx::query(
                "INSERT INTO filebelt_mount.headscale_devices \
                 (tenant_id,id,principal_id,headscale_node_id,oidc_issuer,oidc_subject,display_name,\
                  tailnet_addresses,node_tags,capability_version,observed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet[],$9,$10,clock_timestamp()) \
                 ON CONFLICT (tenant_id,headscale_node_id) DO UPDATE SET \
                   principal_id=EXCLUDED.principal_id,oidc_issuer=EXCLUDED.oidc_issuer,\
                   oidc_subject=EXCLUDED.oidc_subject,display_name=EXCLUDED.display_name,\
                   tailnet_addresses=EXCLUDED.tailnet_addresses,node_tags=EXCLUDED.node_tags,\
                   capability_version=EXCLUDED.capability_version,\
                   ownership_generation=CASE \
                     WHEN filebelt_mount.headscale_devices.principal_id=EXCLUDED.principal_id \
                     THEN filebelt_mount.headscale_devices.ownership_generation \
                     ELSE filebelt_mount.headscale_devices.ownership_generation+1 END,\
                   observed_at=clock_timestamp(),revoked_at=NULL",
            )
            .bind(tenant_id)
            .bind(Uuid::new_v4())
            .bind(observation.principal_id)
            .bind(&observation.headscale_node_id)
            .bind(&observation.issuer)
            .bind(&observation.subject)
            .bind(&observation.display_name)
            .bind(&observation.addresses)
            .bind(&observation.tags)
            .bind(&observation.capability_version)
            .execute(&mut *transaction)
            .await?;
        }
        let observed = observations
            .iter()
            .map(|observation| observation.headscale_node_id.clone())
            .collect::<Vec<_>>();
        sqlx::query(
            "UPDATE filebelt_mount.headscale_devices SET revoked_at=clock_timestamp(),\
             ownership_generation=ownership_generation+1 \
             WHERE tenant_id=$1 AND revoked_at IS NULL AND NOT (headscale_node_id=ANY($2))",
        )
        .bind(tenant_id)
        .bind(&observed)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn nfs_feature_state_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<NfsFeatureStateRecord, DatabaseError> {
    Ok(NfsFeatureStateRecord {
        state: NfsFeatureState::parse(row.get::<String, _>("state").as_str())?,
        generation: row.get("generation"),
        manifest_generation: row.get("manifest_generation"),
        applied_manifest_generation: row.get("applied_manifest_generation"),
        applied_manifest_digest: optional_digest_32(
            row.get::<Option<Vec<u8>>, _>("applied_manifest_digest"),
        )?,
        applied_gateway_id: row.get("applied_gateway_id"),
        applied_gateway_epoch: row.get("applied_gateway_epoch"),
        restore_generation: row.get("restore_generation"),
    })
}

fn optional_digest_32(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, DatabaseError> {
    value
        .map(|digest| {
            digest
                .try_into()
                .map_err(|_| DatabaseError::InvalidPersistedValue)
        })
        .transpose()
}

fn nfs_export_from_row(row: &sqlx::postgres::PgRow) -> Result<NfsExportRecord, DatabaseError> {
    Ok(NfsExportRecord {
        drive_id: row.get("drive_id"),
        export_id: row.get("export_id"),
        export_path: row.get("export_path"),
        desired_state: NfsExportState::parse(row.get::<String, _>("desired_state").as_str())?,
        applied_state: NfsExportState::parse(row.get::<String, _>("applied_state").as_str())?,
        desired_generation: row.get("desired_generation"),
        applied_generation: row.get("applied_generation"),
    })
}

fn nfs_export_manifest_entry_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<NfsExportManifestEntry, DatabaseError> {
    let export_generation = row.get("export_generation");
    let root_node_generation = row.get("root_node_generation");
    if export_generation <= 0 || root_node_generation <= 0 {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(NfsExportManifestEntry {
        drive_id: row.get("drive_id"),
        export_id: row.get("export_id"),
        export_path: row.get("export_path"),
        export_generation,
        root_node_id: row.get("root_node_id"),
        root_node_generation,
    })
}

fn nfs_posix_group_from_row(row: &sqlx::postgres::PgRow) -> NfsPosixGroupRecord {
    NfsPosixGroupRecord {
        group_id: row.get("group_id"),
        posix_name: row.get("posix_name"),
        projected_gid: row.get("projected_gid"),
    }
}

fn valid_nfs_projected_id(value: i64) -> bool {
    (1..=NFS_MAX_PROJECTED_ID).contains(&value) && value != NFS_NOBODY_PROJECTED_ID
}

fn valid_nfs_posix_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=255).contains(&bytes.len())
        && matches!(bytes[0], b'a'..=b'z' | b'_')
        && bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

fn valid_nfs_replay_context(context: &NfsReplayContext<'_>) -> bool {
    fn stable_key(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
            })
    }
    let operation = context.operation.as_bytes();
    stable_key(context.client_id)
        && stable_key(context.nfs_session_id)
        && (0..=1023).contains(&context.slot_id)
        && context.sequence_id > 0
        && (0..=63).contains(&context.operation_index)
        && (1..=64).contains(&operation.len())
        && operation[0].is_ascii_lowercase()
        && operation[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        && context.gateway_epoch > 0
}

fn nfs_posix_user_name(kerberos_principal: &str) -> Result<String, DatabaseError> {
    if kerberos_principal.is_empty()
        || kerberos_principal.len() > 512
        || kerberos_principal
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '/' | '\\'))
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let mut components = kerberos_principal.split('@');
    let user = components.next().unwrap_or_default();
    let realm = components.next().unwrap_or_default();
    if user.is_empty()
        || user.eq_ignore_ascii_case("root")
        || realm.is_empty()
        || components.next().is_some()
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let posix_name = user.to_ascii_lowercase();
    if !valid_nfs_posix_name(&posix_name) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(posix_name)
}

fn mount_credential_from_row(row: &sqlx::postgres::PgRow) -> MountCredentialRecord {
    MountCredentialRecord {
        id: row.get("id"),
        principal_id: row.get("principal_id"),
        protocol: row.get("protocol"),
        username: row.get("username"),
        verifier_kind: row.get("verifier_kind"),
        credential_generation: row.get("credential_generation"),
        authorization_generation: row.get("authorization_generation"),
        read_only: row.get("read_only"),
        allowed_drive_ids: row.get("allowed_drive_ids"),
        bound_device_id: row.get("bound_device_id"),
        created_at: row.get("created_at"),
        last_used_at: row.get("last_used_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
    }
}

fn mount_policy_from_row(row: &sqlx::postgres::PgRow) -> MountPolicyRecord {
    MountPolicyRecord {
        protocol: row.get("protocol"),
        enabled: row.get("enabled"),
        read_only: row.get("read_only"),
        allowed_drive_ids: row.get("allowed_drive_ids"),
        authorization_generation: row.get("authorization_generation"),
        revision: row.get("revision"),
        updated_at: row.get("updated_at"),
    }
}

fn mount_device_from_row(row: &sqlx::postgres::PgRow) -> MountDeviceRecord {
    MountDeviceRecord {
        id: row.get("id"),
        principal_id: row.get("principal_id"),
        headscale_node_id: row.get("headscale_node_id"),
        display_name: row.get("display_name"),
        tailnet_addresses: row.get("tailnet_addresses"),
        node_tags: row.get("node_tags"),
        capability_version: row.get("capability_version"),
        ownership_generation: row.get("ownership_generation"),
        observed_at: row.get("observed_at"),
        revoked_at: row.get("revoked_at"),
    }
}

fn mount_handle_from_row(row: &sqlx::postgres::PgRow) -> MountHandleRecord {
    MountHandleRecord {
        id: row.get("id"),
        session_id: row.get("session_id"),
        drive_id: row.get("drive_id"),
        node_id: row.get("node_id"),
        version_id: row.get("version_id"),
        access_actions: row.get("access_actions"),
        credential_generation: row.get("credential_generation"),
        authorization_generation: row.get("authorization_generation"),
        membership_generation: row.get("membership_generation"),
        drive_acl_generation: row.get("drive_acl_generation"),
        namespace_generation: row.get("namespace_generation"),
        resource_acl_generation: row.get("resource_acl_generation"),
        gateway_epoch: row.get("gateway_epoch"),
    }
}

fn array_12(value: Vec<u8>) -> Result<[u8; 12], DatabaseError> {
    value
        .try_into()
        .map_err(|_| DatabaseError::InvalidPersistedValue)
}

fn array_32(value: Vec<u8>) -> Result<[u8; 32], DatabaseError> {
    value
        .try_into()
        .map_err(|_| DatabaseError::InvalidPersistedValue)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_keeps_secret_queries_inside_the_mount_module() {
        let source = include_str!("mount.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("filebelt_mount_vault.secret_envelopes"));
        assert!(production.contains("policy.enabled"));
        assert!(production.contains("gateway.lease_expires_at>clock_timestamp()"));
        assert!(!production.contains("payload_locator"));
    }

    #[test]
    fn nfs_identity_projection_requires_exact_names_and_reserved_ids() {
        assert_eq!(
            nfs_posix_user_name("Alice_1@EXAMPLE.TEST").expect("valid NFS principal"),
            "alice_1"
        );
        for invalid in [
            "alice",
            "alice/admin@EXAMPLE.TEST",
            "alice@EXAMPLE@TEST",
            "alice\\admin@EXAMPLE.TEST",
            "root@EXAMPLE.TEST",
            "ROOT@EXAMPLE.TEST",
            "1alice@EXAMPLE.TEST",
        ] {
            assert!(matches!(
                nfs_posix_user_name(invalid),
                Err(DatabaseError::InvalidPersistedValue)
            ));
        }
        assert!(valid_nfs_projected_id(1));
        assert!(!valid_nfs_projected_id(0));
        assert!(!valid_nfs_projected_id(NFS_NOBODY_PROJECTED_ID));
        assert!(!valid_nfs_projected_id(NFS_MAX_PROJECTED_ID + 1));
        assert!(valid_nfs_posix_name("project_users"));
        assert!(!valid_nfs_posix_name("ProjectUsers"));
    }

    #[test]
    fn nfs_authority_migration_is_tenant_local_and_staged() {
        let migration = include_str!("../../../migrations/postgres/000012_nfs_authority.sql");
        for table in ["nfs_feature_state", "nfs_exports", "nfs_posix_groups"] {
            assert!(migration.contains(&format!("filebelt_mount.{table}")));
        }
        assert!(migration.contains("'disabled','preflight','active','draining'"));
        assert!(migration.contains("new NFS exports must begin disabled and unapplied"));
        assert!(migration.contains("OLD.applied_state='draining'"));
        assert!(migration.contains("credential.expires_at='infinity'::timestamptz"));
        assert!(migration.contains("feature.state='active'"));
        assert!(migration.contains("manifest_generation=manifest_generation+1"));
        assert!(migration.contains("advance_nfs_restore_generation"));
        assert!(migration.contains("OLD.drain_deadline>statement_timestamp()"));
        assert!(migration.contains("p_gss_expires_at<=clock_timestamp()"));
        assert!(migration.contains("clock_timestamp()+interval '4 hours',p_gss_expires_at"));
        assert!(!migration.contains("filebelt_phase8.activation_state"));
    }
}

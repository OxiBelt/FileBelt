// SPDX-License-Identifier: Apache-2.0

//! Authoritative mount credential, device, gateway, and session mechanics.

use std::collections::{HashSet, VecDeque};

use filebelt_domain::NormalizedName;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{
    AclInputRow, AuthorizationSnapshot, Database, DatabaseError, IdempotencyRecord, PayloadRecord,
    insert_audit, insert_outbox, lock_authorization_fence, map_conflict,
};
use crate::idempotency::{
    IdempotencyInput, IdempotencyReservation, finalize as finalize_idempotency,
    reserve as reserve_idempotency,
};

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
    pub allowed_export_ids: Vec<i64>,
    pub nfs_mapping_generation: Option<i64>,
    pub nfs_feature_generation: Option<i64>,
    pub nfs_manifest_generation: Option<i64>,
    pub nfs_restore_generation: Option<i64>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    pub mutation_outcome: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsNodeMetadata {
    pub node_id: Uuid,
    pub drive_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub kind: String,
    pub namespace_generation: i64,
    pub acl_generation: i64,
    pub handle_generation: i64,
    pub owner_principal_id: Uuid,
    pub posix_group_id: Option<Uuid>,
    pub posix_mode: i32,
    pub projected_uid: i64,
    pub projected_gid: i64,
    pub owner_name: String,
    pub group_name: String,
    pub accessed_at_unix_seconds: i64,
    pub modified_at_unix_seconds: i64,
    pub changed_at_unix_seconds: i64,
    pub created_at_unix_seconds: i64,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsNodeXattr {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsHandlePathNode {
    /// Zero for the target, increasing toward the export root.
    pub depth: i32,
    pub metadata: NfsNodeMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsPathAclEntry {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub principal_id: Uuid,
    pub action: String,
    pub effect: String,
    pub inheritance: String,
    pub generation: i64,
    pub created_by: Uuid,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsHandleResolution {
    pub export_id: i64,
    pub export_generation: i64,
    pub manifest_generation: i64,
    pub restore_generation: i64,
    pub root_node_id: Uuid,
    pub root_handle_generation: i64,
    pub target: NfsNodeMetadata,
    /// Root-to-target order, including both endpoints.
    pub path: Vec<NfsHandlePathNode>,
    /// Direct Core and NFS-tagged rows on every path component. The common
    /// evaluator applies inheritance and deny precedence for the actor.
    pub acl_entries: Vec<NfsPathAclEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsResolvedSymlink {
    pub node_id: Uuid,
    pub kind: String,
    pub symlink_hops: u8,
    pub traversed: Vec<NfsTraversedNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsTraversedNode {
    pub node_id: Uuid,
    pub acl_generation: i64,
    pub namespace_generation: i64,
}

#[derive(Clone, Debug)]
pub struct NfsAuthorizationSnapshot {
    pub snapshot: AuthorizationSnapshot,
    pub feature_generation: i64,
}

#[derive(Clone, Debug)]
pub struct NfsMutationAuthorization {
    pub drive_id: Uuid,
    pub resource_id: Uuid,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub drive_namespace_generation: i64,
    pub resource_acl_generation: i64,
    pub resource_namespace_generation: i64,
}

#[derive(Clone, Debug)]
pub struct NfsAclMutationEntry {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub action: String,
    pub inheritance: String,
}

#[derive(Clone, Debug)]
pub enum NfsNamespaceMutation {
    CreateFile {
        node_id: Uuid,
        display_name: String,
        name_key: String,
        mode: Option<i32>,
    },
    CreateDirectory {
        node_id: Uuid,
        display_name: String,
        name_key: String,
        mode: Option<i32>,
    },
    CreateSymlink {
        node_id: Uuid,
        display_name: String,
        name_key: String,
        target: String,
        mode: Option<i32>,
    },
    Rename {
        old_parent_id: Uuid,
        old_parent_acl_generation: i64,
        old_parent_namespace_generation: i64,
        target_parent_id: Uuid,
        target_display_name: String,
        target_name_key: String,
        target_parent_acl_generation: i64,
        target_parent_namespace_generation: i64,
    },
    Remove {
        parent_id: Uuid,
        parent_acl_generation: i64,
        parent_namespace_generation: i64,
    },
    SetAttributes {
        mode: Option<i32>,
        owner_principal_id: Option<Uuid>,
        posix_group_id: Option<Uuid>,
        accessed_at_unix_seconds: Option<i64>,
        modified_at_unix_seconds: Option<i64>,
    },
    SetXattr {
        name: String,
        value: Vec<u8>,
        create_only: bool,
        replace_only: bool,
    },
    RemoveXattr {
        name: String,
    },
    ReplaceAcl {
        entries: Vec<NfsAclMutationEntry>,
    },
}

#[derive(Clone, Debug)]
pub struct NfsNamespaceMutationInput<'a> {
    pub context: NfsReplayContext<'a>,
    pub gss_binding_digest: &'a [u8; 32],
    pub authorization: NfsMutationAuthorization,
    pub mutation: NfsNamespaceMutation,
    pub response_bytes: &'a [u8],
    pub response_digest: &'a [u8; 32],
}

#[derive(Clone, Debug)]
pub struct CommitNfsWriteInput<'a> {
    pub context: NfsReplayContext<'a>,
    pub gss_binding_digest: &'a [u8; 32],
    pub authorization: NfsMutationAuthorization,
    pub write_session_id: Uuid,
    pub fencing_token: i64,
    pub version_id: Uuid,
    pub conflict_id: Uuid,
    pub success_response_bytes: &'a [u8],
    pub success_response_digest: &'a [u8; 32],
    pub conflict_response_bytes: &'a [u8],
    pub conflict_response_digest: &'a [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsMutationReceipt {
    pub replay: NfsReplayReceipt,
    pub replayed: bool,
    pub outcome: String,
    pub resource_id: Option<Uuid>,
    pub resource_generation: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct CloseNfsHandleInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub handle_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct OpenNfsHandleInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    /// The success replay envelope. A conflict uses the same identity/request
    /// digest and the separately supplied exact conflict response.
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub conflict_response_bytes: &'a [u8],
    pub conflict_response_digest: &'a [u8; 32],
    pub handle_id: Uuid,
    pub authorization: NfsMutationAuthorization,
    pub expected_version_id: Option<Uuid>,
    pub access_actions: &'a [String],
    pub share_read: bool,
    pub share_write: bool,
    pub share_delete: bool,
}

#[derive(Clone, Debug)]
pub struct OpenedNfsHandle {
    pub handle: Option<MountHandleRecord>,
    pub replay: NfsReplayReceipt,
    pub replayed: bool,
    pub outcome: String,
}

#[derive(Clone, Debug)]
pub struct EndNfsSessionInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub reason_code: &'a str,
}

#[derive(Clone, Debug)]
pub struct AcquireNfsByteLockInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub handle_id: Uuid,
    pub lock_id: Uuid,
    pub owner_key: &'a str,
    pub offset_bytes: i64,
    pub length_bytes: i64,
    pub exclusive: bool,
}

#[derive(Clone, Debug)]
pub struct ReleaseNfsByteLockInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub handle_id: Uuid,
    pub lock_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountWriteStorageOperation {
    Write,
    Flush,
    Finalize,
    Abort,
    DeleteStaging,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountWriteRangeOperation {
    WriteData,
    HoleDeallocate,
    Allocate,
    SeekData,
    SeekHole,
}

impl MountWriteRangeOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::WriteData => "write_data",
            Self::HoleDeallocate => "hole_deallocate",
            Self::Allocate => "allocate",
            Self::SeekData => "seek_data",
            Self::SeekHole => "seek_hole",
        }
    }

    fn writes_bytes(self) -> bool {
        matches!(
            self,
            Self::WriteData | Self::HoleDeallocate | Self::Allocate
        )
    }

    fn seeks(self) -> bool {
        matches!(self, Self::SeekData | Self::SeekHole)
    }

    fn io_operation(self) -> MountIoOperation {
        match self {
            Self::WriteData => MountIoOperation::WriteData,
            Self::HoleDeallocate => MountIoOperation::HoleDeallocate,
            Self::Allocate => MountIoOperation::Allocate,
            Self::SeekData => MountIoOperation::SeekData,
            Self::SeekHole => MountIoOperation::SeekHole,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MountWriteCapabilityFence {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub mount_session_id: Uuid,
    pub credential_id: Uuid,
    pub handle_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Option<Uuid>,
    pub write_session_id: Uuid,
    pub credential_generation: i64,
    pub authorization_generation: i64,
    pub membership_generation: i64,
    pub drive_acl_generation: i64,
    pub namespace_generation: i64,
    pub resource_acl_generation: i64,
    pub gateway_epoch: i64,
    pub fencing_token: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MountWriteChunkEvidence {
    pub chunk_number: i64,
    pub size_bytes: i64,
    pub blake3: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MountWriteChunkPlan {
    pub chunk_number: i64,
    pub source_payload_id: Option<Uuid>,
    pub source_chunk_number: Option<i64>,
    pub staging_locator: Uuid,
    pub size_bytes: i64,
    pub dirty: bool,
}

#[derive(Clone, Debug)]
pub struct ExtendNfsWriteChunksInput<'a> {
    pub fence: &'a MountWriteCapabilityFence,
    /// Internal pending protocol identity. Planning does not advance the NFS
    /// replay slot or record a client-visible response.
    pub context: NfsReplayContext<'a>,
    /// The new logical end that must be quota-reserved before a capability is
    /// issued. It may equal but never be lower than the current reservation.
    pub required_reservation_bytes: i64,
    /// Stable range-plan identity retained through bearer reissue.
    pub operation_id: Uuid,
    /// Short-lived opaque fbcap2 identity for this issuance.
    pub capability_id: Uuid,
    pub operation: MountWriteRangeOperation,
    /// Exact signed fbcap2 identity preauthorized with the range plan before
    /// the NFS replay response is committed.
    pub nonce_digest: &'a [u8; 32],
    pub claims_digest: &'a [u8; 32],
    pub expires_at_unix_seconds: i64,
    /// Required only for WriteData and bound into the signed fbcap2 claims.
    pub content_blake3: Option<&'a [u8; 32]>,
    pub range_start: i64,
    pub range_end: i64,
    /// Complete authoritative prefix after this extension.
    pub chunks: &'a [MountWriteChunkPlan],
}

#[derive(Clone, Debug)]
pub struct NfsWriteChunkPlanResult {
    pub write_session_id: Uuid,
    pub reserved_bytes: i64,
    pub operation_id: Uuid,
    pub operation_ordinal: i64,
    pub operation: MountWriteRangeOperation,
    pub content_blake3: Option<[u8; 32]>,
    pub range_start: i64,
    pub range_end: i64,
    pub resulting_logical_size: i64,
    pub chunks: Vec<MountWriteChunkPlan>,
    /// True when the same internal pending protocol operation resumed. This is
    /// not a client-visible NFS replay receipt.
    pub resumed: bool,
}

#[derive(Clone, Debug)]
pub struct MountWriteRangeAdmission {
    pub storage: MountWriteStorageRecord,
    pub operation_id: Uuid,
    pub operation_ordinal: i64,
    pub operation: MountWriteRangeOperation,
    pub content_blake3: Option<[u8; 32]>,
    pub range_start: i64,
    pub range_end: i64,
    pub resulting_logical_size: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NfsWriteExtent {
    pub offset_bytes: i64,
    pub length_bytes: i64,
    pub is_hole: bool,
    pub digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct ApplyNfsWriteExtentInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub fence: &'a MountWriteCapabilityFence,
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub operation_id: Uuid,
    pub operation: MountWriteRangeOperation,
    pub range_start: i64,
    pub range_end: i64,
    pub data_digest: Option<&'a [u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct SeekNfsWriteExtentInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub fence: &'a MountWriteCapabilityFence,
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub operation_id: Uuid,
    pub operation: MountWriteRangeOperation,
    pub range_start: i64,
    pub range_end: i64,
}

#[derive(Clone, Debug)]
pub struct NfsWriteExtentResult {
    pub write_session_id: Uuid,
    pub logical_size_bytes: i64,
    pub extents: Vec<NfsWriteExtent>,
    pub seek_offset: Option<i64>,
    pub replay: NfsReplayReceipt,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountIoOperation {
    WriteData,
    HoleDeallocate,
    Allocate,
    SeekData,
    SeekHole,
    Flush,
    Finalize,
    Abort,
    DeleteStaging,
}

impl MountIoOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::WriteData => "write_data",
            Self::HoleDeallocate => "hole_deallocate",
            Self::Allocate => "allocate",
            Self::SeekData => "seek_data",
            Self::SeekHole => "seek_hole",
            Self::Flush => "flush",
            Self::Finalize => "finalize",
            Self::Abort => "abort",
            Self::DeleteStaging => "delete_staging",
        }
    }

    fn range_operation(self) -> Option<MountWriteRangeOperation> {
        match self {
            Self::WriteData => Some(MountWriteRangeOperation::WriteData),
            Self::HoleDeallocate => Some(MountWriteRangeOperation::HoleDeallocate),
            Self::Allocate => Some(MountWriteRangeOperation::Allocate),
            Self::SeekData => Some(MountWriteRangeOperation::SeekData),
            Self::SeekHole => Some(MountWriteRangeOperation::SeekHole),
            Self::Flush | Self::Finalize | Self::Abort | Self::DeleteStaging => None,
        }
    }

    fn from_persisted(value: &str) -> Result<Self, DatabaseError> {
        match value {
            "write_data" => Ok(Self::WriteData),
            "hole_deallocate" => Ok(Self::HoleDeallocate),
            "allocate" => Ok(Self::Allocate),
            "seek_data" => Ok(Self::SeekData),
            "seek_hole" => Ok(Self::SeekHole),
            "flush" => Ok(Self::Flush),
            "finalize" => Ok(Self::Finalize),
            "abort" => Ok(Self::Abort),
            "delete_staging" => Ok(Self::DeleteStaging),
            _ => Err(DatabaseError::InvalidPersistedValue),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BeginMountIoOperationInput<'a> {
    pub fence: &'a MountWriteCapabilityFence,
    /// Opaque VFS-minted fbcap2 capability identity. PostgreSQL resolves this
    /// short-lived bearer to the stable range-plan identity.
    pub capability_id: Uuid,
    pub nonce_digest: &'a [u8; 32],
    pub claims_digest: &'a [u8; 32],
    pub operation: MountIoOperation,
    pub range_start: Option<i64>,
    pub range_end: Option<i64>,
    pub content_blake3: Option<&'a [u8; 32]>,
    pub expires_at_unix_seconds: i64,
}

#[derive(Clone, Debug)]
pub struct PreauthorizeMountIoOperationInput<'a> {
    pub io: BeginMountIoOperationInput<'a>,
    /// Stable internal identity retained while short-lived fbcap2 admissions
    /// are replaced after a VFS restart.
    pub protocol_operation_id: Uuid,
    /// Internal pending protocol identity. The eventual mutation transaction
    /// alone inserts the client-visible replay response.
    pub context: NfsReplayContext<'a>,
}

#[derive(Clone, Debug)]
pub struct PreauthorizedMountIoOperation {
    pub resumed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingMountIoWorkerState {
    Admission,
    Pending,
    Completed,
}

#[derive(Clone, Debug)]
pub struct PendingMountIoOperation {
    pub protocol_operation_id: Uuid,
    pub write_session_id: Uuid,
    pub capability_id: Uuid,
    pub nonce_digest: [u8; 32],
    pub claims_digest: [u8; 32],
    pub operation: MountIoOperation,
    pub operation_id: Option<Uuid>,
    pub content_blake3: Option<[u8; 32]>,
    pub range_start: Option<i64>,
    pub range_end: Option<i64>,
    pub fencing_token: i64,
    pub capability_expires_at_unix_seconds: i64,
    pub worker_state: PendingMountIoWorkerState,
    pub worker_outcome: Option<MountIoCompletion>,
}

#[derive(Clone, Debug)]
pub struct ReissueMountIoOperationInput<'a> {
    pub context: NfsReplayContext<'a>,
    pub fence: &'a MountWriteCapabilityFence,
    pub protocol_operation_id: Uuid,
    /// Stable range-plan identity. Terminal operations have no range plan.
    pub stable_operation_id: Option<Uuid>,
    pub operation: MountIoOperation,
    pub content_blake3: Option<&'a [u8; 32]>,
    pub range_start: Option<i64>,
    pub range_end: Option<i64>,
    pub new_capability_id: Uuid,
    pub new_nonce_digest: &'a [u8; 32],
    pub new_claims_digest: &'a [u8; 32],
    pub new_expires_at_unix_seconds: i64,
}

#[derive(Clone, Debug)]
pub struct FinalizeNfsInternalIoReplayInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub fence: &'a MountWriteCapabilityFence,
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub operation: MountIoOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MountIoCompletion {
    RangeMutation {
        logical_size_bytes: i64,
        reservation_delta_bytes: i64,
    },
    Seek {
        offset: Option<i64>,
    },
    Flush {
        logical_size_bytes: i64,
        blake3: [u8; 32],
        chunks: Vec<MountWriteChunkEvidence>,
    },
    Finalize {
        logical_size_bytes: i64,
        blake3: [u8; 32],
        chunks: Vec<MountWriteChunkEvidence>,
    },
    Abort,
    DeleteStaging,
    Cleanup,
}

#[derive(Clone, Debug)]
pub struct MountIoCleanupRecord {
    pub tenant_id: Uuid,
    pub write_session_id: Uuid,
    pub fencing_token: i64,
    pub storage: MountWriteStorageRecord,
    pub nonce_digest: [u8; 32],
    pub claims_digest: [u8; 32],
    pub operation: MountIoOperation,
    pub operation_id: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub enum MountIoAdmission {
    Execute(MountWriteStorageRecord),
    Completed(MountIoCompletion),
    CleanupRequired(MountIoCleanupRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MountIoLookup {
    Absent,
    Pending,
    Completed(MountIoCompletion),
}

#[derive(Clone, Debug)]
pub struct MountStagingCleanupJobRecord {
    pub tenant_id: Uuid,
    pub write_session_id: Uuid,
    pub backend_id: Uuid,
    pub worker_id: Uuid,
    pub payload: PayloadRecord,
    pub job_fencing_token: i64,
    pub job_state: String,
    pub reason: String,
    pub completion_kind: String,
    pub source_nonce_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountWriteLockCleanupJobRecord {
    pub tenant_id: Uuid,
    pub write_session_id: Uuid,
    pub backend_id: Uuid,
    pub staging_payload_id: Uuid,
    pub worker_id: Uuid,
    pub job_fencing_token: i64,
    pub job_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredNfsWriterCleanupRecord {
    pub tenant_id: Uuid,
    pub write_session_id: Uuid,
    pub backend_id: Uuid,
    pub staging_payload_id: Uuid,
    pub fencing_token: i64,
    pub source_nonce_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredNfsWriteConflictCleanupRecord {
    pub tenant_id: Uuid,
    pub conflict_id: Uuid,
    pub write_session_id: Uuid,
    pub backend_id: Uuid,
    pub staging_payload_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountPayloadPartRecord {
    pub chunk_number: i64,
    pub locator: Uuid,
    pub size_bytes: i64,
    pub blake3: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct MountWriteStorageRecord {
    pub write_session_id: Uuid,
    pub base_version_id: Option<Uuid>,
    pub logical_size_bytes: i64,
    pub reserved_bytes: i64,
    pub state: String,
    pub staging_payload: PayloadRecord,
    pub base_payload: Option<PayloadRecord>,
    pub base_parts: Vec<MountPayloadPartRecord>,
    pub planned_chunks: Vec<MountWriteChunkPlan>,
}

#[derive(Clone, Debug)]
pub struct ResolvedNfsWrite {
    pub fence: MountWriteCapabilityFence,
    pub storage: MountWriteStorageRecord,
}

#[derive(Clone, Debug)]
pub struct StartNfsWriteInput<'a> {
    pub session: &'a MountSessionFence,
    pub gss_binding_digest: &'a [u8; 32],
    pub replay: RecordNfsReplayReceiptInput<'a>,
    pub handle_id: Uuid,
    pub authorization: NfsMutationAuthorization,
    pub expected_head_version_id: Option<Uuid>,
    pub write_session_id: Uuid,
    pub staging_payload_id: Uuid,
    pub backend_id: Uuid,
    pub staging_locator: Uuid,
    pub reserved_bytes: i64,
}

#[derive(Clone, Debug)]
pub struct CreatedNfsWrite {
    pub fence: MountWriteCapabilityFence,
    pub storage: MountWriteStorageRecord,
    pub replay: NfsReplayReceipt,
}

#[derive(Clone, Debug)]
pub enum StartedNfsWrite {
    /// Newly created writer authority. Only this variant can be used to mint a
    /// storage capability; later calls must re-admit the contained fence.
    Created(Box<CreatedNfsWrite>),
    /// Exact protocol retransmission. The persisted response is byte-stable,
    /// but deliberately carries no current storage-authority projection.
    Replayed { replay: NfsReplayReceipt },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NfsWriteConflictRecord {
    pub id: Uuid,
    pub write_session_id: Uuid,
    pub drive_id: Uuid,
    pub source_node_id: Uuid,
    pub base_version_id: Option<Uuid>,
    pub expected_head_version_id: Option<Uuid>,
    pub observed_head_version_id: Option<Uuid>,
    pub logical_size_bytes: i64,
    pub state: String,
    pub conflict_copy_node_id: Option<Uuid>,
    pub conflict_copy_version_id: Option<Uuid>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug)]
pub struct CopyNfsWriteConflictInput<'a> {
    pub tenant_id: Uuid,
    pub actor_principal_id: Uuid,
    pub api_session_id: Uuid,
    pub conflict_id: Uuid,
    pub authorization: NfsMutationAuthorization,
    pub display_name: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsWriteConflictCopyRecord {
    pub conflict_id: Uuid,
    pub drive_id: Uuid,
    pub node_id: Uuid,
    pub version_id: Uuid,
    pub display_name: String,
    pub size_bytes: i64,
    pub blake3: [u8; 32],
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
    pub allowed_drive_ids: Vec<Uuid>,
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

/// Transaction-local idempotency identity for one NFS administrator mutation.
#[derive(Clone, Debug)]
pub struct NfsAdminIdempotency<'a> {
    pub principal_id: Uuid,
    pub route: &'a str,
    pub key: &'a str,
    pub request_fingerprint: &'a [u8; 32],
    pub legacy_request_fingerprint: Option<&'a [u8; 32]>,
    pub response_status: i32,
}

#[derive(Clone, Debug)]
pub enum NfsAdminIdempotentWrite {
    Created(IdempotencyRecord),
    Replayed(IdempotencyRecord),
    KeyReused,
}

impl NfsAdminIdempotency<'_> {
    fn reservation_input(&self) -> IdempotencyInput<'_> {
        IdempotencyInput {
            principal_id: self.principal_id,
            route: self.route,
            key: self.key,
            request_fingerprint: self.request_fingerprint,
            legacy_request_fingerprint: self.legacy_request_fingerprint,
        }
    }

    fn validate_actor(&self, actor_principal_id: Uuid) -> Result<(), DatabaseError> {
        if self.principal_id != actor_principal_id || !(100..=599).contains(&self.response_status) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        Ok(())
    }
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
        let record = transition_nfs_feature_state_tx(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            expected_generation,
            target,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn transition_nfs_feature_state_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        expected_generation: i64,
        target: NfsFeatureState,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce(&NfsFeatureStateRecord) -> Result<Value, serde_json::Error>,
    {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        idempotency.validate_actor(actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let feature = transition_nfs_feature_state_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    expected_generation,
                    target,
                )
                .await?;
                let response =
                    render_response(&feature).map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
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
             root.handle_generation AS root_node_generation \
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
        let record = register_nfs_export_tx(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            drive_id,
            export_id,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn register_nfs_export_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        drive_id: Uuid,
        export_id: i64,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce(&NfsExportRecord) -> Result<Value, serde_json::Error>,
    {
        if export_id <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        idempotency.validate_actor(actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let access = nfs_admin_drive_access_snapshot_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    &[drive_id],
                )
                .await?;
                let export = register_nfs_export_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    drive_id,
                    export_id,
                )
                .await?;
                revalidate_nfs_admin_drive_access_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    &[drive_id],
                    &access,
                )
                .await?;
                let response =
                    render_response(&export).map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
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
        let record = stage_nfs_export_tx(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            drive_id,
            expected_generation,
            target,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn stage_nfs_export_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        drive_id: Uuid,
        expected_generation: i64,
        target: NfsExportState,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce(&NfsExportRecord) -> Result<Value, serde_json::Error>,
    {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        idempotency.validate_actor(actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let access = nfs_admin_drive_access_snapshot_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    &[drive_id],
                )
                .await?;
                let export = stage_nfs_export_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    drive_id,
                    expected_generation,
                    target,
                )
                .await?;
                revalidate_nfs_admin_drive_access_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    &[drive_id],
                    &access,
                )
                .await?;
                let response =
                    render_response(&export).map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
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
        let record = register_nfs_posix_group_tx(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            group_id,
            posix_name,
            projected_gid,
        )
        .await?;
        transaction.commit().await?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_nfs_posix_group_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        group_id: Uuid,
        posix_name: &str,
        projected_gid: i64,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce(&NfsPosixGroupRecord) -> Result<Value, serde_json::Error>,
    {
        if !valid_nfs_posix_name(posix_name) || !valid_nfs_projected_id(projected_gid) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        idempotency.validate_actor(actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let group = register_nfs_posix_group_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    group_id,
                    posix_name,
                    projected_gid,
                )
                .await?;
                let response =
                    render_response(&group).map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
    }

    /// Lists active NFS identity projections for tenant-administrator review.
    pub async fn list_nfs_principal_mappings(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<NfsPrincipalMapping>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT mapping.kerberos_principal,mapping.principal_id,mapping.credential_id,\
                    mapping.projected_uid,mapping.projected_gid,mapping.generation,\
                    credential.allowed_drive_ids \
             FROM filebelt_mount.nfs_principal_mappings AS mapping \
             JOIN filebelt_mount.credentials AS credential \
               ON credential.tenant_id=mapping.tenant_id AND credential.id=mapping.credential_id \
             WHERE mapping.tenant_id=$1 AND mapping.revoked_at IS NULL \
             ORDER BY mapping.kerberos_principal,mapping.principal_id",
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
                allowed_drive_ids: row.get("allowed_drive_ids"),
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
        let mut transaction = self.pool().begin().await?;
        let mapping = upsert_nfs_principal_mapping_tx(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(mapping)
    }

    pub async fn upsert_nfs_principal_mapping_idempotent<F>(
        &self,
        input: &UpsertNfsPrincipalMappingInput<'_>,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce(&NfsPrincipalMapping) -> Result<Value, serde_json::Error>,
    {
        idempotency.validate_actor(input.actor_principal_id)?;
        validate_nfs_principal_mapping_input(input)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let access = nfs_admin_drive_access_snapshot_tx(
                    &mut transaction,
                    input.tenant_id,
                    input.actor_principal_id,
                    input.allowed_drive_ids,
                )
                .await?;
                let mapping = upsert_nfs_principal_mapping_tx(&mut transaction, input).await?;
                revalidate_nfs_admin_drive_access_tx(
                    &mut transaction,
                    input.tenant_id,
                    input.actor_principal_id,
                    input.allowed_drive_ids,
                    &access,
                )
                .await?;
                let response =
                    render_response(&mapping).map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
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
        revoke_nfs_principal_mapping_tx(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            credential_id,
            expected_generation,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_nfs_principal_mapping_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        credential_id: Uuid,
        expected_generation: i64,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce() -> Result<Value, serde_json::Error>,
    {
        if expected_generation <= 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        idempotency.validate_actor(actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                revoke_nfs_principal_mapping_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    credential_id,
                    expected_generation,
                )
                .await?;
                let response =
                    render_response().map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
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
             mapping.projected_uid,mapping.projected_gid,mapping.generation,\
             credential.allowed_drive_ids \
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
            allowed_drive_ids: row.get("allowed_drive_ids"),
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
                allowed_export_ids: row.get("allowed_export_ids"),
                nfs_mapping_generation: Some(mapping_generation),
                nfs_feature_generation: Some(feature_generation),
                nfs_manifest_generation: Some(row.get("manifest_generation")),
                nfs_restore_generation: Some(row.get("restore_generation")),
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
        let mut transaction = self.pool().begin().await?;
        let slot = sqlx::query(
            "SELECT client_id,current_sequence_id,max_operation_index,gateway_epoch \
             FROM filebelt_mount.nfs_replay_slots \
             WHERE tenant_id=$1 AND mount_session_id=$2 AND nfs_session_id=$3 \
               AND slot_id=$4",
        )
        .bind(context.tenant_id)
        .bind(context.mount_session_id)
        .bind(context.nfs_session_id)
        .bind(context.slot_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(slot) = slot else {
            transaction.commit().await?;
            return Ok(None);
        };
        if slot.get::<String, _>("client_id") != context.client_id
            || slot.get::<i64, _>("gateway_epoch") != context.gateway_epoch
        {
            return Err(DatabaseError::Conflict);
        }
        let current_sequence_id = slot.get::<i64, _>("current_sequence_id");
        if context.sequence_id < current_sequence_id {
            return Err(DatabaseError::StaleGeneration);
        }
        if context.sequence_id > current_sequence_id {
            transaction.commit().await?;
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT client_id,operation,request_digest,response_bytes,response_digest,mutation_outcome,\
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
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            if context.operation_index <= slot.get::<i32, _>("max_operation_index") {
                return Err(DatabaseError::StaleGeneration);
            }
            transaction.commit().await?;
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
        let receipt = NfsReplayReceipt {
            response_bytes: row.get("response_bytes"),
            response_digest,
            gateway_epoch: context.gateway_epoch,
            expires_at_unix_seconds: row.get("expires_at_unix_seconds"),
            mutation_outcome: row.get("mutation_outcome"),
        };
        transaction.commit().await?;
        Ok(Some(receipt))
    }

    /// Persists one replay response in its own database operation. This is a
    /// restart-safe primitive for read-only compounds only. Namespace and
    /// write mutations must use the atomic methods below.
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
        let mut transaction = self.pool().begin().await?;
        let receipt =
            if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, input).await? {
                replay.receipt
            } else {
                record_nfs_atomic_replay_tx(&mut transaction, input, None, None).await?
            };
        transaction.commit().await?;
        Ok(receipt)
    }

    /// Returns the common metadata projection for one live NFS node. Owners or
    /// primary groups without an active immutable POSIX mapping deliberately
    /// project to `nobody` instead of fabricating numeric authority.
    pub async fn nfs_node_metadata(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
    ) -> Result<NfsNodeMetadata, DatabaseError> {
        let row = sqlx::query(
            "SELECT node.id,node.drive_id,node.parent_id,node.kind,node.namespace_generation,\
                    node.acl_generation,node.handle_generation,node.owner_principal_id,\
                    node.posix_group_id,node.posix_mode,\
                    COALESCE(owner_mapping.projected_uid,65534)::bigint AS projected_uid,\
                    COALESCE(owner_mapping.posix_name,'nobody') AS owner_name,\
                    COALESCE(posix_group.projected_gid,65534)::bigint AS projected_gid,\
                    COALESCE(posix_group.posix_name,'nobody') AS group_name,\
                    floor(extract(epoch FROM node.accessed_at))::bigint AS accessed_at_unix_seconds,\
                    floor(extract(epoch FROM node.modified_at))::bigint AS modified_at_unix_seconds,\
                    floor(extract(epoch FROM node.changed_at))::bigint AS changed_at_unix_seconds,\
                    floor(extract(epoch FROM node.created_at))::bigint AS created_at_unix_seconds,\
                    node.symlink_target \
             FROM public.nodes AS node \
             LEFT JOIN LATERAL (\
               SELECT mapping.projected_uid,mapping.posix_name \
               FROM filebelt_mount.nfs_principal_mappings AS mapping \
               WHERE mapping.tenant_id=node.tenant_id \
                 AND mapping.principal_id=node.owner_principal_id \
                 AND mapping.revoked_at IS NULL \
               ORDER BY mapping.generation DESC,mapping.credential_id \
               LIMIT 1\
             ) AS owner_mapping ON true \
             LEFT JOIN filebelt_mount.nfs_posix_groups AS posix_group \
               ON posix_group.tenant_id=node.tenant_id \
              AND posix_group.group_id=node.posix_group_id \
             WHERE node.tenant_id=$1 AND node.drive_id=$2 AND node.id=$3 \
               AND node.trash_root_id IS NULL",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(DatabaseError::NotFound)?;
        Ok(nfs_node_metadata_from_row(&row))
    }

    pub async fn nfs_node_xattrs(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        node_id: Uuid,
    ) -> Result<Vec<NfsNodeXattr>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT xattr.name,xattr.value FROM public.node_xattrs AS xattr \
             JOIN public.nodes AS node ON node.tenant_id=xattr.tenant_id \
               AND node.drive_id=xattr.drive_id AND node.id=xattr.node_id \
             WHERE xattr.tenant_id=$1 AND xattr.drive_id=$2 AND xattr.node_id=$3 \
               AND node.trash_root_id IS NULL ORDER BY xattr.name",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .iter()
            .map(|row| NfsNodeXattr {
                name: row.get("name"),
                value: row.get("value"),
            })
            .collect())
    }

    /// Resolves one persistent NFS handle inside the immutable export scope and
    /// returns a repeatable-read authorization view of every path component.
    /// The caller must still evaluate `TRAVERSE` on each directory and the
    /// requested target action with the common deny-precedence evaluator.
    pub async fn resolve_nfs_handle(
        &self,
        fence: &MountSessionFence,
        gss_binding_digest: &[u8; 32],
        export_id: i64,
        node_id: Uuid,
        expected_handle_generation: Option<i64>,
    ) -> Result<NfsHandleResolution, DatabaseError> {
        let (
            Some(mapping_generation),
            Some(feature_generation),
            Some(manifest_generation),
            Some(restore_generation),
        ) = (
            fence.nfs_mapping_generation,
            fence.nfs_feature_generation,
            fence.nfs_manifest_generation,
            fence.nfs_restore_generation,
        )
        else {
            return Err(DatabaseError::InvalidPersistedValue);
        };
        if fence.protocol != "nfs"
            || export_id <= 0
            || !fence.allowed_export_ids.contains(&export_id)
            || expected_handle_generation.is_some_and(|generation| generation <= 0)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query(
            "SELECT export.export_id,export.desired_generation AS export_generation,\
                    session.nfs_manifest_generation AS manifest_generation,\
                    session.nfs_restore_generation AS restore_generation,\
                    root.id AS root_node_id,root.handle_generation AS root_handle_generation,\
                    target.id,target.drive_id,target.parent_id,target.kind,\
                    target.namespace_generation,target.acl_generation,target.handle_generation,\
                    target.owner_principal_id,target.posix_group_id,target.posix_mode,\
                    COALESCE(owner_identity.projected_uid,65534)::bigint AS projected_uid,\
                    COALESCE(owner_identity.posix_name,'nobody') AS owner_name,\
                    COALESCE(posix_group.projected_gid,65534)::bigint AS projected_gid,\
                    COALESCE(posix_group.posix_name,'nobody') AS group_name,\
                    floor(extract(epoch FROM target.accessed_at))::bigint AS accessed_at_unix_seconds,\
                    floor(extract(epoch FROM target.modified_at))::bigint AS modified_at_unix_seconds,\
                    floor(extract(epoch FROM target.changed_at))::bigint AS changed_at_unix_seconds,\
                    floor(extract(epoch FROM target.created_at))::bigint AS created_at_unix_seconds,\
                    target.symlink_target \
             FROM filebelt_mount.sessions AS session \
             JOIN filebelt_mount.credentials AS credential \
               ON credential.tenant_id=session.tenant_id AND credential.id=session.credential_id \
             JOIN filebelt_mount.policies AS policy \
               ON policy.tenant_id=session.tenant_id \
              AND policy.principal_id=session.user_principal_id \
              AND policy.protocol='nfs' \
             JOIN public.principals AS principal \
               ON principal.tenant_id=session.tenant_id \
              AND principal.id=session.user_principal_id \
             JOIN public.users AS user_account \
               ON user_account.tenant_id=principal.tenant_id \
              AND user_account.principal_id=principal.id \
             JOIN filebelt_mount.nfs_principal_mappings AS mapping \
               ON mapping.tenant_id=session.tenant_id \
              AND mapping.credential_id=session.credential_id \
              AND mapping.principal_id=session.user_principal_id \
             JOIN filebelt_mount.nfs_posix_groups AS mapped_group \
               ON mapped_group.tenant_id=mapping.tenant_id \
              AND mapped_group.group_id=mapping.posix_group_id \
              AND mapped_group.projected_gid=mapping.projected_gid \
             JOIN public.group_memberships AS mapped_membership \
               ON mapped_membership.tenant_id=mapping.tenant_id \
              AND mapped_membership.group_id=mapping.posix_group_id \
              AND mapped_membership.user_principal_id=mapping.principal_id \
             JOIN filebelt_mount.nfs_feature_state AS feature \
               ON feature.tenant_id=session.tenant_id \
             JOIN filebelt_mount.gateway_epochs AS gateway \
               ON gateway.tenant_id=session.tenant_id AND gateway.protocol='nfs' \
              AND gateway.gateway_id=session.gateway_id AND gateway.epoch=session.gateway_epoch \
             JOIN filebelt_mount.nfs_exports AS export \
               ON export.tenant_id=session.tenant_id AND export.export_id=$12 \
             JOIN public.nodes AS root \
               ON root.tenant_id=export.tenant_id AND root.drive_id=export.drive_id \
              AND root.parent_id IS NULL AND root.trash_root_id IS NULL AND root.kind='directory' \
             JOIN public.nodes AS target \
               ON target.tenant_id=root.tenant_id AND target.drive_id=root.drive_id \
              AND target.id=$13 AND target.trash_root_id IS NULL \
             JOIN public.node_ancestry AS scope \
               ON scope.tenant_id=root.tenant_id AND scope.drive_id=root.drive_id \
              AND scope.ancestor_id=root.id AND scope.descendant_id=target.id \
             LEFT JOIN filebelt_mount.nfs_posix_users AS owner_identity \
               ON owner_identity.tenant_id=target.tenant_id \
              AND owner_identity.principal_id=target.owner_principal_id \
             LEFT JOIN filebelt_mount.nfs_posix_groups AS posix_group \
               ON posix_group.tenant_id=target.tenant_id \
              AND posix_group.group_id=target.posix_group_id \
             WHERE session.tenant_id=$1 AND session.id=$2 AND session.protocol='nfs' \
               AND session.user_principal_id=$3 AND session.credential_id=$4 \
               AND session.credential_generation=$5 \
               AND session.authorization_generation=$6 \
               AND session.membership_generation=$7 AND session.gateway_epoch=$8 \
               AND session.nfs_gss_binding_digest=$9 \
               AND session.nfs_mapping_generation=$10 \
               AND session.nfs_feature_generation=$11 \
               AND session.nfs_manifest_generation=$14 \
               AND session.nfs_restore_generation=$15 \
               AND $12=ANY(session.nfs_allowed_export_ids) \
               AND session.state IN ('active','draining') \
               AND session.idle_expires_at>clock_timestamp() \
               AND session.absolute_expires_at>clock_timestamp() \
               AND credential.revoked_at IS NULL AND credential.expires_at>clock_timestamp() \
               AND credential.credential_generation=$5 \
               AND credential.authorization_generation=$6 \
               AND export.drive_id=ANY(credential.allowed_drive_ids) \
               AND policy.enabled AND policy.authorization_generation=$6 \
               AND export.drive_id=ANY(policy.allowed_drive_ids) \
               AND $17=(credential.read_only OR policy.read_only) \
               AND principal.disabled_at IS NULL AND principal.generation=$7 \
               AND user_account.status='active' \
               AND mapping.generation=$10 AND mapping.revoked_at IS NULL \
               AND feature.generation=$11 AND feature.restore_generation=$15 \
               AND feature.applied_manifest_digest IS NOT NULL \
               AND ((session.state='active' AND feature.state='active' \
                     AND feature.manifest_generation=$14 \
                     AND feature.applied_manifest_generation=feature.manifest_generation \
                     AND export.desired_state='active' AND export.applied_state='active' \
                     AND export.desired_generation=export.applied_generation \
                     AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp()) \
                 OR (session.state='draining' AND feature.state IN ('active','draining') \
                     AND export.applied_state IN ('active','draining') \
                     AND gateway.draining AND gateway.drain_deadline>clock_timestamp())) \
               AND ($16::bigint IS NULL OR target.handle_generation=$16)",
        )
        .bind(fence.tenant_id)
        .bind(fence.session_id)
        .bind(fence.user_principal_id)
        .bind(fence.credential_id)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(fence.gateway_epoch)
        .bind(gss_binding_digest.as_slice())
        .bind(mapping_generation)
        .bind(feature_generation)
        .bind(export_id)
        .bind(node_id)
        .bind(manifest_generation)
        .bind(restore_generation)
        .bind(expected_handle_generation)
        .bind(fence.read_only)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let drive_id: Uuid = row.get("drive_id");
        let path_rows = sqlx::query(
            "SELECT ancestry.depth,node.id,node.drive_id,node.parent_id,node.kind,\
                    node.namespace_generation,node.acl_generation,node.handle_generation,\
                    node.owner_principal_id,node.posix_group_id,node.posix_mode,\
                    COALESCE(owner_identity.projected_uid,65534)::bigint AS projected_uid,\
                    COALESCE(owner_identity.posix_name,'nobody') AS owner_name,\
                    COALESCE(posix_group.projected_gid,65534)::bigint AS projected_gid,\
                    COALESCE(posix_group.posix_name,'nobody') AS group_name,\
                    floor(extract(epoch FROM node.accessed_at))::bigint AS accessed_at_unix_seconds,\
                    floor(extract(epoch FROM node.modified_at))::bigint AS modified_at_unix_seconds,\
                    floor(extract(epoch FROM node.changed_at))::bigint AS changed_at_unix_seconds,\
                    floor(extract(epoch FROM node.created_at))::bigint AS created_at_unix_seconds,\
                    node.symlink_target \
             FROM public.node_ancestry AS ancestry \
             JOIN public.nodes AS node ON node.tenant_id=ancestry.tenant_id \
               AND node.drive_id=ancestry.drive_id AND node.id=ancestry.ancestor_id \
             LEFT JOIN filebelt_mount.nfs_posix_users AS owner_identity \
               ON owner_identity.tenant_id=node.tenant_id \
              AND owner_identity.principal_id=node.owner_principal_id \
             LEFT JOIN filebelt_mount.nfs_posix_groups AS posix_group \
               ON posix_group.tenant_id=node.tenant_id \
              AND posix_group.group_id=node.posix_group_id \
             WHERE ancestry.tenant_id=$1 AND ancestry.drive_id=$2 \
               AND ancestry.descendant_id=$3 AND node.trash_root_id IS NULL \
             ORDER BY ancestry.depth DESC",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .fetch_all(&mut *transaction)
        .await?;
        let path: Vec<NfsHandlePathNode> = path_rows
            .iter()
            .map(|path_row| NfsHandlePathNode {
                depth: path_row.get("depth"),
                metadata: nfs_node_metadata_from_row(path_row),
            })
            .collect();
        if path.first().map(|entry| entry.metadata.node_id) != Some(row.get("root_node_id"))
            || path.last().map(|entry| entry.metadata.node_id) != Some(node_id)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let path_ids: Vec<Uuid> = path.iter().map(|entry| entry.metadata.node_id).collect();
        let acl_rows = sqlx::query(
            "SELECT id,resource_id,principal_id,action,effect,inheritance,generation,created_by,source \
             FROM public.acl_entries WHERE tenant_id=$1 AND drive_id=$2 \
               AND resource_id=ANY($3) ORDER BY resource_id,id",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(&path_ids)
        .fetch_all(&mut *transaction)
        .await?;
        let acl_entries = acl_rows
            .iter()
            .map(|acl| NfsPathAclEntry {
                id: acl.get("id"),
                resource_id: acl.get("resource_id"),
                principal_id: acl.get("principal_id"),
                action: acl.get("action"),
                effect: acl.get("effect"),
                inheritance: acl.get("inheritance"),
                generation: acl.get("generation"),
                created_by: acl.get("created_by"),
                source: acl.get("source"),
            })
            .collect();
        let target = nfs_node_metadata_from_row(&row);
        let resolution = NfsHandleResolution {
            export_id: row.get("export_id"),
            export_generation: row.get("export_generation"),
            manifest_generation: row.get("manifest_generation"),
            restore_generation: row.get("restore_generation"),
            root_node_id: row.get("root_node_id"),
            root_handle_generation: row.get("root_handle_generation"),
            target,
            path,
            acl_entries,
        };
        transaction.commit().await?;
        Ok(resolution)
    }

    /// Returns the common authorization facts plus live, feature-scoped
    /// synthetic TRAVERSE allows for the mapped NFS subject. Existing common
    /// deny rows remain in the snapshot and therefore retain deny precedence
    /// in the shared evaluator.
    pub async fn nfs_authorization_snapshot(
        &self,
        fence: &MountSessionFence,
        gss_binding_digest: &[u8; 32],
        drive_id: Uuid,
        resource_id: Uuid,
    ) -> Result<NfsAuthorizationSnapshot, DatabaseError> {
        let (
            Some(mapping_generation),
            Some(feature_generation),
            Some(manifest_generation),
            Some(restore_generation),
        ) = (
            fence.nfs_mapping_generation,
            fence.nfs_feature_generation,
            fence.nfs_manifest_generation,
            fence.nfs_restore_generation,
        )
        else {
            return Err(DatabaseError::InvalidPersistedValue);
        };
        if fence.protocol != "nfs" {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut snapshot = self
            .authorization_snapshot(
                fence.tenant_id,
                fence.user_principal_id,
                drive_id,
                resource_id,
            )
            .await?;
        let mut transaction = self.pool().begin().await?;
        let admitted_feature_generation: i64 = sqlx::query_scalar(
            "SELECT feature.generation \
             FROM filebelt_mount.sessions AS session \
             JOIN filebelt_mount.credentials AS credential \
               ON credential.tenant_id=session.tenant_id AND credential.id=session.credential_id \
             JOIN filebelt_mount.policies AS policy \
               ON policy.tenant_id=session.tenant_id \
              AND policy.principal_id=session.user_principal_id \
              AND policy.protocol='nfs' \
             JOIN public.principals AS principal \
               ON principal.tenant_id=session.tenant_id AND principal.id=session.user_principal_id \
             JOIN public.users AS user_account \
               ON user_account.tenant_id=principal.tenant_id \
              AND user_account.principal_id=principal.id \
             JOIN filebelt_mount.nfs_principal_mappings AS mapping \
               ON mapping.tenant_id=session.tenant_id \
              AND mapping.credential_id=session.credential_id \
              AND mapping.principal_id=session.user_principal_id \
             JOIN filebelt_mount.nfs_posix_groups AS posix_group \
               ON posix_group.tenant_id=mapping.tenant_id \
              AND posix_group.group_id=mapping.posix_group_id \
              AND posix_group.projected_gid=mapping.projected_gid \
             JOIN public.group_memberships AS membership \
               ON membership.tenant_id=mapping.tenant_id \
              AND membership.group_id=mapping.posix_group_id \
              AND membership.user_principal_id=mapping.principal_id \
             JOIN filebelt_mount.nfs_feature_state AS feature \
               ON feature.tenant_id=session.tenant_id \
             JOIN filebelt_mount.gateway_epochs AS gateway \
               ON gateway.tenant_id=session.tenant_id AND gateway.protocol='nfs' \
              AND gateway.gateway_id=session.gateway_id AND gateway.epoch=session.gateway_epoch \
             JOIN public.drives AS drive \
               ON drive.tenant_id=session.tenant_id AND drive.id=$9 \
             JOIN public.nodes AS node \
               ON node.tenant_id=drive.tenant_id AND node.drive_id=drive.id \
              AND node.id=$10 AND node.trash_root_id IS NULL \
             JOIN filebelt_mount.nfs_exports AS export \
               ON export.tenant_id=drive.tenant_id AND export.drive_id=drive.id \
             WHERE session.tenant_id=$1 AND session.id=$2 AND session.protocol='nfs' \
               AND session.user_principal_id=$3 AND session.credential_id=$4 \
               AND session.credential_generation=$5 \
               AND session.authorization_generation=$6 \
               AND session.membership_generation=$7 AND session.gateway_epoch=$8 \
               AND session.nfs_gss_binding_digest=$11 \
               AND session.nfs_mapping_generation=$12 \
               AND session.nfs_feature_generation=$13 \
               AND session.nfs_manifest_generation=$18 \
               AND session.nfs_restore_generation=$14 \
               AND export.export_id=ANY(session.nfs_allowed_export_ids) \
               AND session.state IN ('active','draining') \
               AND session.idle_expires_at>clock_timestamp() \
               AND session.absolute_expires_at>clock_timestamp() \
               AND credential.revoked_at IS NULL AND credential.expires_at>clock_timestamp() \
               AND credential.credential_generation=$5 \
               AND credential.authorization_generation=$6 \
               AND drive.id=ANY(credential.allowed_drive_ids) \
               AND policy.enabled AND policy.authorization_generation=$6 \
               AND drive.id=ANY(policy.allowed_drive_ids) \
               AND $19=(credential.read_only OR policy.read_only) \
               AND principal.disabled_at IS NULL AND principal.generation=$7 \
               AND user_account.status='active' \
               AND mapping.generation=$12 AND mapping.revoked_at IS NULL \
               AND feature.generation=$13 AND feature.restore_generation=$14 \
               AND drive.acl_generation=$15 AND drive.namespace_generation=$16 \
               AND node.acl_generation=$17 AND node.namespace_generation=$20 \
               AND ((session.state='active' AND feature.state='active' \
                     AND session.nfs_manifest_generation=feature.manifest_generation \
                     AND feature.applied_manifest_generation=feature.manifest_generation \
                     AND export.desired_state='active' AND export.applied_state='active' \
                     AND export.desired_generation=export.applied_generation \
                     AND NOT gateway.draining AND gateway.lease_expires_at>clock_timestamp()) \
                 OR (session.state='draining' AND feature.state IN ('active','draining') \
                     AND gateway.draining AND gateway.drain_deadline>clock_timestamp())) \
             FOR SHARE OF session,credential,policy,principal,user_account,mapping,posix_group,
               membership,feature,gateway,drive,node,export",
        )
        .bind(fence.tenant_id)
        .bind(fence.session_id)
        .bind(fence.user_principal_id)
        .bind(fence.credential_id)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(fence.gateway_epoch)
        .bind(drive_id)
        .bind(resource_id)
        .bind(gss_binding_digest.as_slice())
        .bind(mapping_generation)
        .bind(feature_generation)
        .bind(restore_generation)
        .bind(snapshot.drive_acl_generation)
        .bind(snapshot.namespace_generation)
        .bind(snapshot.resource_acl_generation)
        .bind(manifest_generation)
        .bind(fence.read_only)
        .bind(snapshot.resource_namespace_generation)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let mut subjects = vec![fence.user_principal_id];
        subjects.extend(snapshot.actor_groups.iter().map(|group| group.principal_id));
        let rows = sqlx::query(
            "SELECT managed.source_acl_entry_id,managed.principal_id,\
                    managed.source_acl_generation,acl.created_by,acl.direct_share_id,\
                    EXISTS (SELECT 1 FROM public.direct_shares AS share \
                      WHERE share.tenant_id=acl.tenant_id AND share.id=acl.direct_share_id \
                        AND share.revoked_at IS NULL) AS direct_share_active \
             FROM filebelt_mount.nfs_managed_traversal AS managed \
             JOIN public.acl_entries AS acl ON acl.tenant_id=managed.tenant_id \
               AND acl.id=managed.source_acl_entry_id \
             WHERE managed.tenant_id=$1 AND managed.drive_id=$2 \
               AND managed.ancestor_id=$3 AND managed.principal_id=ANY($4) \
               AND managed.feature_generation=$5 \
             ORDER BY managed.source_acl_entry_id,managed.principal_id",
        )
        .bind(fence.tenant_id)
        .bind(drive_id)
        .bind(resource_id)
        .bind(&subjects)
        .bind(admitted_feature_generation)
        .fetch_all(&mut *transaction)
        .await?;
        for row in rows {
            snapshot.entries.push(AclInputRow {
                id: row.get("source_acl_entry_id"),
                resource_id,
                principal_id: row.get("principal_id"),
                action: "TRAVERSE".to_owned(),
                effect: "allow".to_owned(),
                inheritance: "self".to_owned(),
                depth: 0,
                direct: true,
                generation: row.get("source_acl_generation"),
                created_by: row.get("created_by"),
                direct_share_id: row.get("direct_share_id"),
                direct_share_active: row.get("direct_share_active"),
            });
        }
        transaction.commit().await?;
        Ok(NfsAuthorizationSnapshot {
            snapshot,
            feature_generation: admitted_feature_generation,
        })
    }

    /// Resolves a relative symlink beneath one export root. `..` may never
    /// cross the supplied root, absolute targets are rejected, and the full
    /// chain is capped at forty symbolic-link traversals.
    pub async fn resolve_nfs_symlink_target(
        &self,
        tenant_id: Uuid,
        drive_id: Uuid,
        root_node_id: Uuid,
        symlink_node_id: Uuid,
    ) -> Result<NfsResolvedSymlink, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let root_kind: Option<String> = sqlx::query_scalar(
            "SELECT kind FROM public.nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 \
             AND trash_root_id IS NULL",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(root_node_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if root_kind.as_deref() != Some("directory") {
            return Err(DatabaseError::NotFound);
        }
        let initial = sqlx::query(
            "SELECT parent_id,symlink_target,acl_generation,namespace_generation \
             FROM public.nodes \
             WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 AND kind='symlink' \
               AND trash_root_id IS NULL",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(symlink_node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let initial_parent: Uuid = initial
            .get::<Option<Uuid>, _>("parent_id")
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let mut ancestors = sqlx::query_scalar::<_, Uuid>(
            "SELECT path.ancestor_id FROM public.node_ancestry AS path \
             JOIN public.node_ancestry AS root_path \
               ON root_path.tenant_id=path.tenant_id AND root_path.drive_id=path.drive_id \
              AND root_path.ancestor_id=$3 AND root_path.descendant_id=path.ancestor_id \
             WHERE path.tenant_id=$1 AND path.drive_id=$2 AND path.descendant_id=$4 \
             ORDER BY path.depth DESC",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(root_node_id)
        .bind(initial_parent)
        .fetch_all(&mut *transaction)
        .await?;
        if ancestors.first() != Some(&root_node_id) || ancestors.last() != Some(&initial_parent) {
            return Err(DatabaseError::StaleGeneration);
        }
        let initial_target: String = initial.get("symlink_target");
        let mut pending = nfs_relative_target_components(&initial_target)?;
        let mut current = initial_parent;
        let mut symlink_hops = 1_u8;
        let mut traversed = vec![NfsTraversedNode {
            node_id: symlink_node_id,
            acl_generation: initial.get("acl_generation"),
            namespace_generation: initial.get("namespace_generation"),
        }];
        while let Some(component) = pending.pop_front() {
            match component.as_str() {
                "." => continue,
                ".." => {
                    if ancestors.len() == 1 {
                        return Err(DatabaseError::InvalidPersistedValue);
                    }
                    ancestors.pop();
                    current = *ancestors
                        .last()
                        .ok_or(DatabaseError::InvalidPersistedValue)?;
                    let generation = sqlx::query(
                        "SELECT acl_generation,namespace_generation FROM public.nodes \
                         WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 \
                           AND trash_root_id IS NULL",
                    )
                    .bind(tenant_id)
                    .bind(drive_id)
                    .bind(current)
                    .fetch_one(&mut *transaction)
                    .await?;
                    traversed.push(NfsTraversedNode {
                        node_id: current,
                        acl_generation: generation.get("acl_generation"),
                        namespace_generation: generation.get("namespace_generation"),
                    });
                }
                _ => {
                    let normalized = NormalizedName::new(&component)
                        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
                    let child = sqlx::query(
                        "SELECT id,kind,symlink_target,acl_generation,namespace_generation \
                         FROM public.nodes \
                         WHERE tenant_id=$1 AND drive_id=$2 AND parent_id=$3 \
                           AND name_key=$4 AND trash_root_id IS NULL",
                    )
                    .bind(tenant_id)
                    .bind(drive_id)
                    .bind(current)
                    .bind(normalized.comparison_key())
                    .fetch_optional(&mut *transaction)
                    .await?
                    .ok_or(DatabaseError::NotFound)?;
                    let child_id: Uuid = child.get("id");
                    let child_kind: String = child.get("kind");
                    traversed.push(NfsTraversedNode {
                        node_id: child_id,
                        acl_generation: child.get("acl_generation"),
                        namespace_generation: child.get("namespace_generation"),
                    });
                    if child_kind == "symlink" {
                        symlink_hops = symlink_hops
                            .checked_add(1)
                            .filter(|hops| *hops <= 40)
                            .ok_or(DatabaseError::InvalidPersistedValue)?;
                        let nested = nfs_relative_target_components(
                            &child.get::<String, _>("symlink_target"),
                        )?;
                        for item in nested.into_iter().rev() {
                            pending.push_front(item);
                        }
                    } else {
                        current = child_id;
                        ancestors.push(child_id);
                        if !pending.is_empty() && child_kind != "directory" {
                            return Err(DatabaseError::NotFound);
                        }
                    }
                }
            }
        }
        let kind: String = sqlx::query_scalar(
            "SELECT kind FROM public.nodes WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 \
             AND trash_root_id IS NULL",
        )
        .bind(tenant_id)
        .bind(drive_id)
        .bind(current)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        transaction.commit().await?;
        Ok(NfsResolvedSymlink {
            node_id: current,
            kind,
            symlink_hops,
            traversed,
        })
    }

    /// Applies one common namespace mutation and persists its exact NFS reply
    /// in the same PostgreSQL transaction.
    pub async fn mutate_nfs_namespace(
        &self,
        input: &NfsNamespaceMutationInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        if !valid_nfs_replay_context(&input.context)
            || input.response_bytes.is_empty()
            || input.response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mutation = nfs_namespace_mutation_json(input)?;
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT response_bytes,response_digest,receipt_gateway_epoch,\
                    floor(extract(epoch FROM expires_at))::bigint AS expires_at_unix_seconds,\
                    replayed,mutation_outcome,resource_id,resource_generation \
             FROM filebelt_mount.mutate_nfs_namespace(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
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
        .bind(input.context.gateway_epoch)
        .bind(input.gss_binding_digest.as_slice())
        .bind(mutation)
        .bind(input.response_bytes)
        .bind(input.response_digest.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        let receipt = nfs_mutation_receipt_from_row(&row)?;
        if !receipt.replayed {
            insert_audit(
                &mut transaction,
                input.context.tenant_id,
                None,
                None,
                receipt.resource_id,
                "mount.nfs.namespace.mutate",
                "allowed",
                input.context.operation,
                false,
                json!({"nfs_session_id":input.context.nfs_session_id}),
            )
            .await?;
            if let (Some(resource_id), Some(generation)) =
                (receipt.resource_id, receipt.resource_generation)
            {
                insert_outbox(
                    &mut transaction,
                    input.context.tenant_id,
                    "filebelt.v1.namespace.changed",
                    "node",
                    resource_id,
                    generation,
                )
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(receipt)
    }

    /// Publishes a finalized NFS write or retains the exact conflicting bytes
    /// for seven days. Publication/conflict state and the reply receipt commit
    /// atomically.
    pub async fn commit_nfs_write(
        &self,
        input: &CommitNfsWriteInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        if !valid_nfs_replay_context(&input.context)
            || input.context.operation != "commit"
            || input.fencing_token <= 0
            || input.success_response_bytes.is_empty()
            || input.success_response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
            || input.conflict_response_bytes.is_empty()
            || input.conflict_response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
            || !valid_nfs_mutation_authorization(&input.authorization)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mutation = nfs_authorization_json(&input.authorization);
        let mutation = extend_json_object(
            mutation,
            json!({
                "write_session_id":input.write_session_id,
                "fencing_token":input.fencing_token,
                "version_id":input.version_id,
                "conflict_id":input.conflict_id
            }),
        );
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT response_bytes,response_digest,receipt_gateway_epoch,\
                    floor(extract(epoch FROM expires_at))::bigint AS expires_at_unix_seconds,\
                    replayed,mutation_outcome,resource_id,resource_generation \
             FROM filebelt_mount.commit_nfs_write(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
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
        .bind(input.context.gateway_epoch)
        .bind(input.gss_binding_digest.as_slice())
        .bind(mutation)
        .bind(input.success_response_bytes)
        .bind(input.success_response_digest.as_slice())
        .bind(input.conflict_response_bytes)
        .bind(input.conflict_response_digest.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        let receipt = nfs_mutation_receipt_from_row(&row)?;
        if !receipt.replayed {
            insert_audit(
                &mut transaction,
                input.context.tenant_id,
                None,
                None,
                receipt.resource_id,
                "mount.nfs.write.commit",
                if receipt.outcome == "applied" {
                    "allowed"
                } else {
                    "conflict"
                },
                if receipt.outcome == "applied" {
                    "expected_head_committed"
                } else {
                    "expected_head_conflict_retained"
                },
                false,
                json!({"write_session_id":input.write_session_id}),
            )
            .await?;
            if receipt.outcome == "applied"
                && let (Some(resource_id), Some(generation)) =
                    (receipt.resource_id, receipt.resource_generation)
            {
                insert_outbox(
                    &mut transaction,
                    input.context.tenant_id,
                    "filebelt.v1.file.version.committed",
                    "node",
                    resource_id,
                    generation,
                )
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(receipt)
    }

    /// Revalidates one fbcap2 mount-write grant against every authoritative
    /// session, handle, namespace, gateway, and write-session fence before the
    /// storage worker receives payload identifiers.
    pub async fn start_nfs_write(
        &self,
        input: &StartNfsWriteInput<'_>,
    ) -> Result<StartedNfsWrite, DatabaseError> {
        if input.session.protocol != "nfs"
            || input.session.membership_generation != input.authorization.membership_generation
            || input.session.gateway_epoch <= 0
            || input.reserved_bytes < 0
            || input.replay.context.operation != "start_write"
            || input.replay.context.tenant_id != input.session.tenant_id
            || input.replay.context.mount_session_id != input.session.session_id
            || input.replay.context.gateway_epoch != input.session.gateway_epoch
            || !valid_nfs_mutation_authorization(&input.authorization)
            || !valid_nfs_replay_context(&input.replay.context)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT write_session_id,staging_payload_id,fencing_token,\
                    receipt_response_bytes,receipt_response_digest,receipt_gateway_epoch,\
                    floor(extract(epoch FROM receipt_expires_at))::bigint \
                      AS receipt_expires_at_unix_seconds,replayed \
             FROM filebelt_mount.start_nfs_write_replayed(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,\
               $19,$20,$21,$22,$23,$24,$25,$26)",
        )
        .bind(input.session.tenant_id)
        .bind(input.session.session_id)
        .bind(input.session.gateway_epoch)
        .bind(input.gss_binding_digest.as_slice())
        .bind(input.handle_id)
        .bind(input.authorization.drive_id)
        .bind(input.authorization.resource_id)
        .bind(input.authorization.membership_generation)
        .bind(input.authorization.drive_acl_generation)
        .bind(input.authorization.drive_namespace_generation)
        .bind(input.authorization.resource_acl_generation)
        .bind(input.authorization.resource_namespace_generation)
        .bind(input.expected_head_version_id)
        .bind(input.write_session_id)
        .bind(input.staging_payload_id)
        .bind(input.backend_id)
        .bind(input.staging_locator)
        .bind(input.reserved_bytes)
        .bind(input.replay.context.client_id)
        .bind(input.replay.context.nfs_session_id)
        .bind(input.replay.context.slot_id)
        .bind(input.replay.context.sequence_id)
        .bind(input.replay.context.operation_index)
        .bind(input.replay.context.request_digest.as_slice())
        .bind(input.replay.response_bytes)
        .bind(input.replay.response_digest.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        let replay = NfsReplayReceipt {
            response_bytes: row.get("receipt_response_bytes"),
            response_digest: array_32(row.get("receipt_response_digest"))?,
            gateway_epoch: row.get("receipt_gateway_epoch"),
            expires_at_unix_seconds: row.get("receipt_expires_at_unix_seconds"),
            mutation_outcome: Some("applied".to_owned()),
        };
        if row.get::<bool, _>("replayed") {
            transaction.commit().await?;
            return Ok(StartedNfsWrite::Replayed { replay });
        }
        let returned_write_session_id: Uuid = row.get("write_session_id");
        if returned_write_session_id != input.write_session_id
            || row.get::<Uuid, _>("staging_payload_id") != input.staging_payload_id
        {
            return Err(DatabaseError::Conflict);
        }
        let fence = MountWriteCapabilityFence {
            tenant_id: input.session.tenant_id,
            principal_id: input.session.user_principal_id,
            mount_session_id: input.session.session_id,
            credential_id: input.session.credential_id,
            handle_id: input.handle_id,
            drive_id: input.authorization.drive_id,
            node_id: input.authorization.resource_id,
            version_id: input.expected_head_version_id,
            write_session_id: returned_write_session_id,
            credential_generation: input.session.credential_generation,
            authorization_generation: input.session.authorization_generation,
            membership_generation: input.authorization.membership_generation,
            drive_acl_generation: input.authorization.drive_acl_generation,
            namespace_generation: input.authorization.resource_namespace_generation,
            resource_acl_generation: input.authorization.resource_acl_generation,
            gateway_epoch: input.session.gateway_epoch,
            fencing_token: row.get("fencing_token"),
        };
        let storage = admit_mount_write_capability_tx(
            &mut transaction,
            &fence,
            MountWriteStorageOperation::Write,
        )
        .await?;
        transaction.commit().await?;
        Ok(StartedNfsWrite::Created(Box::new(CreatedNfsWrite {
            fence,
            storage,
            replay,
        })))
    }

    pub async fn admit_mount_write_capability(
        &self,
        fence: &MountWriteCapabilityFence,
        operation: MountWriteStorageOperation,
    ) -> Result<MountWriteStorageRecord, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let record = if operation == MountWriteStorageOperation::DeleteStaging {
            admit_mount_staging_cleanup_tx(&mut transaction, fence).await?
        } else {
            admit_mount_write_capability_tx(&mut transaction, fence, operation).await?
        };
        transaction.commit().await?;
        Ok(record)
    }

    /// Admits one exact predeclared fbcap2 range/mode. The worker calls this
    /// before nonce consumption and again after acquiring the COW lock.
    pub async fn admit_mount_write_range(
        &self,
        fence: &MountWriteCapabilityFence,
        capability_id: Uuid,
        operation: MountWriteRangeOperation,
        range_start: i64,
        range_end: i64,
    ) -> Result<MountWriteRangeAdmission, DatabaseError> {
        if range_start < 0
            || range_end < range_start
            || (operation.seeks() && range_start != range_end)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let admission = admit_mount_write_range_tx(
            &mut transaction,
            fence,
            capability_id,
            operation,
            range_start,
            range_end,
        )
        .await?;
        transaction.commit().await?;
        Ok(admission)
    }

    /// Persists an opaque VFS-issued fbcap2 admission and an internal pending
    /// protocol identity without advancing the client replay slot. The final
    /// mutation transaction removes that pending identity and records the sole
    /// client-visible response atomically.
    pub async fn preauthorize_mount_io_operation(
        &self,
        input: &PreauthorizeMountIoOperationInput<'_>,
    ) -> Result<PreauthorizedMountIoOperation, DatabaseError> {
        validate_mount_io_operation_input(&input.io)?;
        if input.io.operation.range_operation().is_some()
            || input.context.tenant_id != input.io.fence.tenant_id
            || input.context.mount_session_id != input.io.fence.mount_session_id
            || input.context.gateway_epoch != input.io.fence.gateway_epoch
            || !valid_nfs_replay_context(&input.context)
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if input.protocol_operation_id.is_nil() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let created = preauthorize_mount_io_tx(
            &mut transaction,
            &input.io,
            &input.context,
            input.protocol_operation_id,
            None,
        )
        .await?;
        transaction.commit().await?;
        Ok(PreauthorizedMountIoOperation { resumed: !created })
    }

    /// Locates the stable internal operation for an exact NFS request after a
    /// VFS restart. This projection deliberately returns only bearer digests;
    /// a lost short-lived token must be atomically reissued through
    /// [`Self::reissue_mount_io_operation`].
    pub async fn inspect_pending_mount_io_operation(
        &self,
        context: &NfsReplayContext<'_>,
    ) -> Result<Option<PendingMountIoOperation>, DatabaseError> {
        if !valid_nfs_replay_context(context) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "SELECT protocol_operation_id,write_session_id,capability_id,nonce_digest,\
                    claims_digest,io_operation,operation_id,content_blake3,range_start,\
                    range_end,fencing_token,capability_expires_at_unix_seconds,\
                    worker_state,worker_outcome \
             FROM filebelt_mount.inspect_nfs_pending_io(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(context.tenant_id)
        .bind(context.mount_session_id)
        .bind(context.client_id)
        .bind(context.nfs_session_id)
        .bind(context.slot_id)
        .bind(context.sequence_id)
        .bind(context.operation_index)
        .bind(context.operation)
        .bind(context.request_digest.as_slice())
        .bind(context.gateway_epoch)
        .fetch_optional(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        row.map(pending_mount_io_operation_from_row).transpose()
    }

    /// Replaces a lost fbcap2 bearer without changing the stable protocol or
    /// range-plan identity. Worker Begin and this reissue serialize on the old
    /// admission, so exactly one can win.
    pub async fn reissue_mount_io_operation(
        &self,
        input: &ReissueMountIoOperationInput<'_>,
    ) -> Result<PendingMountIoOperation, DatabaseError> {
        let range = input.operation.range_operation().is_some();
        if !valid_nfs_replay_context(&input.context)
            || input.context.tenant_id != input.fence.tenant_id
            || input.context.mount_session_id != input.fence.mount_session_id
            || input.context.gateway_epoch != input.fence.gateway_epoch
            || input.protocol_operation_id.is_nil()
            || input.new_capability_id.is_nil()
            || range != input.stable_operation_id.is_some()
            || range != input.range_start.is_some()
            || range != input.range_end.is_some()
            || (input.operation == MountIoOperation::WriteData) != input.content_blake3.is_some()
            || matches!((input.range_start,input.range_end),(Some(start),Some(end)) if start<0 || end<start)
            || matches!((input.operation.range_operation(),input.range_start,input.range_end),
                (Some(operation),Some(start),Some(end)) if operation.seeks() && start!=end)
            || input.new_expires_at_unix_seconds <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let fence = input.fence;
        sqlx::query(
            "SELECT filebelt_mount.reissue_nfs_io(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
               $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)",
        )
        .bind(fence.tenant_id)
        .bind(fence.principal_id)
        .bind(fence.mount_session_id)
        .bind(fence.credential_id)
        .bind(fence.handle_id)
        .bind(fence.drive_id)
        .bind(fence.node_id)
        .bind(fence.version_id)
        .bind(fence.write_session_id)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(fence.drive_acl_generation)
        .bind(fence.namespace_generation)
        .bind(fence.resource_acl_generation)
        .bind(fence.gateway_epoch)
        .bind(fence.fencing_token)
        .bind(input.context.client_id)
        .bind(input.context.nfs_session_id)
        .bind(input.context.slot_id)
        .bind(input.context.sequence_id)
        .bind(input.context.operation_index)
        .bind(input.context.operation)
        .bind(input.context.request_digest.as_slice())
        .bind(input.protocol_operation_id)
        .bind(input.stable_operation_id)
        .bind(input.operation.as_str())
        .bind(input.content_blake3.map(|digest| digest.as_slice()))
        .bind(input.range_start)
        .bind(input.range_end)
        .bind(input.new_capability_id)
        .bind(input.new_nonce_digest.as_slice())
        .bind(input.new_claims_digest.as_slice())
        .bind(input.new_expires_at_unix_seconds)
        .execute(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        self.inspect_pending_mount_io_operation(&input.context)
            .await?
            .ok_or(DatabaseError::StaleGeneration)
    }

    /// Looks up a durable byte-plane outcome without creating a pending
    /// receipt. This lets the worker return an old exact retry before applying
    /// current writer-state admission, while a nonce reused with different
    /// signed claims remains a conflict.
    pub async fn lookup_mount_io_completion(
        &self,
        input: &BeginMountIoOperationInput<'_>,
    ) -> Result<MountIoLookup, DatabaseError> {
        validate_mount_io_operation_input(input)?;
        let row = sqlx::query(
            "SELECT capability_id,write_session_id,operation_id,operation,operation_ordinal,claims_digest,\
                    content_blake3,state,outcome,receipt_live \
             FROM filebelt_mount.read_nfs_io_receipt($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(input.fence.tenant_id)
        .bind(input.nonce_digest.as_slice())
        .bind(input.capability_id)
        .bind(input.fence.write_session_id)
        .bind(input.operation.as_str())
        .bind(input.claims_digest.as_slice())
        .bind(input.content_blake3.map(|digest| digest.as_slice()))
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(MountIoLookup::Absent);
        };
        validate_mount_io_receipt_identity(&row, input)?;
        if row.get::<String, _>("state") == "pending" {
            return Ok(MountIoLookup::Pending);
        }
        mount_io_completion_from_row(&row).map(MountIoLookup::Completed)
    }

    /// Claims one exact signed fbcap2 operation. An exact pending retry may
    /// execute idempotently; an exact completed retry receives the persisted
    /// typed outcome without touching the filesystem. No different or later
    /// operation can overtake a pending writer receipt.
    pub async fn begin_mount_io_operation(
        &self,
        input: &BeginMountIoOperationInput<'_>,
    ) -> Result<MountIoAdmission, DatabaseError> {
        validate_mount_io_operation_input(input)?;
        let mut transaction = self.pool().begin().await?;
        let existing = sqlx::query(
            "SELECT capability_id,write_session_id,operation_id,operation,operation_ordinal,claims_digest,content_blake3,\
                    state,outcome,receipt_live \
             FROM filebelt_mount.read_nfs_io_receipt($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(input.fence.tenant_id)
        .bind(input.nonce_digest.as_slice())
        .bind(input.capability_id)
        .bind(input.fence.write_session_id)
        .bind(input.operation.as_str())
        .bind(input.claims_digest.as_slice())
        .bind(input.content_blake3.map(|digest| digest.as_slice()))
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(row) = existing {
            validate_mount_io_receipt_identity(&row, input)?;
            if row.get::<String, _>("state") == "completed" {
                let outcome = mount_io_completion_from_row(&row)?;
                transaction.commit().await?;
                return Ok(MountIoAdmission::Completed(outcome));
            }
            let writer = sqlx::query(
                "SELECT state,fencing_token,expires_at>clock_timestamp() AS writer_live \
                 FROM filebelt_mount.write_sessions \
                 WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(input.fence.tenant_id)
            .bind(input.fence.write_session_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(DatabaseError::StaleGeneration)?;
            if writer.get::<i64, _>("fencing_token") != input.fence.fencing_token {
                return Err(DatabaseError::StaleGeneration);
            }
            if input.operation == MountIoOperation::Abort
                && writer.get::<String, _>("state") == "aborted"
            {
                let payload_state: String = sqlx::query_scalar(
                    "SELECT payload.state FROM filebelt_mount.write_sessions AS writer \
                     JOIN public.payload_objects AS payload \
                       ON payload.tenant_id=writer.tenant_id \
                      AND payload.id=writer.staging_payload_id \
                     WHERE writer.tenant_id=$1 AND writer.id=$2 \
                       AND writer.fencing_token=$3 FOR SHARE OF payload",
                )
                .bind(input.fence.tenant_id)
                .bind(input.fence.write_session_id)
                .bind(input.fence.fencing_token)
                .fetch_one(&mut *transaction)
                .await?;
                if !matches!(payload_state.as_str(), "abandoned" | "deleted") {
                    return Err(DatabaseError::Conflict);
                }
                let outcome = MountIoCompletion::Abort;
                complete_mount_io_receipt_tx(&mut transaction, input, &outcome).await?;
                transaction.commit().await?;
                return Ok(MountIoAdmission::Completed(outcome));
            }
            if !writer.get::<bool, _>("writer_live") || !row.get::<bool, _>("receipt_live") {
                let cleanup = fence_pending_mount_io_cleanup_tx(
                    &mut transaction,
                    input.fence,
                    input.nonce_digest,
                    input.claims_digest,
                    input.operation,
                    input.content_blake3,
                )
                .await?;
                transaction.commit().await?;
                return Ok(MountIoAdmission::CleanupRequired(cleanup));
            }
            match admit_pending_mount_io_tx(&mut transaction, input).await {
                Ok(storage) => {
                    transaction.commit().await?;
                    return Ok(MountIoAdmission::Execute(storage));
                }
                Err(
                    DatabaseError::StaleGeneration
                    | DatabaseError::NotFound
                    | DatabaseError::Conflict,
                ) => {
                    let cleanup = fence_pending_mount_io_cleanup_tx(
                        &mut transaction,
                        input.fence,
                        input.nonce_digest,
                        input.claims_digest,
                        input.operation,
                        input.content_blake3,
                    )
                    .await?;
                    transaction.commit().await?;
                    return Ok(MountIoAdmission::CleanupRequired(cleanup));
                }
                Err(error) => return Err(error),
            }
        }
        let writer = sqlx::query(
            "SELECT state,expires_at>clock_timestamp() AS writer_live \
             FROM filebelt_mount.write_sessions \
             WHERE tenant_id=$1 AND id=$2 AND fencing_token=$3 FOR UPDATE",
        )
        .bind(input.fence.tenant_id)
        .bind(input.fence.write_session_id)
        .bind(input.fence.fencing_token)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        let capability_live: bool =
            sqlx::query_scalar("SELECT to_timestamp($1::double precision)>clock_timestamp()")
                .bind(input.expires_at_unix_seconds as f64)
                .fetch_one(&mut *transaction)
                .await?;
        if !capability_live || !writer.get::<bool, _>("writer_live") {
            return Err(DatabaseError::StaleGeneration);
        }
        let (expected_operation_ordinal, storage) = if let Some(range_operation) =
            input.operation.range_operation()
        {
            let admission = admit_mount_write_range_tx(
                &mut transaction,
                input.fence,
                input.capability_id,
                range_operation,
                input
                    .range_start
                    .ok_or(DatabaseError::InvalidPersistedValue)?,
                input
                    .range_end
                    .ok_or(DatabaseError::InvalidPersistedValue)?,
            )
            .await?;
            if admission.content_blake3.as_ref() != input.content_blake3.copied().as_ref() {
                return Err(DatabaseError::Conflict);
            }
            (Some(admission.operation_ordinal), admission.storage)
        } else {
            let storage_operation = match input.operation {
                MountIoOperation::Flush => MountWriteStorageOperation::Flush,
                MountIoOperation::Finalize => MountWriteStorageOperation::Finalize,
                MountIoOperation::Abort => MountWriteStorageOperation::Abort,
                MountIoOperation::DeleteStaging => MountWriteStorageOperation::DeleteStaging,
                MountIoOperation::WriteData
                | MountIoOperation::HoleDeallocate
                | MountIoOperation::Allocate
                | MountIoOperation::SeekData
                | MountIoOperation::SeekHole => unreachable!(),
            };
            let storage = if storage_operation == MountWriteStorageOperation::DeleteStaging {
                admit_mount_staging_cleanup_tx(&mut transaction, input.fence).await?
            } else {
                admit_mount_write_capability_tx(&mut transaction, input.fence, storage_operation)
                    .await?
            };
            (None, storage)
        };
        let operation_ordinal = begin_mount_io_receipt_tx(&mut transaction, input).await?;
        if expected_operation_ordinal.is_some_and(|expected| expected != operation_ordinal) {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit().await?;
        Ok(MountIoAdmission::Execute(storage))
    }

    /// Commits the exact typed byte-plane result before the worker returns its
    /// first success. An identical retry is idempotent; changed evidence is a
    /// conflict and leaves the first durable outcome authoritative.
    pub async fn complete_mount_io_operation(
        &self,
        input: &BeginMountIoOperationInput<'_>,
        outcome: &MountIoCompletion,
    ) -> Result<MountIoCompletion, DatabaseError> {
        validate_mount_io_operation_input(input)?;
        if input.operation.range_operation().is_none() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        validate_mount_io_completion(input, outcome)?;
        let mut transaction = self.pool().begin().await?;
        if let Some(existing) = lock_mount_io_receipt_tx(&mut transaction, input).await? {
            if &existing != outcome {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        complete_mount_io_receipt_tx(&mut transaction, input, outcome).await?;
        transaction.commit().await?;
        Ok(outcome.clone())
    }

    /// Atomically persists exact Flush evidence, the writer state transition,
    /// and the byte-plane completion receipt. A crash can therefore leave the
    /// operation pending or completed, never advanced without its reply.
    pub async fn complete_mount_io_flush(
        &self,
        input: &BeginMountIoOperationInput<'_>,
        logical_size_bytes: i64,
        blake3: &[u8; 32],
        chunks: &[MountWriteChunkEvidence],
    ) -> Result<MountIoCompletion, DatabaseError> {
        if input.operation != MountIoOperation::Flush {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        validate_mount_chunk_evidence(logical_size_bytes, chunks)?;
        let outcome = MountIoCompletion::Flush {
            logical_size_bytes,
            blake3: *blake3,
            chunks: chunks.to_vec(),
        };
        let mut transaction = self.pool().begin().await?;
        if let Some(existing) = lock_mount_io_receipt_tx(&mut transaction, input).await? {
            if existing != outcome {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        complete_mount_io_receipt_tx(&mut transaction, input, &outcome).await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Atomically publishes the finalized staging-payload evidence, advances
    /// the writer to committing, and records the exact Finalize outcome.
    pub async fn complete_mount_io_finalize(
        &self,
        input: &BeginMountIoOperationInput<'_>,
        logical_size_bytes: i64,
        blake3: &[u8; 32],
        chunks: &[MountWriteChunkEvidence],
    ) -> Result<MountIoCompletion, DatabaseError> {
        if input.operation != MountIoOperation::Finalize {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        validate_mount_chunk_evidence(logical_size_bytes, chunks)?;
        let outcome = MountIoCompletion::Finalize {
            logical_size_bytes,
            blake3: *blake3,
            chunks: chunks.to_vec(),
        };
        let mut transaction = self.pool().begin().await?;
        if let Some(existing) = lock_mount_io_receipt_tx(&mut transaction, input).await? {
            if existing != outcome {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        complete_mount_io_receipt_tx(&mut transaction, input, &outcome).await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Completes an already-started Abort after the worker has removed the COW
    /// source. Payload/quota/session authority and the exact Abort receipt are
    /// committed together; the destination cleanup job remains independently
    /// recoverable through the common two-phase cleanup queue.
    pub async fn complete_mount_io_abort(
        &self,
        input: &BeginMountIoOperationInput<'_>,
    ) -> Result<MountIoCompletion, DatabaseError> {
        if input.operation != MountIoOperation::Abort {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let outcome = MountIoCompletion::Abort;
        let mut transaction = self.pool().begin().await?;
        if let Some(existing) = lock_mount_io_receipt_tx(&mut transaction, input).await? {
            if existing != outcome {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        complete_mount_io_receipt_tx(&mut transaction, input, &outcome).await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Finalizes the sole client-visible Flush response after the storage
    /// worker has durably completed the exact preauthorized byte-plane work.
    /// Finalize is published by `commit_nfs_write`; Abort/DeleteStaging remain
    /// internal phases consumed by Close/EndSession/error authority.
    pub async fn finalize_nfs_internal_io_replay(
        &self,
        input: &FinalizeNfsInternalIoReplayInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        if input.operation != MountIoOperation::Flush
            || input.session.tenant_id != input.fence.tenant_id
            || input.session.session_id != input.fence.mount_session_id
            || input.session.user_principal_id != input.fence.principal_id
            || input.session.credential_id != input.fence.credential_id
            || input.session.credential_generation != input.fence.credential_generation
            || input.session.authorization_generation != input.fence.authorization_generation
            || input.session.membership_generation != input.fence.membership_generation
            || input.session.gateway_epoch != input.fence.gateway_epoch
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        validate_nfs_state_replay(input.session, &input.replay, "flush")?;
        let fence = input.fence;
        let replay = &input.replay;
        let row = sqlx::query(
            "SELECT response_bytes,response_digest,receipt_gateway_epoch,\
                    floor(extract(epoch FROM expires_at))::bigint AS expires_at_unix_seconds,\
                    replayed \
             FROM filebelt_mount.finalize_nfs_internal_io_replay(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
               $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)",
        )
        .bind(fence.tenant_id)
        .bind(fence.principal_id)
        .bind(fence.mount_session_id)
        .bind(fence.credential_id)
        .bind(fence.handle_id)
        .bind(fence.drive_id)
        .bind(fence.node_id)
        .bind(fence.version_id)
        .bind(fence.write_session_id)
        .bind(fence.credential_generation)
        .bind(fence.authorization_generation)
        .bind(fence.membership_generation)
        .bind(fence.drive_acl_generation)
        .bind(fence.namespace_generation)
        .bind(fence.resource_acl_generation)
        .bind(fence.gateway_epoch)
        .bind(fence.fencing_token)
        .bind(input.gss_binding_digest.as_slice())
        .bind(replay.context.client_id)
        .bind(replay.context.nfs_session_id)
        .bind(replay.context.slot_id)
        .bind(replay.context.sequence_id)
        .bind(replay.context.operation_index)
        .bind(replay.context.operation)
        .bind(replay.context.request_digest.as_slice())
        .bind(input.operation.as_str())
        .bind(replay.response_bytes)
        .bind(replay.response_digest.as_slice())
        .fetch_one(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        let replayed = row.get("replayed");
        Ok(NfsMutationReceipt {
            replay: NfsReplayReceipt {
                response_bytes: row.get("response_bytes"),
                response_digest: array_32(row.get("response_digest"))?,
                gateway_epoch: row.get("receipt_gateway_epoch"),
                expires_at_unix_seconds: row.get("expires_at_unix_seconds"),
                mutation_outcome: Some("applied".to_owned()),
            },
            replayed,
            outcome: "applied".to_owned(),
            resource_id: None,
            resource_generation: None,
        })
    }

    /// Persists one preplanned sparse/data extent result and the exact NFS
    /// replay response in the same PostgreSQL transaction. Physical COW I/O
    /// completes before this authority acknowledgement; publication remains a
    /// separate fenced COMMIT transaction.
    pub async fn apply_nfs_write_extent(
        &self,
        input: &ApplyNfsWriteExtentInput<'_>,
    ) -> Result<NfsWriteExtentResult, DatabaseError> {
        let expected_replay_operation = match input.operation {
            MountWriteRangeOperation::WriteData => "sparse_write",
            MountWriteRangeOperation::HoleDeallocate | MountWriteRangeOperation::Allocate => {
                "sparse_control"
            }
            MountWriteRangeOperation::SeekData | MountWriteRangeOperation::SeekHole => {
                return Err(DatabaseError::InvalidPersistedValue);
            }
        };
        validate_nfs_write_extent_input(
            input.session,
            input.fence,
            &input.replay,
            expected_replay_operation,
        )?;
        if (input.operation == MountWriteRangeOperation::WriteData) != input.data_digest.is_some() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let result = nfs_write_extent_result_from_replay(input.fence, replay)?;
            transaction.commit().await?;
            return Ok(result);
        }
        admit_nfs_handle_tx(
            &mut transaction,
            input.session,
            input.gss_binding_digest,
            input.fence.handle_id,
            Some("WRITE_CONTENT"),
            true,
        )
        .await?;
        let admission = admit_completed_mount_write_range_tx(
            &mut transaction,
            input.fence,
            input.operation_id,
            input.operation,
            input.range_start,
            input.range_end,
        )
        .await?;
        if admission.content_blake3.as_ref() != input.data_digest.copied().as_ref() {
            return Err(DatabaseError::Conflict);
        }
        match completed_mount_io_outcome_tx(
            &mut transaction,
            input.fence.tenant_id,
            input.fence.write_session_id,
            input.operation_id,
        )
        .await?
        {
            MountIoCompletion::RangeMutation {
                logical_size_bytes, ..
            } if logical_size_bytes == admission.resulting_logical_size => {}
            _ => return Err(DatabaseError::Conflict),
        }
        let extents = nfs_write_extents_tx(
            &mut transaction,
            input.fence.tenant_id,
            input.fence.write_session_id,
            true,
        )
        .await?;
        let normalized = apply_nfs_extent_range(
            &extents,
            admission.storage.logical_size_bytes,
            admission.resulting_logical_size,
            input.range_start,
            input.range_end,
            input.operation,
            input.data_digest.copied(),
        )?;
        let offsets: Vec<i64> = normalized
            .iter()
            .map(|extent| extent.offset_bytes)
            .collect();
        let lengths: Vec<i64> = normalized
            .iter()
            .map(|extent| extent.length_bytes)
            .collect();
        let holes: Vec<bool> = normalized.iter().map(|extent| extent.is_hole).collect();
        let digests: Vec<Option<Vec<u8>>> = normalized
            .iter()
            .map(|extent| extent.digest.map(Vec::from))
            .collect();
        sqlx::query("SELECT filebelt_mount.replace_nfs_write_extents($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(input.fence.tenant_id)
            .bind(input.fence.write_session_id)
            .bind(input.fence.fencing_token)
            .bind(input.operation_id)
            .bind(&offsets)
            .bind(&lengths)
            .bind(&holes)
            .bind(&digests)
            .execute(&mut *transaction)
            .await?;
        let mutation_result = json!({
            "write_session_id":input.fence.write_session_id,
            "logical_size_bytes":admission.resulting_logical_size,
            "extents":normalized,
            "seek_offset":Value::Null,
        });
        mark_mount_write_operation_applied_tx(
            &mut transaction,
            input.fence,
            input.operation_id,
            input.operation,
            input.data_digest.copied(),
        )
        .await?;
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &input.replay,
            Some("applied"),
            Some(&mutation_result),
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsWriteExtentResult {
            write_session_id: input.fence.write_session_id,
            logical_size_bytes: admission.resulting_logical_size,
            extents: normalized,
            seek_offset: None,
            replay,
            replayed: false,
        })
    }

    /// Resolves SEEK_DATA/SEEK_HOLE from the persisted normalized extent view
    /// and records the caller's exact wire response for restart-safe replay.
    pub async fn seek_nfs_write_extent(
        &self,
        input: &SeekNfsWriteExtentInput<'_>,
    ) -> Result<NfsWriteExtentResult, DatabaseError> {
        if !matches!(
            input.operation,
            MountWriteRangeOperation::SeekData | MountWriteRangeOperation::SeekHole
        ) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        validate_nfs_write_extent_input(
            input.session,
            input.fence,
            &input.replay,
            "sparse_control",
        )?;
        if input.range_start != input.range_end {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let result = nfs_write_extent_result_from_replay(input.fence, replay)?;
            transaction.commit().await?;
            return Ok(result);
        }
        admit_nfs_handle_tx(
            &mut transaction,
            input.session,
            input.gss_binding_digest,
            input.fence.handle_id,
            Some("READ_CONTENT"),
            true,
        )
        .await?;
        let admission = admit_completed_mount_write_range_tx(
            &mut transaction,
            input.fence,
            input.operation_id,
            input.operation,
            input.range_start,
            input.range_end,
        )
        .await?;
        let extents = nfs_write_extents_tx(
            &mut transaction,
            input.fence.tenant_id,
            input.fence.write_session_id,
            false,
        )
        .await?;
        validate_normalized_nfs_extents(&extents, admission.storage.logical_size_bytes)?;
        let seek_hole = input.operation == MountWriteRangeOperation::SeekHole;
        let seek_offset = seek_nfs_extent(
            &extents,
            admission.storage.logical_size_bytes,
            input.range_start,
            seek_hole,
        );
        match completed_mount_io_outcome_tx(
            &mut transaction,
            input.fence.tenant_id,
            input.fence.write_session_id,
            input.operation_id,
        )
        .await?
        {
            MountIoCompletion::Seek { offset } if offset == seek_offset => {}
            _ => return Err(DatabaseError::Conflict),
        }
        let mutation_result = json!({
            "write_session_id":input.fence.write_session_id,
            "logical_size_bytes":admission.storage.logical_size_bytes,
            "extents":extents,
            "seek_offset":seek_offset,
        });
        mark_mount_write_operation_applied_tx(
            &mut transaction,
            input.fence,
            input.operation_id,
            input.operation,
            None,
        )
        .await?;
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &input.replay,
            Some("applied"),
            Some(&mutation_result),
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsWriteExtentResult {
            write_session_id: input.fence.write_session_id,
            logical_size_bytes: admission.storage.logical_size_bytes,
            extents,
            seek_offset,
            replay,
            replayed: false,
        })
    }

    /// Resolves the single nonterminal writer used by stateless NFS COMMIT and
    /// restart callbacks. The partial unique index on `(tenant,drive,node)` is
    /// the authority that makes zero-or-one a durable invariant; this method
    /// additionally binds the writer to the exact admitted GSS session.
    pub async fn resolve_nfs_write_for_node(
        &self,
        session: &MountSessionFence,
        gss_binding_digest: &[u8; 32],
        drive_id: Uuid,
        node_id: Uuid,
        operation: MountWriteStorageOperation,
    ) -> Result<ResolvedNfsWrite, DatabaseError> {
        if session.protocol != "nfs"
            || session.allowed_export_ids.is_empty()
            || session.nfs_mapping_generation.is_none()
            || session.nfs_feature_generation.is_none()
            || session.nfs_manifest_generation.is_none()
            || session.nfs_restore_generation.is_none()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT writer.id AS write_session_id,writer.fencing_token,\
                    handle.id AS handle_id,handle.version_id,\
                    handle.credential_generation,handle.authorization_generation,\
                    handle.membership_generation,handle.drive_acl_generation,\
                    handle.namespace_generation,handle.resource_acl_generation,\
                    handle.gateway_epoch \
             FROM filebelt_mount.write_sessions AS writer \
             JOIN filebelt_mount.handles AS handle \
               ON handle.tenant_id=writer.tenant_id AND handle.id=writer.handle_id \
             JOIN filebelt_mount.sessions AS mount_session \
               ON mount_session.tenant_id=writer.tenant_id \
              AND mount_session.id=writer.mount_session_id \
             JOIN filebelt_mount.gateway_epochs AS gateway \
               ON gateway.tenant_id=mount_session.tenant_id AND gateway.protocol='nfs' \
              AND gateway.gateway_id=mount_session.gateway_id \
              AND gateway.epoch=mount_session.gateway_epoch \
             JOIN filebelt_mount.nfs_feature_state AS feature \
               ON feature.tenant_id=mount_session.tenant_id \
             WHERE writer.tenant_id=$1 AND writer.mount_session_id=$2 \
               AND writer.drive_id=$3 AND writer.node_id=$4 \
               AND writer.state IN ('open','flushing','committing','aborting') \
               AND handle.session_id=$2 AND handle.closed_at IS NULL \
               AND mount_session.protocol='nfs' \
               AND mount_session.credential_id=$5 \
               AND mount_session.user_principal_id=$6 \
               AND mount_session.credential_generation=$7 \
               AND mount_session.authorization_generation=$8 \
               AND mount_session.membership_generation=$9 \
               AND mount_session.gateway_epoch=$10 \
               AND mount_session.nfs_gss_binding_digest=$11 \
               AND mount_session.nfs_mapping_generation=$12 \
               AND mount_session.nfs_feature_generation=$13 \
               AND mount_session.nfs_manifest_generation=$14 \
               AND mount_session.nfs_restore_generation=$15 \
               AND mount_session.nfs_allowed_export_ids=$16 \
               AND mount_session.absolute_expires_at>clock_timestamp() \
               AND feature.generation=$13 AND feature.restore_generation=$15 \
               AND feature.manifest_generation=$14 \
               AND feature.applied_manifest_generation=feature.manifest_generation \
               AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_exports AS export \
                 WHERE export.tenant_id=writer.tenant_id AND export.drive_id=writer.drive_id \
                   AND export.export_id=ANY(mount_session.nfs_allowed_export_ids) \
                   AND export.desired_state='active' AND export.applied_state='active' \
                   AND export.desired_generation=export.applied_generation) \
               AND ((mount_session.state='active' AND feature.state='active' \
                     AND NOT gateway.draining \
                     AND gateway.lease_expires_at>clock_timestamp()) \
                 OR (mount_session.state='draining' \
                     AND feature.state IN ('active','draining') AND gateway.draining \
                     AND gateway.drain_deadline>clock_timestamp())) \
             FOR UPDATE OF writer,handle,mount_session,gateway,feature",
        )
        .bind(session.tenant_id)
        .bind(session.session_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(session.credential_id)
        .bind(session.user_principal_id)
        .bind(session.credential_generation)
        .bind(session.authorization_generation)
        .bind(session.membership_generation)
        .bind(session.gateway_epoch)
        .bind(gss_binding_digest.as_slice())
        .bind(session.nfs_mapping_generation)
        .bind(session.nfs_feature_generation)
        .bind(session.nfs_manifest_generation)
        .bind(session.nfs_restore_generation)
        .bind(&session.allowed_export_ids)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let fence = MountWriteCapabilityFence {
            tenant_id: session.tenant_id,
            principal_id: session.user_principal_id,
            mount_session_id: session.session_id,
            credential_id: session.credential_id,
            handle_id: row.get("handle_id"),
            drive_id,
            node_id,
            version_id: if matches!(
                operation,
                MountWriteStorageOperation::Abort | MountWriteStorageOperation::DeleteStaging
            ) {
                None
            } else {
                row.get("version_id")
            },
            write_session_id: row.get("write_session_id"),
            credential_generation: row.get("credential_generation"),
            authorization_generation: row.get("authorization_generation"),
            membership_generation: row.get("membership_generation"),
            drive_acl_generation: row.get("drive_acl_generation"),
            namespace_generation: row.get("namespace_generation"),
            resource_acl_generation: row.get("resource_acl_generation"),
            gateway_epoch: row.get("gateway_epoch"),
            fencing_token: row.get("fencing_token"),
        };
        let storage = if operation == MountWriteStorageOperation::DeleteStaging {
            admit_mount_staging_cleanup_tx(&mut transaction, &fence).await?
        } else {
            admit_mount_write_capability_tx(&mut transaction, &fence, operation).await?
        };
        transaction.commit().await?;
        Ok(ResolvedNfsWrite { fence, storage })
    }

    pub async fn mark_mount_write_flushed(
        &self,
        fence: &MountWriteCapabilityFence,
        logical_size_bytes: i64,
        chunks: &[MountWriteChunkEvidence],
    ) -> Result<MountWriteStorageRecord, DatabaseError> {
        validate_mount_chunk_evidence(logical_size_bytes, chunks)?;
        let mut transaction = self.pool().begin().await?;
        let record = admit_mount_write_capability_tx(
            &mut transaction,
            fence,
            MountWriteStorageOperation::Flush,
        )
        .await?;
        if !matches!(record.state.as_str(), "open" | "flushing") {
            return Err(DatabaseError::StaleGeneration);
        }
        persist_mount_chunk_evidence(&mut transaction, fence, chunks, false).await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.write_sessions SET state='flushing',logical_size_bytes=$3,\
                    heartbeat_at=clock_timestamp(),\
                    lease_expires_at=LEAST(expires_at,clock_timestamp()+interval '30 seconds') \
             WHERE tenant_id=$1 AND id=$2 AND fencing_token=$4 \
               AND logical_size_bytes=$3 AND state IN ('open','flushing')",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .bind(logical_size_bytes)
        .bind(fence.fencing_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let record = mount_write_storage_record_tx(&mut transaction, fence).await?;
        transaction.commit().await?;
        Ok(record)
    }

    /// Monotonically extends the exact chunk manifest before each Write
    /// capability is issued. Existing identity/source/locator rows are an
    /// immutable prefix; only the former final chunk may grow or become dirty,
    /// and new chunks append contiguously. Truncation is a separate authority.
    pub async fn extend_mount_write_chunks(
        &self,
        input: &ExtendNfsWriteChunksInput<'_>,
    ) -> Result<NfsWriteChunkPlanResult, DatabaseError> {
        let fence = input.fence;
        let chunks = input.chunks;
        validate_mount_chunk_plan(chunks)?;
        if input.required_reservation_bytes < 0
            || input.range_start < 0
            || input.range_end < input.range_start
            || input.range_end >= input.required_reservation_bytes
            || (input.operation.seeks() && input.range_start != input.range_end)
            || input.context.tenant_id != fence.tenant_id
            || input.context.mount_session_id != fence.mount_session_id
            || input.context.gateway_epoch != fence.gateway_epoch
            || !valid_nfs_replay_context(&input.context)
            || input.expires_at_unix_seconds <= 0
            || (input.operation == MountWriteRangeOperation::WriteData)
                != input.content_blake3.is_some()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let io_input = BeginMountIoOperationInput {
            fence,
            capability_id: input.capability_id,
            nonce_digest: input.nonce_digest,
            claims_digest: input.claims_digest,
            operation: input.operation.io_operation(),
            range_start: Some(input.range_start),
            range_end: Some(input.range_end),
            content_blake3: input.content_blake3,
            expires_at_unix_seconds: input.expires_at_unix_seconds,
        };
        validate_mount_io_operation_input(&io_input)?;
        let mut transaction = self.pool().begin().await?;
        if lookup_mount_io_preauthorization_tx(
            &mut transaction,
            &io_input,
            &input.context,
            input.operation_id,
            Some(input.operation_id),
        )
        .await?
        {
            let result = nfs_write_plan_result_from_pending_tx(&mut transaction, input).await?;
            transaction.commit().await?;
            return Ok(result);
        }
        let recoverable_plan: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.nfs_write_operations \
             WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3 \
               AND state='planned')",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .bind(input.operation_id)
        .fetch_one(&mut *transaction)
        .await?;
        if recoverable_plan {
            let result = nfs_write_plan_result_from_pending_tx(&mut transaction, input).await?;
            if !preauthorize_mount_io_tx(
                &mut transaction,
                &io_input,
                &input.context,
                input.operation_id,
                Some(input.operation_id),
            )
            .await?
            {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(result);
        }
        let record = admit_mount_write_capability_tx(
            &mut transaction,
            fence,
            MountWriteStorageOperation::Write,
        )
        .await?;
        if record.state != "open" || record.staging_payload.state != "staging" {
            return Err(DatabaseError::StaleGeneration);
        }
        let operation_state = sqlx::query(
            "SELECT COALESCE(max(operation_ordinal),0)::bigint AS max_ordinal,\
                    COALESCE(bool_or(state<>'applied'),false) AS has_incomplete \
             FROM filebelt_mount.nfs_write_operations \
             WHERE tenant_id=$1 AND write_session_id=$2",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .fetch_one(&mut *transaction)
        .await?;
        let has_pending_io: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.nfs_io_receipts \
             WHERE tenant_id=$1 AND write_session_id=$2 AND state='pending')",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .fetch_one(&mut *transaction)
        .await?;
        if operation_state.get::<bool, _>("has_incomplete") || has_pending_io {
            return Err(DatabaseError::Conflict);
        }
        let operation_ordinal = operation_state
            .get::<i64, _>("max_ordinal")
            .checked_add(1)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let current_logical_size = record.logical_size_bytes.max(
            record
                .base_payload
                .as_ref()
                .map_or(0, |payload| payload.size_bytes),
        );
        let range_end_exclusive = input
            .range_end
            .checked_add(1)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        let resulting_logical_size = match input.operation {
            MountWriteRangeOperation::WriteData | MountWriteRangeOperation::Allocate => {
                current_logical_size.max(range_end_exclusive)
            }
            MountWriteRangeOperation::HoleDeallocate
            | MountWriteRangeOperation::SeekData
            | MountWriteRangeOperation::SeekHole => current_logical_size,
        };
        if resulting_logical_size > input.required_reservation_bytes {
            return Err(DatabaseError::QuotaExceeded);
        }
        if chunks.iter().any(|chunk| {
            chunk.source_payload_id.is_some()
                && record
                    .base_payload
                    .as_ref()
                    .map(|payload| payload.payload_id)
                    != chunk.source_payload_id
        }) {
            return Err(DatabaseError::Conflict);
        }
        let rows = sqlx::query(
            "SELECT chunk_number,source_payload_id,source_chunk_number,staging_locator,\
                    size_bytes,dirty,state FROM filebelt_mount.write_chunks \
             WHERE tenant_id=$1 AND write_session_id=$2 ORDER BY chunk_number FOR UPDATE",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .fetch_all(&mut *transaction)
        .await?;
        if rows.len() > chunks.len() {
            return Err(DatabaseError::Conflict);
        }
        for (index, row) in rows.iter().enumerate() {
            let chunk = &chunks[index];
            let old_size = row.get::<i64, _>("size_bytes");
            let old_dirty = row.get::<bool, _>("dirty");
            let identity_matches = row.get::<i64, _>("chunk_number") == chunk.chunk_number
                && row.get::<Option<Uuid>, _>("source_payload_id") == chunk.source_payload_id
                && row.get::<Option<i64>, _>("source_chunk_number") == chunk.source_chunk_number
                && row.get::<Option<Uuid>, _>("staging_locator") == Some(chunk.staging_locator)
                && row.get::<String, _>("state") == "writing";
            let mutable_tail = index + 1 == rows.len();
            let evidence_matches = if mutable_tail {
                chunk.size_bytes >= old_size && (!old_dirty || chunk.dirty)
            } else {
                chunk.size_bytes == old_size && chunk.dirty == old_dirty
            };
            if !identity_matches || !evidence_matches {
                return Err(DatabaseError::Conflict);
            }
            if mutable_tail && (chunk.size_bytes != old_size || chunk.dirty != old_dirty) {
                sqlx::query(
                    "UPDATE filebelt_mount.write_chunks SET size_bytes=$4,dirty=$5,\
                            updated_at=clock_timestamp() \
                     WHERE tenant_id=$1 AND write_session_id=$2 AND chunk_number=$3 \
                       AND state='writing' AND size_bytes=$6 AND dirty=$7",
                )
                .bind(fence.tenant_id)
                .bind(fence.write_session_id)
                .bind(chunk.chunk_number)
                .bind(chunk.size_bytes)
                .bind(chunk.dirty)
                .bind(old_size)
                .bind(old_dirty)
                .execute(&mut *transaction)
                .await?;
            }
        }
        for chunk in &chunks[rows.len()..] {
            sqlx::query(
                "INSERT INTO filebelt_mount.write_chunks \
                 (tenant_id,write_session_id,chunk_number,source_payload_id,\
                  source_chunk_number,staging_locator,size_bytes,dirty,state) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'writing')",
            )
            .bind(fence.tenant_id)
            .bind(fence.write_session_id)
            .bind(chunk.chunk_number)
            .bind(chunk.source_payload_id)
            .bind(chunk.source_chunk_number)
            .bind(chunk.staging_locator)
            .bind(chunk.size_bytes)
            .bind(chunk.dirty)
            .execute(&mut *transaction)
            .await?;
        }
        let planned_bytes = chunks
            .iter()
            .try_fold(0_i64, |total, chunk| total.checked_add(chunk.size_bytes));
        if planned_bytes.ok_or(DatabaseError::InvalidPersistedValue)?
            != input.required_reservation_bytes
        {
            return Err(DatabaseError::Conflict);
        }
        let reserved_bytes: i64 =
            sqlx::query_scalar("SELECT filebelt_mount.reserve_nfs_write_bytes($1,$2,$3,$4)")
                .bind(fence.tenant_id)
                .bind(fence.write_session_id)
                .bind(fence.fencing_token)
                .bind(input.required_reservation_bytes)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_nfs_mutation_error)?;
        let writer_changed = sqlx::query(
            "UPDATE filebelt_mount.write_sessions \
             SET logical_size_bytes=$4,heartbeat_at=clock_timestamp(),\
                 lease_expires_at=LEAST(expires_at,clock_timestamp()+interval '30 seconds') \
             WHERE tenant_id=$1 AND id=$2 AND fencing_token=$3 AND state='open' \
               AND logical_size_bytes<=$4",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .bind(fence.fencing_token)
        .bind(resulting_logical_size)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if writer_changed != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let inserted = sqlx::query(
            "INSERT INTO filebelt_mount.nfs_write_operations \
             (tenant_id,write_session_id,operation_id,operation,operation_ordinal,\
              content_blake3,range_start,range_end,resulting_logical_size,reserved_bytes) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
             ON CONFLICT (tenant_id,write_session_id,operation_id) DO NOTHING",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .bind(input.operation_id)
        .bind(input.operation.as_str())
        .bind(operation_ordinal)
        .bind(input.content_blake3.map(|digest| digest.as_slice()))
        .bind(input.range_start)
        .bind(input.range_end)
        .bind(resulting_logical_size)
        .bind(reserved_bytes)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted == 0 {
            let exact: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM filebelt_mount.nfs_write_operations \
                 WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3 \
                   AND operation=$4 AND operation_ordinal=$5 \
                   AND content_blake3 IS NOT DISTINCT FROM $6 \
                   AND range_start=$7 AND range_end=$8 \
                   AND resulting_logical_size=$9 AND reserved_bytes=$10)",
            )
            .bind(fence.tenant_id)
            .bind(fence.write_session_id)
            .bind(input.operation_id)
            .bind(input.operation.as_str())
            .bind(operation_ordinal)
            .bind(input.content_blake3.map(|digest| digest.as_slice()))
            .bind(input.range_start)
            .bind(input.range_end)
            .bind(resulting_logical_size)
            .bind(reserved_bytes)
            .fetch_one(&mut *transaction)
            .await?;
            if !exact {
                return Err(DatabaseError::Conflict);
            }
        }
        if !preauthorize_mount_io_tx(
            &mut transaction,
            &io_input,
            &input.context,
            input.operation_id,
            Some(input.operation_id),
        )
        .await?
        {
            return Err(DatabaseError::Conflict);
        }
        let result = NfsWriteChunkPlanResult {
            write_session_id: fence.write_session_id,
            reserved_bytes,
            operation_id: input.operation_id,
            operation_ordinal,
            operation: input.operation,
            content_blake3: input.content_blake3.copied(),
            range_start: input.range_start,
            range_end: input.range_end,
            resulting_logical_size,
            chunks: chunks.to_vec(),
            resumed: false,
        };
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn finalize_mount_write(
        &self,
        fence: &MountWriteCapabilityFence,
        logical_size_bytes: i64,
        blake3: &[u8; 32],
        chunks: &[MountWriteChunkEvidence],
    ) -> Result<MountWriteStorageRecord, DatabaseError> {
        validate_mount_chunk_evidence(logical_size_bytes, chunks)?;
        let mut transaction = self.pool().begin().await?;
        let record = admit_mount_write_capability_tx(
            &mut transaction,
            fence,
            MountWriteStorageOperation::Finalize,
        )
        .await?;
        if record.state == "committing" {
            if record.logical_size_bytes != logical_size_bytes
                || record.staging_payload.state != "finalized"
                || record.staging_payload.size_bytes != logical_size_bytes
                || record.staging_payload.blake3.as_deref() != Some(blake3.as_slice())
            {
                return Err(DatabaseError::Conflict);
            }
            persist_mount_chunk_evidence(&mut transaction, fence, chunks, true).await?;
            transaction.commit().await?;
            return Ok(record);
        }
        if record.state != "flushing" || record.logical_size_bytes != logical_size_bytes {
            return Err(DatabaseError::StaleGeneration);
        }
        persist_mount_chunk_evidence(&mut transaction, fence, chunks, true).await?;
        let payload_changed = sqlx::query(
            "UPDATE public.payload_objects SET state='finalized',size_bytes=$3,blake3=$4,\
                    finalized_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND drive_id=$5 AND state='staging'",
        )
        .bind(fence.tenant_id)
        .bind(record.staging_payload.payload_id)
        .bind(logical_size_bytes)
        .bind(blake3.as_slice())
        .bind(fence.drive_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let session_changed = sqlx::query(
            "UPDATE filebelt_mount.write_sessions SET state='committing',\
                    heartbeat_at=clock_timestamp(),\
                    lease_expires_at=LEAST(expires_at,clock_timestamp()+interval '30 seconds') \
             WHERE tenant_id=$1 AND id=$2 AND state='flushing' AND fencing_token=$3 \
               AND logical_size_bytes=$4",
        )
        .bind(fence.tenant_id)
        .bind(fence.write_session_id)
        .bind(fence.fencing_token)
        .bind(logical_size_bytes)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if payload_changed != 1 || session_changed != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        let record = mount_write_storage_record_tx(&mut transaction, fence).await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn begin_mount_write_abort(
        &self,
        fence: &MountWriteCapabilityFence,
    ) -> Result<MountWriteStorageRecord, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let record = admit_mount_write_capability_tx(
            &mut transaction,
            fence,
            MountWriteStorageOperation::Abort,
        )
        .await?;
        if !matches!(record.state.as_str(), "open" | "flushing" | "aborting") {
            return Err(DatabaseError::StaleGeneration);
        }
        if record.state != "aborting" {
            let changed = sqlx::query(
                "UPDATE filebelt_mount.write_sessions SET state='aborting',\
                        heartbeat_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND id=$2 AND fencing_token=$3 \
                   AND state IN ('open','flushing')",
            )
            .bind(fence.tenant_id)
            .bind(fence.write_session_id)
            .bind(fence.fencing_token)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(DatabaseError::StaleGeneration);
            }
        }
        let record = mount_write_storage_record_tx(&mut transaction, fence).await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn finish_mount_write_abort(
        &self,
        fence: &MountWriteCapabilityFence,
    ) -> Result<MountWriteStorageRecord, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let record = admit_mount_write_capability_tx(
            &mut transaction,
            fence,
            MountWriteStorageOperation::Abort,
        )
        .await?;
        if record.state == "aborted" {
            if record.staging_payload.state != "abandoned" {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit().await?;
            return Ok(record);
        }
        if record.state != "aborting" || record.staging_payload.state != "staging" {
            return Err(DatabaseError::StaleGeneration);
        }
        let payload_id: Uuid =
            sqlx::query_scalar("SELECT filebelt_mount.finish_nfs_write_abort($1,$2,$3)")
                .bind(fence.tenant_id)
                .bind(fence.write_session_id)
                .bind(fence.fencing_token)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_nfs_mutation_error)?;
        if payload_id != record.staging_payload.payload_id {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let record = mount_write_storage_record_tx(&mut transaction, fence).await?;
        transaction.commit().await?;
        Ok(record)
    }

    /// Fences expired NFS writers and atomically enqueues their existing
    /// two-phase staging cleanup. Completed-but-unapplied byte-plane work is
    /// preserved through the writer's absolute lifetime; unknown pending work
    /// is bound to the cleanup outcome instead of being silently forgotten.
    pub async fn sweep_expired_nfs_writers(
        &self,
        tenant_id: Uuid,
        limit: i32,
    ) -> Result<Vec<ExpiredNfsWriterCleanupRecord>, DatabaseError> {
        if tenant_id.is_nil() || !(1..=1000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let rows = sqlx::query(
            "SELECT write_session_id,backend_id,staging_payload_id,fencing_token,\
                    source_nonce_digest \
             FROM filebelt_mount.sweep_expired_nfs_writers($1,$2)",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        rows.iter()
            .map(|row| {
                let write_session_id = row.get::<Uuid, _>("write_session_id");
                let backend_id = row.get::<Uuid, _>("backend_id");
                let staging_payload_id = row.get::<Uuid, _>("staging_payload_id");
                let fencing_token = row.get::<i64, _>("fencing_token");
                if write_session_id.is_nil()
                    || backend_id.is_nil()
                    || staging_payload_id.is_nil()
                    || fencing_token <= 0
                {
                    return Err(DatabaseError::InvalidPersistedValue);
                }
                Ok(ExpiredNfsWriterCleanupRecord {
                    tenant_id,
                    write_session_id,
                    backend_id,
                    staging_payload_id,
                    fencing_token,
                    source_nonce_digest: optional_digest_32(row.get("source_nonce_digest"))?,
                })
            })
            .collect()
    }

    /// Expires retained conflicts at their fixed seven-day boundary, releases
    /// quota exactly once, fences the writer, and enqueues physical cleanup.
    pub async fn sweep_expired_nfs_write_conflicts(
        &self,
        tenant_id: Uuid,
        limit: i32,
    ) -> Result<Vec<ExpiredNfsWriteConflictCleanupRecord>, DatabaseError> {
        if tenant_id.is_nil() || !(1..=1000).contains(&limit) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let rows = sqlx::query(
            "SELECT conflict_id,write_session_id,backend_id,staging_payload_id \
             FROM filebelt_mount.sweep_expired_nfs_write_conflicts($1,$2)",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        rows.iter()
            .map(|row| {
                let record = ExpiredNfsWriteConflictCleanupRecord {
                    tenant_id,
                    conflict_id: row.get("conflict_id"),
                    write_session_id: row.get("write_session_id"),
                    backend_id: row.get("backend_id"),
                    staging_payload_id: row.get("staging_payload_id"),
                };
                if record.conflict_id.is_nil()
                    || record.write_session_id.is_nil()
                    || record.backend_id.is_nil()
                    || record.staging_payload_id.is_nil()
                {
                    return Err(DatabaseError::InvalidPersistedValue);
                }
                Ok(record)
            })
            .collect()
    }

    /// Leases one authoritative cleanup job for the exact backend/session.
    /// The returned session identity and payload locator are the complete
    /// physical COW deletion authority; callers must not scan tables.
    pub async fn claim_mount_staging_cleanup(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        write_session_id: Uuid,
        worker_id: Uuid,
    ) -> Result<MountStagingCleanupJobRecord, DatabaseError> {
        if tenant_id.is_nil()
            || backend_id.is_nil()
            || write_session_id.is_nil()
            || worker_id.is_nil()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT payload_id,drive_id,backend_id,locator,layout,payload_state,\
                    size_bytes,blake3,job_fencing_token,job_state,reason,completion_kind,\
                    source_nonce_digest \
             FROM filebelt_mount.claim_nfs_staging_cleanup($1,$2,$3,$4)",
        )
        .bind(tenant_id)
        .bind(backend_id)
        .bind(write_session_id)
        .bind(worker_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        let record =
            mount_staging_cleanup_job_from_row(tenant_id, write_session_id, worker_id, &row)?;
        if record.backend_id != backend_id
            || record.job_fencing_token <= 0
            || !matches!(record.job_state.as_str(), "leased" | "physical_deleted")
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        transaction.commit().await?;
        Ok(record)
    }

    /// Atomically discovers and leases the oldest cleanup for one backend.
    /// A worker's still-live prior lease is returned first, making crash retry
    /// deterministic without exposing a raw cleanup-table listing grant.
    pub async fn claim_next_mount_staging_cleanup(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        worker_id: Uuid,
    ) -> Result<Option<MountStagingCleanupJobRecord>, DatabaseError> {
        if tenant_id.is_nil() || backend_id.is_nil() || worker_id.is_nil() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT write_session_id,payload_id,drive_id,backend_id,locator,layout,\
                    payload_state,size_bytes,blake3,job_fencing_token,job_state,reason,\
                    completion_kind,source_nonce_digest \
             FROM filebelt_mount.claim_next_nfs_staging_cleanup($1,$2,$3)",
        )
        .bind(tenant_id)
        .bind(backend_id)
        .bind(worker_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let write_session_id = row.get("write_session_id");
        let record =
            mount_staging_cleanup_job_from_row(tenant_id, write_session_id, worker_id, &row)?;
        if record.backend_id != backend_id
            || record.job_fencing_token <= 0
            || !matches!(record.job_state.as_str(), "leased" | "physical_deleted")
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        transaction.commit().await?;
        Ok(Some(record))
    }

    /// Acknowledges physical source/destination deletion for an exact leased
    /// cleanup job. PostgreSQL then releases any still-held reservation,
    /// closes an unknown pending operation, and makes the job terminal.
    pub async fn complete_mount_staging_cleanup(
        &self,
        cleanup: &MountStagingCleanupJobRecord,
    ) -> Result<(), DatabaseError> {
        if cleanup.tenant_id.is_nil()
            || cleanup.backend_id.is_nil()
            || cleanup.write_session_id.is_nil()
            || cleanup.worker_id.is_nil()
            || cleanup.job_fencing_token <= 0
            || cleanup.payload.tenant_id != cleanup.tenant_id
            || cleanup.payload.backend_id != cleanup.backend_id
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("SELECT filebelt_mount.complete_nfs_staging_cleanup($1,$2,$3,$4,$5)")
            .bind(cleanup.tenant_id)
            .bind(cleanup.backend_id)
            .bind(cleanup.write_session_id)
            .bind(cleanup.worker_id)
            .bind(cleanup.job_fencing_token)
            .execute(self.pool())
            .await
            .map_err(map_nfs_mutation_error)?;
        Ok(())
    }

    /// Persists that both the session-derived COW source and payload
    /// destination have been deleted while retaining a reclaimable lease until
    /// the verified session-lock inode is removed.
    pub async fn mark_mount_staging_cleanup_physical_deleted(
        &self,
        cleanup: &MountStagingCleanupJobRecord,
    ) -> Result<(), DatabaseError> {
        if cleanup.tenant_id.is_nil()
            || cleanup.backend_id.is_nil()
            || cleanup.write_session_id.is_nil()
            || cleanup.worker_id.is_nil()
            || cleanup.job_fencing_token <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query(
            "SELECT filebelt_mount.mark_nfs_staging_cleanup_physical_deleted(\
               $1,$2,$3,$4,$5)",
        )
        .bind(cleanup.tenant_id)
        .bind(cleanup.backend_id)
        .bind(cleanup.write_session_id)
        .bind(cleanup.worker_id)
        .bind(cleanup.job_fencing_token)
        .execute(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        Ok(())
    }

    /// Extends the exact cleanup lease while the worker holds the
    /// cross-process session lock and removes a potentially large COW tree.
    pub async fn heartbeat_mount_staging_cleanup(
        &self,
        cleanup: &MountStagingCleanupJobRecord,
    ) -> Result<(), DatabaseError> {
        if cleanup.tenant_id.is_nil()
            || cleanup.backend_id.is_nil()
            || cleanup.write_session_id.is_nil()
            || cleanup.worker_id.is_nil()
            || cleanup.job_fencing_token <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query("SELECT filebelt_mount.heartbeat_nfs_staging_cleanup($1,$2,$3,$4,$5)")
            .bind(cleanup.tenant_id)
            .bind(cleanup.backend_id)
            .bind(cleanup.write_session_id)
            .bind(cleanup.worker_id)
            .bind(cleanup.job_fencing_token)
            .execute(self.pool())
            .await
            .map_err(map_nfs_mutation_error)?;
        Ok(())
    }

    /// Leases the exact lock-only cleanup enqueued by Finalize. This record
    /// authorizes removal of the session-derived lock inode only; it contains
    /// no payload locator and grants no payload deletion transition.
    pub async fn claim_mount_write_lock_cleanup(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        write_session_id: Uuid,
        worker_id: Uuid,
    ) -> Result<MountWriteLockCleanupJobRecord, DatabaseError> {
        validate_mount_write_lock_cleanup_identity(
            tenant_id,
            backend_id,
            write_session_id,
            worker_id,
        )?;
        let row = sqlx::query(
            "SELECT backend_id,staging_payload_id,job_fencing_token,job_state \
             FROM filebelt_mount.claim_nfs_write_lock_cleanup($1,$2,$3,$4)",
        )
        .bind(tenant_id)
        .bind(backend_id)
        .bind(write_session_id)
        .bind(worker_id)
        .fetch_one(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        mount_write_lock_cleanup_job_from_row(tenant_id, write_session_id, worker_id, &row)
    }

    /// Atomically discovers and leases the oldest lock-only cleanup for one
    /// backend. A live lease owned by the same worker is returned first.
    pub async fn claim_next_mount_write_lock_cleanup(
        &self,
        tenant_id: Uuid,
        backend_id: Uuid,
        worker_id: Uuid,
    ) -> Result<Option<MountWriteLockCleanupJobRecord>, DatabaseError> {
        if tenant_id.is_nil() || backend_id.is_nil() || worker_id.is_nil() {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let row = sqlx::query(
            "SELECT write_session_id,backend_id,staging_payload_id,\
                    job_fencing_token,job_state \
             FROM filebelt_mount.claim_next_nfs_write_lock_cleanup($1,$2,$3)",
        )
        .bind(tenant_id)
        .bind(backend_id)
        .bind(worker_id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_nfs_mutation_error)?;
        row.map(|row| {
            let write_session_id = row.get("write_session_id");
            mount_write_lock_cleanup_job_from_row(tenant_id, write_session_id, worker_id, &row)
        })
        .transpose()
    }

    pub async fn heartbeat_mount_write_lock_cleanup(
        &self,
        cleanup: &MountWriteLockCleanupJobRecord,
    ) -> Result<(), DatabaseError> {
        validate_mount_write_lock_cleanup_record(cleanup)?;
        sqlx::query("SELECT filebelt_mount.heartbeat_nfs_write_lock_cleanup($1,$2,$3,$4,$5)")
            .bind(cleanup.tenant_id)
            .bind(cleanup.backend_id)
            .bind(cleanup.write_session_id)
            .bind(cleanup.worker_id)
            .bind(cleanup.job_fencing_token)
            .execute(self.pool())
            .await
            .map_err(map_nfs_mutation_error)?;
        Ok(())
    }

    /// Acknowledges verified lock-inode removal. Exact retry by the same
    /// worker/fence is idempotent; payload state is never touched.
    pub async fn complete_mount_write_lock_cleanup(
        &self,
        cleanup: &MountWriteLockCleanupJobRecord,
    ) -> Result<(), DatabaseError> {
        validate_mount_write_lock_cleanup_record(cleanup)?;
        sqlx::query("SELECT filebelt_mount.complete_nfs_write_lock_cleanup($1,$2,$3,$4,$5)")
            .bind(cleanup.tenant_id)
            .bind(cleanup.backend_id)
            .bind(cleanup.write_session_id)
            .bind(cleanup.worker_id)
            .bind(cleanup.job_fencing_token)
            .execute(self.pool())
            .await
            .map_err(map_nfs_mutation_error)?;
        Ok(())
    }

    /// Returns normalized ordered parts for upload-origin and NFS-origin
    /// chunked payloads. Whole-object payloads return an empty vector.
    pub async fn payload_parts_for_mount_read(
        &self,
        tenant_id: Uuid,
        payload_id: Uuid,
    ) -> Result<Vec<MountPayloadPartRecord>, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let payload = payload_record_tx(&mut transaction, tenant_id, payload_id).await?;
        if payload.state != "referenced" {
            return Err(DatabaseError::NotFound);
        }
        let parts = mount_payload_parts_tx(&mut transaction, tenant_id, payload_id).await?;
        if payload.layout == "chunked" && parts.is_empty() && payload.size_bytes != 0 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        transaction.commit().await?;
        Ok(parts)
    }

    /// Lists only the caller's unresolved, unexpired NFS write conflicts. No
    /// physical payload locator or GSS material crosses this control-plane API.
    pub async fn list_nfs_write_conflicts(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
    ) -> Result<Vec<NfsWriteConflictRecord>, DatabaseError> {
        let rows = sqlx::query(
            "SELECT conflict.id,conflict.write_session_id,conflict.drive_id,\
                    conflict.node_id AS source_node_id,conflict.base_version_id,\
                    conflict.expected_head_version_id,conflict.observed_head_version_id,\
                    conflict.logical_size_bytes,conflict.state,conflict.conflict_copy_node_id,\
                    conflict.conflict_copy_version_id,conflict.created_at::text,\
                    conflict.expires_at::text \
             FROM filebelt_mount.nfs_write_conflicts AS conflict \
             JOIN filebelt_mount.sessions AS session \
               ON session.tenant_id=conflict.tenant_id \
              AND session.id=conflict.mount_session_id \
             WHERE conflict.tenant_id=$1 AND session.user_principal_id=$2 \
               AND conflict.state='retained' \
               AND conflict.expires_at>clock_timestamp() \
             ORDER BY conflict.created_at DESC,conflict.id",
        )
        .bind(tenant_id)
        .bind(actor_principal_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(nfs_write_conflict_from_row).collect())
    }

    /// Copies retained bytes into a new common-namespace file after the API
    /// has evaluated CREATE_CHILD on the selected parent. The exact API
    /// session and common authorization generations are locked again here.
    pub async fn copy_nfs_write_conflict(
        &self,
        input: &CopyNfsWriteConflictInput<'_>,
    ) -> Result<NfsWriteConflictCopyRecord, DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        let record = self
            .copy_nfs_write_conflict_tx(&mut transaction, input)
            .await?;
        transaction.commit().await?;
        Ok(record)
    }

    /// Atomically copies a retained conflict and persists the exact HTTP
    /// response receipt. A lost response can therefore be replayed without
    /// allocating another node/version or charging quota twice.
    pub async fn copy_nfs_write_conflict_idempotent<F>(
        &self,
        input: &CopyNfsWriteConflictInput<'_>,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce(&NfsWriteConflictCopyRecord) -> Result<Value, serde_json::Error>,
    {
        idempotency.validate_actor(input.actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, input.tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                let copy = self
                    .copy_nfs_write_conflict_tx(&mut transaction, input)
                    .await?;
                let response =
                    render_response(&copy).map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    input.tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
    }

    async fn copy_nfs_write_conflict_tx(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &CopyNfsWriteConflictInput<'_>,
    ) -> Result<NfsWriteConflictCopyRecord, DatabaseError> {
        if !valid_nfs_mutation_authorization(&input.authorization) {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let normalized = NormalizedName::new(input.display_name)
            .map_err(|_| DatabaseError::InvalidPersistedValue)?;
        let conflict = sqlx::query(
            "SELECT conflict.state,conflict.drive_id,conflict.node_id,\
                    conflict.staging_payload_id,conflict.logical_size_bytes,\
                    conflict.conflict_copy_node_id,conflict.conflict_copy_version_id,\
                    write_session.reserved_bytes,payload.size_bytes,payload.blake3,payload.state AS payload_state \
             FROM filebelt_mount.nfs_write_conflicts AS conflict \
             JOIN filebelt_mount.sessions AS session \
               ON session.tenant_id=conflict.tenant_id AND session.id=conflict.mount_session_id \
             JOIN filebelt_mount.write_sessions AS write_session \
               ON write_session.tenant_id=conflict.tenant_id \
              AND write_session.id=conflict.write_session_id \
             JOIN public.payload_objects AS payload \
               ON payload.tenant_id=conflict.tenant_id \
              AND payload.id=conflict.staging_payload_id \
             WHERE conflict.tenant_id=$1 AND conflict.id=$2 \
               AND session.user_principal_id=$3 \
               AND conflict.state IN ('retained','copied') \
               AND (conflict.state='copied' OR conflict.expires_at>clock_timestamp())",
        )
        .bind(input.tenant_id)
        .bind(input.conflict_id)
        .bind(input.actor_principal_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let drive_id: Uuid = conflict.get("drive_id");
        if drive_id != input.authorization.drive_id {
            return Err(DatabaseError::StaleGeneration);
        }
        if conflict.get::<String, _>("state") == "copied" {
            let node_id: Uuid = conflict
                .get::<Option<Uuid>, _>("conflict_copy_node_id")
                .ok_or(DatabaseError::InvalidPersistedValue)?;
            let version_id: Uuid = conflict
                .get::<Option<Uuid>, _>("conflict_copy_version_id")
                .ok_or(DatabaseError::InvalidPersistedValue)?;
            let row = sqlx::query(
                "SELECT node.parent_id,node.display_name,node.name_key,\
                        version.size_bytes,version.blake3 \
                 FROM public.nodes AS node JOIN public.file_versions AS version \
                   ON version.tenant_id=node.tenant_id AND version.node_id=node.id \
                 WHERE node.tenant_id=$1 AND node.drive_id=$2 AND node.id=$3 AND version.id=$4",
            )
            .bind(input.tenant_id)
            .bind(drive_id)
            .bind(node_id)
            .bind(version_id)
            .fetch_one(&mut **transaction)
            .await?;
            if row.get::<Option<Uuid>, _>("parent_id") != Some(input.authorization.resource_id)
                || row.get::<String, _>("display_name") != normalized.display()
                || row.get::<String, _>("name_key") != normalized.comparison_key()
            {
                return Err(DatabaseError::Conflict);
            }
            let record = NfsWriteConflictCopyRecord {
                conflict_id: input.conflict_id,
                drive_id,
                node_id,
                version_id,
                display_name: row.get("display_name"),
                size_bytes: row.get("size_bytes"),
                blake3: array_32(row.get("blake3"))?,
            };
            return Ok(record);
        }
        lock_authorization_fence(
            transaction,
            input.tenant_id,
            input.actor_principal_id,
            input.api_session_id,
            drive_id,
            input.authorization.resource_id,
            [
                input.authorization.membership_generation,
                input.authorization.drive_acl_generation,
                input.authorization.drive_namespace_generation,
                input.authorization.resource_acl_generation,
            ],
        )
        .await?;
        let parent_generation: i64 = sqlx::query_scalar(
            "SELECT namespace_generation FROM public.nodes \
             WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 AND kind='directory' \
               AND trash_root_id IS NULL FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(input.authorization.resource_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        if parent_generation != input.authorization.resource_namespace_generation
            || conflict.get::<String, _>("payload_state") != "finalized"
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let node_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let payload_id: Uuid = conflict.get("staging_payload_id");
        let size_bytes: i64 = conflict.get("size_bytes");
        let logical_size_bytes: i64 = conflict.get("logical_size_bytes");
        let blake3 = array_32(conflict.get("blake3"))?;
        if size_bytes != logical_size_bytes {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query(
            "INSERT INTO public.nodes \
             (tenant_id,drive_id,id,parent_id,kind,display_name,name_key,owner_principal_id) \
             VALUES ($1,$2,$3,$4,'file',$5,$6,$7)",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(input.authorization.resource_id)
        .bind(normalized.display())
        .bind(normalized.comparison_key())
        .bind(input.actor_principal_id)
        .execute(&mut **transaction)
        .await
        .map_err(map_conflict)?;
        sqlx::query(
            "INSERT INTO public.node_ancestry \
             (tenant_id,drive_id,ancestor_id,descendant_id,depth) \
             SELECT tenant_id,drive_id,ancestor_id,$4,depth+1 FROM public.node_ancestry \
             WHERE tenant_id=$1 AND drive_id=$2 AND descendant_id=$3 \
             UNION ALL SELECT $1,$2,$4,$4,0",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(input.authorization.resource_id)
        .bind(node_id)
        .execute(&mut **transaction)
        .await?;
        let creator_display_name: String = sqlx::query_scalar(
            "SELECT display_name FROM public.users \
             WHERE tenant_id=$1 AND principal_id=$2 AND status='active'",
        )
        .bind(input.tenant_id)
        .bind(input.actor_principal_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DatabaseError::StaleGeneration)?;
        sqlx::query(
            "INSERT INTO public.file_versions \
             (tenant_id,node_id,id,ordinal,payload_id,size_bytes,blake3,created_by,\
              origin_kind,creator_display_name) \
             VALUES ($1,$2,$3,1,$4,$5,$6,$7,'nfs',$8)",
        )
        .bind(input.tenant_id)
        .bind(node_id)
        .bind(version_id)
        .bind(payload_id)
        .bind(size_bytes)
        .bind(blake3.as_slice())
        .bind(input.actor_principal_id)
        .bind(creator_display_name)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "UPDATE public.nodes SET head_version_id=$4,namespace_generation=namespace_generation+1,\
                    modified_at=clock_timestamp(),changed_at=clock_timestamp(),\
                    updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND drive_id=$2 AND id=$3",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(node_id)
        .bind(version_id)
        .execute(&mut **transaction)
        .await?;
        let parent_changed = sqlx::query(
            "UPDATE public.nodes SET namespace_generation=namespace_generation+1,\
                    changed_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 \
               AND namespace_generation=$4",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(input.authorization.resource_id)
        .bind(input.authorization.resource_namespace_generation)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        let payload_changed = sqlx::query(
            "UPDATE public.payload_objects SET state='referenced',referenced_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND state='finalized'",
        )
        .bind(input.tenant_id)
        .bind(payload_id)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        let reserved_bytes: i64 = conflict.get("reserved_bytes");
        let drive_generation: Option<i64> = sqlx::query_scalar(
            "UPDATE public.drives SET reserved_bytes=reserved_bytes-$3,\
                    used_physical_bytes=used_physical_bytes+$4,\
                    namespace_generation=namespace_generation+1 \
             WHERE tenant_id=$1 AND id=$2 AND reserved_bytes>=$3 \
             RETURNING namespace_generation",
        )
        .bind(input.tenant_id)
        .bind(drive_id)
        .bind(reserved_bytes)
        .bind(size_bytes)
        .fetch_optional(&mut **transaction)
        .await?;
        sqlx::query(
            "SELECT filebelt_mount.complete_nfs_write_conflict_copy(\
               $1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(input.tenant_id)
        .bind(input.actor_principal_id)
        .bind(input.api_session_id)
        .bind(input.conflict_id)
        .bind(input.authorization.resource_id)
        .bind(normalized.display())
        .bind(normalized.comparison_key())
        .bind(node_id)
        .bind(version_id)
        .execute(&mut **transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        if parent_changed != 1 || payload_changed != 1 || drive_generation.is_none() {
            return Err(DatabaseError::StaleGeneration);
        }
        insert_audit(
            transaction,
            input.tenant_id,
            Some(input.actor_principal_id),
            None,
            Some(node_id),
            "mount.nfs.conflict.copy",
            "allowed",
            "create_child_allowed",
            false,
            json!({"conflict_id":input.conflict_id,"version_id":version_id}),
        )
        .await?;
        insert_outbox(
            transaction,
            input.tenant_id,
            "filebelt.v1.file.version.committed",
            "node",
            node_id,
            drive_generation.ok_or(DatabaseError::StaleGeneration)?,
        )
        .await?;
        Ok(NfsWriteConflictCopyRecord {
            conflict_id: input.conflict_id,
            drive_id,
            node_id,
            version_id,
            display_name: normalized.display().to_owned(),
            size_bytes,
            blake3,
        })
    }

    /// Discards the caller's retained conflict while preserving its inventory
    /// row until the fixed seven-day retention deadline.
    pub async fn discard_nfs_write_conflict(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        api_session_id: Uuid,
        conflict_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut transaction = self.pool().begin().await?;
        self.discard_nfs_write_conflict_tx(
            &mut transaction,
            tenant_id,
            actor_principal_id,
            api_session_id,
            conflict_id,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically discards a retained conflict and stores the empty success
    /// response so retries cannot repeat quota or cleanup mutations.
    #[allow(clippy::too_many_arguments)]
    pub async fn discard_nfs_write_conflict_idempotent<F>(
        &self,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        api_session_id: Uuid,
        conflict_id: Uuid,
        idempotency: &NfsAdminIdempotency<'_>,
        render_response: F,
    ) -> Result<NfsAdminIdempotentWrite, DatabaseError>
    where
        F: FnOnce() -> Result<Value, serde_json::Error>,
    {
        idempotency.validate_actor(actor_principal_id)?;
        let reservation = idempotency.reservation_input();
        let mut transaction = self.pool().begin().await?;
        match reserve_idempotency(&mut transaction, tenant_id, &reservation).await? {
            IdempotencyReservation::Replay(record) => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Replayed(record))
            }
            IdempotencyReservation::KeyReused => {
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::KeyReused)
            }
            IdempotencyReservation::Created => {
                self.discard_nfs_write_conflict_tx(
                    &mut transaction,
                    tenant_id,
                    actor_principal_id,
                    api_session_id,
                    conflict_id,
                )
                .await?;
                let response =
                    render_response().map_err(|_| DatabaseError::InvalidPersistedValue)?;
                let record = finalize_idempotency(
                    &mut transaction,
                    tenant_id,
                    &reservation,
                    idempotency.response_status,
                    &response,
                )
                .await?;
                transaction.commit().await?;
                Ok(NfsAdminIdempotentWrite::Created(record))
            }
        }
    }

    async fn discard_nfs_write_conflict_tx(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant_id: Uuid,
        actor_principal_id: Uuid,
        api_session_id: Uuid,
        conflict_id: Uuid,
    ) -> Result<(), DatabaseError> {
        if tenant_id.is_nil()
            || actor_principal_id.is_nil()
            || api_session_id.is_nil()
            || conflict_id.is_nil()
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        sqlx::query_scalar::<_, Uuid>(
            "SELECT filebelt_mount.discard_nfs_write_conflict($1,$2,$3,$4)",
        )
        .bind(tenant_id)
        .bind(actor_principal_id)
        .bind(api_session_id)
        .bind(conflict_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_nfs_mutation_error)?;
        insert_audit(
            transaction,
            tenant_id,
            Some(actor_principal_id),
            None,
            Some(conflict_id),
            "mount.nfs.conflict.discard",
            "allowed",
            "owner_discarded_retained_conflict",
            false,
            json!({}),
        )
        .await?;
        Ok(())
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
            allowed_export_ids: Vec::new(),
            nfs_mapping_generation: None,
            nfs_feature_generation: None,
            nfs_manifest_generation: None,
            nfs_restore_generation: None,
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
                  filebelt_mount.policies policy,users u \
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
               AND u.tenant_id=p.tenant_id AND u.principal_id=p.id AND u.status='active' \
               AND policy.tenant_id=s.tenant_id AND policy.principal_id=s.user_principal_id \
               AND policy.protocol=s.protocol AND policy.enabled \
               AND policy.authorization_generation=$7 \
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
                     AND feature.applied_manifest_digest IS NOT NULL \
                     AND feature.applied_gateway_id=s.gateway_id \
                     AND feature.applied_gateway_epoch=s.gateway_epoch \
                     AND feature.restore_generation=s.nfs_restore_generation \
                     AND (s.state='draining' OR (\
                       feature.manifest_generation=s.nfs_manifest_generation \
                       AND feature.applied_manifest_generation=feature.manifest_generation))) \
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
                 AND (s.state='draining' OR NOT EXISTS (\
                   SELECT 1 FROM unnest(s.nfs_allowed_export_ids) AS allowed(export_id) \
                   WHERE NOT EXISTS (SELECT 1 FROM filebelt_mount.nfs_exports export \
                     JOIN nodes root ON root.tenant_id=export.tenant_id \
                       AND root.drive_id=export.drive_id AND root.parent_id IS NULL \
                       AND root.trash_root_id IS NULL AND root.kind='directory' \
                     WHERE export.tenant_id=s.tenant_id \
                       AND export.export_id=allowed.export_id \
                       AND export.drive_id=ANY(c.allowed_drive_ids) \
                       AND export.drive_id=ANY(policy.allowed_drive_ids) \
                       AND export.desired_state='active' AND export.applied_state='active' \
                       AND export.desired_generation=export.applied_generation))))) \
             RETURNING s.user_principal_id,s.credential_id,s.protocol,s.credential_generation,\
               s.authorization_generation,s.membership_generation,s.gateway_epoch,\
               s.nfs_mapping_generation,s.nfs_feature_generation,s.nfs_restore_generation,\
               (c.read_only OR policy.read_only) AS read_only,\
               CASE WHEN s.protocol='nfs' THEN ARRAY(\
                 SELECT DISTINCT export.drive_id FROM filebelt_mount.nfs_exports export \
                 JOIN nodes root ON root.tenant_id=export.tenant_id \
                   AND root.drive_id=export.drive_id AND root.parent_id IS NULL \
                   AND root.trash_root_id IS NULL AND root.kind='directory' \
                 WHERE export.tenant_id=s.tenant_id \
                   AND export.export_id=ANY(s.nfs_allowed_export_ids) \
                   AND export.drive_id=ANY(c.allowed_drive_ids) \
                   AND export.drive_id=ANY(policy.allowed_drive_ids) \
                   AND export.desired_state='active' AND export.applied_state='active' \
                   AND export.desired_generation=export.applied_generation \
                 ORDER BY export.drive_id) ELSE ARRAY(\
                   SELECT allowed.drive_id \
                   FROM unnest(c.allowed_drive_ids) AS allowed(drive_id) \
                   WHERE allowed.drive_id=ANY(policy.allowed_drive_ids) \
                   ORDER BY allowed.drive_id\
                 ) END AS allowed_drive_ids,\
               CASE WHEN s.protocol='nfs' THEN s.nfs_allowed_export_ids \
                 ELSE '{}'::bigint[] END AS allowed_export_ids,\
               s.nfs_manifest_generation",
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
            allowed_export_ids: row.get("allowed_export_ids"),
            nfs_mapping_generation: row.get("nfs_mapping_generation"),
            nfs_feature_generation: row.get("nfs_feature_generation"),
            nfs_manifest_generation: row.get("nfs_manifest_generation"),
            nfs_restore_generation: row.get("nfs_restore_generation"),
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
             WHERE tenant_id=$1 AND id=$2 AND state IN ('active','draining')",
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

    /// Opens one NFS handle under the authenticated session/GSS/generation
    /// projection and records either the stable success or share-conflict wire
    /// response in the same transaction. Caller-provided UUIDs keep a lost
    /// response from allocating a second handle.
    pub async fn open_nfs_mount_handle(
        &self,
        input: &OpenNfsHandleInput<'_>,
    ) -> Result<OpenedNfsHandle, DatabaseError> {
        validate_nfs_state_replay(input.session, &input.replay, "open")?;
        let unique_actions = input.access_actions.iter().collect::<HashSet<_>>().len();
        let wants_write = input
            .access_actions
            .iter()
            .any(|action| action == "WRITE_CONTENT");
        let read_only_open = input
            .access_actions
            .iter()
            .all(|action| matches!(action.as_str(), "READ_METADATA" | "READ_CONTENT"));
        if input.handle_id.is_nil()
            || input.session.membership_generation != input.authorization.membership_generation
            || !valid_nfs_mutation_authorization(&input.authorization)
            || input.access_actions.is_empty()
            || input.access_actions.len() > 19
            || unique_actions != input.access_actions.len()
            || !input.access_actions.iter().all(|action| {
                matches!(
                    action.as_str(),
                    "READ_METADATA"
                        | "READ_CONTENT"
                        | "WRITE_CONTENT"
                        | "CREATE_VERSION"
                        | "DELETE"
                        | "MANAGE_LOCK"
                )
            })
            || (wants_write
                && (!input
                    .access_actions
                    .iter()
                    .any(|action| action == "CREATE_VERSION")
                    || input.session.read_only))
            || input.conflict_response_bytes.is_empty()
            || input.conflict_response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let result = nfs_open_result_from_replay(input, replay)?;
            transaction.commit().await?;
            return Ok(result);
        }
        let authorized = if read_only_open {
            sqlx::query(
                "SELECT user_principal_id FROM filebelt_mount.authorize_nfs_handle_open(\
                   $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            )
            .bind(input.session.tenant_id)
            .bind(input.session.session_id)
            .bind(input.session.gateway_epoch)
            .bind(input.gss_binding_digest.as_slice())
            .bind(input.authorization.drive_id)
            .bind(input.authorization.resource_id)
            .bind(input.authorization.membership_generation)
            .bind(input.authorization.drive_acl_generation)
            .bind(input.authorization.drive_namespace_generation)
            .bind(input.authorization.resource_acl_generation)
            .bind(input.authorization.resource_namespace_generation)
            .bind(input.access_actions)
            .fetch_one(&mut *transaction)
            .await
        } else {
            sqlx::query(
                "SELECT user_principal_id FROM filebelt_mount.authorize_nfs_mutation(\
                   $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(input.session.tenant_id)
            .bind(input.session.session_id)
            .bind(input.session.gateway_epoch)
            .bind(input.gss_binding_digest.as_slice())
            .bind(input.authorization.drive_id)
            .bind(input.authorization.resource_id)
            .bind(input.authorization.membership_generation)
            .bind(input.authorization.drive_acl_generation)
            .bind(input.authorization.drive_namespace_generation)
            .bind(input.authorization.resource_acl_generation)
            .bind(input.authorization.resource_namespace_generation)
            .fetch_one(&mut *transaction)
            .await
        };
        authorized.map_err(map_nfs_mutation_error)?;
        let node = sqlx::query(
            "SELECT node.head_version_id,node.namespace_generation,node.acl_generation,\
                    drive.acl_generation AS drive_acl_generation,\
                    drive.namespace_generation AS drive_namespace_generation \
             FROM public.nodes AS node \
             JOIN public.drives AS drive ON drive.tenant_id=node.tenant_id \
               AND drive.id=node.drive_id \
             JOIN filebelt_mount.sessions AS mount_session \
               ON mount_session.tenant_id=node.tenant_id AND mount_session.id=$4 \
             WHERE node.tenant_id=$1 AND node.drive_id=$2 AND node.id=$3 \
               AND node.kind='file' AND node.trash_root_id IS NULL",
        )
        .bind(input.session.tenant_id)
        .bind(input.authorization.drive_id)
        .bind(input.authorization.resource_id)
        .bind(input.session.session_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(DatabaseError::NotFound)?;
        let version_id: Option<Uuid> = node.get("head_version_id");
        if (version_id.is_none() && !wants_write)
            || input
                .expected_version_id
                .is_some_and(|expected| Some(expected) != version_id)
            || node.get::<i64, _>("drive_acl_generation")
                != input.authorization.drive_acl_generation
            || node.get::<i64, _>("drive_namespace_generation")
                != input.authorization.drive_namespace_generation
            || node.get::<i64, _>("namespace_generation")
                != input.authorization.resource_namespace_generation
            || node.get::<i64, _>("acl_generation") != input.authorization.resource_acl_generation
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let wants_read = input
            .access_actions
            .iter()
            .any(|action| action == "READ_CONTENT");
        let wants_delete = input.access_actions.iter().any(|action| action == "DELETE");
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.handles AS handle \
             WHERE handle.tenant_id=$1 AND handle.drive_id=$2 AND handle.node_id=$3 \
               AND handle.closed_at IS NULL AND handle.expires_at>clock_timestamp() AND (\
                 ($4 AND 'WRITE_CONTENT'=ANY(handle.access_actions)) OR \
                 ($5 AND NOT handle.share_read) OR \
                 ('READ_CONTENT'=ANY(handle.access_actions) AND NOT $6) OR \
                 ($4 AND NOT handle.share_write) OR \
                 ('WRITE_CONTENT'=ANY(handle.access_actions) AND NOT $7) OR \
                 ($8 AND NOT handle.share_delete) OR \
                 ('DELETE'=ANY(handle.access_actions) AND NOT $9)))",
        )
        .bind(input.session.tenant_id)
        .bind(input.authorization.drive_id)
        .bind(input.authorization.resource_id)
        .bind(wants_write)
        .bind(wants_read)
        .bind(input.share_read)
        .bind(input.share_write)
        .bind(wants_delete)
        .bind(input.share_delete)
        .fetch_one(&mut *transaction)
        .await?;
        let handle = if conflict {
            None
        } else {
            sqlx::query(
                "INSERT INTO filebelt_mount.handles \
                 (tenant_id,id,session_id,drive_id,node_id,version_id,access_actions,\
                  share_read,share_write,share_delete,credential_generation,\
                  authorization_generation,membership_generation,drive_acl_generation,\
                  namespace_generation,resource_acl_generation,gateway_epoch,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
                   LEAST((SELECT absolute_expires_at FROM filebelt_mount.sessions \
                     WHERE tenant_id=$1 AND id=$3),\
                     clock_timestamp()+interval '15 minutes'))",
            )
            .bind(input.session.tenant_id)
            .bind(input.handle_id)
            .bind(input.session.session_id)
            .bind(input.authorization.drive_id)
            .bind(input.authorization.resource_id)
            .bind(version_id)
            .bind(input.access_actions)
            .bind(input.share_read)
            .bind(input.share_write)
            .bind(input.share_delete)
            .bind(input.session.credential_generation)
            .bind(input.session.authorization_generation)
            .bind(input.session.membership_generation)
            .bind(input.authorization.drive_acl_generation)
            .bind(input.authorization.resource_namespace_generation)
            .bind(input.authorization.resource_acl_generation)
            .bind(input.session.gateway_epoch)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
            Some(MountHandleRecord {
                id: input.handle_id,
                session_id: input.session.session_id,
                drive_id: input.authorization.drive_id,
                node_id: input.authorization.resource_id,
                version_id,
                access_actions: input.access_actions.to_vec(),
                credential_generation: input.session.credential_generation,
                authorization_generation: input.session.authorization_generation,
                membership_generation: input.session.membership_generation,
                drive_acl_generation: input.authorization.drive_acl_generation,
                namespace_generation: input.authorization.resource_namespace_generation,
                resource_acl_generation: input.authorization.resource_acl_generation,
                gateway_epoch: input.session.gateway_epoch,
            })
        };
        let outcome = if conflict { "conflict" } else { "applied" };
        insert_audit(
            &mut transaction,
            input.session.tenant_id,
            Some(input.session.user_principal_id),
            None,
            Some(input.authorization.resource_id),
            "mount.handle.open",
            if conflict { "denied" } else { "allowed" },
            if conflict {
                "nfs_share_or_writer_conflict"
            } else {
                "virtual_acl_allowed"
            },
            false,
            json!({"handle_id":input.handle_id,"protocol":"nfs","write":wants_write}),
        )
        .await?;
        let selected_replay = if conflict {
            RecordNfsReplayReceiptInput {
                context: input.replay.context.clone(),
                response_bytes: input.conflict_response_bytes,
                response_digest: input.conflict_response_digest,
            }
        } else {
            input.replay.clone()
        };
        let mutation_result = json!({
            "drive_id":input.authorization.drive_id,
            "node_id":input.authorization.resource_id,
            "handle":handle,
        });
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &selected_replay,
            Some(outcome),
            Some(&mutation_result),
        )
        .await?;
        transaction.commit().await?;
        Ok(OpenedNfsHandle {
            handle,
            replay,
            replayed: false,
            outcome: outcome.to_owned(),
        })
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
                    "READ_METADATA"
                        | "READ_CONTENT"
                        | "WRITE_CONTENT"
                        | "CREATE_VERSION"
                        | "DELETE"
                        | "MANAGE_LOCK"
                )
            })
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let wants_write = access_actions
            .iter()
            .any(|action| action == "WRITE_CONTENT");
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
        if (version_id.is_none() && !wants_write)
            || expected_version_id.is_some_and(|expected| Some(expected) != version_id)
            || node.get::<i64, _>("drive_acl_generation") != drive_acl_generation
            || node.get::<i64, _>("namespace_generation") != namespace_generation
            || node.get::<i64, _>("acl_generation") != resource_acl_generation
        {
            return Err(DatabaseError::StaleGeneration);
        }
        let wants_read = access_actions.iter().any(|action| action == "READ_CONTENT");
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
            "READ_METADATA"
                | "READ_CONTENT"
                | "WRITE_CONTENT"
                | "CREATE_VERSION"
                | "DELETE"
                | "MANAGE_LOCK"
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

    pub async fn close_nfs_mount_handle(
        &self,
        input: &CloseNfsHandleInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        validate_nfs_state_replay(input.session, &input.replay, "close")?;
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let receipt = nfs_state_receipt(replay, Some(input.handle_id))?;
            transaction.commit().await?;
            return Ok(receipt);
        }
        admit_nfs_handle_tx(
            &mut transaction,
            input.session,
            input.gss_binding_digest,
            input.handle_id,
            None,
            false,
        )
        .await?;
        require_completed_nfs_internal_terminal_tx(
            &mut transaction,
            &input.replay.context,
            Some(input.handle_id),
        )
        .await?;
        fence_nfs_writers_tx(
            &mut transaction,
            input.session.tenant_id,
            input.session.session_id,
            Some(input.handle_id),
            "handle_closed",
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.handles SET closed_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND session_id=$3 AND closed_at IS NULL",
        )
        .bind(input.session.tenant_id)
        .bind(input.handle_id)
        .bind(input.session.session_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query(
            "UPDATE filebelt_mount.byte_locks SET released_at=clock_timestamp() \
             WHERE tenant_id=$1 AND handle_id=$2 AND released_at IS NULL",
        )
        .bind(input.session.tenant_id)
        .bind(input.handle_id)
        .execute(&mut *transaction)
        .await?;
        let result = json!({"resource_id":input.handle_id});
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &input.replay,
            Some("applied"),
            Some(&result),
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsMutationReceipt {
            replay,
            replayed: false,
            outcome: "applied".to_owned(),
            resource_id: Some(input.handle_id),
            resource_generation: None,
        })
    }

    pub async fn end_nfs_mount_session(
        &self,
        input: &EndNfsSessionInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        validate_nfs_state_replay(input.session, &input.replay, "end_session")?;
        if input.reason_code.is_empty() || input.reason_code.len() > 64 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let receipt = nfs_state_receipt(replay, Some(input.session.session_id))?;
            transaction.commit().await?;
            return Ok(receipt);
        }
        let admitted = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM filebelt_mount.sessions AS mount_session \
             JOIN filebelt_mount.gateway_epochs AS gateway \
               ON gateway.tenant_id=mount_session.tenant_id AND gateway.protocol='nfs' \
              AND gateway.gateway_id=mount_session.gateway_id \
              AND gateway.epoch=mount_session.gateway_epoch \
             JOIN filebelt_mount.nfs_feature_state AS feature \
               ON feature.tenant_id=mount_session.tenant_id \
             WHERE mount_session.tenant_id=$1 AND mount_session.id=$2 \
               AND mount_session.credential_id=$3 \
               AND mount_session.user_principal_id=$4 \
               AND mount_session.credential_generation=$5 \
               AND mount_session.authorization_generation=$6 \
               AND mount_session.membership_generation=$7 \
               AND mount_session.gateway_epoch=$8 \
               AND mount_session.nfs_gss_binding_digest=$9 \
               AND mount_session.nfs_mapping_generation=$10 \
               AND mount_session.nfs_feature_generation=$11 \
               AND mount_session.nfs_manifest_generation=$12 \
               AND mount_session.nfs_restore_generation=$13 \
               AND mount_session.nfs_allowed_export_ids=$14 \
               AND mount_session.state IN ('active','draining') \
               AND mount_session.absolute_expires_at>clock_timestamp() \
               AND feature.generation=$11 AND feature.restore_generation=$13 \
               AND ((mount_session.state='active' AND feature.state='active' \
                     AND NOT gateway.draining \
                     AND gateway.lease_expires_at>clock_timestamp()) \
                 OR (mount_session.state='draining' \
                     AND feature.state IN ('active','draining') AND gateway.draining \
                     AND gateway.drain_deadline>clock_timestamp())) \
             FOR UPDATE OF mount_session,gateway,feature",
        )
        .bind(input.session.tenant_id)
        .bind(input.session.session_id)
        .bind(input.session.credential_id)
        .bind(input.session.user_principal_id)
        .bind(input.session.credential_generation)
        .bind(input.session.authorization_generation)
        .bind(input.session.membership_generation)
        .bind(input.session.gateway_epoch)
        .bind(input.gss_binding_digest.as_slice())
        .bind(input.session.nfs_mapping_generation)
        .bind(input.session.nfs_feature_generation)
        .bind(input.session.nfs_manifest_generation)
        .bind(input.session.nfs_restore_generation)
        .bind(&input.session.allowed_export_ids)
        .fetch_optional(&mut *transaction)
        .await?;
        if admitted.is_none() {
            return Err(DatabaseError::StaleGeneration);
        }
        require_completed_nfs_internal_terminal_tx(&mut transaction, &input.replay.context, None)
            .await?;
        fence_nfs_writers_tx(
            &mut transaction,
            input.session.tenant_id,
            input.session.session_id,
            None,
            "session_closed",
        )
        .await?;
        let result = json!({"resource_id":input.session.session_id});
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &input.replay,
            Some("applied"),
            Some(&result),
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.sessions \
             SET state='closed',closed_at=clock_timestamp(),close_reason=$3 \
             WHERE tenant_id=$1 AND id=$2 AND state IN ('active','draining')",
        )
        .bind(input.session.tenant_id)
        .bind(input.session.session_id)
        .bind(input.reason_code)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        transaction.commit().await?;
        Ok(NfsMutationReceipt {
            replay,
            replayed: false,
            outcome: "applied".to_owned(),
            resource_id: Some(input.session.session_id),
            resource_generation: None,
        })
    }

    pub async fn acquire_nfs_byte_lock(
        &self,
        input: &AcquireNfsByteLockInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        validate_nfs_state_replay(input.session, &input.replay, "lock")?;
        let end = input
            .offset_bytes
            .checked_add(input.length_bytes)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        if input.owner_key.is_empty()
            || input.owner_key.len() > 255
            || input.offset_bytes < 0
            || input.length_bytes <= 0
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let receipt = nfs_state_receipt(replay, None)?;
            transaction.commit().await?;
            return Ok(receipt);
        }
        let handle = admit_nfs_handle_tx(
            &mut transaction,
            input.session,
            input.gss_binding_digest,
            input.handle_id,
            Some("MANAGE_LOCK"),
            true,
        )
        .await?;
        // `admit_nfs_handle_tx` holds the common node row FOR UPDATE, so two
        // overlapping requests cannot both pass this predicate.
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM filebelt_mount.byte_locks \
             WHERE tenant_id=$1 AND drive_id=$2 AND node_id=$3 \
               AND released_at IS NULL AND expires_at>clock_timestamp() \
               AND offset_bytes<$4 AND offset_bytes+length_bytes>$5 \
               AND (exclusive OR $6))",
        )
        .bind(input.session.tenant_id)
        .bind(handle.drive_id)
        .bind(handle.node_id)
        .bind(end)
        .bind(input.offset_bytes)
        .bind(input.exclusive)
        .fetch_one(&mut *transaction)
        .await?;
        let (outcome, resource_id) = if conflict {
            ("conflict", None)
        } else {
            sqlx::query(
                "INSERT INTO filebelt_mount.byte_locks \
                 (tenant_id,id,handle_id,drive_id,node_id,owner_key,offset_bytes,\
                  length_bytes,exclusive,gateway_epoch,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,\
                   clock_timestamp()+interval '30 seconds')",
            )
            .bind(input.session.tenant_id)
            .bind(input.lock_id)
            .bind(input.handle_id)
            .bind(handle.drive_id)
            .bind(handle.node_id)
            .bind(input.owner_key)
            .bind(input.offset_bytes)
            .bind(input.length_bytes)
            .bind(input.exclusive)
            .bind(input.session.gateway_epoch)
            .execute(&mut *transaction)
            .await
            .map_err(map_conflict)?;
            ("applied", Some(input.lock_id))
        };
        let result = json!({"resource_id":resource_id});
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &input.replay,
            Some(outcome),
            Some(&result),
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsMutationReceipt {
            replay,
            replayed: false,
            outcome: outcome.to_owned(),
            resource_id,
            resource_generation: None,
        })
    }

    pub async fn release_nfs_byte_lock(
        &self,
        input: &ReleaseNfsByteLockInput<'_>,
    ) -> Result<NfsMutationReceipt, DatabaseError> {
        validate_nfs_state_replay(input.session, &input.replay, "unlock")?;
        let mut transaction = self.pool().begin().await?;
        if let Some(replay) = begin_nfs_atomic_replay_tx(&mut transaction, &input.replay).await? {
            let receipt = nfs_state_receipt(replay, Some(input.lock_id))?;
            transaction.commit().await?;
            return Ok(receipt);
        }
        admit_nfs_handle_tx(
            &mut transaction,
            input.session,
            input.gss_binding_digest,
            input.handle_id,
            Some("MANAGE_LOCK"),
            false,
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE filebelt_mount.byte_locks SET released_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 AND handle_id=$3 AND gateway_epoch=$4 \
               AND released_at IS NULL",
        )
        .bind(input.session.tenant_id)
        .bind(input.lock_id)
        .bind(input.handle_id)
        .bind(input.session.gateway_epoch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let outcome = if changed == 1 { "applied" } else { "conflict" };
        let result = json!({"resource_id":input.lock_id});
        let replay = record_nfs_atomic_replay_tx(
            &mut transaction,
            &input.replay,
            Some(outcome),
            Some(&result),
        )
        .await?;
        transaction.commit().await?;
        Ok(NfsMutationReceipt {
            replay,
            replayed: false,
            outcome: outcome.to_owned(),
            resource_id: Some(input.lock_id),
            resource_generation: None,
        })
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
        let locked = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM public.nodes \
             WHERE tenant_id=$1 AND drive_id=$2 AND id=$3 FOR UPDATE",
        )
        .bind(fence.tenant_id)
        .bind(handle.drive_id)
        .bind(handle.node_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if locked.is_none() {
            return Err(DatabaseError::NotFound);
        }
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

async fn transition_nfs_feature_state_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    expected_generation: i64,
    target: NfsFeatureState,
) -> Result<NfsFeatureStateRecord, DatabaseError> {
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
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::Conflict)?;
    let record = nfs_feature_state_from_row(&row)?;
    insert_audit(
        transaction,
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
        transaction,
        tenant_id,
        "filebelt.v1.mount.nfs.feature.changed",
        "nfs_feature",
        tenant_id,
        record.generation,
    )
    .await?;
    Ok(record)
}

async fn register_nfs_export_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_id: Uuid,
    export_id: i64,
) -> Result<NfsExportRecord, DatabaseError> {
    let row = sqlx::query(
        "INSERT INTO filebelt_mount.nfs_exports (tenant_id,drive_id,export_id) \
         VALUES ($1,$2,$3) RETURNING drive_id,export_id,export_path,desired_state,\
         applied_state,desired_generation,applied_generation",
    )
    .bind(tenant_id)
    .bind(drive_id)
    .bind(export_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_conflict)?;
    let record = nfs_export_from_row(&row)?;
    insert_audit(
        transaction,
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
        transaction,
        tenant_id,
        "filebelt.v1.mount.nfs.export.changed",
        "nfs_export",
        drive_id,
        record.desired_generation,
    )
    .await?;
    Ok(record)
}

async fn stage_nfs_export_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_id: Uuid,
    expected_generation: i64,
    target: NfsExportState,
) -> Result<NfsExportRecord, DatabaseError> {
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
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::Conflict)?;
    let record = nfs_export_from_row(&row)?;
    insert_audit(
        transaction,
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
        transaction,
        tenant_id,
        "filebelt.v1.mount.nfs.export.changed",
        "nfs_export",
        drive_id,
        record.desired_generation,
    )
    .await?;
    Ok(record)
}

async fn register_nfs_posix_group_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    group_id: Uuid,
    posix_name: &str,
    projected_gid: i64,
) -> Result<NfsPosixGroupRecord, DatabaseError> {
    let row = sqlx::query(
        "INSERT INTO filebelt_mount.nfs_posix_groups \
         (tenant_id,group_id,posix_name,projected_gid) VALUES ($1,$2,$3,$4) \
         RETURNING group_id,posix_name,projected_gid",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(posix_name)
    .bind(projected_gid)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_conflict)?;
    let record = nfs_posix_group_from_row(&row);
    insert_audit(
        transaction,
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
        transaction,
        tenant_id,
        "filebelt.v1.mount.nfs.posix_group.changed",
        "nfs_posix_group",
        group_id,
        1,
    )
    .await?;
    Ok(record)
}

fn validate_nfs_principal_mapping_input(
    input: &UpsertNfsPrincipalMappingInput<'_>,
) -> Result<(), DatabaseError> {
    nfs_posix_user_name(input.kerberos_principal)?;
    let mut allowed_drive_ids = input.allowed_drive_ids.to_vec();
    allowed_drive_ids.sort_unstable();
    allowed_drive_ids.dedup();
    if !valid_nfs_projected_id(input.projected_uid)
        || !valid_nfs_projected_id(input.projected_gid)
        || allowed_drive_ids.is_empty()
        || allowed_drive_ids.len() != input.allowed_drive_ids.len()
        || allowed_drive_ids.len() > 256
        || input.expected_generation.is_some_and(|value| value <= 0)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

async fn upsert_nfs_principal_mapping_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &UpsertNfsPrincipalMappingInput<'_>,
) -> Result<NfsPrincipalMapping, DatabaseError> {
    let derived_posix_name = nfs_posix_user_name(input.kerberos_principal)?;
    let mut allowed_drive_ids = input.allowed_drive_ids.to_vec();
    allowed_drive_ids.sort_unstable();
    allowed_drive_ids.dedup();
    validate_nfs_principal_mapping_input(input)?;
    let target_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM principals p JOIN users u ON u.tenant_id=p.tenant_id AND u.principal_id=p.id \
         WHERE p.tenant_id=$1 AND p.id=$2 AND p.kind='user' AND p.disabled_at IS NULL AND u.status='active')",
    )
    .bind(input.tenant_id)
    .bind(input.principal_id)
    .fetch_one(&mut **transaction)
    .await?;
    let drive_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM drives WHERE tenant_id=$1 AND id=ANY($2)")
            .bind(input.tenant_id)
            .bind(&allowed_drive_ids)
            .fetch_one(&mut **transaction)
            .await?;
    if !target_exists || drive_count != allowed_drive_ids.len() as i64 {
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
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::NotFound)?;
    let registered_identity = sqlx::query(
        "SELECT posix_name,posix_group_id,projected_uid,projected_gid \
         FROM filebelt_mount.nfs_posix_users \
         WHERE tenant_id=$1 AND principal_id=$2 FOR UPDATE",
    )
    .bind(input.tenant_id)
    .bind(input.principal_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let posix_name = if let Some(identity) = registered_identity {
        if identity.get::<Uuid, _>("posix_group_id") != posix_group_id
            || identity.get::<i64, _>("projected_uid") != input.projected_uid
            || identity.get::<i64, _>("projected_gid") != input.projected_gid
        {
            return Err(DatabaseError::Conflict);
        }
        identity.get::<String, _>("posix_name")
    } else {
        derived_posix_name
    };

    let existing = sqlx::query(
        "SELECT principal_id,credential_id,projected_uid,posix_name,generation \
         FROM filebelt_mount.nfs_principal_mappings \
         WHERE tenant_id=$1 AND kerberos_principal=$2 FOR UPDATE",
    )
    .bind(input.tenant_id)
    .bind(input.kerberos_principal)
    .fetch_optional(&mut **transaction)
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
        .fetch_one(&mut **transaction)
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
        .bind(&allowed_drive_ids)
        .bind(input.principal_id)
        .execute(&mut **transaction)
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
        .bind(&allowed_drive_ids)
        .execute(&mut **transaction)
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
        .execute(&mut **transaction)
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
    .bind(&allowed_drive_ids)
    .execute(&mut **transaction)
    .await?;
    // The policy trigger advances credential authorization on every policy
    // mutation. Collapse that transaction-local intermediate increment onto
    // the policy's durable generation so sessions and both authority rows
    // share one exact generation fence.
    let aligned = sqlx::query(
        "UPDATE filebelt_mount.credentials AS credential \
         SET authorization_generation=policy.authorization_generation \
         FROM filebelt_mount.policies AS policy \
         WHERE credential.tenant_id=$1 AND credential.id=$2 \
           AND credential.principal_id=$3 AND credential.protocol='nfs' \
           AND policy.tenant_id=credential.tenant_id \
           AND policy.principal_id=credential.principal_id \
           AND policy.protocol=credential.protocol",
    )
    .bind(input.tenant_id)
    .bind(credential_id)
    .bind(input.principal_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if aligned != 1 {
        return Err(DatabaseError::StaleGeneration);
    }
    sqlx::query_scalar::<_, i64>(
        "SELECT filebelt_mount.fence_nfs_mapping_sessions($1,$2,$3,$4,'nfs_mapping_changed')",
    )
    .bind(input.tenant_id)
    .bind(input.principal_id)
    .bind(credential_id)
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await?;
    insert_audit(
        transaction,
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
        transaction,
        input.tenant_id,
        "filebelt.v1.mount.nfs.mapping.changed",
        "nfs_mapping",
        credential_id,
        generation,
    )
    .await?;
    Ok(NfsPrincipalMapping {
        kerberos_principal: input.kerberos_principal.to_owned(),
        principal_id: input.principal_id,
        credential_id,
        projected_uid: input.projected_uid,
        projected_gid: input.projected_gid,
        allowed_drive_ids,
        generation,
    })
}

async fn revoke_nfs_principal_mapping_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    credential_id: Uuid,
    expected_generation: i64,
) -> Result<(), DatabaseError> {
    let row = sqlx::query("UPDATE filebelt_mount.nfs_principal_mappings SET revoked_at=clock_timestamp(),generation=generation+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND credential_id=$2 AND generation=$3 AND revoked_at IS NULL RETURNING principal_id,credential_id,kerberos_principal,generation")
        .bind(tenant_id).bind(credential_id).bind(expected_generation).fetch_optional(&mut **transaction).await?.ok_or(DatabaseError::Conflict)?;
    let principal_id: Uuid = row.get("principal_id");
    let credential_id: Uuid = row.get("credential_id");
    let kerberos_principal: String = row.get("kerberos_principal");
    let generation: i64 = row.get("generation");
    sqlx::query("UPDATE filebelt_mount.credentials SET revoked_at=clock_timestamp(),credential_generation=credential_generation+1,authorization_generation=authorization_generation+1 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL")
        .bind(tenant_id).bind(credential_id).execute(&mut **transaction).await?;
    // A policy is shared by every Kerberos alias of one FileBelt user. Revoking
    // one credential must not disable the remaining active aliases.
    sqlx::query("UPDATE filebelt_mount.policies SET enabled=false,authorization_generation=authorization_generation+1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND protocol='nfs' AND NOT EXISTS (SELECT 1 FROM filebelt_mount.nfs_principal_mappings mapping WHERE mapping.tenant_id=$1 AND mapping.principal_id=$2 AND mapping.revoked_at IS NULL)")
        .bind(tenant_id).bind(principal_id).execute(&mut **transaction).await?;
    sqlx::query(
        "UPDATE filebelt_mount.credentials AS credential \
         SET authorization_generation=policy.authorization_generation \
         FROM filebelt_mount.policies AS policy \
         WHERE credential.tenant_id=$1 AND credential.id=$2 \
           AND policy.tenant_id=credential.tenant_id \
           AND policy.principal_id=credential.principal_id \
           AND policy.protocol=credential.protocol AND policy.protocol='nfs'",
    )
    .bind(tenant_id)
    .bind(credential_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query_scalar::<_, i64>(
        "SELECT filebelt_mount.fence_nfs_mapping_sessions($1,$2,$3,$4,'nfs_mapping_revoked')",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(credential_id)
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await?;
    insert_audit(
        transaction,
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
        transaction,
        tenant_id,
        "filebelt.v1.mount.nfs.mapping.changed",
        "nfs_mapping",
        credential_id,
        generation,
    )
    .await?;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct NfsAdminDriveAccessSnapshot {
    membership_generation: i64,
    drives: Vec<NfsAdminDriveGenerationSnapshot>,
}

#[derive(Debug, Eq, PartialEq)]
struct NfsAdminDriveGenerationSnapshot {
    drive_id: Uuid,
    owner_principal_id: Uuid,
    acl_generation: i64,
}

async fn nfs_admin_drive_access_snapshot_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_ids: &[Uuid],
) -> Result<NfsAdminDriveAccessSnapshot, DatabaseError> {
    if drive_ids.is_empty()
        || drive_ids.len() > 256
        || drive_ids.iter().copied().collect::<HashSet<_>>().len() != drive_ids.len()
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let rows = sqlx::query(
        "SELECT actor.generation AS membership_generation,d.id AS drive_id,\
                d.owner_principal_id,d.acl_generation,(\
           d.owner_principal_id=$2 OR d.owner_principal_id IN (\
             SELECT g.principal_id FROM group_memberships m JOIN groups g \
               ON g.tenant_id=m.tenant_id AND g.id=m.group_id \
             WHERE m.tenant_id=$1 AND m.user_principal_id=$2) OR EXISTS (\
             SELECT 1 FROM acl_entries a WHERE a.tenant_id=d.tenant_id AND a.drive_id=d.id \
               AND a.effect='allow' AND a.action='READ_METADATA' AND (\
                 a.principal_id=$2 OR a.principal_id IN (\
                   SELECT g.principal_id FROM group_memberships m JOIN groups g \
                     ON g.tenant_id=m.tenant_id AND g.id=m.group_id \
                   WHERE m.tenant_id=$1 AND m.user_principal_id=$2)))) AS accessible \
         FROM principals actor JOIN drives d ON d.tenant_id=actor.tenant_id \
         WHERE actor.tenant_id=$1 AND actor.id=$2 AND actor.disabled_at IS NULL \
           AND d.id=ANY($3) ORDER BY d.id",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .bind(drive_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != drive_ids.len() || rows.iter().any(|row| !row.get::<bool, _>("accessible")) {
        return Err(DatabaseError::NotFound);
    }
    let membership_generation = rows
        .first()
        .map(|row| row.get("membership_generation"))
        .ok_or(DatabaseError::NotFound)?;
    Ok(NfsAdminDriveAccessSnapshot {
        membership_generation,
        drives: rows
            .iter()
            .map(|row| NfsAdminDriveGenerationSnapshot {
                drive_id: row.get("drive_id"),
                owner_principal_id: row.get("owner_principal_id"),
                acl_generation: row.get("acl_generation"),
            })
            .collect(),
    })
}

async fn revalidate_nfs_admin_drive_access_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    actor_principal_id: Uuid,
    drive_ids: &[Uuid],
    expected: &NfsAdminDriveAccessSnapshot,
) -> Result<(), DatabaseError> {
    // NFS mapping creation can already hold the primary membership row through
    // its foreign key. Take the generation fences only after the authority
    // mutation so the order is membership -> principal, matching membership
    // deletion. NOWAIT turns any opposite in-flight owner/ACL lock order into a
    // retryable stale result instead of waiting into a cycle. Once these locks
    // succeed, the generation triggers keep later revocations behind commit.
    let membership_generation = sqlx::query_scalar::<_, i64>(
        "SELECT generation FROM principals \
         WHERE tenant_id=$1 AND id=$2 AND disabled_at IS NULL FOR SHARE NOWAIT",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_nfs_admin_authority_lock)?
    .ok_or(DatabaseError::NotFound)?;
    let drive_rows = sqlx::query(
        "SELECT id AS drive_id,owner_principal_id,acl_generation FROM drives \
         WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id FOR SHARE NOWAIT",
    )
    .bind(tenant_id)
    .bind(drive_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_nfs_admin_authority_lock)?;
    if drive_rows.len() != drive_ids.len() {
        return Err(DatabaseError::NotFound);
    }
    let current = NfsAdminDriveAccessSnapshot {
        membership_generation,
        drives: drive_rows
            .iter()
            .map(|row| NfsAdminDriveGenerationSnapshot {
                drive_id: row.get("drive_id"),
                owner_principal_id: row.get("owner_principal_id"),
                acl_generation: row.get("acl_generation"),
            })
            .collect(),
    };
    let accessible_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM drives d WHERE d.tenant_id=$1 AND d.id=ANY($3) AND (\
           d.owner_principal_id=$2 OR d.owner_principal_id IN (\
             SELECT g.principal_id FROM group_memberships m JOIN groups g \
               ON g.tenant_id=m.tenant_id AND g.id=m.group_id \
             WHERE m.tenant_id=$1 AND m.user_principal_id=$2) OR EXISTS (\
             SELECT 1 FROM acl_entries a WHERE a.tenant_id=d.tenant_id AND a.drive_id=d.id \
               AND a.effect='allow' AND a.action='READ_METADATA' AND (\
                 a.principal_id=$2 OR a.principal_id IN (\
                   SELECT g.principal_id FROM group_memberships m JOIN groups g \
                     ON g.tenant_id=m.tenant_id AND g.id=m.group_id \
                   WHERE m.tenant_id=$1 AND m.user_principal_id=$2))))",
    )
    .bind(tenant_id)
    .bind(actor_principal_id)
    .bind(drive_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if accessible_count != drive_ids.len() as i64 {
        return Err(DatabaseError::NotFound);
    }
    if &current != expected {
        return Err(DatabaseError::StaleGeneration);
    }
    Ok(())
}

fn map_nfs_admin_authority_lock(error: sqlx::Error) -> DatabaseError {
    if matches!(&error, sqlx::Error::Database(database) if database.code().as_deref() == Some("55P03"))
    {
        DatabaseError::StaleGeneration
    } else {
        DatabaseError::Sql(error)
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

fn nfs_node_metadata_from_row(row: &sqlx::postgres::PgRow) -> NfsNodeMetadata {
    NfsNodeMetadata {
        node_id: row.get("id"),
        drive_id: row.get("drive_id"),
        parent_id: row.get("parent_id"),
        kind: row.get("kind"),
        namespace_generation: row.get("namespace_generation"),
        acl_generation: row.get("acl_generation"),
        handle_generation: row.get("handle_generation"),
        owner_principal_id: row.get("owner_principal_id"),
        posix_group_id: row.get("posix_group_id"),
        posix_mode: row.get("posix_mode"),
        projected_uid: row.get("projected_uid"),
        projected_gid: row.get("projected_gid"),
        owner_name: row.get("owner_name"),
        group_name: row.get("group_name"),
        accessed_at_unix_seconds: row.get("accessed_at_unix_seconds"),
        modified_at_unix_seconds: row.get("modified_at_unix_seconds"),
        changed_at_unix_seconds: row.get("changed_at_unix_seconds"),
        created_at_unix_seconds: row.get("created_at_unix_seconds"),
        symlink_target: row.get("symlink_target"),
    }
}

fn nfs_write_conflict_from_row(row: &sqlx::postgres::PgRow) -> NfsWriteConflictRecord {
    NfsWriteConflictRecord {
        id: row.get("id"),
        write_session_id: row.get("write_session_id"),
        drive_id: row.get("drive_id"),
        source_node_id: row.get("source_node_id"),
        base_version_id: row.get("base_version_id"),
        expected_head_version_id: row.get("expected_head_version_id"),
        observed_head_version_id: row.get("observed_head_version_id"),
        logical_size_bytes: row.get("logical_size_bytes"),
        state: row.get("state"),
        conflict_copy_node_id: row.get("conflict_copy_node_id"),
        conflict_copy_version_id: row.get("conflict_copy_version_id"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
    }
}

#[derive(Clone, Debug)]
struct NfsAtomicReplayState {
    receipt: NfsReplayReceipt,
    mutation_result: Option<Value>,
}

async fn prepare_nfs_replay_sequence_tx(
    transaction: &mut Transaction<'_, Postgres>,
    context: &NfsReplayContext<'_>,
) -> Result<(), DatabaseError> {
    if !valid_nfs_replay_context(context) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT filebelt_mount.prepare_nfs_replay_sequence(\
           $1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(context.tenant_id)
    .bind(context.mount_session_id)
    .bind(context.client_id)
    .bind(context.nfs_session_id)
    .bind(context.slot_id)
    .bind(context.sequence_id)
    .bind(context.operation_index)
    .bind(context.gateway_epoch)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    Ok(())
}

/// Serializes one replay identity before its mutation runs. The transaction
/// remains open while the caller changes authority state and records the exact
/// result, so a duplicate can never observe an acknowledgement without the
/// mutation (or vice versa).
async fn begin_nfs_atomic_replay_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &RecordNfsReplayReceiptInput<'_>,
) -> Result<Option<NfsAtomicReplayState>, DatabaseError> {
    if !valid_nfs_replay_context(&input.context)
        || input.response_bytes.is_empty()
        || input.response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    prepare_nfs_replay_sequence_tx(transaction, &input.context).await?;
    let row = sqlx::query(
        "SELECT response_bytes,response_digest,mutation_outcome,mutation_result,\
                gateway_epoch,expires_at_unix_seconds \
         FROM filebelt_mount.lock_nfs_replay_receipt(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
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
    .bind(input.context.gateway_epoch)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(NfsAtomicReplayState {
        receipt: NfsReplayReceipt {
            response_bytes: row.get("response_bytes"),
            response_digest: row
                .get::<Vec<u8>, _>("response_digest")
                .try_into()
                .map_err(|_| DatabaseError::InvalidPersistedValue)?,
            gateway_epoch: input.context.gateway_epoch,
            expires_at_unix_seconds: row.get("expires_at_unix_seconds"),
            mutation_outcome: row.get("mutation_outcome"),
        },
        mutation_result: row.get("mutation_result"),
    }))
}

async fn record_nfs_atomic_replay_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &RecordNfsReplayReceiptInput<'_>,
    mutation_outcome: Option<&str>,
    mutation_result: Option<&Value>,
) -> Result<NfsReplayReceipt, DatabaseError> {
    let row = sqlx::query(
        "INSERT INTO filebelt_mount.nfs_replay_receipts \
         (tenant_id,mount_session_id,client_id,nfs_session_id,slot_id,sequence_id,\
          operation_index,operation,request_digest,response_bytes,response_digest,\
          gateway_epoch,expires_at,mutation_outcome,mutation_result) \
         SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,\
                session.absolute_expires_at,$13,$14 \
         FROM filebelt_mount.sessions AS session \
         WHERE session.tenant_id=$1 AND session.id=$2 \
           AND session.absolute_expires_at>statement_timestamp() \
         RETURNING response_bytes,response_digest,gateway_epoch,mutation_outcome,\
           floor(extract(epoch FROM expires_at))::bigint AS expires_at_unix_seconds",
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
    .bind(mutation_outcome)
    .bind(mutation_result)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    Ok(NfsReplayReceipt {
        response_bytes: row.get("response_bytes"),
        response_digest: row
            .get::<Vec<u8>, _>("response_digest")
            .try_into()
            .map_err(|_| DatabaseError::InvalidPersistedValue)?,
        gateway_epoch: row.get("gateway_epoch"),
        expires_at_unix_seconds: row.get("expires_at_unix_seconds"),
        mutation_outcome: row.get("mutation_outcome"),
    })
}

async fn nfs_write_plan_result_from_pending_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &ExtendNfsWriteChunksInput<'_>,
) -> Result<NfsWriteChunkPlanResult, DatabaseError> {
    let row = sqlx::query(
        "SELECT operation_ordinal,content_blake3,resulting_logical_size,reserved_bytes \
         FROM filebelt_mount.nfs_write_operations \
         WHERE tenant_id=$1 AND write_session_id=$2 AND operation_id=$3 \
           AND operation=$4 AND range_start=$5 AND range_end=$6",
    )
    .bind(input.fence.tenant_id)
    .bind(input.fence.write_session_id)
    .bind(input.operation_id)
    .bind(input.operation.as_str())
    .bind(input.range_start)
    .bind(input.range_end)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    let operation_ordinal = row.get::<i64, _>("operation_ordinal");
    let content_blake3 = optional_digest_32(row.get("content_blake3"))?;
    let resulting_logical_size = row.get::<i64, _>("resulting_logical_size");
    let reserved_bytes = row.get::<i64, _>("reserved_bytes");
    let chunks = mount_write_chunk_plan_tx(
        transaction,
        input.fence.tenant_id,
        input.fence.write_session_id,
    )
    .await?;
    if operation_ordinal <= 0
        || content_blake3.as_ref() != input.content_blake3.copied().as_ref()
        || reserved_bytes != input.required_reservation_bytes
        || reserved_bytes <= input.range_end
        || resulting_logical_size < 0
        || chunks != input.chunks
    {
        return Err(DatabaseError::Conflict);
    }
    Ok(NfsWriteChunkPlanResult {
        write_session_id: input.fence.write_session_id,
        reserved_bytes,
        operation_id: input.operation_id,
        operation_ordinal,
        operation: input.operation,
        content_blake3,
        range_start: input.range_start,
        range_end: input.range_end,
        resulting_logical_size,
        chunks,
        resumed: true,
    })
}

fn validate_nfs_write_extent_input(
    session: &MountSessionFence,
    fence: &MountWriteCapabilityFence,
    replay: &RecordNfsReplayReceiptInput<'_>,
    operation: &str,
) -> Result<(), DatabaseError> {
    validate_nfs_state_replay(session, replay, operation)?;
    if fence.tenant_id != session.tenant_id
        || fence.principal_id != session.user_principal_id
        || fence.mount_session_id != session.session_id
        || fence.credential_id != session.credential_id
        || fence.credential_generation != session.credential_generation
        || fence.authorization_generation != session.authorization_generation
        || fence.membership_generation != session.membership_generation
        || fence.gateway_epoch != session.gateway_epoch
        || fence.handle_id.is_nil()
        || fence.write_session_id.is_nil()
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validate_mount_io_operation_input(
    input: &BeginMountIoOperationInput<'_>,
) -> Result<(), DatabaseError> {
    let range_operation = input.operation.range_operation();
    let fence_operation = match input.operation {
        MountIoOperation::WriteData
        | MountIoOperation::HoleDeallocate
        | MountIoOperation::Allocate
        | MountIoOperation::SeekData
        | MountIoOperation::SeekHole => MountWriteStorageOperation::Write,
        MountIoOperation::Flush => MountWriteStorageOperation::Flush,
        MountIoOperation::Finalize => MountWriteStorageOperation::Finalize,
        MountIoOperation::Abort => MountWriteStorageOperation::Abort,
        MountIoOperation::DeleteStaging => MountWriteStorageOperation::DeleteStaging,
    };
    if input.fence.write_session_id.is_nil()
        || input.capability_id.is_nil()
        || input.expires_at_unix_seconds <= 0
        || (input.operation == MountIoOperation::WriteData) != input.content_blake3.is_some()
        || range_operation.is_some() != input.range_start.is_some()
        || range_operation.is_some() != input.range_end.is_some()
        || input.range_start.is_some_and(|value| value < 0)
        || matches!((input.range_start, input.range_end), (Some(start), Some(end)) if end<start)
        || matches!(
            (range_operation, input.range_start, input.range_end),
            (Some(operation), Some(start), Some(end)) if operation.seeks() && start != end
        )
        || !valid_mount_write_fence(input.fence, fence_operation)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validate_mount_io_receipt_identity(
    row: &sqlx::postgres::PgRow,
    input: &BeginMountIoOperationInput<'_>,
) -> Result<(), DatabaseError> {
    let content_blake3 = optional_digest_32(row.get("content_blake3"))?;
    if row.get::<Uuid, _>("capability_id") != input.capability_id
        || row.get::<Uuid, _>("write_session_id") != input.fence.write_session_id
        || row.get::<Option<Uuid>, _>("operation_id").is_some()
            != input.operation.range_operation().is_some()
        || row.get::<String, _>("operation") != input.operation.as_str()
        || row.get::<Vec<u8>, _>("claims_digest").as_slice() != input.claims_digest
        || content_blake3.as_ref() != input.content_blake3.copied().as_ref()
    {
        return Err(DatabaseError::Conflict);
    }
    Ok(())
}

fn mount_io_completion_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<MountIoCompletion, DatabaseError> {
    serde_json::from_value(
        row.get::<Option<Value>, _>("outcome")
            .ok_or(DatabaseError::InvalidPersistedValue)?,
    )
    .map_err(|_| DatabaseError::InvalidPersistedValue)
}

fn pending_mount_io_operation_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<PendingMountIoOperation, DatabaseError> {
    let worker_state = match row.get::<String, _>("worker_state").as_str() {
        "admission" => PendingMountIoWorkerState::Admission,
        "pending" => PendingMountIoWorkerState::Pending,
        "completed" => PendingMountIoWorkerState::Completed,
        _ => return Err(DatabaseError::InvalidPersistedValue),
    };
    let worker_outcome = row
        .get::<Option<Value>, _>("worker_outcome")
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    if (worker_state == PendingMountIoWorkerState::Completed) != worker_outcome.is_some() {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(PendingMountIoOperation {
        protocol_operation_id: row.get("protocol_operation_id"),
        write_session_id: row.get("write_session_id"),
        capability_id: row.get("capability_id"),
        nonce_digest: array_32(row.get("nonce_digest"))?,
        claims_digest: array_32(row.get("claims_digest"))?,
        operation: MountIoOperation::from_persisted(&row.get::<String, _>("io_operation"))?,
        operation_id: row.get("operation_id"),
        content_blake3: optional_digest_32(row.get("content_blake3"))?,
        range_start: row.get("range_start"),
        range_end: row.get("range_end"),
        fencing_token: row.get("fencing_token"),
        capability_expires_at_unix_seconds: row.get("capability_expires_at_unix_seconds"),
        worker_state,
        worker_outcome,
    })
}

fn validate_mount_io_completion(
    input: &BeginMountIoOperationInput<'_>,
    outcome: &MountIoCompletion,
) -> Result<(), DatabaseError> {
    let valid = match (input.operation, outcome) {
        (
            MountIoOperation::WriteData
            | MountIoOperation::HoleDeallocate
            | MountIoOperation::Allocate,
            MountIoCompletion::RangeMutation {
                logical_size_bytes,
                reservation_delta_bytes,
            },
        ) => *logical_size_bytes >= 0 && *reservation_delta_bytes >= 0,
        (
            MountIoOperation::SeekData | MountIoOperation::SeekHole,
            MountIoCompletion::Seek { offset },
        ) => offset.is_none_or(|value| input.range_start.is_some_and(|start| value >= start)),
        (
            MountIoOperation::Flush,
            MountIoCompletion::Flush {
                logical_size_bytes,
                chunks,
                ..
            },
        )
        | (
            MountIoOperation::Finalize,
            MountIoCompletion::Finalize {
                logical_size_bytes,
                chunks,
                ..
            },
        ) => validate_mount_chunk_evidence(*logical_size_bytes, chunks).is_ok(),
        (MountIoOperation::Abort, MountIoCompletion::Abort)
        | (MountIoOperation::DeleteStaging, MountIoCompletion::DeleteStaging) => true,
        _ => false,
    };
    if !valid {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

async fn preauthorize_mount_io_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BeginMountIoOperationInput<'_>,
    context: &NfsReplayContext<'_>,
    protocol_operation_id: Uuid,
    stable_operation_id: Option<Uuid>,
) -> Result<bool, DatabaseError> {
    let created: bool = sqlx::query_scalar(
        "SELECT filebelt_mount.preauthorize_nfs_io(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)",
    )
    .bind(input.fence.tenant_id)
    .bind(input.fence.principal_id)
    .bind(input.fence.mount_session_id)
    .bind(input.fence.credential_id)
    .bind(input.fence.handle_id)
    .bind(input.fence.drive_id)
    .bind(input.fence.node_id)
    .bind(input.fence.version_id)
    .bind(input.fence.write_session_id)
    .bind(input.fence.credential_generation)
    .bind(input.fence.authorization_generation)
    .bind(input.fence.membership_generation)
    .bind(input.fence.drive_acl_generation)
    .bind(input.fence.namespace_generation)
    .bind(input.fence.resource_acl_generation)
    .bind(input.fence.gateway_epoch)
    .bind(input.fence.fencing_token)
    .bind(context.client_id)
    .bind(context.nfs_session_id)
    .bind(context.slot_id)
    .bind(context.sequence_id)
    .bind(context.operation_index)
    .bind(context.operation)
    .bind(context.request_digest.as_slice())
    .bind(protocol_operation_id)
    .bind(input.capability_id)
    .bind(input.nonce_digest.as_slice())
    .bind(stable_operation_id)
    .bind(input.operation.as_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .bind(input.range_start)
    .bind(input.range_end)
    .bind(input.expires_at_unix_seconds)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    Ok(created)
}

async fn lookup_mount_io_preauthorization_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BeginMountIoOperationInput<'_>,
    context: &NfsReplayContext<'_>,
    protocol_operation_id: Uuid,
    stable_operation_id: Option<Uuid>,
) -> Result<bool, DatabaseError> {
    sqlx::query_scalar(
        "SELECT filebelt_mount.lookup_nfs_io_preauthorization(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22)",
    )
    .bind(input.fence.tenant_id)
    .bind(input.fence.mount_session_id)
    .bind(context.client_id)
    .bind(context.nfs_session_id)
    .bind(context.slot_id)
    .bind(context.sequence_id)
    .bind(context.operation_index)
    .bind(context.operation)
    .bind(context.request_digest.as_slice())
    .bind(input.fence.gateway_epoch)
    .bind(protocol_operation_id)
    .bind(input.fence.write_session_id)
    .bind(input.capability_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.claims_digest.as_slice())
    .bind(input.operation.as_str())
    .bind(stable_operation_id)
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .bind(input.range_start)
    .bind(input.range_end)
    .bind(input.fence.fencing_token)
    .bind(input.expires_at_unix_seconds)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)
}

async fn begin_mount_io_receipt_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BeginMountIoOperationInput<'_>,
) -> Result<i64, DatabaseError> {
    let operation_ordinal: i64 = sqlx::query_scalar(
        "SELECT filebelt_mount.begin_nfs_io_receipt(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23,$24)",
    )
    .bind(input.fence.tenant_id)
    .bind(input.fence.principal_id)
    .bind(input.fence.mount_session_id)
    .bind(input.fence.credential_id)
    .bind(input.fence.handle_id)
    .bind(input.fence.drive_id)
    .bind(input.fence.node_id)
    .bind(input.fence.version_id)
    .bind(input.fence.write_session_id)
    .bind(input.fence.credential_generation)
    .bind(input.fence.authorization_generation)
    .bind(input.fence.membership_generation)
    .bind(input.fence.drive_acl_generation)
    .bind(input.fence.namespace_generation)
    .bind(input.fence.resource_acl_generation)
    .bind(input.fence.gateway_epoch)
    .bind(input.fence.fencing_token)
    .bind(input.capability_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.operation.as_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .bind(input.range_start)
    .bind(input.range_end)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    if operation_ordinal <= 0 {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(operation_ordinal)
}

async fn lock_mount_io_receipt_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BeginMountIoOperationInput<'_>,
) -> Result<Option<MountIoCompletion>, DatabaseError> {
    let row = sqlx::query(
        "SELECT capability_id,write_session_id,operation_id,operation,operation_ordinal,claims_digest,\
                content_blake3,state,outcome,receipt_live \
         FROM filebelt_mount.read_nfs_io_receipt($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(input.fence.tenant_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.capability_id)
    .bind(input.fence.write_session_id)
    .bind(input.operation.as_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    validate_mount_io_receipt_identity(&row, input)?;
    if row.get::<String, _>("state") == "completed" {
        return mount_io_completion_from_row(&row).map(Some);
    }
    Ok(None)
}

async fn complete_mount_io_receipt_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BeginMountIoOperationInput<'_>,
    outcome: &MountIoCompletion,
) -> Result<(), DatabaseError> {
    validate_mount_io_completion(input, outcome)?;
    let serialized =
        serde_json::to_value(outcome).map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let persisted: Value = sqlx::query_scalar(
        "SELECT filebelt_mount.complete_nfs_io_receipt(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21,$22,$23)",
    )
    .bind(input.fence.tenant_id)
    .bind(input.fence.principal_id)
    .bind(input.fence.mount_session_id)
    .bind(input.fence.credential_id)
    .bind(input.fence.handle_id)
    .bind(input.fence.drive_id)
    .bind(input.fence.node_id)
    .bind(input.fence.version_id)
    .bind(input.fence.write_session_id)
    .bind(input.fence.credential_generation)
    .bind(input.fence.authorization_generation)
    .bind(input.fence.membership_generation)
    .bind(input.fence.drive_acl_generation)
    .bind(input.fence.namespace_generation)
    .bind(input.fence.resource_acl_generation)
    .bind(input.fence.gateway_epoch)
    .bind(input.fence.fencing_token)
    .bind(input.capability_id)
    .bind(input.nonce_digest.as_slice())
    .bind(input.operation.as_str())
    .bind(input.claims_digest.as_slice())
    .bind(input.content_blake3.map(|digest| digest.as_slice()))
    .bind(serialized)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    let persisted = serde_json::from_value::<MountIoCompletion>(persisted)
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    if &persisted != outcome {
        return Err(DatabaseError::Conflict);
    }
    Ok(())
}

async fn completed_mount_io_outcome_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    write_session_id: Uuid,
    operation_id: Uuid,
) -> Result<MountIoCompletion, DatabaseError> {
    let outcome: Value = sqlx::query_scalar(
        "SELECT receipt.outcome FROM filebelt_mount.nfs_io_receipts AS receipt \
         JOIN filebelt_mount.nfs_write_operations AS operation \
           ON operation.tenant_id=receipt.tenant_id \
          AND operation.write_session_id=receipt.write_session_id \
          AND operation.operation_id=receipt.operation_id \
         WHERE receipt.tenant_id=$1 AND receipt.write_session_id=$2 \
           AND receipt.operation_id=$3 AND receipt.state='completed' \
           AND operation.state='io_completed' \
         ORDER BY receipt.operation_ordinal DESC LIMIT 1 FOR SHARE OF receipt,operation",
    )
    .bind(tenant_id)
    .bind(write_session_id)
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    serde_json::from_value(outcome).map_err(|_| DatabaseError::InvalidPersistedValue)
}

async fn mark_mount_write_operation_applied_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
    operation_id: Uuid,
    operation: MountWriteRangeOperation,
    content_blake3: Option<[u8; 32]>,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "SELECT filebelt_mount.apply_completed_nfs_write_operation(\
           $1,$2,$3,$4,$5,$6)",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .bind(fence.fencing_token)
    .bind(operation_id)
    .bind(operation.as_str())
    .bind(content_blake3.map(Vec::from))
    .execute(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    Ok(())
}

async fn admit_pending_mount_io_tx(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BeginMountIoOperationInput<'_>,
) -> Result<MountWriteStorageRecord, DatabaseError> {
    if let Some(range_operation) = input.operation.range_operation() {
        let admission = admit_mount_write_range_tx(
            transaction,
            input.fence,
            input.capability_id,
            range_operation,
            input
                .range_start
                .ok_or(DatabaseError::InvalidPersistedValue)?,
            input
                .range_end
                .ok_or(DatabaseError::InvalidPersistedValue)?,
        )
        .await?;
        if admission.content_blake3.as_ref() != input.content_blake3.copied().as_ref() {
            return Err(DatabaseError::Conflict);
        }
        return Ok(admission.storage);
    }
    let operation = match input.operation {
        MountIoOperation::Flush => MountWriteStorageOperation::Flush,
        MountIoOperation::Finalize => MountWriteStorageOperation::Finalize,
        MountIoOperation::Abort => MountWriteStorageOperation::Abort,
        MountIoOperation::DeleteStaging => MountWriteStorageOperation::DeleteStaging,
        MountIoOperation::WriteData
        | MountIoOperation::HoleDeallocate
        | MountIoOperation::Allocate
        | MountIoOperation::SeekData
        | MountIoOperation::SeekHole => return Err(DatabaseError::InvalidPersistedValue),
    };
    if operation == MountWriteStorageOperation::DeleteStaging {
        admit_mount_staging_cleanup_tx(transaction, input.fence).await
    } else {
        admit_mount_write_capability_tx(transaction, input.fence, operation).await
    }
}

async fn fence_pending_mount_io_cleanup_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
    nonce_digest: &[u8; 32],
    claims_digest: &[u8; 32],
    operation: MountIoOperation,
    content_blake3: Option<&[u8; 32]>,
) -> Result<MountIoCleanupRecord, DatabaseError> {
    let operation_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT filebelt_mount.fence_pending_nfs_io_cleanup(\
           $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .bind(fence.fencing_token)
    .bind(nonce_digest.as_slice())
    .bind(claims_digest.as_slice())
    .bind(operation.as_str())
    .bind(content_blake3.map(|digest| digest.as_slice()))
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?;
    let storage = mount_write_storage_record_tx(transaction, fence).await?;
    Ok(MountIoCleanupRecord {
        tenant_id: fence.tenant_id,
        write_session_id: fence.write_session_id,
        fencing_token: fence.fencing_token,
        storage,
        nonce_digest: *nonce_digest,
        claims_digest: *claims_digest,
        operation,
        operation_id,
    })
}

fn nfs_write_extent_result_from_replay(
    fence: &MountWriteCapabilityFence,
    replay: NfsAtomicReplayState,
) -> Result<NfsWriteExtentResult, DatabaseError> {
    let mutation = replay
        .mutation_result
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    let write_session_id = serde_json::from_value::<Uuid>(
        mutation
            .get("write_session_id")
            .cloned()
            .ok_or(DatabaseError::InvalidPersistedValue)?,
    )
    .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let logical_size_bytes = mutation
        .get("logical_size_bytes")
        .and_then(Value::as_i64)
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    let extents = serde_json::from_value::<Vec<NfsWriteExtent>>(
        mutation
            .get("extents")
            .cloned()
            .ok_or(DatabaseError::InvalidPersistedValue)?,
    )
    .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let seek_offset = mutation
        .get("seek_offset")
        .ok_or(DatabaseError::InvalidPersistedValue)?
        .as_i64();
    if write_session_id != fence.write_session_id {
        return Err(DatabaseError::Conflict);
    }
    validate_normalized_nfs_extents(&extents, logical_size_bytes)?;
    Ok(NfsWriteExtentResult {
        write_session_id,
        logical_size_bytes,
        extents,
        seek_offset,
        replay: replay.receipt,
        replayed: true,
    })
}

async fn nfs_write_extents_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    write_session_id: Uuid,
    lock: bool,
) -> Result<Vec<NfsWriteExtent>, DatabaseError> {
    let rows = if lock {
        sqlx::query(
            "SELECT offset_bytes,length_bytes,is_hole,digest \
             FROM filebelt_mount.nfs_write_extents \
             WHERE tenant_id=$1 AND write_session_id=$2 \
             ORDER BY offset_bytes FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(write_session_id)
        .fetch_all(&mut **transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT offset_bytes,length_bytes,is_hole,digest \
             FROM filebelt_mount.nfs_write_extents \
             WHERE tenant_id=$1 AND write_session_id=$2 ORDER BY offset_bytes",
        )
        .bind(tenant_id)
        .bind(write_session_id)
        .fetch_all(&mut **transaction)
        .await?
    };
    rows.iter()
        .map(|row| {
            Ok(NfsWriteExtent {
                offset_bytes: row.get("offset_bytes"),
                length_bytes: row.get("length_bytes"),
                is_hole: row.get("is_hole"),
                digest: optional_digest_32(row.get("digest"))?,
            })
        })
        .collect()
}

fn apply_nfs_extent_range(
    current: &[NfsWriteExtent],
    _planned_logical_size: i64,
    resulting_logical_size: i64,
    range_start: i64,
    range_end: i64,
    operation: MountWriteRangeOperation,
    data_digest: Option<[u8; 32]>,
) -> Result<Vec<NfsWriteExtent>, DatabaseError> {
    let current_size = normalized_nfs_extent_size(current)?;
    let range_end_exclusive = range_end
        .checked_add(1)
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    if range_start < 0
        || range_end < range_start
        || resulting_logical_size < current_size
        || range_end_exclusive > resulting_logical_size
    {
        return Err(DatabaseError::StaleGeneration);
    }
    let mut source = current.to_vec();
    if current_size < resulting_logical_size {
        source.push(NfsWriteExtent {
            offset_bytes: current_size,
            length_bytes: resulting_logical_size - current_size,
            is_hole: true,
            digest: None,
        });
    }
    let replacement = NfsWriteExtent {
        offset_bytes: range_start,
        length_bytes: range_end_exclusive - range_start,
        is_hole: operation == MountWriteRangeOperation::HoleDeallocate,
        digest: data_digest,
    };
    let mut result = Vec::with_capacity(source.len().saturating_add(2));
    let mut inserted = false;
    for extent in source {
        let extent_end = extent
            .offset_bytes
            .checked_add(extent.length_bytes)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        if extent_end <= range_start || extent.offset_bytes >= range_end_exclusive {
            if !inserted && extent.offset_bytes >= range_end_exclusive {
                push_normalized_nfs_extent(&mut result, replacement.clone())?;
                inserted = true;
            }
            push_normalized_nfs_extent(&mut result, extent)?;
            continue;
        }
        if extent.offset_bytes < range_start {
            push_normalized_nfs_extent(
                &mut result,
                NfsWriteExtent {
                    offset_bytes: extent.offset_bytes,
                    length_bytes: range_start - extent.offset_bytes,
                    is_hole: extent.is_hole,
                    digest: None,
                },
            )?;
        }
        if !inserted {
            push_normalized_nfs_extent(&mut result, replacement.clone())?;
            inserted = true;
        }
        if extent_end > range_end_exclusive {
            push_normalized_nfs_extent(
                &mut result,
                NfsWriteExtent {
                    offset_bytes: range_end_exclusive,
                    length_bytes: extent_end - range_end_exclusive,
                    is_hole: extent.is_hole,
                    digest: None,
                },
            )?;
        }
    }
    if !inserted {
        push_normalized_nfs_extent(&mut result, replacement)?;
    }
    validate_normalized_nfs_extents(&result, resulting_logical_size)?;
    Ok(result)
}

fn push_normalized_nfs_extent(
    extents: &mut Vec<NfsWriteExtent>,
    extent: NfsWriteExtent,
) -> Result<(), DatabaseError> {
    if extent.length_bytes <= 0 || (extent.is_hole && extent.digest.is_some()) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    if let Some(previous) = extents.last_mut() {
        let previous_end = previous
            .offset_bytes
            .checked_add(previous.length_bytes)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
        if previous_end != extent.offset_bytes {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        if previous.is_hole == extent.is_hole
            && previous.digest.is_none()
            && extent.digest.is_none()
        {
            previous.length_bytes = previous
                .length_bytes
                .checked_add(extent.length_bytes)
                .ok_or(DatabaseError::InvalidPersistedValue)?;
            return Ok(());
        }
    } else if extent.offset_bytes != 0 {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    extents.push(extent);
    Ok(())
}

fn normalized_nfs_extent_size(extents: &[NfsWriteExtent]) -> Result<i64, DatabaseError> {
    let mut end = 0_i64;
    for extent in extents {
        if extent.offset_bytes != end
            || extent.length_bytes <= 0
            || (extent.is_hole && extent.digest.is_some())
        {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        end = end
            .checked_add(extent.length_bytes)
            .ok_or(DatabaseError::InvalidPersistedValue)?;
    }
    Ok(end)
}

fn validate_normalized_nfs_extents(
    extents: &[NfsWriteExtent],
    logical_size_bytes: i64,
) -> Result<(), DatabaseError> {
    if logical_size_bytes < 0
        || extents.len() > 1_048_576
        || normalized_nfs_extent_size(extents)? != logical_size_bytes
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn seek_nfs_extent(
    extents: &[NfsWriteExtent],
    logical_size_bytes: i64,
    requested_offset: i64,
    seek_hole: bool,
) -> Option<i64> {
    if requested_offset > logical_size_bytes {
        return None;
    }
    if seek_hole && requested_offset == logical_size_bytes {
        return Some(logical_size_bytes);
    }
    for extent in extents {
        let extent_end = extent.offset_bytes.saturating_add(extent.length_bytes);
        if extent_end <= requested_offset {
            continue;
        }
        if extent.is_hole == seek_hole {
            return Some(extent.offset_bytes.max(requested_offset));
        }
    }
    if seek_hole {
        Some(logical_size_bytes)
    } else {
        None
    }
}

async fn admit_nfs_handle_tx(
    transaction: &mut Transaction<'_, Postgres>,
    session: &MountSessionFence,
    gss_binding_digest: &[u8; 32],
    handle_id: Uuid,
    required_action: Option<&str>,
    require_live_node: bool,
) -> Result<MountHandleRecord, DatabaseError> {
    if session.protocol != "nfs"
        || session.allowed_export_ids.is_empty()
        || session.nfs_mapping_generation.is_none()
        || session.nfs_feature_generation.is_none()
        || session.nfs_manifest_generation.is_none()
        || session.nfs_restore_generation.is_none()
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let row = sqlx::query(
        "SELECT handle.id,handle.session_id,handle.drive_id,handle.node_id,handle.version_id,\
                handle.access_actions,handle.credential_generation,\
                handle.authorization_generation,handle.membership_generation,\
                handle.drive_acl_generation,handle.namespace_generation,\
                handle.resource_acl_generation,handle.gateway_epoch \
         FROM filebelt_mount.handles AS handle \
         JOIN filebelt_mount.sessions AS mount_session \
           ON mount_session.tenant_id=handle.tenant_id \
          AND mount_session.id=handle.session_id \
         JOIN filebelt_mount.credentials AS credential \
           ON credential.tenant_id=mount_session.tenant_id \
          AND credential.id=mount_session.credential_id \
         JOIN filebelt_mount.policies AS policy \
           ON policy.tenant_id=mount_session.tenant_id \
          AND policy.principal_id=mount_session.user_principal_id \
          AND policy.protocol='nfs' \
         JOIN public.principals AS principal \
           ON principal.tenant_id=mount_session.tenant_id \
          AND principal.id=mount_session.user_principal_id \
         JOIN public.users AS user_account \
           ON user_account.tenant_id=principal.tenant_id \
          AND user_account.principal_id=principal.id \
         JOIN filebelt_mount.nfs_principal_mappings AS mapping \
           ON mapping.tenant_id=mount_session.tenant_id \
          AND mapping.credential_id=mount_session.credential_id \
          AND mapping.principal_id=mount_session.user_principal_id \
         JOIN public.group_memberships AS membership \
           ON membership.tenant_id=mapping.tenant_id \
          AND membership.group_id=mapping.posix_group_id \
          AND membership.user_principal_id=mapping.principal_id \
         JOIN filebelt_mount.gateway_epochs AS gateway \
           ON gateway.tenant_id=mount_session.tenant_id AND gateway.protocol='nfs' \
          AND gateway.gateway_id=mount_session.gateway_id \
          AND gateway.epoch=mount_session.gateway_epoch \
         JOIN filebelt_mount.nfs_feature_state AS feature \
           ON feature.tenant_id=mount_session.tenant_id \
         JOIN public.drives AS drive \
           ON drive.tenant_id=handle.tenant_id AND drive.id=handle.drive_id \
         JOIN public.nodes AS node \
           ON node.tenant_id=handle.tenant_id AND node.drive_id=handle.drive_id \
          AND node.id=handle.node_id \
         JOIN filebelt_mount.nfs_exports AS export \
           ON export.tenant_id=handle.tenant_id AND export.drive_id=handle.drive_id \
         WHERE handle.tenant_id=$1 AND handle.id=$2 AND handle.session_id=$3 \
           AND handle.closed_at IS NULL AND handle.expires_at>clock_timestamp() \
           AND ($16::text IS NULL OR $16=ANY(handle.access_actions)) \
           AND mount_session.credential_id=$4 \
           AND mount_session.user_principal_id=$5 \
           AND mount_session.credential_generation=$6 \
           AND mount_session.authorization_generation=$7 \
           AND mount_session.membership_generation=$8 \
           AND mount_session.gateway_epoch=$9 \
           AND mount_session.nfs_gss_binding_digest=$10 \
           AND mount_session.nfs_mapping_generation=$11 \
           AND mount_session.nfs_feature_generation=$12 \
           AND mount_session.nfs_manifest_generation=$13 \
           AND mount_session.nfs_restore_generation=$14 \
           AND mount_session.nfs_allowed_export_ids=$15 \
           AND mount_session.idle_expires_at>clock_timestamp() \
           AND mount_session.absolute_expires_at>clock_timestamp() \
           AND credential.revoked_at IS NULL \
           AND credential.expires_at>clock_timestamp() \
           AND credential.credential_generation=$6 \
           AND credential.authorization_generation=$7 \
           AND handle.drive_id=ANY(credential.allowed_drive_ids) \
           AND policy.enabled AND handle.drive_id=ANY(policy.allowed_drive_ids) \
           AND policy.authorization_generation=$7 \
           AND principal.generation=$8 AND principal.disabled_at IS NULL \
           AND user_account.status='active' \
           AND mapping.generation=$11 AND mapping.revoked_at IS NULL \
           AND handle.credential_generation=$6 \
           AND handle.authorization_generation=$7 \
           AND handle.membership_generation=$8 AND handle.gateway_epoch=$9 \
           AND drive.acl_generation=handle.drive_acl_generation \
           AND (NOT $17 OR (node.trash_root_id IS NULL \
             AND node.namespace_generation=handle.namespace_generation \
             AND node.acl_generation=handle.resource_acl_generation)) \
           AND feature.generation=$12 AND feature.restore_generation=$14 \
           AND feature.manifest_generation=$13 \
           AND feature.applied_manifest_generation=feature.manifest_generation \
           AND feature.applied_manifest_digest IS NOT NULL \
           AND feature.applied_gateway_id=mount_session.gateway_id \
           AND feature.applied_gateway_epoch=mount_session.gateway_epoch \
           AND export.export_id=ANY(mount_session.nfs_allowed_export_ids) \
           AND export.desired_state='active' AND export.applied_state='active' \
           AND export.desired_generation=export.applied_generation \
           AND ((mount_session.state='active' AND feature.state='active' \
                 AND NOT gateway.draining \
                 AND gateway.lease_expires_at>clock_timestamp()) \
             OR (mount_session.state='draining' \
                 AND feature.state IN ('active','draining') AND gateway.draining \
                 AND gateway.drain_deadline>clock_timestamp())) \
         FOR UPDATE OF handle,mount_session,credential,policy,principal,user_account,\
           mapping,membership,gateway,feature,drive,node,export",
    )
    .bind(session.tenant_id)
    .bind(handle_id)
    .bind(session.session_id)
    .bind(session.credential_id)
    .bind(session.user_principal_id)
    .bind(session.credential_generation)
    .bind(session.authorization_generation)
    .bind(session.membership_generation)
    .bind(session.gateway_epoch)
    .bind(gss_binding_digest.as_slice())
    .bind(session.nfs_mapping_generation)
    .bind(session.nfs_feature_generation)
    .bind(session.nfs_manifest_generation)
    .bind(session.nfs_restore_generation)
    .bind(&session.allowed_export_ids)
    .bind(required_action)
    .bind(require_live_node)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    Ok(mount_handle_from_row(&row))
}

fn validate_nfs_state_replay(
    session: &MountSessionFence,
    replay: &RecordNfsReplayReceiptInput<'_>,
    operation: &str,
) -> Result<(), DatabaseError> {
    if session.protocol != "nfs"
        || replay.context.operation != operation
        || replay.context.tenant_id != session.tenant_id
        || replay.context.mount_session_id != session.session_id
        || replay.context.gateway_epoch != session.gateway_epoch
        || replay.response_bytes.is_empty()
        || replay.response_bytes.len() > NFS_MAX_REPLAY_RESPONSE_BYTES
        || !valid_nfs_replay_context(&replay.context)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn nfs_state_receipt(
    replay: NfsAtomicReplayState,
    expected_id: Option<Uuid>,
) -> Result<NfsMutationReceipt, DatabaseError> {
    let result = replay
        .mutation_result
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    let resource_id = result
        .get("resource_id")
        .cloned()
        .map(serde_json::from_value::<Uuid>)
        .transpose()
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    if expected_id.is_some() && resource_id != expected_id {
        return Err(DatabaseError::Conflict);
    }
    Ok(NfsMutationReceipt {
        outcome: replay
            .receipt
            .mutation_outcome
            .clone()
            .unwrap_or_else(|| "applied".to_owned()),
        replay: replay.receipt,
        replayed: true,
        resource_id,
        resource_generation: None,
    })
}

fn nfs_open_result_from_replay(
    input: &OpenNfsHandleInput<'_>,
    replay: NfsAtomicReplayState,
) -> Result<OpenedNfsHandle, DatabaseError> {
    let mutation = replay
        .mutation_result
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    let drive_id = serde_json::from_value::<Uuid>(
        mutation
            .get("drive_id")
            .cloned()
            .ok_or(DatabaseError::InvalidPersistedValue)?,
    )
    .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let node_id = serde_json::from_value::<Uuid>(
        mutation
            .get("node_id")
            .cloned()
            .ok_or(DatabaseError::InvalidPersistedValue)?,
    )
    .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let handle = mutation
        .get("handle")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value::<MountHandleRecord>)
        .transpose()
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let outcome = replay
        .receipt
        .mutation_outcome
        .clone()
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    if drive_id != input.authorization.drive_id
        || node_id != input.authorization.resource_id
        || (outcome == "applied") != handle.is_some()
        || (outcome == "conflict") != handle.is_none()
        || handle.as_ref().is_some_and(|handle| {
            handle.session_id != input.session.session_id
                || handle.drive_id != drive_id
                || handle.node_id != node_id
        })
    {
        return Err(DatabaseError::Conflict);
    }
    Ok(OpenedNfsHandle {
        handle,
        replay: replay.receipt,
        replayed: true,
        outcome,
    })
}

async fn require_completed_nfs_internal_terminal_tx(
    transaction: &mut Transaction<'_, Postgres>,
    context: &NfsReplayContext<'_>,
    handle_id: Option<Uuid>,
) -> Result<bool, DatabaseError> {
    sqlx::query_scalar(
        "SELECT filebelt_mount.require_completed_nfs_internal_terminal(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(context.tenant_id)
    .bind(context.mount_session_id)
    .bind(context.client_id)
    .bind(context.nfs_session_id)
    .bind(context.slot_id)
    .bind(context.sequence_id)
    .bind(context.operation_index)
    .bind(context.operation)
    .bind(context.request_digest.as_slice())
    .bind(context.gateway_epoch)
    .bind(handle_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)
}

async fn fence_nfs_writers_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    mount_session_id: Uuid,
    handle_id: Option<Uuid>,
    reason: &str,
) -> Result<(), DatabaseError> {
    let rows = sqlx::query(
        "SELECT writer.id,pending.pending_count,pending.nonce_digest \
         FROM filebelt_mount.write_sessions AS writer \
         CROSS JOIN LATERAL (SELECT count(*)::integer AS pending_count,\
                                    min(receipt.nonce_digest) AS nonce_digest \
           FROM filebelt_mount.nfs_io_receipts AS receipt \
           WHERE receipt.tenant_id=writer.tenant_id \
             AND receipt.write_session_id=writer.id AND receipt.state='pending') AS pending \
         WHERE writer.tenant_id=$1 AND writer.mount_session_id=$2 \
           AND ($3::uuid IS NULL OR writer.handle_id=$3) \
           AND writer.state IN ('open','flushing','committing','aborting') \
         ORDER BY writer.id FOR UPDATE OF writer",
    )
    .bind(tenant_id)
    .bind(mount_session_id)
    .bind(handle_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        if row.get::<i32, _>("pending_count") > 1 {
            return Err(DatabaseError::InvalidPersistedValue);
        }
        let write_session_id = row.get::<Uuid, _>("id");
        let source_nonce_digest = row.get::<Option<Vec<u8>>, _>("nonce_digest");
        let changed = sqlx::query(
            "UPDATE filebelt_mount.write_sessions \
             SET state='expired',fencing_token=fencing_token+1,\
                 finished_at=COALESCE(finished_at,clock_timestamp()),\
                 heartbeat_at=clock_timestamp() \
             WHERE tenant_id=$1 AND id=$2 \
               AND state IN ('open','flushing','committing','aborting')",
        )
        .bind(tenant_id)
        .bind(write_session_id)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(DatabaseError::StaleGeneration);
        }
        sqlx::query("SELECT filebelt_mount.enqueue_nfs_staging_cleanup($1,$2,$3,$4,'cleanup')")
            .bind(tenant_id)
            .bind(write_session_id)
            .bind(reason)
            .bind(source_nonce_digest)
            .execute(&mut **transaction)
            .await
            .map_err(map_nfs_mutation_error)?;
    }
    Ok(())
}

async fn admit_mount_write_capability_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
    operation: MountWriteStorageOperation,
) -> Result<MountWriteStorageRecord, DatabaseError> {
    if !valid_mount_write_fence(fence, operation) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let row = sqlx::query(
        "SELECT write_session.id AS write_session_id,write_session.base_version_id,\
                write_session.logical_size_bytes,write_session.reserved_bytes,write_session.state,\
                staging.tenant_id AS staging_tenant_id,staging.id AS staging_payload_id,\
                staging.drive_id AS staging_drive_id,staging.backend_id AS staging_backend_id,\
                staging.locator AS staging_locator,staging.layout AS staging_layout,\
                staging.state AS staging_state,staging.size_bytes AS staging_size_bytes,\
                staging.blake3 AS staging_blake3,\
                base_payload.tenant_id AS base_tenant_id,base_payload.id AS base_payload_id,\
                base_payload.drive_id AS base_drive_id,base_payload.backend_id AS base_backend_id,\
                base_payload.locator AS base_locator,base_payload.layout AS base_layout,\
                base_payload.state AS base_state,base_payload.size_bytes AS base_size_bytes,\
                base_payload.blake3 AS base_blake3 \
         FROM filebelt_mount.write_sessions AS write_session \
         JOIN filebelt_mount.handles AS handle \
           ON handle.tenant_id=write_session.tenant_id AND handle.id=write_session.handle_id \
         JOIN filebelt_mount.sessions AS session \
           ON session.tenant_id=handle.tenant_id AND session.id=handle.session_id \
         JOIN filebelt_mount.credentials AS credential \
           ON credential.tenant_id=session.tenant_id AND credential.id=session.credential_id \
         JOIN filebelt_mount.policies AS policy \
           ON policy.tenant_id=session.tenant_id AND policy.principal_id=session.user_principal_id \
          AND policy.protocol=session.protocol \
         JOIN public.principals AS principal \
           ON principal.tenant_id=session.tenant_id AND principal.id=session.user_principal_id \
         JOIN public.users AS user_account \
           ON user_account.tenant_id=principal.tenant_id \
          AND user_account.principal_id=principal.id \
         JOIN public.drives AS drive \
           ON drive.tenant_id=handle.tenant_id AND drive.id=handle.drive_id \
         JOIN public.nodes AS node \
           ON node.tenant_id=handle.tenant_id AND node.drive_id=handle.drive_id \
          AND node.id=handle.node_id \
         JOIN filebelt_mount.gateway_epochs AS gateway \
           ON gateway.tenant_id=session.tenant_id AND gateway.protocol=session.protocol \
          AND gateway.gateway_id=session.gateway_id AND gateway.epoch=session.gateway_epoch \
         JOIN public.payload_objects AS staging \
           ON staging.tenant_id=write_session.tenant_id \
          AND staging.id=write_session.staging_payload_id \
         LEFT JOIN public.file_versions AS base_version \
           ON base_version.tenant_id=write_session.tenant_id \
          AND base_version.node_id=write_session.node_id \
          AND base_version.id=write_session.base_version_id \
         LEFT JOIN public.payload_objects AS base_payload \
           ON base_payload.tenant_id=base_version.tenant_id \
          AND base_payload.id=base_version.payload_id \
         WHERE write_session.tenant_id=$1 AND write_session.id=$2 \
           AND write_session.mount_session_id=$3 AND write_session.handle_id=$4 \
           AND write_session.drive_id=$5 AND write_session.node_id=$6 \
           AND write_session.fencing_token=$7 AND write_session.gateway_epoch=$8 \
           AND write_session.authorization_generation=$9 \
           AND write_session.lease_expires_at>clock_timestamp() \
           AND write_session.expires_at>clock_timestamp() \
           AND handle.session_id=$3 AND handle.closed_at IS NULL \
           AND handle.expires_at>clock_timestamp() \
           AND 'WRITE_CONTENT'=ANY(handle.access_actions) \
           AND handle.credential_generation=$10 \
           AND handle.authorization_generation=$9 \
           AND handle.membership_generation=$11 \
           AND handle.drive_acl_generation=$12 \
           AND handle.namespace_generation=$13 \
           AND handle.resource_acl_generation=$14 AND handle.gateway_epoch=$8 \
           AND ($18 OR handle.version_id IS NOT DISTINCT FROM $15) \
           AND session.id=$3 AND session.user_principal_id=$16 \
           AND session.credential_id=$17 AND session.credential_generation=$10 \
           AND session.authorization_generation=$9 \
           AND session.membership_generation=$11 AND session.gateway_epoch=$8 \
           AND session.state IN ('active','draining') \
           AND session.idle_expires_at>clock_timestamp() \
           AND session.absolute_expires_at>clock_timestamp() \
           AND credential.credential_generation=$10 \
           AND credential.authorization_generation=$9 \
           AND credential.revoked_at IS NULL AND credential.expires_at>clock_timestamp() \
           AND NOT credential.read_only AND $5=ANY(credential.allowed_drive_ids) \
           AND policy.enabled AND NOT policy.read_only AND $5=ANY(policy.allowed_drive_ids) \
           AND policy.authorization_generation=$9 \
           AND principal.generation=$11 AND principal.disabled_at IS NULL \
           AND user_account.status='active' \
           AND drive.acl_generation=$12 \
           AND node.acl_generation=$14 AND node.namespace_generation=$13 \
           AND node.kind='file' AND node.trash_root_id IS NULL \
           AND staging.drive_id=$5 \
           AND (base_payload.id IS NULL OR (base_payload.drive_id=$5 \
             AND base_payload.state='referenced')) \
           AND ((session.state='active' AND NOT gateway.draining \
                 AND gateway.lease_expires_at>clock_timestamp()) \
             OR (session.state='draining' AND gateway.draining \
                 AND gateway.drain_deadline>clock_timestamp())) \
           AND (session.protocol<>'nfs' OR (session.nfs_gss_binding_digest IS NOT NULL \
             AND EXISTS (SELECT 1 \
               FROM filebelt_mount.nfs_principal_mappings AS mapping \
               JOIN public.group_memberships AS membership \
                 ON membership.tenant_id=mapping.tenant_id \
                AND membership.group_id=mapping.posix_group_id \
                AND membership.user_principal_id=mapping.principal_id \
               WHERE mapping.tenant_id=session.tenant_id \
                 AND mapping.credential_id=session.credential_id \
                 AND mapping.principal_id=session.user_principal_id \
                 AND mapping.generation=session.nfs_mapping_generation \
                 AND mapping.revoked_at IS NULL) \
             AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_feature_state AS feature \
               WHERE feature.tenant_id=session.tenant_id \
                 AND feature.generation=session.nfs_feature_generation \
                 AND feature.restore_generation=session.nfs_restore_generation \
                 AND feature.manifest_generation=session.nfs_manifest_generation \
                 AND feature.applied_manifest_generation=feature.manifest_generation \
                 AND feature.applied_gateway_id=session.gateway_id \
                 AND feature.applied_gateway_epoch=session.gateway_epoch \
                 AND ((session.state='active' AND feature.state='active') \
                   OR (session.state='draining' AND feature.state IN ('active','draining')))) \
             AND EXISTS (SELECT 1 FROM filebelt_mount.nfs_exports AS export \
               WHERE export.tenant_id=session.tenant_id AND export.drive_id=$5 \
                 AND export.export_id=ANY(session.nfs_allowed_export_ids) \
                 AND export.desired_state='active' AND export.applied_state='active' \
                 AND export.desired_generation=export.applied_generation))) \
         FOR UPDATE OF write_session,handle,session,credential,policy,principal,\
           drive,node,gateway,staging",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .bind(fence.mount_session_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.fencing_token)
    .bind(fence.gateway_epoch)
    .bind(fence.authorization_generation)
    .bind(fence.credential_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.version_id)
    .bind(fence.principal_id)
    .bind(fence.credential_id)
    .bind(matches!(operation, MountWriteStorageOperation::Abort))
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    let mut record = mount_write_storage_record_from_row(&row)?;
    let allowed = match operation {
        MountWriteStorageOperation::Write => {
            matches!(record.state.as_str(), "open" | "flushing")
                && record.staging_payload.state == "staging"
        }
        MountWriteStorageOperation::Flush => {
            matches!(record.state.as_str(), "open" | "flushing")
                && record.staging_payload.state == "staging"
        }
        MountWriteStorageOperation::Finalize => {
            matches!(record.state.as_str(), "flushing" | "committing")
                && matches!(
                    record.staging_payload.state.as_str(),
                    "staging" | "finalized"
                )
        }
        MountWriteStorageOperation::Abort => {
            matches!(
                record.state.as_str(),
                "open" | "flushing" | "aborting" | "aborted"
            ) && matches!(
                record.staging_payload.state.as_str(),
                "staging" | "abandoned"
            )
        }
        MountWriteStorageOperation::DeleteStaging => {
            matches!(record.state.as_str(), "aborted" | "expired")
                && matches!(
                    record.staging_payload.state.as_str(),
                    "abandoned" | "deleting" | "deleted"
                )
        }
    };
    if !allowed {
        return Err(DatabaseError::StaleGeneration);
    }
    if let Some(payload) = &record.base_payload {
        record.base_parts =
            mount_payload_parts_tx(transaction, fence.tenant_id, payload.payload_id).await?;
    }
    record.planned_chunks =
        mount_write_chunk_plan_tx(transaction, fence.tenant_id, fence.write_session_id).await?;
    Ok(record)
}

async fn admit_mount_write_range_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
    capability_id: Uuid,
    operation: MountWriteRangeOperation,
    range_start: i64,
    range_end: i64,
) -> Result<MountWriteRangeAdmission, DatabaseError> {
    if capability_id.is_nil()
        || range_start < 0
        || range_end < range_start
        || (operation.seeks() && range_start != range_end)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let storage =
        admit_mount_write_capability_tx(transaction, fence, MountWriteStorageOperation::Write)
            .await?;
    let row = sqlx::query(
        "SELECT operation_id,operation,operation_ordinal,content_blake3,range_start,range_end,\
                resulting_logical_size,reserved_bytes \
         FROM filebelt_mount.read_nfs_write_operation(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
           $18,$19,$20,$21)",
    )
    .bind(fence.tenant_id)
    .bind(fence.principal_id)
    .bind(fence.mount_session_id)
    .bind(fence.credential_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.version_id)
    .bind(fence.write_session_id)
    .bind(fence.credential_generation)
    .bind(fence.authorization_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.gateway_epoch)
    .bind(fence.fencing_token)
    .bind(capability_id)
    .bind(operation.as_str())
    .bind(range_start)
    .bind(range_end)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_nfs_mutation_error)?
    .ok_or(DatabaseError::StaleGeneration)?;
    let planned_operation = row.get::<String, _>("operation");
    let operation_id = row.get::<Uuid, _>("operation_id");
    let operation_ordinal = row.get::<i64, _>("operation_ordinal");
    let content_blake3 = optional_digest_32(row.get("content_blake3"))?;
    let planned_start = row.get::<i64, _>("range_start");
    let planned_end = row.get::<i64, _>("range_end");
    let planned_reserved = row.get::<i64, _>("reserved_bytes");
    let resulting_logical_size = row.get::<i64, _>("resulting_logical_size");
    let planned_bytes = storage
        .planned_chunks
        .iter()
        .try_fold(0_i64, |total, chunk| total.checked_add(chunk.size_bytes))
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    if planned_operation != operation.as_str()
        || operation_ordinal <= 0
        || planned_start != range_start
        || planned_end != range_end
        || planned_reserved <= range_end
        || planned_reserved != storage.reserved_bytes
        || planned_bytes != planned_reserved
        || resulting_logical_size > planned_reserved
        || (operation.writes_bytes() && storage.state != "open")
        || (operation == MountWriteRangeOperation::WriteData) != content_blake3.is_some()
    {
        return Err(DatabaseError::StaleGeneration);
    }
    Ok(MountWriteRangeAdmission {
        storage,
        operation_id,
        operation_ordinal,
        operation,
        content_blake3,
        range_start,
        range_end,
        resulting_logical_size,
    })
}

/// Re-admits a byte-plane-completed range operation for the VFS authority
/// acknowledgement. The 30-second worker lease is intentionally not part of
/// this projection: a worker may have durably completed I/O immediately before
/// a crash. The authenticated NFS session/handle/policy path is rechecked by
/// the caller, while this query binds the immutable writer and operation
/// generations through the writer's absolute lifetime.
async fn admit_completed_mount_write_range_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
    operation_id: Uuid,
    operation: MountWriteRangeOperation,
    range_start: i64,
    range_end: i64,
) -> Result<MountWriteRangeAdmission, DatabaseError> {
    if operation_id.is_nil()
        || range_start < 0
        || range_end < range_start
        || (operation.seeks() && range_start != range_end)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let row = sqlx::query(
        "SELECT operation.operation,operation.operation_ordinal,\
                operation.content_blake3,operation.range_start,operation.range_end,\
                operation.resulting_logical_size,operation.reserved_bytes \
         FROM filebelt_mount.nfs_write_operations AS operation \
         JOIN filebelt_mount.write_sessions AS writer \
           ON writer.tenant_id=operation.tenant_id \
          AND writer.id=operation.write_session_id \
         JOIN filebelt_mount.handles AS handle \
           ON handle.tenant_id=writer.tenant_id AND handle.id=writer.handle_id \
         WHERE operation.tenant_id=$1 AND operation.write_session_id=$2 \
           AND operation.operation_id=$3 AND operation.state='io_completed' \
           AND writer.mount_session_id=$4 AND writer.handle_id=$5 \
           AND writer.drive_id=$6 AND writer.node_id=$7 \
           AND writer.fencing_token=$8 AND writer.gateway_epoch=$9 \
           AND writer.authorization_generation=$10 \
           AND writer.state='open' AND writer.expires_at>clock_timestamp() \
           AND handle.session_id=$4 AND handle.drive_id=$6 AND handle.node_id=$7 \
           AND handle.credential_generation=$11 \
           AND handle.authorization_generation=$10 \
           AND handle.membership_generation=$12 \
           AND handle.drive_acl_generation=$13 \
           AND handle.namespace_generation=$14 \
           AND handle.resource_acl_generation=$15 \
           AND handle.gateway_epoch=$9 \
           AND handle.version_id IS NOT DISTINCT FROM $16 \
         FOR UPDATE OF operation,writer",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .bind(operation_id)
    .bind(fence.mount_session_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.fencing_token)
    .bind(fence.gateway_epoch)
    .bind(fence.authorization_generation)
    .bind(fence.credential_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.version_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    let storage = mount_write_storage_record_tx(transaction, fence).await?;
    let planned_operation = row.get::<String, _>("operation");
    let operation_ordinal = row.get::<i64, _>("operation_ordinal");
    let content_blake3 = optional_digest_32(row.get("content_blake3"))?;
    let planned_start = row.get::<i64, _>("range_start");
    let planned_end = row.get::<i64, _>("range_end");
    let planned_reserved = row.get::<i64, _>("reserved_bytes");
    let resulting_logical_size = row.get::<i64, _>("resulting_logical_size");
    let planned_bytes = storage
        .planned_chunks
        .iter()
        .try_fold(0_i64, |total, chunk| total.checked_add(chunk.size_bytes))
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    if planned_operation != operation.as_str()
        || operation_ordinal <= 0
        || planned_start != range_start
        || planned_end != range_end
        || planned_reserved <= range_end
        || planned_reserved != storage.reserved_bytes
        || planned_bytes != planned_reserved
        || resulting_logical_size > planned_reserved
        || storage.state != "open"
        || (operation == MountWriteRangeOperation::WriteData) != content_blake3.is_some()
    {
        return Err(DatabaseError::StaleGeneration);
    }
    Ok(MountWriteRangeAdmission {
        storage,
        operation_id,
        operation_ordinal,
        operation,
        content_blake3,
        range_start,
        range_end,
        resulting_logical_size,
    })
}

async fn admit_mount_staging_cleanup_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
) -> Result<MountWriteStorageRecord, DatabaseError> {
    if !valid_mount_write_fence(fence, MountWriteStorageOperation::DeleteStaging) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let row = sqlx::query(
        "SELECT write_session.id AS write_session_id,write_session.base_version_id,\
                write_session.logical_size_bytes,write_session.reserved_bytes,write_session.state,\
                staging.tenant_id AS staging_tenant_id,staging.id AS staging_payload_id,\
                staging.drive_id AS staging_drive_id,staging.backend_id AS staging_backend_id,\
                staging.locator AS staging_locator,staging.layout AS staging_layout,\
                staging.state AS staging_state,staging.size_bytes AS staging_size_bytes,\
                staging.blake3 AS staging_blake3,\
                base_payload.tenant_id AS base_tenant_id,base_payload.id AS base_payload_id,\
                base_payload.drive_id AS base_drive_id,base_payload.backend_id AS base_backend_id,\
                base_payload.locator AS base_locator,base_payload.layout AS base_layout,\
                base_payload.state AS base_state,base_payload.size_bytes AS base_size_bytes,\
                base_payload.blake3 AS base_blake3 \
         FROM filebelt_mount.write_sessions AS write_session \
         JOIN filebelt_mount.handles AS handle \
           ON handle.tenant_id=write_session.tenant_id AND handle.id=write_session.handle_id \
         JOIN filebelt_mount.sessions AS session \
           ON session.tenant_id=write_session.tenant_id \
          AND session.id=write_session.mount_session_id \
         JOIN public.payload_objects AS staging \
           ON staging.tenant_id=write_session.tenant_id \
          AND staging.id=write_session.staging_payload_id \
         LEFT JOIN public.file_versions AS base_version \
           ON base_version.tenant_id=write_session.tenant_id \
          AND base_version.node_id=write_session.node_id \
          AND base_version.id=write_session.base_version_id \
         LEFT JOIN public.payload_objects AS base_payload \
           ON base_payload.tenant_id=base_version.tenant_id \
          AND base_payload.id=base_version.payload_id \
         WHERE write_session.tenant_id=$1 AND write_session.id=$2 \
           AND write_session.mount_session_id=$3 AND write_session.handle_id=$4 \
           AND write_session.drive_id=$5 AND write_session.node_id=$6 \
           AND write_session.fencing_token=$7 AND write_session.gateway_epoch=$8 \
           AND write_session.authorization_generation=$9 \
           AND write_session.state IN ('aborted','expired') \
           AND handle.session_id=$3 AND handle.drive_id=$5 AND handle.node_id=$6 \
           AND handle.credential_generation=$10 \
           AND handle.authorization_generation=$9 \
           AND handle.membership_generation=$11 \
           AND handle.drive_acl_generation=$12 \
           AND handle.namespace_generation=$13 \
           AND handle.resource_acl_generation=$14 AND handle.gateway_epoch=$8 \
           AND session.user_principal_id=$15 AND session.credential_id=$16 \
           AND session.credential_generation=$10 \
           AND session.authorization_generation=$9 \
           AND session.membership_generation=$11 AND session.gateway_epoch=$8 \
           AND staging.drive_id=$5 AND staging.state IN ('abandoned','deleting','deleted') \
           AND NOT EXISTS (SELECT 1 FROM public.file_versions AS version \
             WHERE version.tenant_id=staging.tenant_id AND version.payload_id=staging.id) \
           AND NOT EXISTS (SELECT 1 FROM filebelt_mount.nfs_write_conflicts AS conflict \
             WHERE conflict.tenant_id=staging.tenant_id \
               AND conflict.staging_payload_id=staging.id AND conflict.state='retained') \
         FOR UPDATE OF write_session,staging",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .bind(fence.mount_session_id)
    .bind(fence.handle_id)
    .bind(fence.drive_id)
    .bind(fence.node_id)
    .bind(fence.fencing_token)
    .bind(fence.gateway_epoch)
    .bind(fence.authorization_generation)
    .bind(fence.credential_generation)
    .bind(fence.membership_generation)
    .bind(fence.drive_acl_generation)
    .bind(fence.namespace_generation)
    .bind(fence.resource_acl_generation)
    .bind(fence.principal_id)
    .bind(fence.credential_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    let mut record = mount_write_storage_record_from_row(&row)?;
    if let Some(payload) = &record.base_payload {
        record.base_parts =
            mount_payload_parts_tx(transaction, fence.tenant_id, payload.payload_id).await?;
    }
    record.planned_chunks =
        mount_write_chunk_plan_tx(transaction, fence.tenant_id, fence.write_session_id).await?;
    Ok(record)
}

async fn mount_write_storage_record_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
) -> Result<MountWriteStorageRecord, DatabaseError> {
    let row = sqlx::query(
        "SELECT write_session.id AS write_session_id,write_session.base_version_id,\
                write_session.logical_size_bytes,write_session.reserved_bytes,write_session.state,\
                staging.tenant_id AS staging_tenant_id,staging.id AS staging_payload_id,\
                staging.drive_id AS staging_drive_id,staging.backend_id AS staging_backend_id,\
                staging.locator AS staging_locator,staging.layout AS staging_layout,\
                staging.state AS staging_state,staging.size_bytes AS staging_size_bytes,\
                staging.blake3 AS staging_blake3,\
                base_payload.tenant_id AS base_tenant_id,base_payload.id AS base_payload_id,\
                base_payload.drive_id AS base_drive_id,base_payload.backend_id AS base_backend_id,\
                base_payload.locator AS base_locator,base_payload.layout AS base_layout,\
                base_payload.state AS base_state,base_payload.size_bytes AS base_size_bytes,\
                base_payload.blake3 AS base_blake3 \
         FROM filebelt_mount.write_sessions AS write_session \
         JOIN public.payload_objects AS staging ON staging.tenant_id=write_session.tenant_id \
           AND staging.id=write_session.staging_payload_id \
         LEFT JOIN public.file_versions AS base_version \
           ON base_version.tenant_id=write_session.tenant_id \
          AND base_version.node_id=write_session.node_id \
          AND base_version.id=write_session.base_version_id \
         LEFT JOIN public.payload_objects AS base_payload \
           ON base_payload.tenant_id=base_version.tenant_id \
          AND base_payload.id=base_version.payload_id \
         WHERE write_session.tenant_id=$1 AND write_session.id=$2 \
           AND write_session.fencing_token=$3 FOR UPDATE OF write_session,staging",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .bind(fence.fencing_token)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::StaleGeneration)?;
    let mut record = mount_write_storage_record_from_row(&row)?;
    if let Some(payload) = &record.base_payload {
        record.base_parts =
            mount_payload_parts_tx(transaction, fence.tenant_id, payload.payload_id).await?;
    }
    record.planned_chunks =
        mount_write_chunk_plan_tx(transaction, fence.tenant_id, fence.write_session_id).await?;
    Ok(record)
}

fn mount_staging_cleanup_job_from_row(
    tenant_id: Uuid,
    write_session_id: Uuid,
    worker_id: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<MountStagingCleanupJobRecord, DatabaseError> {
    Ok(MountStagingCleanupJobRecord {
        tenant_id,
        write_session_id,
        backend_id: row.get("backend_id"),
        worker_id,
        payload: PayloadRecord {
            tenant_id,
            payload_id: row.get("payload_id"),
            drive_id: row.get("drive_id"),
            backend_id: row.get("backend_id"),
            locator: row.get("locator"),
            layout: row.get("layout"),
            state: row.get("payload_state"),
            size_bytes: row.get("size_bytes"),
            blake3: row.get("blake3"),
        },
        job_fencing_token: row.get("job_fencing_token"),
        job_state: row.get("job_state"),
        reason: row.get("reason"),
        completion_kind: row.get("completion_kind"),
        source_nonce_digest: optional_digest_32(row.get("source_nonce_digest"))?,
    })
}

fn validate_mount_write_lock_cleanup_identity(
    tenant_id: Uuid,
    backend_id: Uuid,
    write_session_id: Uuid,
    worker_id: Uuid,
) -> Result<(), DatabaseError> {
    if tenant_id.is_nil() || backend_id.is_nil() || write_session_id.is_nil() || worker_id.is_nil()
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validate_mount_write_lock_cleanup_record(
    cleanup: &MountWriteLockCleanupJobRecord,
) -> Result<(), DatabaseError> {
    validate_mount_write_lock_cleanup_identity(
        cleanup.tenant_id,
        cleanup.backend_id,
        cleanup.write_session_id,
        cleanup.worker_id,
    )?;
    if cleanup.staging_payload_id.is_nil()
        || cleanup.job_fencing_token <= 0
        || !matches!(cleanup.job_state.as_str(), "leased" | "completed")
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn mount_write_lock_cleanup_job_from_row(
    tenant_id: Uuid,
    write_session_id: Uuid,
    worker_id: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<MountWriteLockCleanupJobRecord, DatabaseError> {
    let record = MountWriteLockCleanupJobRecord {
        tenant_id,
        write_session_id,
        backend_id: row.get("backend_id"),
        staging_payload_id: row.get("staging_payload_id"),
        worker_id,
        job_fencing_token: row.get("job_fencing_token"),
        job_state: row.get("job_state"),
    };
    validate_mount_write_lock_cleanup_record(&record)?;
    Ok(record)
}

fn mount_write_storage_record_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<MountWriteStorageRecord, DatabaseError> {
    let staging_payload = payload_record_from_prefixed_row(row, "staging")?
        .ok_or(DatabaseError::InvalidPersistedValue)?;
    Ok(MountWriteStorageRecord {
        write_session_id: row.get("write_session_id"),
        base_version_id: row.get("base_version_id"),
        logical_size_bytes: row.get("logical_size_bytes"),
        reserved_bytes: row.get("reserved_bytes"),
        state: row.get("state"),
        staging_payload,
        base_payload: payload_record_from_prefixed_row(row, "base")?,
        base_parts: Vec::new(),
        planned_chunks: Vec::new(),
    })
}

async fn mount_write_chunk_plan_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    write_session_id: Uuid,
) -> Result<Vec<MountWriteChunkPlan>, DatabaseError> {
    let rows = sqlx::query(
        "SELECT chunk_number,source_payload_id,source_chunk_number,staging_locator,\
                size_bytes,dirty \
         FROM filebelt_mount.write_chunks \
         WHERE tenant_id=$1 AND write_session_id=$2 ORDER BY chunk_number",
    )
    .bind(tenant_id)
    .bind(write_session_id)
    .fetch_all(&mut **transaction)
    .await?;
    let chunks = rows
        .iter()
        .map(|row| -> Result<MountWriteChunkPlan, DatabaseError> {
            Ok(MountWriteChunkPlan {
                chunk_number: row.get("chunk_number"),
                source_payload_id: row.get("source_payload_id"),
                source_chunk_number: row.get("source_chunk_number"),
                staging_locator: row
                    .get::<Option<Uuid>, _>("staging_locator")
                    .ok_or(DatabaseError::InvalidPersistedValue)?,
                size_bytes: row.get("size_bytes"),
                dirty: row.get("dirty"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_mount_chunk_plan(&chunks)?;
    Ok(chunks)
}

fn payload_record_from_prefixed_row(
    row: &sqlx::postgres::PgRow,
    prefix: &str,
) -> Result<Option<PayloadRecord>, DatabaseError> {
    let tenant_id: Option<Uuid> = row.get(format!("{prefix}_tenant_id").as_str());
    let Some(tenant_id) = tenant_id else {
        return Ok(None);
    };
    Ok(Some(PayloadRecord {
        tenant_id,
        payload_id: row.get(format!("{prefix}_payload_id").as_str()),
        drive_id: row.get(format!("{prefix}_drive_id").as_str()),
        backend_id: row.get(format!("{prefix}_backend_id").as_str()),
        locator: row.get(format!("{prefix}_locator").as_str()),
        layout: row.get(format!("{prefix}_layout").as_str()),
        state: row.get(format!("{prefix}_state").as_str()),
        size_bytes: row.get(format!("{prefix}_size_bytes").as_str()),
        blake3: row.get(format!("{prefix}_blake3").as_str()),
    }))
}

async fn payload_record_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    payload_id: Uuid,
) -> Result<PayloadRecord, DatabaseError> {
    let row = sqlx::query(
        "SELECT tenant_id,id AS payload_id,drive_id,backend_id,locator,layout,state,size_bytes,blake3 \
         FROM public.payload_objects WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(payload_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DatabaseError::NotFound)?;
    Ok(PayloadRecord {
        tenant_id: row.get("tenant_id"),
        payload_id: row.get("payload_id"),
        drive_id: row.get("drive_id"),
        backend_id: row.get("backend_id"),
        locator: row.get("locator"),
        layout: row.get("layout"),
        state: row.get("state"),
        size_bytes: row.get("size_bytes"),
        blake3: row.get("blake3"),
    })
}

async fn mount_payload_parts_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    payload_id: Uuid,
) -> Result<Vec<MountPayloadPartRecord>, DatabaseError> {
    let rows = sqlx::query(
        "SELECT part.origin,part.chunk_number,part.locator,part.size_bytes,part.blake3 FROM (\
           SELECT upload_part.part_number::bigint AS chunk_number,upload_part.locator,\
                  upload_part.size_bytes::bigint AS size_bytes,upload_part.blake3,'upload' AS origin \
           FROM public.upload_sessions AS upload \
           JOIN public.upload_parts AS upload_part \
             ON upload_part.tenant_id=upload.tenant_id AND upload_part.upload_id=upload.id \
           WHERE upload.tenant_id=$1 AND upload.payload_id=$2 \
             AND upload_part.state='durable' \
           UNION ALL \
           SELECT write_chunk.chunk_number,write_chunk.staging_locator AS locator,\
                  write_chunk.size_bytes,write_chunk.blake3,'mount' AS origin \
           FROM filebelt_mount.write_sessions AS write_session \
           JOIN filebelt_mount.write_chunks AS write_chunk \
             ON write_chunk.tenant_id=write_session.tenant_id \
            AND write_chunk.write_session_id=write_session.id \
           WHERE write_session.tenant_id=$1 AND write_session.staging_payload_id=$2 \
             AND write_session.state IN ('committed','conflicted') \
             AND write_chunk.state='published' AND write_chunk.staging_locator IS NOT NULL\
         ) AS part ORDER BY part.chunk_number",
    )
    .bind(tenant_id)
    .bind(payload_id)
    .fetch_all(&mut **transaction)
    .await?;
    if rows
        .windows(2)
        .any(|pair| pair[0].get::<i64, _>("chunk_number") == pair[1].get::<i64, _>("chunk_number"))
        || rows.first().is_some_and(|first| {
            rows.iter()
                .any(|row| row.get::<String, _>("origin") != first.get::<String, _>("origin"))
        })
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    rows.iter()
        .map(|row| {
            Ok(MountPayloadPartRecord {
                chunk_number: row.get("chunk_number"),
                locator: row.get("locator"),
                size_bytes: row.get("size_bytes"),
                blake3: row
                    .get::<Vec<u8>, _>("blake3")
                    .try_into()
                    .map_err(|_| DatabaseError::InvalidPersistedValue)?,
            })
        })
        .collect()
}

async fn persist_mount_chunk_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MountWriteCapabilityFence,
    chunks: &[MountWriteChunkEvidence],
    publish: bool,
) -> Result<(), DatabaseError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM filebelt_mount.write_chunks \
         WHERE tenant_id=$1 AND write_session_id=$2",
    )
    .bind(fence.tenant_id)
    .bind(fence.write_session_id)
    .fetch_one(&mut **transaction)
    .await?;
    if count != chunks.len() as i64 {
        return Err(DatabaseError::Conflict);
    }
    for chunk in chunks {
        let changed = if publish {
            sqlx::query(
                "UPDATE filebelt_mount.write_chunks SET state='published',updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND write_session_id=$2 AND chunk_number=$3 \
                   AND size_bytes=$4 AND blake3=$5 AND staging_locator IS NOT NULL \
                   AND state IN ('ready','published')",
            )
            .bind(fence.tenant_id)
            .bind(fence.write_session_id)
            .bind(chunk.chunk_number)
            .bind(chunk.size_bytes)
            .bind(chunk.blake3.as_slice())
            .execute(&mut **transaction)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE filebelt_mount.write_chunks SET size_bytes=$4,blake3=$5,state='ready',\
                        updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND write_session_id=$2 AND chunk_number=$3 \
                   AND staging_locator IS NOT NULL AND (state='writing' \
                     OR (state='ready' AND size_bytes=$4 AND blake3=$5))",
            )
            .bind(fence.tenant_id)
            .bind(fence.write_session_id)
            .bind(chunk.chunk_number)
            .bind(chunk.size_bytes)
            .bind(chunk.blake3.as_slice())
            .execute(&mut **transaction)
            .await?
            .rows_affected()
        };
        if changed != 1 {
            return Err(DatabaseError::Conflict);
        }
    }
    Ok(())
}

fn valid_mount_write_fence(
    fence: &MountWriteCapabilityFence,
    operation: MountWriteStorageOperation,
) -> bool {
    (!matches!(
        operation,
        MountWriteStorageOperation::Abort | MountWriteStorageOperation::DeleteStaging
    ) || fence.version_id.is_none())
        && fence.credential_generation > 0
        && fence.authorization_generation > 0
        && fence.membership_generation > 0
        && fence.drive_acl_generation > 0
        && fence.namespace_generation > 0
        && fence.resource_acl_generation > 0
        && fence.gateway_epoch > 0
        && fence.fencing_token > 0
}

fn validate_mount_chunk_evidence(
    logical_size_bytes: i64,
    chunks: &[MountWriteChunkEvidence],
) -> Result<(), DatabaseError> {
    let represented_size = chunks
        .iter()
        .try_fold(0_i64, |total, chunk| total.checked_add(chunk.size_bytes));
    if logical_size_bytes < 0
        || chunks.len() > 1_048_576
        || chunks.iter().any(|chunk| chunk.size_bytes <= 0)
        || chunks
            .windows(2)
            .any(|pair| pair[0].chunk_number.checked_add(1) != Some(pair[1].chunk_number))
        || chunks.first().is_some_and(|chunk| chunk.chunk_number != 0)
        || represented_size != Some(logical_size_bytes)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validate_mount_chunk_plan(chunks: &[MountWriteChunkPlan]) -> Result<(), DatabaseError> {
    let unique_locators = chunks
        .iter()
        .map(|chunk| chunk.staging_locator)
        .collect::<HashSet<_>>()
        .len()
        == chunks.len();
    if chunks.len() > 1_048_576
        || !unique_locators
        || chunks.iter().any(|chunk| {
            chunk.chunk_number < 0
                || chunk.size_bytes <= 0
                || chunk.staging_locator.is_nil()
                || chunk.source_payload_id.is_some() != chunk.source_chunk_number.is_some()
                || chunk.source_chunk_number.is_some_and(|number| number < 0)
        })
        || chunks
            .windows(2)
            .any(|pair| pair[0].chunk_number.checked_add(1) != Some(pair[1].chunk_number))
        || chunks.first().is_some_and(|chunk| chunk.chunk_number != 0)
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn valid_nfs_mutation_authorization(value: &NfsMutationAuthorization) -> bool {
    value.membership_generation > 0
        && value.drive_acl_generation > 0
        && value.drive_namespace_generation > 0
        && value.resource_acl_generation > 0
        && value.resource_namespace_generation > 0
}

fn nfs_authorization_json(value: &NfsMutationAuthorization) -> Value {
    json!({
        "drive_id":value.drive_id,
        "resource_id":value.resource_id,
        "membership_generation":value.membership_generation,
        "drive_acl_generation":value.drive_acl_generation,
        "drive_namespace_generation":value.drive_namespace_generation,
        "resource_acl_generation":value.resource_acl_generation,
        "resource_namespace_generation":value.resource_namespace_generation
    })
}

fn extend_json_object(mut base: Value, extra: Value) -> Value {
    let Some(base) = base.as_object_mut() else {
        return Value::Null;
    };
    if let Some(extra) = extra.as_object() {
        base.extend(extra.clone());
    }
    Value::Object(base.clone())
}

fn nfs_namespace_mutation_json(
    input: &NfsNamespaceMutationInput<'_>,
) -> Result<Value, DatabaseError> {
    if !valid_nfs_mutation_authorization(&input.authorization) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    let operation = input.context.operation;
    let extra = match &input.mutation {
        NfsNamespaceMutation::CreateFile {
            node_id,
            display_name,
            name_key,
            mode,
        }
        | NfsNamespaceMutation::CreateDirectory {
            node_id,
            display_name,
            name_key,
            mode,
        } => {
            let expected_operation =
                if matches!(input.mutation, NfsNamespaceMutation::CreateFile { .. }) {
                    "create"
                } else {
                    "mkdir"
                };
            validate_nfs_namespace_name(operation, expected_operation, display_name, name_key)?;
            validate_nfs_mode(*mode)?;
            json!({"node_id":node_id,"display_name":display_name,"name_key":name_key,"mode":mode})
        }
        NfsNamespaceMutation::CreateSymlink {
            node_id,
            display_name,
            name_key,
            target,
            mode,
        } => {
            validate_nfs_namespace_name(operation, "symlink", display_name, name_key)?;
            validate_nfs_mode(*mode)?;
            let _ = nfs_relative_target_components(target)?;
            json!({
                "node_id":node_id,"display_name":display_name,"name_key":name_key,
                "symlink_target":target,"mode":mode
            })
        }
        NfsNamespaceMutation::Rename {
            old_parent_id,
            old_parent_acl_generation,
            old_parent_namespace_generation,
            target_parent_id,
            target_display_name,
            target_name_key,
            target_parent_acl_generation,
            target_parent_namespace_generation,
        } => {
            validate_nfs_namespace_name(operation, "rename", target_display_name, target_name_key)?;
            if *old_parent_acl_generation <= 0
                || *old_parent_namespace_generation <= 0
                || *target_parent_acl_generation <= 0
                || *target_parent_namespace_generation <= 0
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            json!({
                "old_parent_id":old_parent_id,
                "old_parent_acl_generation":old_parent_acl_generation,
                "old_parent_namespace_generation":old_parent_namespace_generation,
                "target_parent_id":target_parent_id,
                "display_name":target_display_name,
                "name_key":target_name_key,
                "target_parent_acl_generation":target_parent_acl_generation,
                "target_parent_namespace_generation":target_parent_namespace_generation
            })
        }
        NfsNamespaceMutation::Remove {
            parent_id,
            parent_acl_generation,
            parent_namespace_generation,
        } => {
            if operation != "remove"
                || *parent_acl_generation <= 0
                || *parent_namespace_generation <= 0
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            json!({
                "parent_id":parent_id,
                "parent_acl_generation":parent_acl_generation,
                "parent_namespace_generation":parent_namespace_generation
            })
        }
        NfsNamespaceMutation::SetAttributes {
            mode,
            owner_principal_id,
            posix_group_id,
            accessed_at_unix_seconds,
            modified_at_unix_seconds,
        } => {
            if operation != "set_attributes"
                || (mode.is_none()
                    && owner_principal_id.is_none()
                    && posix_group_id.is_none()
                    && accessed_at_unix_seconds.is_none()
                    && modified_at_unix_seconds.is_none())
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            validate_nfs_mode(*mode)?;
            json!({
                "mode":mode,"owner_principal_id":owner_principal_id,
                "posix_group_id":posix_group_id,
                "accessed_at_unix_seconds":accessed_at_unix_seconds,
                "modified_at_unix_seconds":modified_at_unix_seconds
            })
        }
        NfsNamespaceMutation::SetXattr {
            name,
            value,
            create_only,
            replace_only,
        } => {
            if operation != "set_xattr"
                || !valid_nfs_xattr_name(name)
                || value.len() > 65_536
                || (*create_only && *replace_only)
            {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            json!({
                "name":name,"value_hex":lower_hex(value),
                "create_only":create_only,"replace_only":replace_only
            })
        }
        NfsNamespaceMutation::RemoveXattr { name } => {
            if operation != "remove_xattr" || !valid_nfs_xattr_name(name) {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            json!({"name":name})
        }
        NfsNamespaceMutation::ReplaceAcl { entries } => {
            if operation != "set_acl" || entries.len() > 256 {
                return Err(DatabaseError::InvalidPersistedValue);
            }
            let mut identities = std::collections::BTreeSet::new();
            for entry in entries {
                if !identities.insert((entry.principal_id, &entry.action, &entry.inheritance)) {
                    return Err(DatabaseError::InvalidPersistedValue);
                }
            }
            json!({"entries":entries.iter().map(|entry| json!({
                "id":entry.id,"principal_id":entry.principal_id,
                "action":entry.action,"inheritance":entry.inheritance
            })).collect::<Vec<_>>()})
        }
    };
    Ok(extend_json_object(
        nfs_authorization_json(&input.authorization),
        extra,
    ))
}

fn validate_nfs_namespace_name(
    actual_operation: &str,
    expected_operation: &str,
    display_name: &str,
    name_key: &str,
) -> Result<(), DatabaseError> {
    let normalized =
        NormalizedName::new(display_name).map_err(|_| DatabaseError::InvalidPersistedValue)?;
    if actual_operation != expected_operation
        || normalized.display() != display_name
        || normalized.comparison_key() != name_key
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn validate_nfs_mode(mode: Option<i32>) -> Result<(), DatabaseError> {
    if mode.is_some_and(|mode| !(0..=0o777).contains(&mode)) {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(())
}

fn valid_nfs_xattr_name(name: &str) -> bool {
    name.starts_with("user.")
        && (6..=255).contains(&name.len())
        && !name.chars().any(char::is_control)
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn nfs_relative_target_components(target: &str) -> Result<VecDeque<String>, DatabaseError> {
    if target.is_empty() || target.len() > 4096 || target.starts_with('/') || target.contains('\0')
    {
        return Err(DatabaseError::InvalidPersistedValue);
    }
    Ok(target
        .split('/')
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect())
}

fn nfs_mutation_receipt_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<NfsMutationReceipt, DatabaseError> {
    let response_digest = row
        .get::<Vec<u8>, _>("response_digest")
        .try_into()
        .map_err(|_| DatabaseError::InvalidPersistedValue)?;
    let outcome: String = row.get("mutation_outcome");
    Ok(NfsMutationReceipt {
        replay: NfsReplayReceipt {
            response_bytes: row.get("response_bytes"),
            response_digest,
            gateway_epoch: row.get("receipt_gateway_epoch"),
            expires_at_unix_seconds: row.get("expires_at_unix_seconds"),
            mutation_outcome: Some(outcome.clone()),
        },
        replayed: row.get("replayed"),
        outcome,
        resource_id: row.get("resource_id"),
        resource_generation: row.get("resource_generation"),
    })
}

fn map_nfs_mutation_error(error: sqlx::Error) -> DatabaseError {
    if matches!(&error,sqlx::Error::Database(database) if database.code().as_deref()==Some("40001"))
    {
        DatabaseError::StaleGeneration
    } else {
        map_conflict(error)
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

    #[test]
    fn nfs_authorization_snapshot_rechecks_the_exact_resource_generation() {
        let source = include_str!("mount.rs");
        let method = source
            .split_once("pub async fn nfs_authorization_snapshot(")
            .expect("NFS authorization snapshot method exists")
            .1
            .split_once("pub async fn resolve_nfs_symlink_target(")
            .expect("symlink resolver follows NFS authorization snapshot")
            .0;
        assert!(method.contains("node.namespace_generation=$20"));
        assert!(method.contains(".bind(snapshot.resource_namespace_generation)"));
    }
}

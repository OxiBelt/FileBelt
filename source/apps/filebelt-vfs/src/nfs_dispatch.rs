// SPDX-License-Identifier: Apache-2.0

//! Qualified NFS filesystem operations. Every mutation in this module uses a
//! database method that owns the matching NFS replay coordinate atomically.

use std::cmp::Ordering;
use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_database::mount::{
    ApplyNfsWriteExtentInput, BeginMountIoOperationInput, CloseNfsHandleInput, EndNfsSessionInput,
    ExtendNfsWriteChunksInput, FinalizeNfsInternalIoReplayInput, MountHandleRecord,
    MountIoCompletion, MountIoOperation, MountSessionFence, MountWriteCapabilityFence,
    MountWriteChunkPlan, MountWriteRangeOperation, MountWriteStorageOperation,
    MountWriteStorageRecord, NfsHandleResolution, NfsMutationAuthorization, NfsReplayContext,
    OpenNfsHandleInput, PendingMountIoOperation, PendingMountIoWorkerState,
    PreauthorizeMountIoOperationInput, RecordNfsReplayReceiptInput, ReissueMountIoOperationInput,
    SeekNfsWriteExtentInput,
};
use filebelt_database::{DatabaseError, NodeRecord};
use filebelt_domain::{Action, NormalizedName};
use filebelt_storage_protocol::{
    MountCapabilityClaims, MountStorageCapabilityUse, mount_capability_claims_digest,
    sign_mount_storage_capability, unix_time_now,
};
use filebelt_vfs_protocol::{
    DirectoryEntry, NodeAttributes, NodeKind, PROTOCOL_VERSION, RequestFence, SparseControlKind,
    VfsAction, VfsError, VfsResponse,
};
use prost::Message as _;
use reqwest::Method;
use serde::Deserialize;
use uuid::Uuid;

use super::{VfsState, decode_nfs_replay, denied, invalid, unavailable};

pub enum DispatchResult {
    /// A read or deterministic no-op result that the caller may persist with
    /// the standalone replay-receipt primitive.
    ReadOnly(VfsResponse),
    /// A transient byte-plane state with no client-visible replay receipt yet.
    /// The gateway must retry the same NFS slot instead of freezing this
    /// response as the operation's durable result.
    Retryable(VfsResponse),
    /// A mutation whose database method already persisted the exact response.
    Atomic(VfsResponse),
}

struct ResolvedTarget {
    export_id: i64,
    resolution: NfsHandleResolution,
    node: NodeRecord,
    traversal_fence: Option<super::policy::AuthorizationCommonFence>,
}

#[derive(Debug)]
struct NodeCursor {
    kind: String,
    name_key: String,
    id: Uuid,
}

const MOUNT_CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";
const MOUNT_CAPABILITY_NONCE_DOMAIN: &[u8] = b"filebelt-mount-capability-nonce-v2\0";
const MOUNT_CAPABILITY_LIFETIME_SECONDS: i64 = 15;
const MAX_MOUNT_IO_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_MOUNT_CHUNKS: usize = 1_048_576;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountWriteResult {
    write_session_id: Uuid,
    logical_size_bytes: u64,
    reservation_delta_bytes: u64,
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountSeekResult {
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountChunkResult {
    chunk_number: u64,
    size_bytes: u64,
    blake3: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountManifestResult {
    write_session_id: Uuid,
    logical_size_bytes: u64,
    blake3: String,
    chunks: Vec<MountChunkResult>,
    state: String,
}

struct PreparedMountCapability {
    claims: MountCapabilityClaims,
    purpose: MountStorageCapabilityUse,
    capability_id: Uuid,
    nonce_digest: [u8; 32],
    claims_digest: [u8; 32],
}

impl PreparedMountCapability {
    fn signed(&self, state: &VfsState) -> Result<String, ()> {
        sign_mount_storage_capability(
            &self.claims,
            self.purpose,
            state.io.signing_generation,
            state.io.signer.as_ref(),
        )
        .map_err(|_| ())
    }
}

#[derive(Clone, Copy)]
struct RangeSpec {
    operation: MountWriteRangeOperation,
    io_operation: MountIoOperation,
    capability_use: MountStorageCapabilityUse,
    range_start: i64,
    range_end: i64,
    content_blake3: Option<[u8; 32]>,
}

impl RangeSpec {
    fn mutates(self) -> bool {
        matches!(
            self.operation,
            MountWriteRangeOperation::WriteData
                | MountWriteRangeOperation::HoleDeallocate
                | MountWriteRangeOperation::Allocate
        )
    }
}

pub async fn dispatch(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    operation: &filebelt_vfs_protocol::vfs_request::Operation,
) -> DispatchResult {
    use filebelt_vfs_protocol::vfs_request::Operation;
    match operation {
        Operation::List(request) => {
            DispatchResult::ReadOnly(list(state, fence, session, request).await)
        }
        Operation::Stat(request) => {
            DispatchResult::ReadOnly(stat(state, fence, session, request).await)
        }
        Operation::Open(request) => {
            if request.requested_actions.iter().any(|value| {
                !matches!(
                    VfsAction::try_from(*value),
                    Ok(VfsAction::ReadMetadata | VfsAction::ReadContent)
                )
            }) {
                DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "open"))
            } else {
                open(state, fence, session, context, request).await
            }
        }
        Operation::Read(request) => {
            DispatchResult::ReadOnly(read(state, fence, session, request).await)
        }
        Operation::Close(request) => close(state, fence, session, context, request).await,
        Operation::Rename(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "rename")),
        Operation::Remove(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "remove")),
        Operation::SetAttributes(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "set_attributes"))
        }
        Operation::GetXattr(request) => {
            DispatchResult::ReadOnly(get_xattr(state, fence, session, request).await)
        }
        Operation::SetXattr(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "set_xattr"))
        }
        Operation::ListXattr(request) => {
            DispatchResult::ReadOnly(list_xattr(state, fence, session, request).await)
        }
        Operation::RemoveXattr(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "remove_xattr"))
        }
        Operation::Readlink(request) => {
            DispatchResult::ReadOnly(readlink(state, fence, session, request).await)
        }
        Operation::ResolveHandle(request) => {
            DispatchResult::ReadOnly(resolve_handle(state, fence, session, request).await)
        }
        Operation::ExportRoot(request) => {
            DispatchResult::ReadOnly(export_root(state, fence, session, request).await)
        }
        Operation::Lookup(request) => {
            DispatchResult::ReadOnly(lookup(state, fence, session, request).await)
        }
        Operation::Access(request) => {
            DispatchResult::ReadOnly(access(state, fence, session, request).await)
        }
        Operation::GetAcl(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "get_acl"))
        }
        Operation::LeaseAcknowledge(_) => {
            DispatchResult::ReadOnly(super::nfs_not_supported(fence, "lease_acknowledge"))
        }
        Operation::Heartbeat(_) => DispatchResult::ReadOnly(super::ok(fence)),
        Operation::Write(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "write")),
        // A worker-side cleanup can currently finish the byte-plane receipt
        // without an operation-specific DB transaction that finalizes the
        // stable client replay. Do not create such pending work until that
        // terminal-error surface exists.
        Operation::Flush(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "flush")),
        Operation::Commit(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "commit")),
        Operation::Create(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "create")),
        Operation::Mkdir(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "mkdir")),
        Operation::Lock(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "lock")),
        Operation::TestLock(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "test_lock"))
        }
        Operation::Unlock(_) => DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "unlock")),
        Operation::EndSession(request) => {
            end_session(state, fence, session, context, request).await
        }
        Operation::Symlink(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "symlink"))
        }
        Operation::SparseWrite(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "sparse_write"))
        }
        Operation::Reclaim(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "reclaim"))
        }
        Operation::OpenUnlinked(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "open_unlinked"))
        }
        Operation::FilesystemInfo(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "filesystem_info"))
        }
        Operation::SetAcl(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "set_acl"))
        }
        Operation::SparseControl(_) => {
            DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "sparse_control"))
        }
        Operation::Authenticate(_)
        | Operation::NfsAuthenticate(_)
        | Operation::AllocatePassivePort(_)
        | Operation::GatewayHello(_)
        | Operation::GatewayDrain(_)
        | Operation::GatewayReconcile(_) => DispatchResult::ReadOnly(invalid(fence)),
    }
}

async fn resolve_persistent_handle(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    handle: &[u8],
) -> Result<ResolvedTarget, VfsResponse> {
    let Some(runtime) = state.nfs.as_deref() else {
        return Err(VfsResponse::failure(
            fence.request_id,
            VfsError::NotSupported,
            "vfs.nfs_disabled",
        ));
    };
    let scope = match super::nfs::validate_handle(handle, &runtime.handle_keyring) {
        Ok(scope) => scope,
        Err(super::nfs::NfsHandleError::Malformed) => return Err(invalid(fence)),
        Err(super::nfs::NfsHandleError::Stale) => {
            return Err(stale(fence, "vfs.nfs_handle_stale"));
        }
    };
    if scope.tenant_id != fence.tenant_id {
        return Err(denied(fence, "vfs.resource_not_found"));
    }
    let (Ok(export_id), Ok(handle_generation), Ok(export_generation), Ok(restore_generation)) = (
        i64::try_from(scope.export_id),
        i64::try_from(scope.node_generation),
        i64::try_from(scope.export_generation),
        i64::try_from(scope.restore_generation),
    ) else {
        return Err(stale(fence, "vfs.nfs_handle_stale"));
    };
    let gss = gss_binding(fence).map_err(|()| invalid(fence))?;
    let resolution = match state
        .database
        .resolve_nfs_handle(
            session,
            gss,
            export_id,
            scope.node_id,
            Some(handle_generation),
        )
        .await
    {
        Ok(resolution) => resolution,
        Err(DatabaseError::NotFound | DatabaseError::StaleGeneration) => {
            return Err(stale(fence, "vfs.nfs_handle_stale"));
        }
        Err(_) => return Err(unavailable(fence, "vfs.nfs_handle_unavailable")),
    };
    if resolution.export_id != export_id
        || resolution.export_generation != export_generation
        || resolution.restore_generation != restore_generation
        || resolution.target.node_id != scope.node_id
        || resolution.target.handle_generation != handle_generation
        || session.nfs_manifest_generation != Some(resolution.manifest_generation)
        || !session.allowed_export_ids.contains(&export_id)
        || validate_resolution_path(&resolution).is_err()
    {
        return Err(stale(fence, "vfs.nfs_handle_stale"));
    }
    finish_resolution(state, fence, session, resolution).await
}

async fn resolve_identity(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    export_id: i64,
    node_id: Uuid,
) -> Result<ResolvedTarget, VfsResponse> {
    let resolution = match state
        .database
        .resolve_nfs_handle(
            session,
            gss_binding(fence).map_err(|()| invalid(fence))?,
            export_id,
            node_id,
            None,
        )
        .await
    {
        Ok(resolution) => resolution,
        Err(DatabaseError::NotFound | DatabaseError::StaleGeneration) => {
            return Err(denied(fence, "vfs.resource_not_found"));
        }
        Err(_) => return Err(unavailable(fence, "vfs.nfs_handle_unavailable")),
    };
    if resolution.export_id != export_id
        || resolution.target.node_id != node_id
        || validate_resolution_path(&resolution).is_err()
    {
        return Err(stale(fence, "vfs.nfs_handle_stale"));
    }
    finish_resolution(state, fence, session, resolution).await
}

async fn finish_resolution(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    resolution: NfsHandleResolution,
) -> Result<ResolvedTarget, VfsResponse> {
    let ancestors = resolution
        .path
        .iter()
        .take(resolution.path.len().saturating_sub(1))
        .map(|entry| entry.metadata.node_id)
        .collect::<Vec<_>>();
    let traversal_grants = if ancestors.is_empty() {
        Vec::new()
    } else {
        match super::policy::authorize_traverse(
            &state.database,
            session,
            gss_binding(fence).map_err(|()| invalid(fence))?,
            resolution.target.drive_id,
            &ancestors,
        )
        .await
        {
            Ok(grants) => grants,
            Err(()) => return Err(denied(fence, "vfs.resource_not_found")),
        }
    };
    if traversal_grants.len() != ancestors.len() {
        return Err(stale(fence, "vfs.authorization_changed"));
    }
    let mut traversal_fence = None;
    for (entry, grant) in resolution.path.iter().zip(&traversal_grants) {
        if grant.resource_acl_generation != entry.metadata.acl_generation
            || grant.resource_namespace_generation != entry.metadata.namespace_generation
            || merge_common_fence(&mut traversal_fence, grant.common_fence()).is_err()
        {
            return Err(stale(fence, "vfs.authorization_changed"));
        }
    }
    let node = match state
        .database
        .node(
            fence.tenant_id,
            resolution.target.drive_id,
            resolution.target.node_id,
        )
        .await
    {
        Ok(node) => node,
        Err(DatabaseError::NotFound) => return Err(denied(fence, "vfs.resource_not_found")),
        Err(_) => return Err(unavailable(fence, "vfs.database_unavailable")),
    };
    if node.id != resolution.target.node_id
        || node.drive_id != resolution.target.drive_id
        || node.parent_id != resolution.target.parent_id
        || node.kind != resolution.target.kind
        || node.namespace_generation != resolution.target.namespace_generation
        || node.acl_generation != resolution.target.acl_generation
        || node.trashed
    {
        return Err(stale(fence, "vfs.nfs_handle_stale"));
    }
    Ok(ResolvedTarget {
        export_id: resolution.export_id,
        resolution,
        node,
        traversal_fence,
    })
}

fn validate_resolution_path(resolution: &NfsHandleResolution) -> Result<(), ()> {
    if resolution.path.is_empty()
        || resolution.path.len() > 129
        || resolution.path.first().map(|entry| entry.metadata.node_id)
            != Some(resolution.root_node_id)
        || resolution.path.last().map(|entry| entry.metadata.node_id)
            != Some(resolution.target.node_id)
    {
        return Err(());
    }
    for (index, entry) in resolution.path.iter().enumerate() {
        if entry.depth != i32::try_from(resolution.path.len() - index - 1).map_err(|_| ())?
            || entry.metadata.drive_id != resolution.target.drive_id
            || (index + 1 < resolution.path.len() && entry.metadata.kind != "directory")
        {
            return Err(());
        }
        if let Some(child) = resolution.path.get(index + 1)
            && child.metadata.parent_id != Some(entry.metadata.node_id)
        {
            return Err(());
        }
    }
    Ok(())
}

async fn authorize(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    target: &ResolvedTarget,
    action: Action,
) -> Result<super::policy::AuthorizationGrant, VfsResponse> {
    let grant = super::policy::authorize_nfs(
        &state.database,
        session,
        gss_binding(fence).map_err(|()| invalid(fence))?,
        target.resolution.target.drive_id,
        target.resolution.target.node_id,
        action,
    )
    .await
    .map_err(|()| denied(fence, "vfs.resource_not_found"))?;
    if target
        .traversal_fence
        .is_some_and(|traversal| traversal != grant.common_fence())
        || grant.resource_acl_generation != target.resolution.target.acl_generation
        || grant.resource_namespace_generation != target.resolution.target.namespace_generation
    {
        return Err(stale(fence, "vfs.authorization_changed"));
    }
    Ok(grant)
}

fn merge_common_fence(
    current: &mut Option<super::policy::AuthorizationCommonFence>,
    next: super::policy::AuthorizationCommonFence,
) -> Result<(), ()> {
    if current.is_some_and(|current| current != next) {
        return Err(());
    }
    *current = Some(next);
    Ok(())
}

fn mutation_authorization(
    target: &ResolvedTarget,
    grant: super::policy::AuthorizationGrant,
) -> NfsMutationAuthorization {
    NfsMutationAuthorization {
        drive_id: target.resolution.target.drive_id,
        resource_id: target.resolution.target.node_id,
        membership_generation: grant.membership_generation,
        drive_acl_generation: grant.drive_acl_generation,
        drive_namespace_generation: grant.namespace_generation,
        resource_acl_generation: grant.resource_acl_generation,
        resource_namespace_generation: grant.resource_namespace_generation,
    }
}

fn gss_binding(fence: &RequestFence) -> Result<&[u8; 32], ()> {
    fence
        .nfs_context
        .as_ref()
        .map(|context| &context.gss_binding_digest)
        .ok_or(())
}

async fn admit_current_handle(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    handle_id: Uuid,
    required_action: &'static str,
    common_action: Action,
    requires_writable_session: bool,
) -> Result<MountHandleRecord, VfsResponse> {
    if handle_id.is_nil() || requires_writable_session && session.read_only {
        return Err(denied(fence, "vfs.resource_not_found"));
    }
    let handle = state
        .database
        .admit_mount_handle(session, handle_id, required_action)
        .await
        .map_err(|_| denied(fence, "vfs.handle_fence_stale"))?;
    let grant = super::policy::authorize_nfs(
        &state.database,
        session,
        gss_binding(fence).map_err(|()| invalid(fence))?,
        handle.drive_id,
        handle.node_id,
        common_action,
    )
    .await
    .map_err(|()| denied(fence, "vfs.resource_not_found"))?;
    if handle.id != handle_id
        || handle.session_id != session.session_id
        || handle.credential_generation != session.credential_generation
        || handle.authorization_generation != session.authorization_generation
        || handle.membership_generation != session.membership_generation
        || handle.gateway_epoch != session.gateway_epoch
        || grant.membership_generation != handle.membership_generation
        || grant.drive_acl_generation != handle.drive_acl_generation
        || grant.resource_namespace_generation != handle.namespace_generation
        || grant.resource_acl_generation != handle.resource_acl_generation
    {
        return Err(stale(fence, "vfs.authorization_changed"));
    }
    Ok(handle)
}

async fn read(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::ReadRequest,
) -> VfsResponse {
    let Ok(handle_id) = parse_non_nil_uuid(&request.handle_id) else {
        return invalid(fence);
    };
    let handle = match admit_current_handle(
        state,
        fence,
        session,
        handle_id,
        "READ_CONTENT",
        Action::ReadContent,
        false,
    )
    .await
    {
        Ok(handle) => handle,
        Err(response) => return response,
    };
    let initial_target = match resolve_mount_handle_target(state, fence, session, &handle).await {
        Ok(target) => target,
        Err(response) => return response,
    };
    let initial_grant =
        match authorize(state, fence, session, &initial_target, Action::ReadContent).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
    let Some(version_id) = handle.version_id.filter(|version_id| !version_id.is_nil()) else {
        return stale(fence, "vfs.handle_version_missing");
    };
    let payload = match state
        .database
        .payload_for_node(fence.tenant_id, handle.node_id, Some(version_id))
        .await
    {
        Ok(payload) => payload,
        Err(DatabaseError::NotFound) => return stale(fence, "vfs.handle_version_stale"),
        Err(_) => return unavailable(fence, "vfs.database_unavailable"),
    };
    let Ok(logical_size_bytes) = u64::try_from(payload.size_bytes) else {
        return unavailable(fence, "vfs.persisted_payload_invalid");
    };
    if payload.tenant_id != fence.tenant_id
        || payload.drive_id != handle.drive_id
        || payload.state != "referenced"
    {
        return stale(fence, "vfs.handle_version_stale");
    }
    let mut response = super::read_handle(state, fence, session, request).await;
    if response.error == VfsError::Ok as i32 {
        let final_handle = match admit_current_handle(
            state,
            fence,
            session,
            handle_id,
            "READ_CONTENT",
            Action::ReadContent,
            false,
        )
        .await
        {
            Ok(handle) => handle,
            Err(response) => return response,
        };
        if final_handle != handle {
            return stale(fence, "vfs.authorization_changed");
        }
        let final_target =
            match resolve_mount_handle_target(state, fence, session, &final_handle).await {
                Ok(target) => target,
                Err(response) => return response,
            };
        let final_grant =
            match authorize(state, fence, session, &final_target, Action::ReadContent).await {
                Ok(grant) => grant,
                Err(response) => return response,
            };
        if final_grant != initial_grant {
            return stale(fence, "vfs.authorization_changed");
        }
        response.end_of_file =
            match read_ends_at_eof(request.offset, response.data.len(), logical_size_bytes) {
                Ok(end_of_file) => end_of_file,
                Err(()) => return unavailable(fence, "vfs.storage_response_invalid"),
            };
    }
    response
}

async fn resolve_mount_handle_target(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    handle: &MountHandleRecord,
) -> Result<ResolvedTarget, VfsResponse> {
    let manifest = state
        .database
        .nfs_export_manifest(fence.tenant_id)
        .await
        .map_err(|_| unavailable(fence, "vfs.nfs_manifest_unavailable"))?;
    if session.nfs_manifest_generation != Some(manifest.manifest_generation)
        || session.nfs_restore_generation != Some(manifest.restore_generation)
    {
        return Err(stale(fence, "vfs.nfs_export_stale"));
    }
    let exports = manifest
        .exports
        .iter()
        .filter(|export| {
            export.drive_id == handle.drive_id
                && session.allowed_export_ids.contains(&export.export_id)
        })
        .collect::<Vec<_>>();
    let [export] = exports.as_slice() else {
        return Err(denied(fence, "vfs.resource_not_found"));
    };
    let target = resolve_identity(state, fence, session, export.export_id, handle.node_id).await?;
    if target.node.drive_id != handle.drive_id || target.node.id != handle.node_id {
        return Err(stale(fence, "vfs.nfs_handle_stale"));
    }
    Ok(target)
}

fn read_ends_at_eof(
    offset: u64,
    returned_bytes: usize,
    logical_size_bytes: u64,
) -> Result<bool, ()> {
    let returned_bytes = u64::try_from(returned_bytes).map_err(|_| ())?;
    if returned_bytes == 0 && offset >= logical_size_bytes {
        return Ok(true);
    }
    let returned_end = offset.checked_add(returned_bytes).ok_or(())?;
    if returned_end > logical_size_bytes {
        return Err(());
    }
    Ok(returned_end == logical_size_bytes)
}

fn write_fence(
    session: &MountSessionFence,
    handle: &MountHandleRecord,
    write_session_id: Uuid,
    fencing_token: i64,
) -> Result<MountWriteCapabilityFence, ()> {
    if session.tenant_id.is_nil()
        || session.user_principal_id.is_nil()
        || session.session_id.is_nil()
        || session.credential_id.is_nil()
        || write_session_id.is_nil()
        || fencing_token <= 0
        || handle.id.is_nil()
        || handle.drive_id.is_nil()
        || handle.node_id.is_nil()
        || handle
            .version_id
            .is_none_or(|version_id| version_id.is_nil())
    {
        return Err(());
    }
    Ok(MountWriteCapabilityFence {
        tenant_id: session.tenant_id,
        principal_id: session.user_principal_id,
        mount_session_id: session.session_id,
        credential_id: session.credential_id,
        handle_id: handle.id,
        drive_id: handle.drive_id,
        node_id: handle.node_id,
        version_id: handle.version_id,
        write_session_id,
        credential_generation: handle.credential_generation,
        authorization_generation: handle.authorization_generation,
        membership_generation: handle.membership_generation,
        drive_acl_generation: handle.drive_acl_generation,
        namespace_generation: handle.namespace_generation,
        resource_acl_generation: handle.resource_acl_generation,
        gateway_epoch: handle.gateway_epoch,
        fencing_token,
    })
}

fn parse_non_nil_uuid(value: &str) -> Result<Uuid, ()> {
    Uuid::parse_str(value)
        .ok()
        .filter(|value| !value.is_nil())
        .ok_or(())
}

#[derive(Debug, Eq, PartialEq)]
enum ReadOpenHeadError {
    MissingResolvedHead,
    InvalidExpectedHead,
    ExpectedHeadChanged,
}

fn bind_read_open_head(
    resolved_head: Option<Uuid>,
    expected_head: &str,
) -> Result<Uuid, ReadOpenHeadError> {
    let resolved_head = resolved_head
        .filter(|value| !value.is_nil())
        .ok_or(ReadOpenHeadError::MissingResolvedHead)?;
    if expected_head.is_empty() {
        return Ok(resolved_head);
    }
    let expected_head =
        parse_non_nil_uuid(expected_head).map_err(|()| ReadOpenHeadError::InvalidExpectedHead)?;
    if expected_head != resolved_head {
        return Err(ReadOpenHeadError::ExpectedHeadChanged);
    }
    Ok(resolved_head)
}

fn positive_i64(value: u64) -> Result<i64, ()> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(())
}

fn positive_u64_claim(value: i64) -> Result<u64, ()> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(())
}

fn prepare_mount_capability(
    write: &MountWriteCapabilityFence,
    purpose: MountStorageCapabilityUse,
    range_start: u64,
    range_end: u64,
    content_blake3: Option<[u8; 32]>,
) -> Result<PreparedMountCapability, ()> {
    let version_id = write.version_id.filter(|value| !value.is_nil()).ok_or(())?;
    if write.tenant_id.is_nil()
        || write.principal_id.is_nil()
        || write.mount_session_id.is_nil()
        || write.credential_id.is_nil()
        || write.handle_id.is_nil()
        || write.drive_id.is_nil()
        || write.node_id.is_nil()
        || write.write_session_id.is_nil()
        || range_end < range_start
        || matches!(
            purpose,
            MountStorageCapabilityUse::SeekData | MountStorageCapabilityUse::SeekHole
        ) && range_start != range_end
        || matches!(
            purpose,
            MountStorageCapabilityUse::Flush
                | MountStorageCapabilityUse::Finalize
                | MountStorageCapabilityUse::Abort
                | MountStorageCapabilityUse::DeleteStaging
        ) && (range_start != 0 || range_end != 0)
        || (purpose == MountStorageCapabilityUse::WriteData) != content_blake3.is_some()
        || purpose != MountStorageCapabilityUse::WriteData && content_blake3.is_some()
    {
        return Err(());
    }
    let issued_at_unix_seconds = unix_time_now().map_err(|_| ())?;
    let expires_at_unix_seconds = issued_at_unix_seconds
        .checked_add(MOUNT_CAPABILITY_LIFETIME_SECONDS)
        .ok_or(())?;
    let capability_id = Uuid::new_v4();
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ())?;
    let claims = MountCapabilityClaims {
        capability_id: capability_id.to_string(),
        audience: MOUNT_CAPABILITY_AUDIENCE.to_owned(),
        operation: purpose.operation() as i32,
        tenant_id: write.tenant_id.to_string(),
        principal_id: write.principal_id.to_string(),
        mount_session_id: write.mount_session_id.to_string(),
        credential_id: write.credential_id.to_string(),
        drive_id: write.drive_id.to_string(),
        resource_id: write.node_id.to_string(),
        version_id: version_id.to_string(),
        write_session_id: write.write_session_id.to_string(),
        range_start,
        range_end,
        credential_generation: positive_u64_claim(write.credential_generation)?,
        authorization_generation: positive_u64_claim(write.authorization_generation)?,
        membership_generation: positive_u64_claim(write.membership_generation)?,
        drive_acl_generation: positive_u64_claim(write.drive_acl_generation)?,
        namespace_generation: positive_u64_claim(write.namespace_generation)?,
        resource_acl_generation: positive_u64_claim(write.resource_acl_generation)?,
        gateway_epoch: positive_u64_claim(write.gateway_epoch)?,
        fencing_token: positive_u64_claim(write.fencing_token)?,
        nonce: nonce.to_vec(),
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        grant_id: write.handle_id.to_string(),
        content_blake3: content_blake3.map_or_else(Vec::new, Vec::from),
    };
    let nonce_digest = mount_nonce_digest(&nonce);
    let claims_digest = mount_capability_claims_digest(&claims);
    Ok(PreparedMountCapability {
        claims,
        purpose,
        capability_id,
        nonce_digest,
        claims_digest,
    })
}

fn mount_nonce_digest(nonce: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MOUNT_CAPABILITY_NONCE_DOMAIN);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

fn validate_mount_storage(
    runtime: &super::NfsRuntime,
    write: &MountWriteCapabilityFence,
    storage: &MountWriteStorageRecord,
) -> Result<(), ()> {
    if storage.write_session_id != write.write_session_id
        || storage.base_version_id != write.version_id
        || storage.logical_size_bytes < 0
        || storage.reserved_bytes < storage.logical_size_bytes
        || storage.state != "open"
        || storage.staging_payload.tenant_id != write.tenant_id
        || storage.staging_payload.drive_id != write.drive_id
        || storage.staging_payload.backend_id != runtime.backend_id
        || storage.staging_payload.payload_id.is_nil()
        || storage.staging_payload.locator.is_nil()
        || storage.staging_payload.layout != "chunked"
        || storage.staging_payload.state != "staging"
        || storage.base_payload.as_ref().is_some_and(|payload| {
            payload.tenant_id != write.tenant_id
                || payload.drive_id != write.drive_id
                || payload.backend_id != runtime.backend_id
                || payload.payload_id.is_nil()
                || payload.locator.is_nil()
                || !matches!(payload.layout.as_str(), "whole" | "chunked")
                || payload.state != "referenced"
                || payload.size_bytes < 0
                || payload.size_bytes > storage.reserved_bytes
                || payload
                    .blake3
                    .as_ref()
                    .is_none_or(|digest| digest.len() != 32)
        })
        || validate_base_parts(storage, runtime.chunk_size_bytes).is_err()
    {
        return Err(());
    }
    Ok(())
}

fn validate_base_parts(storage: &MountWriteStorageRecord, chunk_size_bytes: u64) -> Result<(), ()> {
    let chunk_size = i64::try_from(chunk_size_bytes)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(())?;
    let Some(base) = storage.base_payload.as_ref() else {
        return storage.base_parts.is_empty().then_some(()).ok_or(());
    };
    if base.layout == "whole" {
        return storage.base_parts.is_empty().then_some(()).ok_or(());
    }
    if base.layout != "chunked" || storage.base_parts.len() > MAX_MOUNT_CHUNKS {
        return Err(());
    }
    let mut represented = 0_i64;
    let mut locators = HashSet::with_capacity(storage.base_parts.len());
    for (index, part) in storage.base_parts.iter().enumerate() {
        if part.chunk_number != i64::try_from(index).map_err(|_| ())?
            || part.locator.is_nil()
            || !locators.insert(part.locator)
            || part.size_bytes <= 0
            || part.size_bytes > chunk_size
            || index + 1 < storage.base_parts.len() && part.size_bytes != chunk_size
        {
            return Err(());
        }
        represented = represented.checked_add(part.size_bytes).ok_or(())?;
    }
    (represented == base.size_bytes).then_some(()).ok_or(())
}

fn required_reservation(
    storage: &MountWriteStorageRecord,
    operation: MountWriteRangeOperation,
    range_end: i64,
    max_file_bytes: u64,
) -> Result<i64, ()> {
    let max_file_bytes = i64::try_from(max_file_bytes).map_err(|_| ())?;
    let end_exclusive = range_end.checked_add(1).ok_or(())?;
    let required = match operation {
        MountWriteRangeOperation::WriteData | MountWriteRangeOperation::Allocate => {
            storage.reserved_bytes.max(end_exclusive)
        }
        MountWriteRangeOperation::HoleDeallocate
        | MountWriteRangeOperation::SeekData
        | MountWriteRangeOperation::SeekHole => storage.reserved_bytes,
    };
    if required <= range_end || required <= 0 || required > max_file_bytes {
        return Err(());
    }
    Ok(required)
}

fn build_mount_chunk_plan(
    storage: &MountWriteStorageRecord,
    required_reservation_bytes: i64,
    chunk_size_bytes: u64,
) -> Result<Vec<MountWriteChunkPlan>, ()> {
    let chunk_size = i64::try_from(chunk_size_bytes)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(())?;
    let required_chunk_count = required_reservation_bytes
        .checked_add(chunk_size - 1)
        .and_then(|bytes| bytes.checked_div(chunk_size))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(())?;
    if required_reservation_bytes < storage.reserved_bytes
        || required_reservation_bytes <= 0
        || storage.planned_chunks.len() > MAX_MOUNT_CHUNKS
        || required_chunk_count > MAX_MOUNT_CHUNKS
    {
        return Err(());
    }
    let base_payload_id = storage
        .base_payload
        .as_ref()
        .map(|payload| payload.payload_id);
    let base_size = storage
        .base_payload
        .as_ref()
        .map_or(0, |payload| payload.size_bytes);
    let mut locator_set = HashSet::with_capacity(storage.planned_chunks.len());
    let mut represented = 0_i64;
    for (index, chunk) in storage.planned_chunks.iter().enumerate() {
        let chunk_number = i64::try_from(index).map_err(|_| ())?;
        let chunk_offset = chunk_number.checked_mul(chunk_size).ok_or(())?;
        let expected_source = if chunk_offset < base_size {
            (base_payload_id, Some(chunk_number))
        } else {
            (None, None)
        };
        if chunk.chunk_number != chunk_number
            || chunk.size_bytes <= 0
            || chunk.size_bytes > chunk_size
            || index + 1 < storage.planned_chunks.len() && chunk.size_bytes != chunk_size
            || chunk.staging_locator.is_nil()
            || !locator_set.insert(chunk.staging_locator)
            || (chunk.source_payload_id, chunk.source_chunk_number) != expected_source
            || !chunk.dirty
        {
            return Err(());
        }
        represented = represented.checked_add(chunk.size_bytes).ok_or(())?;
    }
    if represented != storage.reserved_bytes {
        return Err(());
    }

    let mut chunks = storage.planned_chunks.clone();
    let mut remaining = required_reservation_bytes
        .checked_sub(represented)
        .ok_or(())?;
    if remaining > 0
        && let Some(tail) = chunks.last_mut()
        && tail.size_bytes < chunk_size
    {
        let growth = remaining.min(chunk_size - tail.size_bytes);
        tail.size_bytes = tail.size_bytes.checked_add(growth).ok_or(())?;
        remaining -= growth;
    }
    while remaining > 0 {
        let chunk_number = i64::try_from(chunks.len()).map_err(|_| ())?;
        let chunk_offset = chunk_number.checked_mul(chunk_size).ok_or(())?;
        let size_bytes = remaining.min(chunk_size);
        let (source_payload_id, source_chunk_number) = if chunk_offset < base_size {
            (base_payload_id, Some(chunk_number))
        } else {
            (None, None)
        };
        let mut staging_locator = Uuid::new_v4();
        while !locator_set.insert(staging_locator) {
            staging_locator = Uuid::new_v4();
        }
        chunks.push(MountWriteChunkPlan {
            chunk_number,
            source_payload_id,
            source_chunk_number,
            staging_locator,
            size_bytes,
            dirty: true,
        });
        remaining -= size_bytes;
    }
    let planned = chunks
        .iter()
        .try_fold(0_i64, |total, chunk| total.checked_add(chunk.size_bytes))
        .ok_or(())?;
    if planned != required_reservation_bytes {
        return Err(());
    }
    Ok(chunks)
}

async fn mount_io_json<T: for<'de> Deserialize<'de>>(
    state: &VfsState,
    fence: &RequestFence,
    method: Method,
    path: &str,
    capability: &str,
    body: Option<Vec<u8>>,
) -> Result<T, DispatchResult> {
    let url = state
        .io
        .io_url
        .join(path)
        .map_err(|_| DispatchResult::Retryable(unavailable(fence, "vfs.io_url_invalid")))?;
    let mut request = state
        .io
        .http
        .request(method, url)
        .header(reqwest::header::AUTHORIZATION, capability);
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| DispatchResult::Retryable(unavailable(fence, "vfs.storage_unavailable")))?;
    if !response.status().is_success() {
        let result = if response.status() == reqwest::StatusCode::NOT_IMPLEMENTED {
            VfsResponse::failure(
                fence.request_id,
                VfsError::NotSupported,
                "vfs.nfs_sparse_storage_unsupported",
            )
        } else if response.status() == reqwest::StatusCode::CONFLICT {
            VfsResponse::failure(fence.request_id, VfsError::Conflict, "vfs.mount_io_pending")
        } else if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            stale(fence, "vfs.authorization_changed")
        } else {
            unavailable(fence, "vfs.storage_unavailable")
        };
        return Err(DispatchResult::Retryable(result));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MOUNT_IO_RESPONSE_BYTES as u64)
    {
        return Err(DispatchResult::Retryable(unavailable(
            fence,
            "vfs.storage_response_invalid",
        )));
    }
    let mut bytes = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|_| {
            DispatchResult::Retryable(unavailable(fence, "vfs.storage_unavailable"))
        })?;
        let Some(chunk) = chunk else { break };
        if bytes.len().saturating_add(chunk.len()) > MAX_MOUNT_IO_RESPONSE_BYTES {
            return Err(DispatchResult::Retryable(unavailable(
                fence,
                "vfs.storage_response_invalid",
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid")))
}

fn range_success_response(
    fence: &RequestFence,
    write: &MountWriteCapabilityFence,
    spec: RangeSpec,
    completion: &MountIoCompletion,
) -> Result<VfsResponse, ()> {
    match completion {
        MountIoCompletion::RangeMutation {
            logical_size_bytes,
            reservation_delta_bytes,
        } if spec.mutates() && *logical_size_bytes >= 0 && *reservation_delta_bytes >= 0 => {
            Ok(VfsResponse {
                protocol_version: PROTOCOL_VERSION,
                request_id: fence.request_id.to_string(),
                error: VfsError::Ok as i32,
                write_session_id: write.write_session_id.to_string(),
                fencing_token: positive_u64_claim(write.fencing_token)?,
                ..VfsResponse::default()
            })
        }
        MountIoCompletion::Seek { offset } if !spec.mutates() => Ok(VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: fence.request_id.to_string(),
            error: VfsError::Ok as i32,
            write_session_id: write.write_session_id.to_string(),
            fencing_token: positive_u64_claim(write.fencing_token)?,
            sparse_offset: offset
                .map(u64::try_from)
                .transpose()
                .map_err(|_| ())?
                .unwrap_or(0),
            end_of_file: offset.is_none(),
            ..VfsResponse::default()
        }),
        _ => Err(()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_range_result(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    write: &MountWriteCapabilityFence,
    spec: RangeSpec,
    stable_operation_id: Uuid,
    completion: MountIoCompletion,
) -> DispatchResult {
    let response = match range_success_response(fence, write, spec, &completion) {
        Ok(response) => response,
        Err(()) => {
            return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
        }
    };
    let (response_bytes, response_digest) = response_template(&response);
    let replay = RecordNfsReplayReceiptInput {
        context: context.clone(),
        response_bytes: &response_bytes,
        response_digest: &response_digest,
    };
    let result = if spec.mutates() {
        state
            .database
            .apply_nfs_write_extent(&ApplyNfsWriteExtentInput {
                session,
                gss_binding_digest: match gss_binding(fence) {
                    Ok(value) => value,
                    Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
                },
                fence: write,
                replay,
                operation_id: stable_operation_id,
                operation: spec.operation,
                range_start: spec.range_start,
                range_end: spec.range_end,
                data_digest: spec.content_blake3.as_ref(),
            })
            .await
    } else {
        state
            .database
            .seek_nfs_write_extent(&SeekNfsWriteExtentInput {
                session,
                gss_binding_digest: match gss_binding(fence) {
                    Ok(value) => value,
                    Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
                },
                fence: write,
                replay,
                operation_id: stable_operation_id,
                operation: spec.operation,
                range_start: spec.range_start,
                range_end: spec.range_end,
            })
            .await
    };
    match result {
        Ok(result) => DispatchResult::Atomic(decode_nfs_replay(fence, &result.replay)),
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration) => {
            DispatchResult::Retryable(stale(fence, "vfs.mount_io_result_pending"))
        }
        Err(error) => {
            DispatchResult::Retryable(mutation_error(fence, error, "vfs.mount_io_apply_failed"))
        }
    }
}

fn issue_handle_for_tenant(
    state: &VfsState,
    tenant_id: Uuid,
    target: &ResolvedTarget,
) -> Result<Vec<u8>, ()> {
    let runtime = state.nfs.as_deref().ok_or(())?;
    Ok(super::nfs::issue_handle(
        super::nfs::NfsHandleScope {
            tenant_id,
            export_id: u64::try_from(target.export_id).map_err(|_| ())?,
            node_id: target.resolution.target.node_id,
            export_generation: u64::try_from(target.resolution.export_generation)
                .map_err(|_| ())?,
            node_generation: u64::try_from(target.resolution.target.handle_generation)
                .map_err(|_| ())?,
            restore_generation: u64::try_from(target.resolution.restore_generation)
                .map_err(|_| ())?,
        },
        runtime.handle_keyring.current(),
    )
    .to_vec())
}

fn attributes(target: &ResolvedTarget, read_only: bool) -> Result<NodeAttributes, ()> {
    let metadata = &target.resolution.target;
    let kind = match metadata.kind.as_str() {
        "file" => NodeKind::File,
        "directory" => NodeKind::Directory,
        "symlink" => NodeKind::Symlink,
        _ => return Err(()),
    };
    let size_bytes = match kind {
        NodeKind::File => {
            u64::try_from(target.node.size_bytes.unwrap_or_default()).map_err(|_| ())?
        }
        NodeKind::Directory => 0,
        NodeKind::Symlink => {
            u64::try_from(metadata.symlink_target.as_deref().ok_or(())?.len()).map_err(|_| ())?
        }
        NodeKind::Unspecified => return Err(()),
    };
    let head_version_id = if kind == NodeKind::File {
        target
            .node
            .head_version_id
            .map_or_else(String::new, |value| value.to_string())
    } else {
        String::new()
    };
    let mode = u32::try_from(metadata.posix_mode).map_err(|_| ())?;
    let projected_uid = positive_generation(metadata.projected_uid)?;
    let projected_gid = positive_generation(metadata.projected_gid)?;
    if mode & !0o777 != 0 || projected_uid > 4_294_967_294 || projected_gid > 4_294_967_294 {
        return Err(());
    }
    Ok(NodeAttributes {
        kind: kind as i32,
        size_bytes,
        head_version_id,
        namespace_generation: positive_generation(metadata.namespace_generation)?,
        acl_generation: positive_generation(metadata.acl_generation)?,
        modified_at_unix_seconds: metadata.modified_at_unix_seconds,
        read_only,
        mode,
        projected_uid,
        projected_gid,
        link_count: if kind == NodeKind::Directory { 2 } else { 1 },
        sparse: false,
        accessed_at_unix_seconds: metadata.accessed_at_unix_seconds,
        created_at_unix_seconds: metadata.created_at_unix_seconds,
        changed_at_unix_seconds: metadata.changed_at_unix_seconds,
        owner_name: metadata.owner_name.clone(),
        group_name: metadata.group_name.clone(),
    })
}

fn positive_generation(value: i64) -> Result<u64, ()> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(())
}

async fn resolve_handle(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::ResolveHandleRequest,
) -> VfsResponse {
    let target =
        match resolve_persistent_handle(state, fence, session, &request.persistent_handle).await {
            Ok(target) => target,
            Err(response) => return response,
        };
    if let Err(response) = authorize(state, fence, session, &target, Action::ReadMetadata).await {
        return response;
    }
    target_response(state, fence, session, &target)
}

async fn export_root(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::ExportRootRequest,
) -> VfsResponse {
    let Ok(export_id) = i64::try_from(request.export_id) else {
        return invalid(fence);
    };
    if !session.allowed_export_ids.contains(&export_id) {
        return denied(fence, "vfs.resource_not_found");
    }
    let manifest = match state.database.nfs_export_manifest(fence.tenant_id).await {
        Ok(manifest) => manifest,
        Err(_) => return unavailable(fence, "vfs.nfs_manifest_unavailable"),
    };
    let Some(export) = manifest
        .exports
        .iter()
        .find(|entry| entry.export_id == export_id)
    else {
        return denied(fence, "vfs.resource_not_found");
    };
    let target = match resolve_identity(state, fence, session, export_id, export.root_node_id).await
    {
        Ok(target) => target,
        Err(response) => return response,
    };
    if target.resolution.target.node_id != target.resolution.root_node_id
        || target.resolution.target.kind != "directory"
    {
        return stale(fence, "vfs.nfs_export_stale");
    }
    if let Err(response) = authorize(state, fence, session, &target, Action::Traverse).await {
        return response;
    }
    target_response(state, fence, session, &target)
}

async fn lookup(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::LookupRequest,
) -> VfsResponse {
    let parent =
        match resolve_persistent_handle(state, fence, session, &request.parent_handle).await {
            Ok(parent) => parent,
            Err(response) => return response,
        };
    if parent.resolution.target.kind != "directory" {
        return VfsResponse::failure(
            fence.request_id,
            VfsError::NotDirectory,
            "vfs.not_directory",
        );
    }
    if let Err(response) = authorize(state, fence, session, &parent, Action::Traverse).await {
        return response;
    }
    let name = match NormalizedName::new(&request.display_name) {
        Ok(name) => name,
        Err(_) => return invalid(fence),
    };
    let children = match state
        .database
        .list_children(fence.tenant_id, parent.node.drive_id, parent.node.id)
        .await
    {
        Ok(children) => children,
        Err(_) => return unavailable(fence, "vfs.database_unavailable"),
    };
    let Some(child) = children
        .into_iter()
        .find(|child| child.name_key == name.comparison_key())
    else {
        return denied(fence, "vfs.resource_not_found");
    };
    let target = match resolve_identity(state, fence, session, parent.export_id, child.id).await {
        Ok(target) if target.node.parent_id == Some(parent.node.id) => target,
        Ok(_) => return denied(fence, "vfs.resource_not_found"),
        Err(response) => return response,
    };
    if let Err(response) = authorize(state, fence, session, &target, Action::ReadMetadata).await {
        return response;
    }
    target_response(state, fence, session, &target)
}

async fn stat(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::StatRequest,
) -> VfsResponse {
    if request.persistent_handle.is_empty() {
        return invalid(fence);
    }
    let target =
        match resolve_persistent_handle(state, fence, session, &request.persistent_handle).await {
            Ok(target) => target,
            Err(response) => return response,
        };
    if request.drive_id != target.node.drive_id.to_string()
        || request.resource_id != target.node.id.to_string()
    {
        return denied(fence, "vfs.resource_not_found");
    }
    if let Err(response) = authorize(state, fence, session, &target, Action::ReadMetadata).await {
        return response;
    }
    target_response(state, fence, session, &target)
}

fn target_response(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    target: &ResolvedTarget,
) -> VfsResponse {
    let (Ok(persistent_handle), Ok(attributes)) = (
        issue_handle_for_tenant(state, fence.tenant_id, target),
        attributes(target, session.read_only),
    ) else {
        return unavailable(fence, "vfs.persisted_node_invalid");
    };
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        resource_id: target.node.id.to_string(),
        export_id: u64::try_from(target.export_id).unwrap_or_default(),
        persistent_handle,
        attributes: Some(attributes),
        ..VfsResponse::default()
    }
}

async fn list(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::ListRequest,
) -> VfsResponse {
    if request.directory_handle.is_empty() {
        return invalid(fence);
    }
    let parent =
        match resolve_persistent_handle(state, fence, session, &request.directory_handle).await {
            Ok(parent) => parent,
            Err(response) => return response,
        };
    if request.drive_id != parent.node.drive_id.to_string()
        || request.directory_id != parent.node.id.to_string()
    {
        return denied(fence, "vfs.resource_not_found");
    }
    if parent.resolution.target.kind != "directory" {
        return VfsResponse::failure(
            fence.request_id,
            VfsError::NotDirectory,
            "vfs.not_directory",
        );
    }
    let initial_parent_grant = match authorize_list_parent(state, fence, session, &parent).await {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let cursor = if request.cursor.is_empty() {
        None
    } else {
        match decode_cursor(&request.cursor) {
            Ok(cursor) => Some(cursor),
            Err(()) => return invalid(fence),
        }
    };
    let children = match state
        .database
        .list_children(fence.tenant_id, parent.node.drive_id, parent.node.id)
        .await
    {
        Ok(children) => children,
        Err(_) => return unavailable(fence, "vfs.database_unavailable"),
    };
    let limit = request.limit as usize;
    let mut visible = Vec::new();
    for child in children {
        if cursor
            .as_ref()
            .is_some_and(|cursor| compare_cursor(&child, cursor) != Ordering::Greater)
        {
            continue;
        }
        let target = match resolve_identity(state, fence, session, parent.export_id, child.id).await
        {
            Ok(target) if target.node.parent_id == Some(parent.node.id) => target,
            Ok(_) => continue,
            Err(response)
                if matches!(
                    VfsError::try_from(response.error),
                    Ok(VfsError::NotFound | VfsError::StaleGeneration)
                ) =>
            {
                continue;
            }
            Err(response) => return response,
        };
        if authorize(state, fence, session, &target, Action::ReadMetadata)
            .await
            .is_err()
        {
            continue;
        }
        let (Ok(attributes), Ok(persistent_handle)) = (
            attributes(&target, session.read_only),
            issue_handle_for_tenant(state, fence.tenant_id, &target),
        ) else {
            return unavailable(fence, "vfs.persisted_node_invalid");
        };
        visible.push((
            target.node.clone(),
            DirectoryEntry {
                resource_id: target.node.id.to_string(),
                display_name: target.node.display_name.clone(),
                attributes: Some(attributes),
                persistent_handle,
            },
        ));
        if visible.len() > limit {
            break;
        }
    }
    let next_cursor = if visible.len() > limit {
        visible.pop();
        visible
            .last()
            .map(|(node, _)| encode_cursor(node))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let final_parent_grant = match authorize_list_parent(state, fence, session, &parent).await {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if final_parent_grant != initial_parent_grant {
        return stale(fence, "vfs.authorization_changed");
    }
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        entries: visible.into_iter().map(|(_, entry)| entry).collect(),
        next_cursor,
        ..VfsResponse::default()
    }
}

async fn authorize_list_parent(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    parent: &ResolvedTarget,
) -> Result<super::policy::AuthorizationGrant, VfsResponse> {
    let traverse = authorize(state, fence, session, parent, Action::Traverse).await?;
    let list = authorize(state, fence, session, parent, Action::ListChildren).await?;
    if traverse != list {
        return Err(stale(fence, "vfs.authorization_changed"));
    }
    Ok(traverse)
}

fn encode_cursor(node: &NodeRecord) -> String {
    URL_SAFE_NO_PAD.encode(format!("{}\0{}\0{}", node.kind, node.name_key, node.id))
}

fn decode_cursor(value: &str) -> Result<NodeCursor, ()> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    let decoded = String::from_utf8(bytes).map_err(|_| ())?;
    let mut fields = decoded.split('\0');
    let kind = fields.next().unwrap_or_default().to_owned();
    let name_key = fields.next().unwrap_or_default().to_owned();
    let id = Uuid::parse_str(fields.next().unwrap_or_default()).map_err(|_| ())?;
    if fields.next().is_some()
        || id.is_nil()
        || name_key.is_empty()
        || !matches!(kind.as_str(), "file" | "directory" | "symlink")
    {
        return Err(());
    }
    Ok(NodeCursor { kind, name_key, id })
}

fn compare_cursor(node: &NodeRecord, cursor: &NodeCursor) -> Ordering {
    node.kind
        .cmp(&cursor.kind)
        .reverse()
        .then_with(|| node.name_key.cmp(&cursor.name_key))
        .then_with(|| node.id.cmp(&cursor.id))
}

async fn access(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::AccessRequest,
) -> VfsResponse {
    let target =
        match resolve_persistent_handle(state, fence, session, &request.persistent_handle).await {
            Ok(target) => target,
            Err(response) => return response,
        };
    let mut allowed_actions = Vec::new();
    let mut allowed_common_actions = Vec::new();
    let mut coherent_grant = None;
    for requested in &request.requested_actions {
        let Ok(action) = VfsAction::try_from(*requested) else {
            return invalid(fence);
        };
        if !access_action_has_qualified_handler(action, &target.node.kind) {
            continue;
        }
        let Some(common) = common_action(action) else {
            continue;
        };
        if session.read_only && action_mutates(action) {
            continue;
        }
        if let Ok(grant) = authorize(state, fence, session, &target, common).await {
            if merge_coherent_grant(&mut coherent_grant, grant).is_err() {
                return stale(fence, "vfs.authorization_changed");
            }
            allowed_actions.push(*requested);
            allowed_common_actions.push(common);
        }
    }
    if let Some(expected_grant) = coherent_grant {
        for action in allowed_common_actions {
            let grant = match authorize(state, fence, session, &target, action).await {
                Ok(grant) => grant,
                Err(response) => return response,
            };
            if grant != expected_grant {
                return stale(fence, "vfs.authorization_changed");
            }
        }
    }
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        allowed_actions,
        ..VfsResponse::default()
    }
}

fn merge_coherent_grant(
    current: &mut Option<super::policy::AuthorizationGrant>,
    next: super::policy::AuthorizationGrant,
) -> Result<(), ()> {
    if current.is_some_and(|current| current != next) {
        return Err(());
    }
    *current = Some(next);
    Ok(())
}

/// ACCESS reports the intersection of current common ACL authority and the
/// operations this VFS can actually execute for this target. Namespace and
/// metadata mutations remain held until their handle-generation semantics are
/// qualified, so ACCESS never advertises them.
fn access_action_has_qualified_handler(action: VfsAction, target_kind: &str) -> bool {
    match action {
        VfsAction::ReadMetadata => true,
        VfsAction::ReadContent => target_kind == "file",
        VfsAction::ListChildren | VfsAction::Traverse => target_kind == "directory",
        VfsAction::Unspecified
        | VfsAction::CreateChild
        | VfsAction::WriteContent
        | VfsAction::Delete
        | VfsAction::Rename
        | VfsAction::Move
        | VfsAction::WriteMetadata
        | VfsAction::ManageLock
        | VfsAction::ManageAcl => false,
    }
}

const fn common_action(action: VfsAction) -> Option<Action> {
    match action {
        VfsAction::ReadMetadata => Some(Action::ReadMetadata),
        VfsAction::ReadContent => Some(Action::ReadContent),
        VfsAction::CreateChild => Some(Action::CreateChild),
        VfsAction::WriteContent => Some(Action::WriteContent),
        VfsAction::Delete => Some(Action::Delete),
        VfsAction::Rename => Some(Action::Rename),
        VfsAction::Move => Some(Action::Move),
        VfsAction::WriteMetadata => Some(Action::SetAttributes),
        VfsAction::ManageLock => None,
        VfsAction::ListChildren => Some(Action::ListChildren),
        VfsAction::Traverse => Some(Action::Traverse),
        VfsAction::ManageAcl => Some(Action::ManageAcl),
        VfsAction::Unspecified => None,
    }
}

const fn action_mutates(action: VfsAction) -> bool {
    matches!(
        action,
        VfsAction::CreateChild
            | VfsAction::WriteContent
            | VfsAction::Delete
            | VfsAction::Rename
            | VfsAction::Move
            | VfsAction::WriteMetadata
            | VfsAction::ManageAcl
    )
}

async fn open(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    request: &filebelt_vfs_protocol::OpenRequest,
) -> DispatchResult {
    if request.persistent_handle.is_empty() {
        return DispatchResult::ReadOnly(invalid(fence));
    }
    let target =
        match resolve_persistent_handle(state, fence, session, &request.persistent_handle).await {
            Ok(target) => target,
            Err(response) => return DispatchResult::ReadOnly(response),
        };
    if request.drive_id != target.node.drive_id.to_string()
        || request.resource_id != target.node.id.to_string()
        || target.node.kind != "file"
    {
        return DispatchResult::ReadOnly(denied(fence, "vfs.resource_not_found"));
    }
    let mut selected_grant = None;
    let mut actions = Vec::with_capacity(request.requested_actions.len());
    for requested in &request.requested_actions {
        let Ok(requested) = VfsAction::try_from(*requested) else {
            return DispatchResult::ReadOnly(invalid(fence));
        };
        let (common, persisted) = match requested {
            VfsAction::ReadMetadata => (Action::ReadMetadata, "READ_METADATA"),
            VfsAction::ReadContent => (Action::ReadContent, "READ_CONTENT"),
            _ => {
                return DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "open"));
            }
        };
        let grant = match authorize(state, fence, session, &target, common).await {
            Ok(grant) => grant,
            Err(response) => return DispatchResult::ReadOnly(response),
        };
        if selected_grant.is_some_and(|existing| existing != grant) {
            return DispatchResult::ReadOnly(stale(fence, "vfs.authorization_changed"));
        }
        selected_grant = Some(grant);
        actions.push(persisted.to_owned());
    }
    let Some(grant) = selected_grant else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let resolved_head =
        match bind_read_open_head(target.node.head_version_id, &request.expected_version_id) {
            Ok(resolved_head) => resolved_head,
            Err(ReadOpenHeadError::MissingResolvedHead) => {
                return DispatchResult::ReadOnly(stale(fence, "vfs.handle_version_missing"));
            }
            Err(ReadOpenHeadError::InvalidExpectedHead) => {
                return DispatchResult::ReadOnly(invalid(fence));
            }
            Err(ReadOpenHeadError::ExpectedHeadChanged) => {
                return DispatchResult::ReadOnly(stale(fence, "vfs.handle_version_stale"));
            }
        };
    let handle_id = Uuid::new_v4();
    let success = VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        handle_id: handle_id.to_string(),
        version_id: resolved_head.to_string(),
        ..VfsResponse::default()
    };
    let conflict = VfsResponse::failure(
        fence.request_id,
        VfsError::Conflict,
        "vfs.share_mode_conflict",
    );
    let (success_bytes, success_digest) = response_template(&success);
    let (conflict_bytes, conflict_digest) = response_template(&conflict);
    match state
        .database
        .open_nfs_mount_handle(&OpenNfsHandleInput {
            session,
            gss_binding_digest: match gss_binding(fence) {
                Ok(value) => value,
                Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
            },
            replay: RecordNfsReplayReceiptInput {
                context: context.clone(),
                response_bytes: &success_bytes,
                response_digest: &success_digest,
            },
            conflict_response_bytes: &conflict_bytes,
            conflict_response_digest: &conflict_digest,
            handle_id,
            authorization: mutation_authorization(&target, grant),
            expected_version_id: Some(resolved_head),
            access_actions: &actions,
            share_read: request.share_read,
            share_write: request.share_write,
            share_delete: request.share_delete,
        })
        .await
    {
        Ok(result) => DispatchResult::Atomic(decode_nfs_replay(fence, &result.replay)),
        Err(error) => {
            DispatchResult::ReadOnly(mutation_error(fence, error, "vfs.handle_open_failed"))
        }
    }
}

async fn close(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    request: &filebelt_vfs_protocol::CloseRequest,
) -> DispatchResult {
    let Ok(handle_id) = parse_non_nil_uuid(&request.handle_id) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let response = super::ok(fence);
    let (response_bytes, response_digest) = response_template(&response);
    match state
        .database
        .close_nfs_mount_handle(&CloseNfsHandleInput {
            session,
            gss_binding_digest: match gss_binding(fence) {
                Ok(value) => value,
                Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
            },
            replay: RecordNfsReplayReceiptInput {
                context: context.clone(),
                response_bytes: &response_bytes,
                response_digest: &response_digest,
            },
            handle_id,
        })
        .await
    {
        Ok(result) => DispatchResult::Atomic(decode_nfs_replay(fence, &result.replay)),
        Err(error) => {
            DispatchResult::ReadOnly(mutation_error(fence, error, "vfs.handle_close_failed"))
        }
    }
}

async fn end_session(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    request: &filebelt_vfs_protocol::EndSessionRequest,
) -> DispatchResult {
    let gss = match gss_binding(fence) {
        Ok(gss) => gss,
        Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
    };
    let response = super::ok(fence);
    let (response_bytes, response_digest) = response_template(&response);
    match state
        .database
        .end_nfs_mount_session(&EndNfsSessionInput {
            session,
            gss_binding_digest: gss,
            replay: RecordNfsReplayReceiptInput {
                context: context.clone(),
                response_bytes: &response_bytes,
                response_digest: &response_digest,
            },
            reason_code: &request.reason_code,
        })
        .await
    {
        Ok(result) => DispatchResult::Atomic(decode_nfs_replay(fence, &result.replay)),
        Err(error) => {
            DispatchResult::ReadOnly(mutation_error(fence, error, "vfs.session_close_failed"))
        }
    }
}

fn pending_range_matches(
    pending: &PendingMountIoOperation,
    spec: RangeSpec,
    explicit_write_session_id: Option<Uuid>,
    explicit_fencing_token: Option<i64>,
) -> bool {
    pending.operation == spec.io_operation
        && pending.operation_id.is_some_and(|operation_id| {
            !operation_id.is_nil() && operation_id == pending.protocol_operation_id
        })
        && pending.range_start == Some(spec.range_start)
        && pending.range_end == Some(spec.range_end)
        && pending.content_blake3 == spec.content_blake3
        && explicit_write_session_id.is_none_or(|id| id == pending.write_session_id)
        && explicit_fencing_token.is_none_or(|token| token == pending.fencing_token)
}

// Kept compile- and test-covered for the next qualification tranche. It must
// not be reachable until cleanup can atomically finalize the client replay.
#[allow(dead_code)]
async fn sparse_write(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    request: &filebelt_vfs_protocol::SparseWriteRequest,
) -> DispatchResult {
    if request.hole {
        // Hole deallocation is qualified through the operation-specific
        // SparseControl route. The DB intentionally accepts WriteData under
        // `sparse_write` and deallocation under `sparse_control`, so the
        // legacy multiplexed WRITE_PLUS shape cannot be finalized atomically.
        return DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "sparse_write"));
    }
    let (Ok(handle_id), Ok(write_session_id), Ok(fencing_token), Ok(range_start)) = (
        parse_non_nil_uuid(&request.handle_id),
        parse_non_nil_uuid(&request.write_session_id),
        positive_i64(request.fencing_token),
        i64::try_from(request.offset),
    ) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let Some(range_end_u64) = request
        .offset
        .checked_add(request.length)
        .and_then(|end| end.checked_sub(1))
    else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let Ok(range_end) = i64::try_from(range_end_u64) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let content_blake3 = *blake3::hash(&request.data).as_bytes();
    execute_range(
        state,
        fence,
        session,
        context,
        handle_id,
        Some((write_session_id, fencing_token)),
        RangeSpec {
            operation: MountWriteRangeOperation::WriteData,
            io_operation: MountIoOperation::WriteData,
            capability_use: MountStorageCapabilityUse::WriteData,
            range_start,
            range_end,
            content_blake3: Some(content_blake3),
        },
        Some(request.data.clone()),
    )
    .await
}

#[allow(dead_code)]
async fn sparse_control(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    request: &filebelt_vfs_protocol::SparseControlRequest,
) -> DispatchResult {
    let Ok(handle_id) = parse_non_nil_uuid(&request.handle_id) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let Ok(kind) = SparseControlKind::try_from(request.kind) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let Ok(range_start) = i64::try_from(request.offset) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let (operation, io_operation, capability_use, range_end) = match kind {
        SparseControlKind::SeekData => (
            MountWriteRangeOperation::SeekData,
            MountIoOperation::SeekData,
            MountStorageCapabilityUse::SeekData,
            range_start,
        ),
        SparseControlKind::SeekHole => (
            MountWriteRangeOperation::SeekHole,
            MountIoOperation::SeekHole,
            MountStorageCapabilityUse::SeekHole,
            range_start,
        ),
        SparseControlKind::Allocate | SparseControlKind::Deallocate => {
            if request.length > filebelt_vfs_protocol::MAX_DATA_BYTES as u64 {
                return DispatchResult::ReadOnly(invalid(fence));
            }
            let Some(range_end_u64) = request
                .offset
                .checked_add(request.length)
                .and_then(|end| end.checked_sub(1))
            else {
                return DispatchResult::ReadOnly(invalid(fence));
            };
            let Ok(range_end) = i64::try_from(range_end_u64) else {
                return DispatchResult::ReadOnly(invalid(fence));
            };
            if kind == SparseControlKind::Allocate {
                (
                    MountWriteRangeOperation::Allocate,
                    MountIoOperation::Allocate,
                    MountStorageCapabilityUse::Allocate,
                    range_end,
                )
            } else {
                (
                    MountWriteRangeOperation::HoleDeallocate,
                    MountIoOperation::HoleDeallocate,
                    MountStorageCapabilityUse::Deallocate,
                    range_end,
                )
            }
        }
        SparseControlKind::Unspecified => return DispatchResult::ReadOnly(invalid(fence)),
    };
    execute_range(
        state,
        fence,
        session,
        context,
        handle_id,
        None,
        RangeSpec {
            operation,
            io_operation,
            capability_use,
            range_start,
            range_end,
            content_blake3: None,
        },
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_range(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    handle_id: Uuid,
    explicit_writer: Option<(Uuid, i64)>,
    spec: RangeSpec,
    body: Option<Vec<u8>>,
) -> DispatchResult {
    let Some(runtime) = state.nfs.as_deref() else {
        return DispatchResult::ReadOnly(super::nfs_not_qualified(fence, context.operation));
    };
    let required_action = if spec.mutates() {
        ("WRITE_CONTENT", Action::WriteContent)
    } else {
        ("READ_CONTENT", Action::ReadContent)
    };
    let handle = match admit_current_handle(
        state,
        fence,
        session,
        handle_id,
        required_action.0,
        required_action.1,
        true,
    )
    .await
    {
        Ok(handle) => handle,
        Err(response) => return DispatchResult::ReadOnly(response),
    };
    let pending = match state
        .database
        .inspect_pending_mount_io_operation(context)
        .await
    {
        Ok(pending) => pending,
        Err(DatabaseError::Conflict) => {
            return DispatchResult::ReadOnly(VfsResponse::failure(
                fence.request_id,
                VfsError::Conflict,
                "vfs.nfs_replay_mismatch",
            ));
        }
        Err(error) => {
            return DispatchResult::Retryable(mutation_error(
                fence,
                error,
                "vfs.mount_io_inspection_failed",
            ));
        }
    };
    let explicit_write_session_id = explicit_writer.map(|value| value.0);
    let explicit_fencing_token = explicit_writer.map(|value| value.1);
    if pending.as_ref().is_some_and(|pending| {
        !pending_range_matches(
            pending,
            spec,
            explicit_write_session_id,
            explicit_fencing_token,
        )
    }) {
        return DispatchResult::ReadOnly(VfsResponse::failure(
            fence.request_id,
            VfsError::Conflict,
            "vfs.nfs_replay_mismatch",
        ));
    }

    let (write, initial_storage) = if let Some(pending) = &pending {
        let write = match write_fence(
            session,
            &handle,
            pending.write_session_id,
            pending.fencing_token,
        ) {
            Ok(write) => write,
            Err(()) => {
                return DispatchResult::ReadOnly(super::nfs_not_qualified(
                    fence,
                    context.operation,
                ));
            }
        };
        (write, None)
    } else if let Some((write_session_id, fencing_token)) = explicit_writer {
        let write = match write_fence(session, &handle, write_session_id, fencing_token) {
            Ok(write) => write,
            Err(()) => {
                return DispatchResult::ReadOnly(super::nfs_not_qualified(
                    fence,
                    context.operation,
                ));
            }
        };
        let storage = match state
            .database
            .admit_mount_write_capability(&write, MountWriteStorageOperation::Write)
            .await
        {
            Ok(storage) => storage,
            Err(error) => {
                return DispatchResult::ReadOnly(mutation_error(
                    fence,
                    error,
                    "vfs.mount_write_not_admitted",
                ));
            }
        };
        (write, Some(storage))
    } else {
        let resolved = match state
            .database
            .resolve_nfs_write_for_node(
                session,
                match gss_binding(fence) {
                    Ok(value) => value,
                    Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
                },
                handle.drive_id,
                handle.node_id,
                MountWriteStorageOperation::Write,
            )
            .await
        {
            Ok(resolved) => resolved,
            Err(error) => {
                return DispatchResult::ReadOnly(mutation_error(
                    fence,
                    error,
                    "vfs.mount_write_not_found",
                ));
            }
        };
        if resolved.fence.handle_id != handle.id {
            return DispatchResult::ReadOnly(VfsResponse::failure(
                fence.request_id,
                VfsError::Conflict,
                "vfs.mount_write_ambiguous",
            ));
        }
        (resolved.fence, Some(resolved.storage))
    };

    if write.handle_id != handle.id
        || write.drive_id != handle.drive_id
        || write.node_id != handle.node_id
        || explicit_writer
            .is_some_and(|(id, token)| id != write.write_session_id || token != write.fencing_token)
    {
        return DispatchResult::ReadOnly(stale(fence, "vfs.mount_write_fence_stale"));
    }

    if let Some(pending) = pending {
        return resume_range(
            state, fence, session, context, runtime, &write, spec, pending, body,
        )
        .await;
    }
    let Some(storage) = initial_storage else {
        return DispatchResult::Retryable(unavailable(fence, "vfs.mount_write_not_found"));
    };
    if validate_mount_storage(runtime, &write, &storage).is_err() {
        return DispatchResult::ReadOnly(stale(fence, "vfs.mount_write_fence_stale"));
    }
    let required_reservation_bytes = match required_reservation(
        &storage,
        spec.operation,
        spec.range_end,
        runtime.max_file_bytes,
    ) {
        Ok(value) => value,
        Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
    };
    let chunks = match build_mount_chunk_plan(
        &storage,
        required_reservation_bytes,
        runtime.chunk_size_bytes,
    ) {
        Ok(chunks) => chunks,
        Err(()) => {
            return DispatchResult::ReadOnly(unavailable(fence, "vfs.mount_write_plan_invalid"));
        }
    };
    let prepared = match prepare_mount_capability(
        &write,
        spec.capability_use,
        u64::try_from(spec.range_start).unwrap_or_default(),
        u64::try_from(spec.range_end).unwrap_or_default(),
        spec.content_blake3,
    ) {
        Ok(prepared) => prepared,
        Err(()) => {
            return DispatchResult::Retryable(unavailable(
                fence,
                "vfs.capability_generation_failed",
            ));
        }
    };
    let stable_operation_id = Uuid::new_v4();
    let plan = match state
        .database
        .extend_mount_write_chunks(&ExtendNfsWriteChunksInput {
            fence: &write,
            context: context.clone(),
            required_reservation_bytes,
            operation_id: stable_operation_id,
            capability_id: prepared.capability_id,
            operation: spec.operation,
            nonce_digest: &prepared.nonce_digest,
            claims_digest: &prepared.claims_digest,
            expires_at_unix_seconds: prepared.claims.expires_at_unix_seconds,
            content_blake3: spec.content_blake3.as_ref(),
            range_start: spec.range_start,
            range_end: spec.range_end,
            chunks: &chunks,
        })
        .await
    {
        Ok(plan) => plan,
        Err(error) => {
            return DispatchResult::ReadOnly(mutation_error(
                fence,
                error,
                "vfs.mount_write_plan_failed",
            ));
        }
    };
    if plan.operation_id != stable_operation_id
        || plan.write_session_id != write.write_session_id
        || plan.operation != spec.operation
        || plan.range_start != spec.range_start
        || plan.range_end != spec.range_end
        || plan.content_blake3 != spec.content_blake3
        || plan.reserved_bytes != required_reservation_bytes
        || plan.chunks != chunks
    {
        return DispatchResult::Retryable(unavailable(fence, "vfs.mount_write_plan_invalid"));
    }
    execute_planned_range(
        state,
        fence,
        session,
        context,
        &write,
        spec,
        prepared,
        plan.operation_id,
        plan.resulting_logical_size,
        plan.reserved_bytes,
        body,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn resume_range(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    runtime: &super::NfsRuntime,
    write: &MountWriteCapabilityFence,
    spec: RangeSpec,
    pending: PendingMountIoOperation,
    body: Option<Vec<u8>>,
) -> DispatchResult {
    let Some(stable_operation_id) = pending.operation_id else {
        return DispatchResult::Retryable(unavailable(fence, "vfs.mount_io_pending_invalid"));
    };
    match pending.worker_state {
        PendingMountIoWorkerState::Completed => {
            let Some(completion) = pending.worker_outcome else {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_io_pending_invalid",
                ));
            };
            return apply_range_result(
                state,
                fence,
                session,
                context,
                write,
                spec,
                stable_operation_id,
                completion,
            )
            .await;
        }
        PendingMountIoWorkerState::Pending => {
            return DispatchResult::Retryable(VfsResponse::failure(
                fence.request_id,
                VfsError::Unavailable,
                "vfs.mount_io_pending",
            ));
        }
        PendingMountIoWorkerState::Admission => {}
    }

    let prepared = match prepare_mount_capability(
        write,
        spec.capability_use,
        u64::try_from(spec.range_start).unwrap_or_default(),
        u64::try_from(spec.range_end).unwrap_or_default(),
        spec.content_blake3,
    ) {
        Ok(prepared) => prepared,
        Err(()) => {
            return DispatchResult::Retryable(unavailable(
                fence,
                "vfs.capability_generation_failed",
            ));
        }
    };
    let reissued = match state
        .database
        .reissue_mount_io_operation(&ReissueMountIoOperationInput {
            context: context.clone(),
            fence: write,
            protocol_operation_id: pending.protocol_operation_id,
            stable_operation_id: Some(stable_operation_id),
            operation: spec.io_operation,
            content_blake3: spec.content_blake3.as_ref(),
            range_start: Some(spec.range_start),
            range_end: Some(spec.range_end),
            new_capability_id: prepared.capability_id,
            new_nonce_digest: &prepared.nonce_digest,
            new_claims_digest: &prepared.claims_digest,
            new_expires_at_unix_seconds: prepared.claims.expires_at_unix_seconds,
        })
        .await
    {
        Ok(reissued) => reissued,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration) => {
            return DispatchResult::Retryable(VfsResponse::failure(
                fence.request_id,
                VfsError::Unavailable,
                "vfs.mount_io_pending",
            ));
        }
        Err(error) => {
            return DispatchResult::Retryable(mutation_error(
                fence,
                error,
                "vfs.mount_io_reissue_failed",
            ));
        }
    };
    if !pending_range_matches(
        &reissued,
        spec,
        Some(write.write_session_id),
        Some(write.fencing_token),
    ) || reissued.protocol_operation_id != pending.protocol_operation_id
        || reissued.operation_id != Some(stable_operation_id)
    {
        return DispatchResult::Retryable(unavailable(fence, "vfs.mount_io_pending_invalid"));
    }
    match reissued.worker_state {
        PendingMountIoWorkerState::Completed => {
            let Some(completion) = reissued.worker_outcome else {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_io_pending_invalid",
                ));
            };
            apply_range_result(
                state,
                fence,
                session,
                context,
                write,
                spec,
                stable_operation_id,
                completion,
            )
            .await
        }
        PendingMountIoWorkerState::Pending => DispatchResult::Retryable(VfsResponse::failure(
            fence.request_id,
            VfsError::Unavailable,
            "vfs.mount_io_pending",
        )),
        PendingMountIoWorkerState::Admission => {
            if reissued.capability_id != prepared.capability_id
                || reissued.nonce_digest != prepared.nonce_digest
                || reissued.claims_digest != prepared.claims_digest
                || reissued.capability_expires_at_unix_seconds
                    != prepared.claims.expires_at_unix_seconds
            {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_io_pending_invalid",
                ));
            }
            let admission = match state
                .database
                .admit_mount_write_range(
                    write,
                    prepared.capability_id,
                    spec.operation,
                    spec.range_start,
                    spec.range_end,
                )
                .await
            {
                Ok(admission) => admission,
                Err(error) => {
                    return DispatchResult::Retryable(mutation_error(
                        fence,
                        error,
                        "vfs.mount_io_reissue_failed",
                    ));
                }
            };
            if admission.operation_id != stable_operation_id
                || admission.operation != spec.operation
                || admission.range_start != spec.range_start
                || admission.range_end != spec.range_end
                || admission.content_blake3 != spec.content_blake3
                || admission.resulting_logical_size != admission.storage.logical_size_bytes
                || validate_mount_storage(runtime, write, &admission.storage).is_err()
                || build_mount_chunk_plan(
                    &admission.storage,
                    admission.storage.reserved_bytes,
                    runtime.chunk_size_bytes,
                )
                .is_err()
            {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_write_plan_invalid",
                ));
            }
            execute_planned_range(
                state,
                fence,
                session,
                context,
                write,
                spec,
                prepared,
                stable_operation_id,
                admission.resulting_logical_size,
                admission.storage.reserved_bytes,
                body,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_planned_range(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    write: &MountWriteCapabilityFence,
    spec: RangeSpec,
    prepared: PreparedMountCapability,
    stable_operation_id: Uuid,
    resulting_logical_size: i64,
    reserved_bytes: i64,
    body: Option<Vec<u8>>,
) -> DispatchResult {
    if (spec.operation == MountWriteRangeOperation::WriteData) != body.is_some() {
        return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
    }
    let capability = match prepared.signed(state) {
        Ok(capability) => capability,
        Err(()) => {
            return DispatchResult::Retryable(unavailable(
                fence,
                "vfs.capability_generation_failed",
            ));
        }
    };
    let (method, path) = range_endpoint(write.write_session_id, spec.operation);
    let completion = if spec.mutates() {
        let result: MountWriteResult =
            match mount_io_json(state, fence, method, &path, &capability, body).await {
                Ok(result) => result,
                Err(result) => return result,
            };
        let (Ok(logical_size_bytes), Ok(reservation_delta_bytes)) = (
            i64::try_from(result.logical_size_bytes),
            i64::try_from(result.reservation_delta_bytes),
        ) else {
            return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
        };
        if result.write_session_id != write.write_session_id
            || result.state != "staging"
            || logical_size_bytes != resulting_logical_size
            || reservation_delta_bytes < 0
            || reservation_delta_bytes > reserved_bytes
        {
            return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
        }
        MountIoCompletion::RangeMutation {
            logical_size_bytes,
            reservation_delta_bytes,
        }
    } else {
        if body.is_some() {
            return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
        }
        let result: MountSeekResult =
            match mount_io_json(state, fence, method, &path, &capability, None).await {
                Ok(result) => result,
                Err(result) => return result,
            };
        let offset = match result.offset.map(i64::try_from).transpose() {
            Ok(offset) => offset,
            Err(_) => {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.storage_response_invalid",
                ));
            }
        };
        if offset.is_some_and(|offset| offset < spec.range_start || offset > resulting_logical_size)
        {
            return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
        }
        MountIoCompletion::Seek { offset }
    };
    apply_range_result(
        state,
        fence,
        session,
        context,
        write,
        spec,
        stable_operation_id,
        completion,
    )
    .await
}

fn range_endpoint(write_session_id: Uuid, operation: MountWriteRangeOperation) -> (Method, String) {
    let path = match operation {
        MountWriteRangeOperation::WriteData => {
            format!("io/v1/mount-writes/{write_session_id}")
        }
        MountWriteRangeOperation::HoleDeallocate => {
            format!("io/v1/mount-writes/{write_session_id}/deallocate")
        }
        MountWriteRangeOperation::Allocate => {
            format!("io/v1/mount-writes/{write_session_id}/allocate")
        }
        MountWriteRangeOperation::SeekData => {
            format!("io/v1/mount-writes/{write_session_id}/seek-data")
        }
        MountWriteRangeOperation::SeekHole => {
            format!("io/v1/mount-writes/{write_session_id}/seek-hole")
        }
    };
    let method = match operation {
        MountWriteRangeOperation::WriteData => Method::PUT,
        MountWriteRangeOperation::SeekData | MountWriteRangeOperation::SeekHole => Method::GET,
        MountWriteRangeOperation::HoleDeallocate | MountWriteRangeOperation::Allocate => {
            Method::POST
        }
    };
    (method, path)
}

fn pending_flush_matches(
    pending: &PendingMountIoOperation,
    write_session_id: Uuid,
    fencing_token: i64,
) -> bool {
    pending.operation == MountIoOperation::Flush
        && pending.operation_id.is_none()
        && pending.range_start.is_none()
        && pending.range_end.is_none()
        && pending.content_blake3.is_none()
        && pending.write_session_id == write_session_id
        && pending.fencing_token == fencing_token
        && !pending.protocol_operation_id.is_nil()
}

#[allow(dead_code)]
async fn flush(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    request: &filebelt_vfs_protocol::FlushRequest,
) -> DispatchResult {
    let (Ok(handle_id), Ok(write_session_id), Ok(fencing_token)) = (
        parse_non_nil_uuid(&request.handle_id),
        parse_non_nil_uuid(&request.write_session_id),
        positive_i64(request.fencing_token),
    ) else {
        return DispatchResult::ReadOnly(invalid(fence));
    };
    let handle = match admit_current_handle(
        state,
        fence,
        session,
        handle_id,
        "WRITE_CONTENT",
        Action::WriteContent,
        true,
    )
    .await
    {
        Ok(handle) => handle,
        Err(response) => return DispatchResult::ReadOnly(response),
    };
    let write = match write_fence(session, &handle, write_session_id, fencing_token) {
        Ok(write) => write,
        Err(()) => return DispatchResult::ReadOnly(super::nfs_not_qualified(fence, "flush")),
    };
    let pending = match state
        .database
        .inspect_pending_mount_io_operation(context)
        .await
    {
        Ok(pending) => pending,
        Err(DatabaseError::Conflict) => {
            return DispatchResult::ReadOnly(VfsResponse::failure(
                fence.request_id,
                VfsError::Conflict,
                "vfs.nfs_replay_mismatch",
            ));
        }
        Err(error) => {
            return DispatchResult::Retryable(mutation_error(
                fence,
                error,
                "vfs.mount_io_inspection_failed",
            ));
        }
    };
    if let Some(pending) = pending {
        if !pending_flush_matches(&pending, write_session_id, fencing_token) {
            return DispatchResult::ReadOnly(VfsResponse::failure(
                fence.request_id,
                VfsError::Conflict,
                "vfs.nfs_replay_mismatch",
            ));
        }
        return resume_flush(state, fence, session, context, &write, pending).await;
    }
    let prepared =
        match prepare_mount_capability(&write, MountStorageCapabilityUse::Flush, 0, 0, None) {
            Ok(prepared) => prepared,
            Err(()) => {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.capability_generation_failed",
                ));
            }
        };
    let protocol_operation_id = Uuid::new_v4();
    let io = BeginMountIoOperationInput {
        fence: &write,
        capability_id: prepared.capability_id,
        nonce_digest: &prepared.nonce_digest,
        claims_digest: &prepared.claims_digest,
        operation: MountIoOperation::Flush,
        range_start: None,
        range_end: None,
        content_blake3: None,
        expires_at_unix_seconds: prepared.claims.expires_at_unix_seconds,
    };
    let preauthorized = state
        .database
        .preauthorize_mount_io_operation(&PreauthorizeMountIoOperationInput {
            io,
            protocol_operation_id,
            context: context.clone(),
        })
        .await;
    match preauthorized {
        Ok(result) if !result.resumed => {
            execute_flush(state, fence, session, context, &write, prepared).await
        }
        Ok(_) => DispatchResult::Retryable(VfsResponse::failure(
            fence.request_id,
            VfsError::Unavailable,
            "vfs.mount_io_pending",
        )),
        Err(error) => {
            DispatchResult::ReadOnly(mutation_error(fence, error, "vfs.mount_flush_not_admitted"))
        }
    }
}

async fn resume_flush(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    write: &MountWriteCapabilityFence,
    pending: PendingMountIoOperation,
) -> DispatchResult {
    match pending.worker_state {
        PendingMountIoWorkerState::Completed => {
            let Some(completion) = pending.worker_outcome else {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_io_pending_invalid",
                ));
            };
            return finalize_flush(state, fence, session, context, write, &completion).await;
        }
        PendingMountIoWorkerState::Pending => {
            return DispatchResult::Retryable(VfsResponse::failure(
                fence.request_id,
                VfsError::Unavailable,
                "vfs.mount_io_pending",
            ));
        }
        PendingMountIoWorkerState::Admission => {}
    }
    let prepared =
        match prepare_mount_capability(write, MountStorageCapabilityUse::Flush, 0, 0, None) {
            Ok(prepared) => prepared,
            Err(()) => {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.capability_generation_failed",
                ));
            }
        };
    let reissued = match state
        .database
        .reissue_mount_io_operation(&ReissueMountIoOperationInput {
            context: context.clone(),
            fence: write,
            protocol_operation_id: pending.protocol_operation_id,
            stable_operation_id: None,
            operation: MountIoOperation::Flush,
            content_blake3: None,
            range_start: None,
            range_end: None,
            new_capability_id: prepared.capability_id,
            new_nonce_digest: &prepared.nonce_digest,
            new_claims_digest: &prepared.claims_digest,
            new_expires_at_unix_seconds: prepared.claims.expires_at_unix_seconds,
        })
        .await
    {
        Ok(reissued) => reissued,
        Err(DatabaseError::Conflict | DatabaseError::StaleGeneration) => {
            return DispatchResult::Retryable(VfsResponse::failure(
                fence.request_id,
                VfsError::Unavailable,
                "vfs.mount_io_pending",
            ));
        }
        Err(error) => {
            return DispatchResult::Retryable(mutation_error(
                fence,
                error,
                "vfs.mount_io_reissue_failed",
            ));
        }
    };
    if !pending_flush_matches(&reissued, write.write_session_id, write.fencing_token)
        || reissued.protocol_operation_id != pending.protocol_operation_id
    {
        return DispatchResult::Retryable(unavailable(fence, "vfs.mount_io_pending_invalid"));
    }
    match reissued.worker_state {
        PendingMountIoWorkerState::Completed => {
            let Some(completion) = reissued.worker_outcome else {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_io_pending_invalid",
                ));
            };
            finalize_flush(state, fence, session, context, write, &completion).await
        }
        PendingMountIoWorkerState::Pending => DispatchResult::Retryable(VfsResponse::failure(
            fence.request_id,
            VfsError::Unavailable,
            "vfs.mount_io_pending",
        )),
        PendingMountIoWorkerState::Admission => {
            if reissued.capability_id != prepared.capability_id
                || reissued.nonce_digest != prepared.nonce_digest
                || reissued.claims_digest != prepared.claims_digest
                || reissued.capability_expires_at_unix_seconds
                    != prepared.claims.expires_at_unix_seconds
            {
                return DispatchResult::Retryable(unavailable(
                    fence,
                    "vfs.mount_io_pending_invalid",
                ));
            }
            execute_flush(state, fence, session, context, write, prepared).await
        }
    }
}

async fn execute_flush(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    write: &MountWriteCapabilityFence,
    prepared: PreparedMountCapability,
) -> DispatchResult {
    let capability = match prepared.signed(state) {
        Ok(capability) => capability,
        Err(()) => {
            return DispatchResult::Retryable(unavailable(
                fence,
                "vfs.capability_generation_failed",
            ));
        }
    };
    let path = format!("io/v1/mount-writes/{}/flush", write.write_session_id);
    let result: MountManifestResult =
        match mount_io_json(state, fence, Method::POST, &path, &capability, None).await {
            Ok(result) => result,
            Err(result) => return result,
        };
    let completion = match manifest_completion(state, write, result) {
        Ok(completion) => completion,
        Err(()) => {
            return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
        }
    };
    finalize_flush(state, fence, session, context, write, &completion).await
}

fn manifest_completion(
    state: &VfsState,
    write: &MountWriteCapabilityFence,
    result: MountManifestResult,
) -> Result<MountIoCompletion, ()> {
    let runtime = state.nfs.as_deref().ok_or(())?;
    let logical_size_bytes = i64::try_from(result.logical_size_bytes).map_err(|_| ())?;
    let blake3 = decode_hex_digest(&result.blake3)?;
    let chunk_count = result.chunks.len();
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut represented = 0_i64;
    for (index, chunk) in result.chunks.into_iter().enumerate() {
        let chunk_number = i64::try_from(chunk.chunk_number).map_err(|_| ())?;
        let size_bytes = i64::try_from(chunk.size_bytes).map_err(|_| ())?;
        if chunk_number != i64::try_from(index).map_err(|_| ())?
            || size_bytes <= 0
            || u64::try_from(size_bytes).map_err(|_| ())? > runtime.chunk_size_bytes
            || index + 1 < chunk_count
                && u64::try_from(size_bytes).map_err(|_| ())? != runtime.chunk_size_bytes
        {
            return Err(());
        }
        represented = represented.checked_add(size_bytes).ok_or(())?;
        chunks.push(filebelt_database::mount::MountWriteChunkEvidence {
            chunk_number,
            size_bytes,
            blake3: decode_hex_digest(&chunk.blake3)?,
        });
    }
    if result.write_session_id != write.write_session_id
        || result.state != "flushed"
        || represented != logical_size_bytes
        || (logical_size_bytes == 0) != chunks.is_empty()
    {
        return Err(());
    }
    Ok(MountIoCompletion::Flush {
        logical_size_bytes,
        blake3,
        chunks,
    })
}

async fn finalize_flush(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    context: &NfsReplayContext<'_>,
    write: &MountWriteCapabilityFence,
    completion: &MountIoCompletion,
) -> DispatchResult {
    if validate_flush_completion(state, write, completion).is_err() {
        return DispatchResult::Retryable(unavailable(fence, "vfs.storage_response_invalid"));
    }
    let response = VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        write_session_id: write.write_session_id.to_string(),
        fencing_token: match positive_u64_claim(write.fencing_token) {
            Ok(value) => value,
            Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
        },
        ..VfsResponse::default()
    };
    let (response_bytes, response_digest) = response_template(&response);
    match state
        .database
        .finalize_nfs_internal_io_replay(&FinalizeNfsInternalIoReplayInput {
            session,
            gss_binding_digest: match gss_binding(fence) {
                Ok(value) => value,
                Err(()) => return DispatchResult::ReadOnly(invalid(fence)),
            },
            fence: write,
            replay: RecordNfsReplayReceiptInput {
                context: context.clone(),
                response_bytes: &response_bytes,
                response_digest: &response_digest,
            },
            operation: MountIoOperation::Flush,
        })
        .await
    {
        Ok(result) => DispatchResult::Atomic(decode_nfs_replay(fence, &result.replay)),
        Err(error) => DispatchResult::Retryable(mutation_error(
            fence,
            error,
            "vfs.mount_flush_finalize_failed",
        )),
    }
}

fn validate_flush_completion(
    state: &VfsState,
    write: &MountWriteCapabilityFence,
    completion: &MountIoCompletion,
) -> Result<(), ()> {
    let MountIoCompletion::Flush {
        logical_size_bytes,
        chunks,
        ..
    } = completion
    else {
        return Err(());
    };
    let runtime = state.nfs.as_deref().ok_or(())?;
    let mut represented = 0_i64;
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.chunk_number != i64::try_from(index).map_err(|_| ())?
            || chunk.size_bytes <= 0
            || u64::try_from(chunk.size_bytes).map_err(|_| ())? > runtime.chunk_size_bytes
            || index + 1 < chunks.len()
                && u64::try_from(chunk.size_bytes).map_err(|_| ())? != runtime.chunk_size_bytes
        {
            return Err(());
        }
        represented = represented.checked_add(chunk.size_bytes).ok_or(())?;
    }
    if *logical_size_bytes < 0
        || represented != *logical_size_bytes
        || (*logical_size_bytes == 0) != chunks.is_empty()
        || write.write_session_id.is_nil()
    {
        return Err(());
    }
    Ok(())
}

fn decode_hex_digest(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 {
        return Err(());
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(digest)
}

const fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

async fn get_xattr(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::GetXattrRequest,
) -> VfsResponse {
    let (target, initial_grant) = match resolve_request_target(
        state,
        fence,
        session,
        &request.drive_id,
        &request.resource_id,
        &request.persistent_handle,
        Action::ReadMetadata,
    )
    .await
    {
        Ok(target) => target,
        Err(response) => return response,
    };
    let xattrs = match state
        .database
        .nfs_node_xattrs(fence.tenant_id, target.node.drive_id, target.node.id)
        .await
    {
        Ok(xattrs) => xattrs,
        Err(_) => return unavailable(fence, "vfs.database_unavailable"),
    };
    if let Err(response) = reauthorize_exact(
        state,
        fence,
        session,
        &target,
        Action::ReadMetadata,
        initial_grant,
    )
    .await
    {
        return response;
    }
    let Some(xattr) = xattrs.into_iter().find(|xattr| xattr.name == request.name) else {
        return denied(fence, "vfs.xattr_not_found");
    };
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        xattr_value: xattr.value,
        ..VfsResponse::default()
    }
}

async fn list_xattr(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::ListXattrRequest,
) -> VfsResponse {
    let (target, initial_grant) = match resolve_request_target(
        state,
        fence,
        session,
        &request.drive_id,
        &request.resource_id,
        &request.persistent_handle,
        Action::ReadMetadata,
    )
    .await
    {
        Ok(target) => target,
        Err(response) => return response,
    };
    let xattrs = match state
        .database
        .nfs_node_xattrs(fence.tenant_id, target.node.drive_id, target.node.id)
        .await
    {
        Ok(xattrs) => xattrs,
        Err(_) => return unavailable(fence, "vfs.database_unavailable"),
    };
    if let Err(response) = reauthorize_exact(
        state,
        fence,
        session,
        &target,
        Action::ReadMetadata,
        initial_grant,
    )
    .await
    {
        return response;
    }
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        xattr_names: xattrs.into_iter().map(|xattr| xattr.name).collect(),
        ..VfsResponse::default()
    }
}

async fn resolve_request_target(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    drive_id: &str,
    resource_id: &str,
    handle: &[u8],
    action: Action,
) -> Result<(ResolvedTarget, super::policy::AuthorizationGrant), VfsResponse> {
    if handle.is_empty() {
        return Err(invalid(fence));
    }
    let target = resolve_persistent_handle(state, fence, session, handle).await?;
    if drive_id != target.node.drive_id.to_string() || resource_id != target.node.id.to_string() {
        return Err(denied(fence, "vfs.resource_not_found"));
    }
    let grant = authorize(state, fence, session, &target, action).await?;
    Ok((target, grant))
}

async fn reauthorize_exact(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    target: &ResolvedTarget,
    action: Action,
    initial_grant: super::policy::AuthorizationGrant,
) -> Result<(), VfsResponse> {
    let final_grant = authorize(state, fence, session, target, action).await?;
    if final_grant != initial_grant {
        return Err(stale(fence, "vfs.authorization_changed"));
    }
    Ok(())
}

async fn readlink(
    state: &VfsState,
    fence: &RequestFence,
    session: &MountSessionFence,
    request: &filebelt_vfs_protocol::ReadlinkRequest,
) -> VfsResponse {
    let (target, _) = match resolve_request_target(
        state,
        fence,
        session,
        &request.drive_id,
        &request.resource_id,
        &request.persistent_handle,
        Action::ReadMetadata,
    )
    .await
    {
        Ok(target) => target,
        Err(response) => return response,
    };
    let Some(symlink_target) = target.resolution.target.symlink_target else {
        return VfsResponse::failure(
            fence.request_id,
            VfsError::InvalidRequest,
            "vfs.not_symlink",
        );
    };
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        symlink_target,
        ..VfsResponse::default()
    }
}

fn response_template(response: &VfsResponse) -> (Vec<u8>, [u8; 32]) {
    let mut response = response.clone();
    response.request_id.clear();
    let bytes = response.encode_to_vec();
    let digest = *blake3::hash(&bytes).as_bytes();
    (bytes, digest)
}

fn mutation_error(fence: &RequestFence, error: DatabaseError, reason: &str) -> VfsResponse {
    match error {
        DatabaseError::NotFound => denied(fence, "vfs.resource_not_found"),
        DatabaseError::Conflict => {
            VfsResponse::failure(fence.request_id, VfsError::Conflict, "vfs.state_conflict")
        }
        DatabaseError::QuotaExceeded => VfsResponse::failure(
            fence.request_id,
            VfsError::QuotaExceeded,
            "vfs.quota_exceeded",
        ),
        DatabaseError::StorageUnavailable => VfsResponse::failure(
            fence.request_id,
            VfsError::StorageUnavailable,
            "vfs.storage_unavailable",
        ),
        DatabaseError::AdmissionLimited => VfsResponse::failure(
            fence.request_id,
            VfsError::RateLimited,
            "vfs.admission_limited",
        ),
        DatabaseError::StaleGeneration => stale(fence, "vfs.authorization_changed"),
        DatabaseError::SecurityAdmissionBlocked => denied(fence, "vfs.resource_not_found"),
        DatabaseError::Sql(_)
        | DatabaseError::Migration(_)
        | DatabaseError::InvalidPersistedValue => unavailable(fence, reason),
    }
}

fn stale(fence: &RequestFence, reason: &str) -> VfsResponse {
    VfsResponse::failure(fence.request_id, VfsError::StaleGeneration, reason)
}

#[cfg(test)]
mod tests {
    use super::{
        MOUNT_CAPABILITY_AUDIENCE, MOUNT_CAPABILITY_LIFETIME_SECONDS, NodeCursor, RangeSpec,
        ReadOpenHeadError, access_action_has_qualified_handler, bind_read_open_head,
        build_mount_chunk_plan, compare_cursor, decode_cursor, decode_hex_digest, encode_cursor,
        merge_coherent_grant, merge_common_fence, pending_flush_matches, pending_range_matches,
        prepare_mount_capability, range_endpoint, read_ends_at_eof, required_reservation,
        validate_base_parts,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use filebelt_database::mount::{
        MountIoOperation, MountPayloadPartRecord, MountWriteCapabilityFence, MountWriteChunkPlan,
        MountWriteRangeOperation, MountWriteStorageRecord, PendingMountIoOperation,
        PendingMountIoWorkerState,
    };
    use filebelt_database::{NodeRecord, PayloadRecord};
    use filebelt_storage_protocol::MountStorageCapabilityUse;
    use filebelt_vfs_protocol::VfsAction;
    use reqwest::Method;
    use uuid::Uuid;

    fn node(kind: &str, key: &str, id: Uuid) -> NodeRecord {
        NodeRecord {
            id,
            drive_id: Uuid::new_v4(),
            parent_id: Some(Uuid::new_v4()),
            kind: kind.into(),
            display_name: key.into(),
            name_key: key.into(),
            head_version_id: None,
            namespace_generation: 1,
            acl_generation: 1,
            trashed: false,
            updated_at: "2026-08-11T00:00:00Z".into(),
            size_bytes: None,
            version_ordinal: None,
            head_media_type: None,
        }
    }

    fn write_fence() -> MountWriteCapabilityFence {
        MountWriteCapabilityFence {
            tenant_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            mount_session_id: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            handle_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            version_id: Some(Uuid::new_v4()),
            write_session_id: Uuid::new_v4(),
            credential_generation: 1,
            authorization_generation: 2,
            membership_generation: 3,
            drive_acl_generation: 4,
            namespace_generation: 5,
            resource_acl_generation: 6,
            gateway_epoch: 7,
            fencing_token: 8,
        }
    }

    fn payload(
        tenant_id: Uuid,
        drive_id: Uuid,
        backend_id: Uuid,
        layout: &str,
        state: &str,
        size_bytes: i64,
    ) -> PayloadRecord {
        PayloadRecord {
            tenant_id,
            payload_id: Uuid::new_v4(),
            drive_id,
            backend_id,
            locator: Uuid::new_v4(),
            layout: layout.into(),
            state: state.into(),
            size_bytes,
            blake3: None,
        }
    }

    fn empty_storage() -> MountWriteStorageRecord {
        let tenant_id = Uuid::new_v4();
        let drive_id = Uuid::new_v4();
        let backend_id = Uuid::new_v4();
        MountWriteStorageRecord {
            write_session_id: Uuid::new_v4(),
            base_version_id: None,
            logical_size_bytes: 0,
            reserved_bytes: 0,
            state: "open".into(),
            staging_payload: payload(tenant_id, drive_id, backend_id, "chunked", "staging", 0),
            base_payload: None,
            base_parts: Vec::new(),
            planned_chunks: Vec::new(),
        }
    }

    fn range_spec(operation: MountWriteRangeOperation) -> RangeSpec {
        let (io_operation, capability_use, content_blake3, range_end) = match operation {
            MountWriteRangeOperation::WriteData => (
                MountIoOperation::WriteData,
                MountStorageCapabilityUse::WriteData,
                Some([9; 32]),
                15,
            ),
            MountWriteRangeOperation::HoleDeallocate => (
                MountIoOperation::HoleDeallocate,
                MountStorageCapabilityUse::Deallocate,
                None,
                15,
            ),
            MountWriteRangeOperation::Allocate => (
                MountIoOperation::Allocate,
                MountStorageCapabilityUse::Allocate,
                None,
                15,
            ),
            MountWriteRangeOperation::SeekData => (
                MountIoOperation::SeekData,
                MountStorageCapabilityUse::SeekData,
                None,
                8,
            ),
            MountWriteRangeOperation::SeekHole => (
                MountIoOperation::SeekHole,
                MountStorageCapabilityUse::SeekHole,
                None,
                8,
            ),
        };
        RangeSpec {
            operation,
            io_operation,
            capability_use,
            range_start: 8,
            range_end,
            content_blake3,
        }
    }

    #[test]
    fn nfs_cursor_matches_the_common_namespace_order_and_rejects_substitution() {
        let original = node("directory", "alpha", Uuid::new_v4());
        let encoded = encode_cursor(&original);
        let decoded = decode_cursor(&encoded).expect("canonical cursor");
        assert_eq!(decoded.kind, original.kind);
        assert_eq!(decoded.name_key, original.name_key);
        assert_eq!(decoded.id, original.id);
        assert_eq!(
            compare_cursor(&original, &decoded),
            std::cmp::Ordering::Equal
        );
        assert!(decode_cursor("not-base64!").is_err());
        assert!(
            decode_cursor(&URL_SAFE_NO_PAD.encode(
                "file\0alpha\0\x30\x30\x30\x30\x30\x30\x30\x30-0000-0000-0000-000000000000"
            ))
            .is_err()
        );
        let later = node("file", "beta", Uuid::new_v4());
        assert_ne!(
            compare_cursor(
                &later,
                &NodeCursor {
                    kind: original.kind,
                    name_key: original.name_key,
                    id: original.id,
                }
            ),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn access_masks_every_action_without_a_qualified_handler() {
        let actions = [
            VfsAction::Unspecified,
            VfsAction::ReadMetadata,
            VfsAction::ReadContent,
            VfsAction::CreateChild,
            VfsAction::WriteContent,
            VfsAction::Delete,
            VfsAction::Rename,
            VfsAction::Move,
            VfsAction::WriteMetadata,
            VfsAction::ManageLock,
            VfsAction::ListChildren,
            VfsAction::Traverse,
            VfsAction::ManageAcl,
        ];
        let file = actions
            .into_iter()
            .filter(|action| access_action_has_qualified_handler(*action, "file"))
            .collect::<Vec<_>>();
        assert_eq!(file, vec![VfsAction::ReadMetadata, VfsAction::ReadContent,]);
        let directory = actions
            .into_iter()
            .filter(|action| access_action_has_qualified_handler(*action, "directory"))
            .collect::<Vec<_>>();
        assert_eq!(
            directory,
            vec![
                VfsAction::ReadMetadata,
                VfsAction::ListChildren,
                VfsAction::Traverse,
            ]
        );
        for held in [
            VfsAction::CreateChild,
            VfsAction::WriteContent,
            VfsAction::Delete,
            VfsAction::Rename,
            VfsAction::Move,
            VfsAction::WriteMetadata,
            VfsAction::ManageLock,
            VfsAction::ManageAcl,
        ] {
            assert!(!access_action_has_qualified_handler(held, "file"));
            assert!(!access_action_has_qualified_handler(held, "directory"));
        }
    }

    #[test]
    fn access_rejects_generation_substitution_between_action_checks() {
        let grant = super::super::policy::AuthorizationGrant {
            membership_generation: 1,
            drive_acl_generation: 2,
            namespace_generation: 3,
            resource_acl_generation: 4,
            resource_namespace_generation: 5,
        };
        let mut coherent = None;
        assert_eq!(merge_coherent_grant(&mut coherent, grant), Ok(()));
        assert_eq!(merge_coherent_grant(&mut coherent, grant), Ok(()));
        for substituted in [
            super::super::policy::AuthorizationGrant {
                membership_generation: 9,
                ..grant
            },
            super::super::policy::AuthorizationGrant {
                drive_acl_generation: 9,
                ..grant
            },
            super::super::policy::AuthorizationGrant {
                namespace_generation: 9,
                ..grant
            },
            super::super::policy::AuthorizationGrant {
                resource_acl_generation: 9,
                ..grant
            },
            super::super::policy::AuthorizationGrant {
                resource_namespace_generation: 9,
                ..grant
            },
        ] {
            assert_eq!(merge_coherent_grant(&mut coherent, substituted), Err(()));
        }
    }

    #[test]
    fn ancestor_and_target_grants_must_share_one_common_generation_fence() {
        let original = super::super::policy::AuthorizationCommonFence {
            membership_generation: 1,
            drive_acl_generation: 2,
            namespace_generation: 3,
        };
        let mut common = None;
        assert_eq!(merge_common_fence(&mut common, original), Ok(()));
        assert_eq!(merge_common_fence(&mut common, original), Ok(()));
        for substituted in [
            super::super::policy::AuthorizationCommonFence {
                membership_generation: 9,
                ..original
            },
            super::super::policy::AuthorizationCommonFence {
                drive_acl_generation: 9,
                ..original
            },
            super::super::policy::AuthorizationCommonFence {
                namespace_generation: 9,
                ..original
            },
        ] {
            assert_eq!(merge_common_fence(&mut common, substituted), Err(()));
        }
    }

    #[test]
    fn read_rechecks_exact_authority_after_fetch_before_returning_data() {
        let handler = include_str!("nfs_dispatch.rs")
            .split_once("async fn read(")
            .unwrap()
            .1
            .split_once("async fn resolve_mount_handle_target(")
            .unwrap()
            .0;
        let fetch = handler.find("super::read_handle").unwrap();
        let final_target = handler.find("final_target").unwrap();
        let comparison = handler.find("final_grant != initial_grant").unwrap();
        let returned_data = handler.rfind("\n    response\n").unwrap();
        assert!(fetch < final_target);
        assert!(final_target < comparison);
        assert!(comparison < returned_data);
    }

    #[test]
    fn read_open_requires_one_exact_non_nil_resolved_head() {
        let resolved_head = Uuid::new_v4();
        assert_eq!(
            bind_read_open_head(Some(resolved_head), ""),
            Ok(resolved_head)
        );
        assert_eq!(
            bind_read_open_head(Some(resolved_head), &resolved_head.to_string()),
            Ok(resolved_head)
        );
        assert_eq!(
            bind_read_open_head(None, ""),
            Err(ReadOpenHeadError::MissingResolvedHead)
        );
        assert_eq!(
            bind_read_open_head(Some(Uuid::nil()), ""),
            Err(ReadOpenHeadError::MissingResolvedHead)
        );
        assert_eq!(
            bind_read_open_head(Some(resolved_head), "not-a-uuid"),
            Err(ReadOpenHeadError::InvalidExpectedHead)
        );
        assert_eq!(
            bind_read_open_head(Some(resolved_head), &Uuid::nil().to_string()),
            Err(ReadOpenHeadError::InvalidExpectedHead)
        );
        assert_eq!(
            bind_read_open_head(Some(resolved_head), &Uuid::new_v4().to_string()),
            Err(ReadOpenHeadError::ExpectedHeadChanged)
        );
    }

    #[test]
    fn read_open_binds_the_response_and_atomic_admission_to_the_same_head() {
        let handler = include_str!("nfs_dispatch.rs")
            .split_once("async fn open(")
            .unwrap()
            .1
            .split_once("async fn close(")
            .unwrap()
            .0;
        let binding = handler.find("match bind_read_open_head").unwrap();
        let handle_id = handler.find("let handle_id = Uuid::new_v4()").unwrap();
        let response = handler
            .find("version_id: resolved_head.to_string()")
            .unwrap();
        let admission = handler
            .find("expected_version_id: Some(resolved_head)")
            .unwrap();
        assert!(binding < handle_id);
        assert!(handle_id < response);
        assert!(response < admission);
        assert!(!handler.contains("expected_version_id: None"));
    }

    #[test]
    fn xattr_reads_recheck_exact_authority_after_metadata_fetch() {
        let source = include_str!("nfs_dispatch.rs");
        for (start, end) in [
            ("async fn get_xattr(", "async fn list_xattr("),
            ("async fn list_xattr(", "async fn resolve_request_target("),
        ] {
            let handler = source
                .split_once(start)
                .unwrap()
                .1
                .split_once(end)
                .unwrap()
                .0;
            let fetch = handler.find("nfs_node_xattrs").unwrap();
            let recheck = handler.find("reauthorize_exact").unwrap();
            let response = handler.rfind("VfsResponse {").unwrap();
            assert!(fetch < recheck);
            assert!(recheck < response);
        }
    }

    #[test]
    fn list_rechecks_parent_authority_after_child_enumeration() {
        let handler = include_str!("nfs_dispatch.rs")
            .split_once("async fn list(")
            .unwrap()
            .1
            .split_once("async fn authorize_list_parent(")
            .unwrap()
            .0;
        let initial = handler.find("initial_parent_grant").unwrap();
        let children = handler.find("for child in children").unwrap();
        let final_check = handler.find("final_parent_grant").unwrap();
        let comparison = handler
            .find("final_parent_grant != initial_parent_grant")
            .unwrap();
        assert!(initial < children);
        assert!(children < final_check);
        assert!(final_check < comparison);
    }

    #[test]
    fn read_eof_uses_the_exact_logical_end_and_rejects_overflow() {
        assert_eq!(read_ends_at_eof(0, 0, 0), Ok(true));
        assert_eq!(read_ends_at_eof(8, 0, 4), Ok(true));
        assert_eq!(read_ends_at_eof(0, 4, 8), Ok(false));
        assert_eq!(read_ends_at_eof(4, 4, 8), Ok(true));
        assert_eq!(read_ends_at_eof(0, 8, 8), Ok(true));
        assert_eq!(read_ends_at_eof(0, 9, 8), Err(()));
        assert_eq!(read_ends_at_eof(u64::MAX, 1, u64::MAX), Err(()));
    }

    #[test]
    fn held_operations_stay_fail_closed_before_authority_or_io() {
        let dispatch = include_str!("nfs_dispatch.rs")
            .split_once("pub async fn dispatch(")
            .unwrap()
            .1
            .split_once("async fn resolve_persistent_handle(")
            .unwrap()
            .0;
        for operation in [
            "Operation::Write(_)",
            "Operation::Flush(_)",
            "Operation::Commit(_)",
            "Operation::GetAcl(_)",
            "Operation::Rename(_)",
            "Operation::Remove(_)",
            "Operation::SetAttributes(_)",
            "Operation::TestLock(_)",
            "Operation::SetXattr(_)",
            "Operation::RemoveXattr(_)",
            "Operation::SparseWrite(_)",
            "Operation::SparseControl(_)",
        ] {
            assert!(dispatch.contains(operation), "missing {operation} sentinel");
        }
        for unreachable_call in [
            "get_acl(state",
            "rename(state",
            "remove(state",
            "set_attributes(state",
            "set_xattr(state",
            "remove_xattr(state",
            "sparse_write(state",
            "sparse_control(state",
            "flush(state",
        ] {
            assert!(
                !dispatch.contains(unreachable_call),
                "byte-plane dispatch unexpectedly calls {unreachable_call}"
            );
        }
        assert_eq!(dispatch.matches("nfs_not_qualified(fence").count(), 22);
    }

    #[test]
    fn mount_range_routes_are_selected_only_by_the_signed_operation() {
        let write_session_id = Uuid::from_u128(42);
        let cases = [
            (
                MountWriteRangeOperation::WriteData,
                Method::PUT,
                format!("io/v1/mount-writes/{write_session_id}"),
            ),
            (
                MountWriteRangeOperation::HoleDeallocate,
                Method::POST,
                format!("io/v1/mount-writes/{write_session_id}/deallocate"),
            ),
            (
                MountWriteRangeOperation::Allocate,
                Method::POST,
                format!("io/v1/mount-writes/{write_session_id}/allocate"),
            ),
            (
                MountWriteRangeOperation::SeekData,
                Method::GET,
                format!("io/v1/mount-writes/{write_session_id}/seek-data"),
            ),
            (
                MountWriteRangeOperation::SeekHole,
                Method::GET,
                format!("io/v1/mount-writes/{write_session_id}/seek-hole"),
            ),
        ];
        for (operation, expected_method, expected_path) in cases {
            let (method, path) = range_endpoint(write_session_id, operation);
            assert_eq!(method, expected_method);
            assert_eq!(path, expected_path);
        }
    }

    #[test]
    fn mount_capability_claims_bind_every_range_operation_and_data_digest() {
        let write = write_fence();
        let uses = [
            MountStorageCapabilityUse::WriteData,
            MountStorageCapabilityUse::Deallocate,
            MountStorageCapabilityUse::Allocate,
            MountStorageCapabilityUse::SeekData,
            MountStorageCapabilityUse::SeekHole,
        ];
        let mut operations = std::collections::HashSet::new();
        for purpose in uses {
            let digest = (purpose == MountStorageCapabilityUse::WriteData).then_some([11; 32]);
            let range_end = if matches!(
                purpose,
                MountStorageCapabilityUse::SeekData | MountStorageCapabilityUse::SeekHole
            ) {
                7
            } else {
                13
            };
            let prepared = prepare_mount_capability(&write, purpose, 7, range_end, digest)
                .expect("complete positive write fence");
            assert_eq!(prepared.claims.audience, MOUNT_CAPABILITY_AUDIENCE);
            assert_eq!(prepared.claims.operation, purpose.operation() as i32);
            assert_eq!(prepared.claims.range_start, 7);
            assert_eq!(prepared.claims.range_end, range_end);
            assert_eq!(
                prepared.claims.expires_at_unix_seconds - prepared.claims.issued_at_unix_seconds,
                MOUNT_CAPABILITY_LIFETIME_SECONDS
            );
            assert_eq!(
                prepared.claims.content_blake3,
                digest.map_or_else(Vec::new, Vec::from)
            );
            assert_eq!(
                Uuid::parse_str(&prepared.claims.capability_id).unwrap(),
                prepared.capability_id
            );
            assert!(!prepared.capability_id.is_nil());
            assert_eq!(prepared.claims.nonce.len(), 32);
            assert!(operations.insert(prepared.claims.operation));
        }
        assert_eq!(operations.len(), uses.len());
    }

    #[test]
    fn mount_capability_generation_rejects_nil_cross_mode_and_open_range_claims() {
        let write = write_fence();
        assert!(
            prepare_mount_capability(&write, MountStorageCapabilityUse::WriteData, 0, 0, None,)
                .is_err()
        );
        assert!(
            prepare_mount_capability(
                &write,
                MountStorageCapabilityUse::Allocate,
                0,
                0,
                Some([1; 32]),
            )
            .is_err()
        );
        assert!(
            prepare_mount_capability(&write, MountStorageCapabilityUse::SeekData, 0, 1, None,)
                .is_err()
        );
        assert!(
            prepare_mount_capability(&write, MountStorageCapabilityUse::Flush, 1, 1, None,)
                .is_err()
        );
        let mut nil = write;
        nil.handle_id = Uuid::nil();
        assert!(
            prepare_mount_capability(
                &nil,
                MountStorageCapabilityUse::WriteData,
                0,
                0,
                Some([1; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn base_chunk_evidence_is_complete_contiguous_and_layout_closed() {
        let mut storage = empty_storage();
        let mut base = payload(
            storage.staging_payload.tenant_id,
            storage.staging_payload.drive_id,
            storage.staging_payload.backend_id,
            "chunked",
            "referenced",
            5,
        );
        base.blake3 = Some(vec![7; 32]);
        storage.base_payload = Some(base);
        storage.base_parts = vec![
            MountPayloadPartRecord {
                chunk_number: 0,
                locator: Uuid::new_v4(),
                size_bytes: 4,
                blake3: [1; 32],
            },
            MountPayloadPartRecord {
                chunk_number: 1,
                locator: Uuid::new_v4(),
                size_bytes: 1,
                blake3: [2; 32],
            },
        ];
        assert!(validate_base_parts(&storage, 4).is_ok());
        storage.base_parts[1].chunk_number = 2;
        assert!(validate_base_parts(&storage, 4).is_err());
        storage.base_parts[1].chunk_number = 1;
        storage.base_parts[1].locator = storage.base_parts[0].locator;
        assert!(validate_base_parts(&storage, 4).is_err());

        storage.base_parts.clear();
        storage.base_payload.as_mut().unwrap().layout = "whole".into();
        assert!(validate_base_parts(&storage, 4).is_ok());
        storage.base_parts.push(MountPayloadPartRecord {
            chunk_number: 0,
            locator: Uuid::new_v4(),
            size_bytes: 4,
            blake3: [3; 32],
        });
        assert!(validate_base_parts(&storage, 4).is_err());
    }

    #[test]
    fn complete_chunk_plan_is_contiguous_exact_and_rejects_substitution() {
        let empty = empty_storage();
        let chunks = build_mount_chunk_plan(&empty, 9, 4).expect("new exact plan");
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.iter().map(|chunk| chunk.size_bytes).sum::<i64>(), 9);
        assert_eq!(chunks[0].chunk_number, 0);
        assert_eq!(chunks[1].chunk_number, 1);
        assert_eq!(chunks[2].chunk_number, 2);
        assert_eq!((chunks[0].size_bytes, chunks[1].size_bytes), (4, 4));
        assert_eq!(chunks[2].size_bytes, 1);
        assert!(chunks.iter().all(|chunk| chunk.dirty));
        assert!(chunks.iter().all(|chunk| {
            chunk.source_payload_id.is_none() && chunk.source_chunk_number.is_none()
        }));

        let mut based = empty_storage();
        let base = payload(
            based.staging_payload.tenant_id,
            based.staging_payload.drive_id,
            based.staging_payload.backend_id,
            "whole",
            "referenced",
            5,
        );
        based.base_payload = Some(base.clone());
        based.logical_size_bytes = 5;
        based.reserved_bytes = 5;
        based.planned_chunks = vec![
            MountWriteChunkPlan {
                chunk_number: 0,
                source_payload_id: Some(base.payload_id),
                source_chunk_number: Some(0),
                staging_locator: Uuid::new_v4(),
                size_bytes: 4,
                dirty: true,
            },
            MountWriteChunkPlan {
                chunk_number: 1,
                source_payload_id: Some(base.payload_id),
                source_chunk_number: Some(1),
                staging_locator: Uuid::new_v4(),
                size_bytes: 1,
                dirty: true,
            },
        ];
        let extended = build_mount_chunk_plan(&based, 9, 4).expect("exact extended prefix");
        assert_eq!(extended.len(), 3);
        assert_eq!(extended[1].size_bytes, 4);
        assert_eq!(extended[2].size_bytes, 1);
        assert_eq!(extended[0].source_payload_id, Some(base.payload_id));
        assert_eq!(extended[1].source_chunk_number, Some(1));
        assert_eq!(extended[2].source_payload_id, None);

        let mut substituted = based.clone();
        substituted.planned_chunks[1].staging_locator =
            substituted.planned_chunks[0].staging_locator;
        assert!(build_mount_chunk_plan(&substituted, 9, 4).is_err());
        substituted = based.clone();
        substituted.planned_chunks[0].source_chunk_number = Some(1);
        assert!(build_mount_chunk_plan(&substituted, 9, 4).is_err());
        substituted = based;
        substituted.planned_chunks[0].dirty = false;
        assert!(build_mount_chunk_plan(&substituted, 9, 4).is_err());
    }

    #[test]
    fn range_reservation_is_inclusive_and_never_uses_unused_headroom_implicitly() {
        let mut storage = empty_storage();
        storage.reserved_bytes = 16;
        storage.logical_size_bytes = 8;
        assert_eq!(
            required_reservation(&storage, MountWriteRangeOperation::WriteData, 16, 64),
            Ok(17)
        );
        assert_eq!(
            required_reservation(&storage, MountWriteRangeOperation::Allocate, 0, 64),
            Ok(16)
        );
        assert_eq!(
            required_reservation(&storage, MountWriteRangeOperation::HoleDeallocate, 15, 64),
            Ok(16)
        );
        assert!(
            required_reservation(&storage, MountWriteRangeOperation::HoleDeallocate, 16, 64)
                .is_err()
        );
        assert!(
            required_reservation(&storage, MountWriteRangeOperation::SeekData, 16, 64).is_err()
        );
        assert!(
            required_reservation(&storage, MountWriteRangeOperation::WriteData, 64, 64).is_err()
        );
    }

    #[test]
    fn pending_range_resume_rejects_every_identity_and_claim_substitution() {
        let spec = range_spec(MountWriteRangeOperation::WriteData);
        let protocol_operation_id = Uuid::new_v4();
        let write_session_id = Uuid::new_v4();
        let mut pending = PendingMountIoOperation {
            protocol_operation_id,
            write_session_id,
            capability_id: Uuid::new_v4(),
            nonce_digest: [1; 32],
            claims_digest: [2; 32],
            operation: spec.io_operation,
            operation_id: Some(protocol_operation_id),
            content_blake3: spec.content_blake3,
            range_start: Some(spec.range_start),
            range_end: Some(spec.range_end),
            fencing_token: 9,
            capability_expires_at_unix_seconds: 1_800_000_000,
            worker_state: PendingMountIoWorkerState::Admission,
            worker_outcome: None,
        };
        assert!(pending_range_matches(
            &pending,
            spec,
            Some(write_session_id),
            Some(9)
        ));

        pending.operation = MountIoOperation::Allocate;
        assert!(!pending_range_matches(&pending, spec, None, None));
        pending.operation = spec.io_operation;
        pending.operation_id = Some(Uuid::new_v4());
        assert!(!pending_range_matches(&pending, spec, None, None));
        pending.operation_id = Some(protocol_operation_id);
        pending.range_start = Some(spec.range_start + 1);
        assert!(!pending_range_matches(&pending, spec, None, None));
        pending.range_start = Some(spec.range_start);
        pending.range_end = Some(spec.range_end + 1);
        assert!(!pending_range_matches(&pending, spec, None, None));
        pending.range_end = Some(spec.range_end);
        pending.content_blake3 = Some([3; 32]);
        assert!(!pending_range_matches(&pending, spec, None, None));
        pending.content_blake3 = spec.content_blake3;
        assert!(!pending_range_matches(
            &pending,
            spec,
            Some(Uuid::new_v4()),
            Some(9)
        ));
        assert!(!pending_range_matches(
            &pending,
            spec,
            Some(write_session_id),
            Some(10)
        ));
    }

    #[test]
    fn pending_flush_resume_is_closed_to_range_and_fence_substitution() {
        let protocol_operation_id = Uuid::new_v4();
        let write_session_id = Uuid::new_v4();
        let mut pending = PendingMountIoOperation {
            protocol_operation_id,
            write_session_id,
            capability_id: Uuid::new_v4(),
            nonce_digest: [1; 32],
            claims_digest: [2; 32],
            operation: MountIoOperation::Flush,
            operation_id: None,
            content_blake3: None,
            range_start: None,
            range_end: None,
            fencing_token: 9,
            capability_expires_at_unix_seconds: 1_800_000_000,
            worker_state: PendingMountIoWorkerState::Completed,
            worker_outcome: None,
        };
        assert!(pending_flush_matches(&pending, write_session_id, 9));
        pending.operation = MountIoOperation::Finalize;
        assert!(!pending_flush_matches(&pending, write_session_id, 9));
        pending.operation = MountIoOperation::Flush;
        pending.range_start = Some(0);
        assert!(!pending_flush_matches(&pending, write_session_id, 9));
        pending.range_start = None;
        assert!(!pending_flush_matches(&pending, Uuid::new_v4(), 9));
        assert!(!pending_flush_matches(&pending, write_session_id, 10));
    }

    #[test]
    fn worker_manifest_digest_decoding_is_exact_and_canonical() {
        assert_eq!(decode_hex_digest(&"ab".repeat(32)), Ok([0xab; 32]));
        assert!(decode_hex_digest(&"AB".repeat(32)).is_err());
        assert!(decode_hex_digest(&"0".repeat(63)).is_err());
        assert!(decode_hex_digest(&format!("{}g", "0".repeat(63))).is_err());
    }
}

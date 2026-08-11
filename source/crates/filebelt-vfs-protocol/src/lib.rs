// SPDX-License-Identifier: Apache-2.0

//! Bounded, protocol-neutral virtual-filesystem RPC types.

#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::net::IpAddr;

use thiserror::Error;
use uuid::Uuid;

mod generated {
    include!("../../../../protocol/generated/rust/filebelt/vfs/v1/filebelt.vfs.v1.rs");
}

pub use generated::*;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 1_114_112;
pub const MAX_RESPONSE_BYTES: usize = 1_114_112;
pub const MAX_DATA_BYTES: usize = 1_048_576;
pub const MAX_DIRECTORY_ENTRIES: usize = 1_000;
pub const MAX_PERSISTENT_HANDLE_BYTES: usize = 128;
pub const MAX_XATTR_BYTES: usize = 65_536;
pub const NFS_GATEWAY_LEASE_SECONDS: u32 = 30;
pub const NFS_CONFIG_FORMAT: u32 = 8;
pub const NFS_AUTHORITY_SCHEMA_REVISION: u32 = 1;

const MAX_ACL_ENTRIES: usize = 256;
const MAX_PROJECTED_ID: u64 = 4_294_967_294;
const NFS_NOBODY_PROJECTED_ID: u64 = 65_534;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    Authenticate,
    NfsAuthenticate,
    List,
    Stat,
    Open,
    Read,
    Write,
    Flush,
    Commit,
    Close,
    Create,
    Mkdir,
    Rename,
    Remove,
    SetAttributes,
    Lock,
    Unlock,
    LeaseAcknowledge,
    AllocatePassivePort,
    Heartbeat,
    EndSession,
    GatewayHello,
    GetXattr,
    SetXattr,
    ListXattr,
    RemoveXattr,
    Readlink,
    Symlink,
    SparseWrite,
    Reclaim,
    OpenUnlinked,
    ResolveHandle,
    ExportRoot,
    Lookup,
    Access,
    FilesystemInfo,
    GetAcl,
    SetAcl,
    SparseControl,
    GatewayDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestClass {
    Bootstrap,
    GatewayControl,
    Session,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedNfsContext {
    pub gss_binding_digest: [u8; 32],
    pub client_id: String,
    pub nfs_session_id: String,
    pub slot_id: u16,
    pub sequence_id: i64,
    pub operation_index: u8,
    pub request_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFence {
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub protocol: MountProtocol,
    pub gateway_id: String,
    pub gateway_epoch: i64,
    pub session_id: Option<Uuid>,
    pub credential_generation: Option<i64>,
    pub authorization_generation: Option<i64>,
    pub nfs_context: Option<ValidatedNfsContext>,
    pub operation: OperationKind,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("unsupported VFS protocol version")]
    Version,
    #[error("invalid VFS request envelope")]
    Envelope,
    #[error("invalid VFS operation")]
    Operation,
    #[error("invalid VFS identifier")]
    Identifier,
    #[error("invalid VFS name")]
    Name,
    #[error("VFS request exceeds its bounded envelope")]
    Limit,
}

impl VfsRequest {
    pub fn validate(&self) -> Result<RequestFence, ValidationError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ValidationError::Version);
        }
        let request_id = uuid(&self.request_id)?;
        let protocol =
            MountProtocol::try_from(self.protocol).map_err(|_| ValidationError::Envelope)?;
        if protocol == MountProtocol::Unspecified
            || self.gateway_epoch > i64::MAX as u64
            || !stable_key(&self.gateway_id, 255)
        {
            return Err(ValidationError::Envelope);
        }
        let operation = self.operation.as_ref().ok_or(ValidationError::Operation)?;
        let kind = operation_kind(operation);
        validate_operation(operation, protocol, &self.gateway_id, self.gateway_epoch)?;
        let request_class = request_class(operation);
        let tenant_id = if protocol == MountProtocol::Nfs
            && matches!(operation, vfs_request::Operation::GatewayHello(_))
            && self.tenant_id.is_empty()
        {
            Uuid::nil()
        } else {
            uuid(&self.tenant_id)?
        };
        if matches!(operation, vfs_request::Operation::GatewayHello(_)) != (self.gateway_epoch == 0)
        {
            return Err(ValidationError::Envelope);
        }
        let (session_id, credential_generation, authorization_generation) =
            if request_class != RequestClass::Session {
                if !self.session_id.is_empty()
                    || self.credential_generation != 0
                    || self.authorization_generation != 0
                {
                    return Err(ValidationError::Envelope);
                }
                (None, None, None)
            } else {
                if self.credential_generation == 0
                    || self.authorization_generation == 0
                    || self.credential_generation > i64::MAX as u64
                    || self.authorization_generation > i64::MAX as u64
                {
                    return Err(ValidationError::Envelope);
                }
                (
                    Some(uuid(&self.session_id)?),
                    Some(self.credential_generation as i64),
                    Some(self.authorization_generation as i64),
                )
            };
        let nfs_context = validate_nfs_context(
            self.nfs_context.as_ref(),
            protocol,
            request_class != RequestClass::Session,
            operation,
        )?;
        Ok(RequestFence {
            request_id,
            tenant_id,
            protocol,
            gateway_id: self.gateway_id.clone(),
            gateway_epoch: self.gateway_epoch as i64,
            session_id,
            credential_generation,
            authorization_generation,
            nfs_context,
            operation: kind,
        })
    }
}

impl VfsResponse {
    pub fn validate_for(&self, request_id: Uuid) -> Result<(), ValidationError> {
        if self.protocol_version != PROTOCOL_VERSION || uuid(&self.request_id)? != request_id {
            return Err(ValidationError::Envelope);
        }
        let error = VfsError::try_from(self.error).map_err(|_| ValidationError::Envelope)?;
        if error == VfsError::Unspecified
            || !self.reason_code.is_empty() && !stable_key(&self.reason_code, 128)
            || self.data.len() > MAX_DATA_BYTES
            || self.entries.len() > MAX_DIRECTORY_ENTRIES
            || self.next_cursor.len() > 4_096
            || self.xattr_value.len() > MAX_XATTR_BYTES
            || self.xattr_names.len() > 256
            || self.symlink_target.len() > 4_096
            || self.symlink_target.as_bytes().contains(&0)
            || self.persistent_handle.len() > MAX_PERSISTENT_HANDLE_BYTES
            || self.export_id > i64::MAX as u64
        {
            return Err(ValidationError::Limit);
        }
        for identifier in [
            &self.session_id,
            &self.handle_id,
            &self.write_session_id,
            &self.lock_id,
            &self.lease_id,
            &self.version_id,
            &self.state_id,
            &self.resource_id,
        ] {
            optional_uuid(identifier)?;
        }
        if error == VfsError::Ok && !self.reason_code.is_empty() {
            return Err(ValidationError::Envelope);
        }
        for entry in &self.entries {
            uuid(&entry.resource_id)?;
            validate_display_name(&entry.display_name)?;
            optional_persistent_handle(&entry.persistent_handle, MountProtocol::Nfs)?;
            if let Some(attributes) = &entry.attributes {
                validate_attributes(attributes)?;
            }
        }
        if let Some(attributes) = &self.attributes {
            validate_attributes(attributes)?;
        }
        for name in &self.xattr_names {
            validate_xattr_name(name)?;
        }
        if let Some(hello) = &self.nfs_gateway_hello {
            if error != VfsError::Ok || self.gateway_epoch == 0 {
                return Err(ValidationError::Envelope);
            }
            validate_nfs_gateway_hello_response(hello)?;
        }
        if let Some(projection) = &self.nfs_session_projection {
            if error != VfsError::Ok
                || self.session_id.is_empty()
                || self.credential_generation == 0
                || self.authorization_generation == 0
            {
                return Err(ValidationError::Envelope);
            }
            validate_nfs_session_projection(projection)?;
        }
        if let Some(filesystem) = &self.filesystem_info {
            validate_filesystem_info(filesystem)?;
        }
        if let Some(acl) = &self.acl {
            validate_acl(acl, None)?;
        }
        if !self.allowed_actions.is_empty() {
            validate_actions(&self.allowed_actions)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn failure(request_id: Uuid, error: VfsError, reason_code: &str) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            error: error as i32,
            reason_code: reason_code.to_owned(),
            ..Self::default()
        }
    }
}

fn validate_operation(
    operation: &vfs_request::Operation,
    protocol: MountProtocol,
    gateway_id: &str,
    gateway_epoch: u64,
) -> Result<(), ValidationError> {
    use vfs_request::Operation;
    match operation {
        Operation::Authenticate(request) => {
            let scheme = AuthenticationScheme::try_from(request.scheme)
                .map_err(|_| ValidationError::Operation)?;
            if !stable_key(&request.username, 96)
                || request.username.len() < 16
                || !(32..=4_096).contains(&request.exchange.len())
                || request.channel_binding.len() > 512
                || request.source_address.parse::<IpAddr>().is_err()
                || optional_uuid(&request.device_id).is_err()
                || !matches!(
                    (protocol, scheme),
                    (MountProtocol::Smb, AuthenticationScheme::Ntlmv2Response)
                        | (
                            MountProtocol::Ftps,
                            AuthenticationScheme::PasswordHmacSha256
                        )
                )
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::NfsAuthenticate(request) => {
            let protection = RpcsecGssProtection::try_from(request.protection)
                .map_err(|_| ValidationError::Operation)?;
            if protocol != MountProtocol::Nfs
                || !valid_kerberos_principal(&request.kerberos_principal)
                || request.gss_binding_digest.len() != 32
                || request.source_address.parse::<IpAddr>().is_err()
                || protection != RpcsecGssProtection::Privacy
                || request.context_expires_at_unix_seconds <= 0
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::List(request) => {
            uuids(&[&request.drive_id, &request.directory_id])?;
            optional_persistent_handle(&request.directory_handle, protocol)?;
            if !(1..=MAX_DIRECTORY_ENTRIES as u32).contains(&request.limit)
                || request.cursor.len() > 4_096
            {
                return Err(ValidationError::Limit);
            }
        }
        Operation::Stat(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::Open(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            optional_uuid(&request.expected_version_id)?;
            validate_actions(&request.requested_actions)?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::Read(request) => {
            uuid(&request.handle_id)?;
            if request.length == 0
                || request.length > MAX_DATA_BYTES as u64
                || request.offset.checked_add(request.length).is_none()
            {
                return Err(ValidationError::Limit);
            }
        }
        Operation::Write(request) => {
            uuids(&[&request.handle_id, &request.write_session_id])?;
            if request.fencing_token == 0
                || request.data.is_empty()
                || request.data.len() > MAX_DATA_BYTES
                || request
                    .offset
                    .checked_add(request.data.len() as u64)
                    .is_none()
            {
                return Err(ValidationError::Limit);
            }
        }
        Operation::Flush(request) => {
            uuids(&[&request.handle_id, &request.write_session_id])?;
            positive(request.fencing_token)?;
        }
        Operation::Commit(request) => {
            uuids(&[&request.handle_id, &request.write_session_id])?;
            optional_uuid(&request.expected_head_version_id)?;
            positive(request.fencing_token)?;
        }
        Operation::Close(request) => {
            uuid(&request.handle_id)?;
        }
        Operation::Create(request) => {
            uuids(&[&request.drive_id, &request.parent_id])?;
            validate_display_name(&request.display_name)?;
            positive(request.expected_parent_generation)?;
            validate_actions(&request.requested_actions)?;
            optional_persistent_handle(&request.parent_handle, protocol)?;
        }
        Operation::Mkdir(request) => {
            uuids(&[&request.drive_id, &request.parent_id])?;
            validate_display_name(&request.display_name)?;
            positive(request.expected_parent_generation)?;
            optional_persistent_handle(&request.parent_handle, protocol)?;
        }
        Operation::Rename(request) => {
            uuids(&[
                &request.drive_id,
                &request.resource_id,
                &request.target_parent_id,
            ])?;
            validate_display_name(&request.target_display_name)?;
            positive(request.expected_namespace_generation)?;
            optional_persistent_handle(&request.resource_handle, protocol)?;
            optional_persistent_handle(&request.target_parent_handle, protocol)?;
        }
        Operation::Remove(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            positive(request.expected_namespace_generation)?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::SetAttributes(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
            if request.modified_at_unix_seconds.is_none()
                && request.accessed_at_unix_seconds.is_none()
                && request.read_only.is_none()
                && request.size_bytes.is_none()
                && request.mode.is_none()
                && request.projected_uid.is_none()
                && request.projected_gid.is_none()
                && request.owner_name.is_none()
                && request.group_name.is_none()
            {
                return Err(ValidationError::Operation);
            }
            let nfs_attributes = request.size_bytes.is_some()
                || request.mode.is_some()
                || request.projected_uid.is_some()
                || request.projected_gid.is_some()
                || request.owner_name.is_some()
                || request.group_name.is_some();
            if nfs_attributes && protocol != MountProtocol::Nfs
                || request.mode.is_some_and(|mode| mode & !0o777 != 0)
                || request
                    .projected_uid
                    .is_some_and(|value| !(1..=MAX_PROJECTED_ID).contains(&value))
                || request
                    .projected_gid
                    .is_some_and(|value| !(1..=MAX_PROJECTED_ID).contains(&value))
                || request
                    .owner_name
                    .as_deref()
                    .is_some_and(|value| !valid_lowercase_posix_name(value))
                || request
                    .group_name
                    .as_deref()
                    .is_some_and(|value| !valid_lowercase_posix_name(value))
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::Lock(request) => {
            uuid(&request.handle_id)?;
            if !stable_key(&request.owner_key, 255)
                || request.length == 0
                || request.offset.checked_add(request.length).is_none()
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::Unlock(request) => uuids(&[&request.handle_id, &request.lock_id])?,
        Operation::LeaseAcknowledge(request) => {
            uuids(&[&request.handle_id, &request.lease_id])?;
            positive(request.fencing_token)?;
            let state =
                LeaseState::try_from(request.state).map_err(|_| ValidationError::Operation)?;
            if !matches!(state, LeaseState::Broken | LeaseState::Released) {
                return Err(ValidationError::Operation);
            }
        }
        Operation::AllocatePassivePort(request) => {
            if protocol != MountProtocol::Ftps
                || request.source_address.parse::<IpAddr>().is_err()
                || request.binding_digest.len() != 32
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::Heartbeat(_) => {}
        Operation::EndSession(request) => {
            if !stable_key(&request.reason_code, 64) {
                return Err(ValidationError::Operation);
            }
        }
        Operation::GatewayHello(request) => {
            if protocol == MountProtocol::Nfs {
                if !request.shard_key.is_empty()
                    || !valid_tenant_slug(&request.tenant_slug)
                    || uuid(&request.boot_id).is_err()
                    || gateway_id != request.boot_id
                    || request
                        .nfs_compatibility
                        .as_ref()
                        .is_none_or(|value| validate_nfs_compatibility(value).is_err())
                {
                    return Err(ValidationError::Operation);
                }
            } else if !stable_key(&request.shard_key, 255)
                || !request.tenant_slug.is_empty()
                || !request.boot_id.is_empty()
                || request.nfs_compatibility.is_some()
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::GetXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            validate_xattr_name(&request.name)?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::RemoveXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            validate_xattr_name(&request.name)?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::SetXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            validate_xattr_name(&request.name)?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
            if request.value.len() > MAX_XATTR_BYTES
                || (request.create_only && request.replace_only)
            {
                return Err(ValidationError::Limit);
            }
        }
        Operation::ListXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::Readlink(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            optional_persistent_handle(&request.persistent_handle, protocol)?;
        }
        Operation::Symlink(request) => {
            uuids(&[&request.drive_id, &request.parent_id])?;
            validate_display_name(&request.display_name)?;
            if request.target.is_empty()
                || request.target.len() > 4_096
                || request.target.starts_with('/')
                || request.target.as_bytes().contains(&0)
            {
                return Err(ValidationError::Name);
            }
            positive(request.expected_parent_generation)?;
            optional_persistent_handle(&request.parent_handle, protocol)?;
        }
        Operation::SparseWrite(request) => {
            uuids(&[&request.handle_id, &request.write_session_id])?;
            positive(request.fencing_token)?;
            if request.length == 0
                || request.length > MAX_DATA_BYTES as u64
                || request.offset.checked_add(request.length).is_none()
                || (request.hole && !request.data.is_empty())
                || (!request.hole && request.data.len() as u64 != request.length)
            {
                return Err(ValidationError::Limit);
            }
        }
        Operation::Reclaim(request) => {
            if protocol != MountProtocol::Nfs
                || !stable_key(&request.client_id, 255)
                || uuid(&request.state_id).is_err()
                || request.gateway_epoch == 0
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::OpenUnlinked(request) => {
            uuids(&[&request.handle_id, &request.write_session_id])?;
            positive(request.fencing_token)?;
        }
        Operation::ResolveHandle(request) => {
            nfs_only(protocol)?;
            required_persistent_handle(&request.persistent_handle)?;
        }
        Operation::ExportRoot(request) => {
            nfs_only(protocol)?;
            positive(request.export_id)?;
        }
        Operation::Lookup(request) => {
            nfs_only(protocol)?;
            required_persistent_handle(&request.parent_handle)?;
            validate_display_name(&request.display_name)?;
        }
        Operation::Access(request) => {
            nfs_only(protocol)?;
            required_persistent_handle(&request.persistent_handle)?;
            validate_actions(&request.requested_actions)?;
        }
        Operation::FilesystemInfo(request) => {
            nfs_only(protocol)?;
            positive(request.export_id)?;
        }
        Operation::GetAcl(request) => {
            nfs_only(protocol)?;
            required_persistent_handle(&request.persistent_handle)?;
        }
        Operation::SetAcl(request) => {
            nfs_only(protocol)?;
            required_persistent_handle(&request.persistent_handle)?;
            positive(request.expected_acl_generation)?;
            let acl = request.acl.as_ref().ok_or(ValidationError::Operation)?;
            if acl.representation != AclRepresentation::Tagged as i32
                || acl.generation != request.expected_acl_generation
            {
                return Err(ValidationError::Operation);
            }
            validate_acl(acl, Some(AclRepresentation::Tagged))?;
            if acl
                .entries
                .iter()
                .any(|entry| entry.entry_type != AclEntryType::Allow as i32)
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::SparseControl(request) => {
            nfs_only(protocol)?;
            uuid(&request.handle_id)?;
            let kind = SparseControlKind::try_from(request.kind)
                .map_err(|_| ValidationError::Operation)?;
            match kind {
                SparseControlKind::SeekData | SparseControlKind::SeekHole => {
                    if request.length != 0 {
                        return Err(ValidationError::Operation);
                    }
                }
                SparseControlKind::Allocate | SparseControlKind::Deallocate => {
                    if request.length == 0 || request.offset.checked_add(request.length).is_none() {
                        return Err(ValidationError::Limit);
                    }
                }
                SparseControlKind::Unspecified => return Err(ValidationError::Operation),
            }
        }
        Operation::GatewayDrain(request) => {
            nfs_only(protocol)?;
            uuid(&request.boot_id)?;
            positive(gateway_epoch)?;
            if gateway_id != request.boot_id {
                return Err(ValidationError::Operation);
            }
        }
    }
    Ok(())
}

const fn operation_kind(operation: &vfs_request::Operation) -> OperationKind {
    use vfs_request::Operation;
    match operation {
        Operation::Authenticate(_) => OperationKind::Authenticate,
        Operation::NfsAuthenticate(_) => OperationKind::NfsAuthenticate,
        Operation::List(_) => OperationKind::List,
        Operation::Stat(_) => OperationKind::Stat,
        Operation::Open(_) => OperationKind::Open,
        Operation::Read(_) => OperationKind::Read,
        Operation::Write(_) => OperationKind::Write,
        Operation::Flush(_) => OperationKind::Flush,
        Operation::Commit(_) => OperationKind::Commit,
        Operation::Close(_) => OperationKind::Close,
        Operation::Create(_) => OperationKind::Create,
        Operation::Mkdir(_) => OperationKind::Mkdir,
        Operation::Rename(_) => OperationKind::Rename,
        Operation::Remove(_) => OperationKind::Remove,
        Operation::SetAttributes(_) => OperationKind::SetAttributes,
        Operation::Lock(_) => OperationKind::Lock,
        Operation::Unlock(_) => OperationKind::Unlock,
        Operation::LeaseAcknowledge(_) => OperationKind::LeaseAcknowledge,
        Operation::AllocatePassivePort(_) => OperationKind::AllocatePassivePort,
        Operation::Heartbeat(_) => OperationKind::Heartbeat,
        Operation::EndSession(_) => OperationKind::EndSession,
        Operation::GatewayHello(_) => OperationKind::GatewayHello,
        Operation::GetXattr(_) => OperationKind::GetXattr,
        Operation::SetXattr(_) => OperationKind::SetXattr,
        Operation::ListXattr(_) => OperationKind::ListXattr,
        Operation::RemoveXattr(_) => OperationKind::RemoveXattr,
        Operation::Readlink(_) => OperationKind::Readlink,
        Operation::Symlink(_) => OperationKind::Symlink,
        Operation::SparseWrite(_) => OperationKind::SparseWrite,
        Operation::Reclaim(_) => OperationKind::Reclaim,
        Operation::OpenUnlinked(_) => OperationKind::OpenUnlinked,
        Operation::ResolveHandle(_) => OperationKind::ResolveHandle,
        Operation::ExportRoot(_) => OperationKind::ExportRoot,
        Operation::Lookup(_) => OperationKind::Lookup,
        Operation::Access(_) => OperationKind::Access,
        Operation::FilesystemInfo(_) => OperationKind::FilesystemInfo,
        Operation::GetAcl(_) => OperationKind::GetAcl,
        Operation::SetAcl(_) => OperationKind::SetAcl,
        Operation::SparseControl(_) => OperationKind::SparseControl,
        Operation::GatewayDrain(_) => OperationKind::GatewayDrain,
    }
}

const fn request_class(operation: &vfs_request::Operation) -> RequestClass {
    match operation {
        vfs_request::Operation::Authenticate(_)
        | vfs_request::Operation::NfsAuthenticate(_)
        | vfs_request::Operation::GatewayHello(_) => RequestClass::Bootstrap,
        vfs_request::Operation::GatewayDrain(_) => RequestClass::GatewayControl,
        _ => RequestClass::Session,
    }
}

fn validate_nfs_context(
    context: Option<&NfsRequestContext>,
    protocol: MountProtocol,
    bootstrap: bool,
    operation: &vfs_request::Operation,
) -> Result<Option<ValidatedNfsContext>, ValidationError> {
    if protocol != MountProtocol::Nfs || bootstrap {
        return if context.is_none() {
            Ok(None)
        } else {
            Err(ValidationError::Envelope)
        };
    }
    let context = context.ok_or(ValidationError::Envelope)?;
    if !stable_key(&context.client_id, 255)
        || !stable_key(&context.nfs_session_id, 255)
        || context.slot_id > 1_023
        || context.sequence_id == 0
        || context.sequence_id > i64::MAX as u64
        || context.operation_index > 63
    {
        return Err(ValidationError::Envelope);
    }
    let mutation = nfs_operation_requires_digest(operation)?;
    let request_digest = if mutation {
        Some(digest_32(&context.request_digest)?)
    } else if context.request_digest.is_empty() {
        None
    } else {
        return Err(ValidationError::Envelope);
    };
    Ok(Some(ValidatedNfsContext {
        gss_binding_digest: digest_32(&context.gss_binding_digest)?,
        client_id: context.client_id.clone(),
        nfs_session_id: context.nfs_session_id.clone(),
        slot_id: context.slot_id as u16,
        sequence_id: context.sequence_id as i64,
        operation_index: context.operation_index as u8,
        request_digest,
    }))
}

fn nfs_operation_requires_digest(
    operation: &vfs_request::Operation,
) -> Result<bool, ValidationError> {
    use vfs_request::Operation;
    Ok(match operation {
        Operation::Open(_)
        | Operation::Write(_)
        | Operation::Flush(_)
        | Operation::Commit(_)
        | Operation::Close(_)
        | Operation::Create(_)
        | Operation::Mkdir(_)
        | Operation::Rename(_)
        | Operation::Remove(_)
        | Operation::SetAttributes(_)
        | Operation::Lock(_)
        | Operation::Unlock(_)
        | Operation::LeaseAcknowledge(_)
        | Operation::EndSession(_)
        | Operation::SetXattr(_)
        | Operation::RemoveXattr(_)
        | Operation::Symlink(_)
        | Operation::SparseWrite(_)
        | Operation::Reclaim(_)
        | Operation::OpenUnlinked(_)
        | Operation::SetAcl(_) => true,
        Operation::SparseControl(request) => matches!(
            SparseControlKind::try_from(request.kind).map_err(|_| ValidationError::Operation)?,
            SparseControlKind::Allocate | SparseControlKind::Deallocate
        ),
        Operation::Authenticate(_)
        | Operation::NfsAuthenticate(_)
        | Operation::GatewayHello(_)
        | Operation::List(_)
        | Operation::Stat(_)
        | Operation::Read(_)
        | Operation::AllocatePassivePort(_)
        | Operation::Heartbeat(_)
        | Operation::GetXattr(_)
        | Operation::ListXattr(_)
        | Operation::Readlink(_)
        | Operation::ResolveHandle(_)
        | Operation::ExportRoot(_)
        | Operation::Lookup(_)
        | Operation::Access(_)
        | Operation::FilesystemInfo(_)
        | Operation::GetAcl(_)
        | Operation::GatewayDrain(_) => false,
    })
}

fn validate_nfs_compatibility(
    compatibility: &NfsGatewayCompatibility,
) -> Result<(), ValidationError> {
    if compatibility.minimum_protocol_version == 0
        || compatibility.minimum_protocol_version > PROTOCOL_VERSION
        || compatibility.maximum_protocol_version < PROTOCOL_VERSION
        || compatibility.minimum_protocol_version > compatibility.maximum_protocol_version
        || compatibility.features.is_empty()
        || compatibility.features.len() > 6
        || compatibility.release_revision.len() < 7
        || !stable_key(&compatibility.release_revision, 64)
        || compatibility.config_format != NFS_CONFIG_FORMAT
        || compatibility.authority_schema_revision != NFS_AUTHORITY_SCHEMA_REVISION
    {
        return Err(ValidationError::Operation);
    }
    let mut previous = 0;
    for feature in &compatibility.features {
        let parsed =
            NfsGatewayFeature::try_from(*feature).map_err(|_| ValidationError::Operation)?;
        if parsed == NfsGatewayFeature::Unspecified || *feature <= previous {
            return Err(ValidationError::Operation);
        }
        previous = *feature;
    }
    Ok(())
}

fn validate_nfs_gateway_hello_response(
    response: &NfsGatewayHelloResponse,
) -> Result<(), ValidationError> {
    uuid(&response.tenant_id)?;
    positive(response.feature_generation)?;
    positive(response.export_generation)?;
    if response.lease_seconds != NFS_GATEWAY_LEASE_SECONDS
        || response.active_exports.len() > MAX_DIRECTORY_ENTRIES
    {
        return Err(ValidationError::Envelope);
    }
    let mut previous_export_id = 0;
    for export in &response.active_exports {
        positive(export.export_id)?;
        positive(export.generation)?;
        let drive_id = uuid(&export.drive_id)?;
        if export.export_id <= previous_export_id
            || export.generation > response.export_generation
            || export.export_path != format!("/filebelt/{drive_id}")
        {
            return Err(ValidationError::Envelope);
        }
        required_persistent_handle(&export.root_handle)?;
        previous_export_id = export.export_id;
    }
    Ok(())
}

fn validate_nfs_session_projection(
    projection: &NfsSessionProjection,
) -> Result<(), ValidationError> {
    if !valid_lowercase_posix_name(&projection.posix_name)
        || !valid_lowercase_posix_name(&projection.primary_group_name)
        || !valid_projected_id(projection.projected_uid)
        || !valid_projected_id(projection.projected_gid)
        || projection.mapping_generation == 0
        || projection.feature_generation == 0
        || projection.absolute_expires_at_unix_seconds <= 0
        || projection.allowed_export_ids.is_empty()
        || projection.allowed_export_ids.len() > MAX_DIRECTORY_ENTRIES
    {
        return Err(ValidationError::Envelope);
    }
    let mut previous_export_id = 0;
    for export_id in &projection.allowed_export_ids {
        if *export_id == 0 || *export_id <= previous_export_id {
            return Err(ValidationError::Envelope);
        }
        previous_export_id = *export_id;
    }
    Ok(())
}

fn validate_filesystem_info(info: &FilesystemInfo) -> Result<(), ValidationError> {
    if info.free_bytes > info.total_bytes
        || info.available_bytes > info.free_bytes
        || info.free_files > info.total_files
        || info.maximum_file_size == 0
        || !(1..=255).contains(&info.maximum_name_bytes)
        || !(1..=MAX_DATA_BYTES as u32).contains(&info.preferred_io_bytes)
    {
        return Err(ValidationError::Envelope);
    }
    Ok(())
}

fn validate_acl(
    acl: &VfsAcl,
    expected_representation: Option<AclRepresentation>,
) -> Result<(), ValidationError> {
    let representation =
        AclRepresentation::try_from(acl.representation).map_err(|_| ValidationError::Operation)?;
    if representation == AclRepresentation::Unspecified
        || expected_representation.is_some_and(|expected| representation != expected)
        || acl.generation == 0
        || acl.entries.len() > MAX_ACL_ENTRIES
    {
        return Err(ValidationError::Operation);
    }
    for entry in &acl.entries {
        let entry_type =
            AclEntryType::try_from(entry.entry_type).map_err(|_| ValidationError::Operation)?;
        let principal_kind = AclPrincipalKind::try_from(entry.principal_kind)
            .map_err(|_| ValidationError::Operation)?;
        let inheritance =
            AclInheritance::try_from(entry.inheritance).map_err(|_| ValidationError::Operation)?;
        if entry_type == AclEntryType::Unspecified
            || principal_kind == AclPrincipalKind::Unspecified
            || inheritance == AclInheritance::Unspecified
        {
            return Err(ValidationError::Operation);
        }
        match principal_kind {
            AclPrincipalKind::Owner | AclPrincipalKind::OwnerGroup | AclPrincipalKind::Everyone => {
                if !entry.principal.is_empty() {
                    return Err(ValidationError::Operation);
                }
            }
            AclPrincipalKind::NamedUser => {
                if !valid_kerberos_principal(&entry.principal) {
                    return Err(ValidationError::Operation);
                }
            }
            AclPrincipalKind::NamedGroup => {
                if !valid_lowercase_posix_name(&entry.principal) {
                    return Err(ValidationError::Operation);
                }
            }
            AclPrincipalKind::Unspecified => return Err(ValidationError::Operation),
        }
        validate_actions(&entry.actions)?;
    }
    Ok(())
}

fn nfs_only(protocol: MountProtocol) -> Result<(), ValidationError> {
    if protocol == MountProtocol::Nfs {
        Ok(())
    } else {
        Err(ValidationError::Operation)
    }
}

fn optional_persistent_handle(
    value: &[u8],
    protocol: MountProtocol,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        Ok(())
    } else if protocol != MountProtocol::Nfs {
        Err(ValidationError::Operation)
    } else {
        required_persistent_handle(value)
    }
}

fn required_persistent_handle(value: &[u8]) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > MAX_PERSISTENT_HANDLE_BYTES {
        Err(ValidationError::Limit)
    } else {
        Ok(())
    }
}

fn digest_32(value: &[u8]) -> Result<[u8; 32], ValidationError> {
    value.try_into().map_err(|_| ValidationError::Envelope)
}

fn validate_actions(actions: &[i32]) -> Result<(), ValidationError> {
    if actions.is_empty() || actions.len() > 12 {
        return Err(ValidationError::Operation);
    }
    let mut unique = BTreeSet::new();
    for action in actions {
        let action = VfsAction::try_from(*action).map_err(|_| ValidationError::Operation)?;
        if action == VfsAction::Unspecified || !unique.insert(action) {
            return Err(ValidationError::Operation);
        }
    }
    Ok(())
}

fn validate_attributes(attributes: &NodeAttributes) -> Result<(), ValidationError> {
    let kind = NodeKind::try_from(attributes.kind).map_err(|_| ValidationError::Envelope)?;
    if kind == NodeKind::Unspecified
        || attributes.namespace_generation == 0
        || attributes.acl_generation == 0
        || attributes.mode & !0o777 != 0
        || attributes.projected_uid == 0 && attributes.projected_gid != 0
        || attributes.projected_gid == 0 && attributes.projected_uid != 0
        || attributes.projected_uid > MAX_PROJECTED_ID
        || attributes.projected_gid > MAX_PROJECTED_ID
        || attributes.owner_name.is_empty() != attributes.group_name.is_empty()
        || !attributes.owner_name.is_empty() && !valid_lowercase_posix_name(&attributes.owner_name)
        || !attributes.group_name.is_empty() && !valid_lowercase_posix_name(&attributes.group_name)
    {
        return Err(ValidationError::Envelope);
    }
    optional_uuid(&attributes.head_version_id)?;
    if kind == NodeKind::Directory
        && (!attributes.head_version_id.is_empty() || attributes.size_bytes != 0)
    {
        return Err(ValidationError::Envelope);
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.chars().any(|character| {
            character == '/' || character == '\\' || character == '\0' || character.is_control()
        })
    {
        return Err(ValidationError::Name);
    }
    Ok(())
}

fn stable_key(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

fn valid_kerberos_principal(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 {
        return false;
    }
    let mut components = value.split('@');
    let Some(user) = components.next() else {
        return false;
    };
    let Some(realm) = components.next() else {
        return false;
    };
    if components.next().is_some()
        || user.is_empty()
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\' | b'@'))
        || realm.is_empty()
        || !realm.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        || !realm
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !realm
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    true
}

fn valid_lowercase_posix_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && value.len() <= 255
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn valid_projected_id(value: u64) -> bool {
    (1..=MAX_PROJECTED_ID).contains(&value) && value != NFS_NOBODY_PROJECTED_ID
}

fn valid_tenant_slug(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_xattr_name(value: &str) -> Result<(), ValidationError> {
    if !value.starts_with("user.")
        || value.len() > 255
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError::Name);
    }
    Ok(())
}

fn uuid(value: &str) -> Result<Uuid, ValidationError> {
    Uuid::parse_str(value).map_err(|_| ValidationError::Identifier)
}

fn optional_uuid(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        Ok(())
    } else {
        uuid(value).map(|_| ())
    }
}

fn uuids(values: &[&str]) -> Result<(), ValidationError> {
    for value in values {
        uuid(value)?;
    }
    Ok(())
}

fn positive(value: u64) -> Result<(), ValidationError> {
    if value == 0 || value > i64::MAX as u64 {
        Err(ValidationError::Operation)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: vfs_request::Operation) -> VfsRequest {
        VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            protocol: MountProtocol::Smb as i32,
            gateway_id: "smb-gateway-0".into(),
            gateway_epoch: 7,
            session_id: Uuid::new_v4().to_string(),
            credential_generation: 3,
            authorization_generation: 5,
            nfs_context: None,
            operation: Some(operation),
        }
    }

    fn nfs_context(mutation: bool) -> NfsRequestContext {
        NfsRequestContext {
            gss_binding_digest: vec![7; 32],
            client_id: "nfs-client-1".into(),
            nfs_session_id: "nfs-session-1".into(),
            slot_id: 1_023,
            sequence_id: 9,
            operation_index: 63,
            request_digest: if mutation { vec![9; 32] } else { Vec::new() },
        }
    }

    fn nfs_request(operation: vfs_request::Operation, mutation: bool) -> VfsRequest {
        let mut request = request(operation);
        request.protocol = MountProtocol::Nfs as i32;
        request.gateway_id = "nfs-gateway-0".into();
        request.nfs_context = Some(nfs_context(mutation));
        request
    }

    #[test]
    fn ordinary_operations_require_a_complete_session_fence() {
        let request = request(vfs_request::Operation::Stat(StatRequest {
            drive_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            persistent_handle: Vec::new(),
        }));
        assert_eq!(request.validate().unwrap().operation, OperationKind::Stat);
        let mut stale = request;
        stale.authorization_generation = 0;
        assert_eq!(stale.validate(), Err(ValidationError::Envelope));
    }

    #[test]
    fn authentication_scheme_is_bound_to_the_mount_protocol() {
        let mut request = request(vfs_request::Operation::Authenticate(AuthenticateRequest {
            username: "fb-0123456789abcdef".into(),
            scheme: AuthenticationScheme::Ntlmv2Response as i32,
            exchange: vec![7; 64],
            channel_binding: vec![9; 32],
            source_address: "100.64.0.10".into(),
            device_id: String::new(),
        }));
        request.session_id.clear();
        request.credential_generation = 0;
        request.authorization_generation = 0;
        assert!(request.validate().is_ok());
        request.protocol = MountProtocol::Ftps as i32;
        assert_eq!(request.validate(), Err(ValidationError::Operation));
    }

    #[test]
    fn names_ranges_and_payloads_are_bounded() {
        let mut request = request(vfs_request::Operation::Create(CreateRequest {
            drive_id: Uuid::new_v4().to_string(),
            parent_id: Uuid::new_v4().to_string(),
            display_name: "../escape".into(),
            expected_parent_generation: 1,
            requested_actions: vec![VfsAction::WriteContent as i32],
            parent_handle: Vec::new(),
        }));
        assert_eq!(request.validate(), Err(ValidationError::Name));
        request.operation = Some(vfs_request::Operation::Read(ReadRequest {
            handle_id: Uuid::new_v4().to_string(),
            offset: u64::MAX,
            length: 2,
        }));
        assert_eq!(request.validate(), Err(ValidationError::Limit));
    }

    #[test]
    fn nfs_gateway_hello_resolves_an_empty_tenant_by_slug() {
        let boot_id = Uuid::new_v4().to_string();
        let mut request = request(vfs_request::Operation::GatewayHello(GatewayHelloRequest {
            shard_key: String::new(),
            tenant_slug: "tenant-one".into(),
            boot_id: boot_id.clone(),
            nfs_compatibility: Some(NfsGatewayCompatibility {
                minimum_protocol_version: PROTOCOL_VERSION,
                maximum_protocol_version: PROTOCOL_VERSION,
                features: vec![
                    NfsGatewayFeature::RpcsecGssPrivacy as i32,
                    NfsGatewayFeature::PersistentHandles as i32,
                ],
                release_revision: "abcdef1".into(),
                config_format: NFS_CONFIG_FORMAT,
                authority_schema_revision: NFS_AUTHORITY_SCHEMA_REVISION,
            }),
        }));
        request.protocol = MountProtocol::Nfs as i32;
        request.gateway_id = boot_id;
        request.gateway_epoch = 0;
        request.tenant_id.clear();
        request.session_id.clear();
        request.credential_generation = 0;
        request.authorization_generation = 0;
        let fence = request.validate().unwrap();
        assert!(fence.tenant_id.is_nil());
        assert_eq!(fence.operation, OperationKind::GatewayHello);
        assert!(fence.nfs_context.is_none());

        request.gateway_id = Uuid::new_v4().to_string();
        assert_eq!(request.validate(), Err(ValidationError::Operation));
        let Some(vfs_request::Operation::GatewayHello(hello)) = request.operation.as_ref() else {
            unreachable!();
        };
        request.gateway_id = hello.boot_id.clone();
        if let Some(vfs_request::Operation::GatewayHello(hello)) = request.operation.as_mut() {
            hello.tenant_slug = "tenant-".into();
        }
        assert_eq!(request.validate(), Err(ValidationError::Operation));
        if let Some(vfs_request::Operation::GatewayHello(hello)) = request.operation.as_mut() {
            hello.tenant_slug = "tenant-one".into();
            hello.nfs_compatibility.as_mut().unwrap().config_format -= 1;
        }
        assert_eq!(request.validate(), Err(ValidationError::Operation));
        if let Some(vfs_request::Operation::GatewayHello(hello)) = request.operation.as_mut() {
            let compatibility = hello.nfs_compatibility.as_mut().unwrap();
            compatibility.config_format = NFS_CONFIG_FORMAT;
            compatibility.authority_schema_revision += 1;
        }
        assert_eq!(request.validate(), Err(ValidationError::Operation));
        if let Some(vfs_request::Operation::GatewayHello(hello)) = request.operation.as_mut() {
            let compatibility = hello.nfs_compatibility.as_mut().unwrap();
            compatibility.authority_schema_revision = NFS_AUTHORITY_SCHEMA_REVISION;
            compatibility.release_revision = "short".into();
        }
        assert_eq!(request.validate(), Err(ValidationError::Operation));
        if let Some(vfs_request::Operation::GatewayHello(hello)) = request.operation.as_mut() {
            hello.nfs_compatibility.as_mut().unwrap().release_revision = "abcdef1".into();
        }
        request.nfs_context = Some(nfs_context(false));
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
        request.nfs_context = None;
        request.tenant_id = "not-a-uuid".into();
        assert_eq!(request.validate(), Err(ValidationError::Identifier));
    }

    #[test]
    fn nfs_authentication_requires_exact_principal_privacy_and_expiry() {
        let mut request = request(vfs_request::Operation::NfsAuthenticate(
            NfsAuthenticateRequest {
                kerberos_principal: "alice@EXAMPLE.COM".into(),
                gss_binding_digest: vec![3; 32],
                source_address: "100.64.0.20".into(),
                protection: RpcsecGssProtection::Privacy as i32,
                context_expires_at_unix_seconds: 1_800_000_000,
            },
        ));
        request.protocol = MountProtocol::Nfs as i32;
        request.gateway_id = "nfs-gateway-0".into();
        request.session_id.clear();
        request.credential_generation = 0;
        request.authorization_generation = 0;
        assert!(request.validate().is_ok());

        for invalid in [
            "alice/admin@EXAMPLE.COM",
            "alice\\admin@EXAMPLE.COM",
            "alice smith@EXAMPLE.COM",
            "alice@example.com",
            "alice@EXAMPLE_REALM",
            "alice@@EXAMPLE.COM",
            "@EXAMPLE.COM",
        ] {
            let Some(vfs_request::Operation::NfsAuthenticate(authentication)) =
                request.operation.as_mut()
            else {
                unreachable!();
            };
            authentication.kerberos_principal = invalid.into();
            assert_eq!(request.validate(), Err(ValidationError::Operation));
        }
        let Some(vfs_request::Operation::NfsAuthenticate(authentication)) =
            request.operation.as_mut()
        else {
            unreachable!();
        };
        authentication.kerberos_principal = "alice@EXAMPLE.COM".into();
        request.nfs_context = Some(nfs_context(false));
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
    }

    #[test]
    fn nfs_gateway_drain_is_sessionless_gateway_control() {
        let boot_id = Uuid::new_v4().to_string();
        let mut request = request(vfs_request::Operation::GatewayDrain(GatewayDrainRequest {
            boot_id: boot_id.clone(),
        }));
        request.protocol = MountProtocol::Nfs as i32;
        request.gateway_id = boot_id;
        request.session_id.clear();
        request.credential_generation = 0;
        request.authorization_generation = 0;
        let fence = request.validate().unwrap();
        assert_eq!(fence.operation, OperationKind::GatewayDrain);
        assert!(fence.session_id.is_none());
        assert!(fence.nfs_context.is_none());

        request.session_id = Uuid::new_v4().to_string();
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
        request.session_id.clear();
        request.nfs_context = Some(nfs_context(false));
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
        request.nfs_context = None;
        request.tenant_id.clear();
        assert_eq!(request.validate(), Err(ValidationError::Identifier));
        request.tenant_id = Uuid::new_v4().to_string();
        request.gateway_id = Uuid::new_v4().to_string();
        assert_eq!(request.validate(), Err(ValidationError::Operation));
    }

    #[test]
    fn nfs_reads_require_context_and_forbid_a_request_digest() {
        let operation = vfs_request::Operation::Read(ReadRequest {
            handle_id: Uuid::new_v4().to_string(),
            offset: 0,
            length: 64,
        });
        let mut request = nfs_request(operation, false);
        let fence = request.validate().unwrap();
        let context = fence.nfs_context.unwrap();
        assert_eq!(context.slot_id, 1_023);
        assert_eq!(context.operation_index, 63);
        assert!(context.request_digest.is_none());

        request.nfs_context = None;
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
        request.nfs_context = Some(nfs_context(false));
        request.nfs_context.as_mut().unwrap().request_digest = vec![1; 32];
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
        request.nfs_context.as_mut().unwrap().request_digest.clear();
        request.nfs_context.as_mut().unwrap().slot_id = 1_024;
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
    }

    #[test]
    fn every_nfs_mutation_requires_an_exact_request_digest() {
        let operation = vfs_request::Operation::Close(CloseRequest {
            handle_id: Uuid::new_v4().to_string(),
        });
        let mut request = nfs_request(operation, true);
        assert_eq!(
            request
                .validate()
                .unwrap()
                .nfs_context
                .unwrap()
                .request_digest,
            Some([9; 32])
        );
        request.nfs_context.as_mut().unwrap().request_digest.clear();
        assert_eq!(request.validate(), Err(ValidationError::Envelope));
        request.nfs_context.as_mut().unwrap().request_digest = vec![9; 31];
        assert_eq!(request.validate(), Err(ValidationError::Envelope));

        request.operation = Some(vfs_request::Operation::SparseControl(
            SparseControlRequest {
                handle_id: Uuid::new_v4().to_string(),
                kind: SparseControlKind::Allocate as i32,
                offset: 0,
                length: 4_096,
            },
        ));
        request.nfs_context.as_mut().unwrap().request_digest = vec![5; 32];
        assert!(request.validate().is_ok());
        request.nfs_context.as_mut().unwrap().request_digest.clear();
        assert_eq!(request.validate(), Err(ValidationError::Envelope));

        let Some(vfs_request::Operation::SparseControl(sparse)) = request.operation.as_mut() else {
            unreachable!();
        };
        sparse.kind = SparseControlKind::SeekHole as i32;
        sparse.length = 0;
        assert!(request.validate().is_ok());
    }

    #[test]
    fn persistent_handles_are_nfs_only_and_bounded() {
        let operation = vfs_request::Operation::Lookup(LookupRequest {
            parent_handle: vec![1; MAX_PERSISTENT_HANDLE_BYTES],
            display_name: "child".into(),
        });
        let mut nfs = nfs_request(operation, false);
        assert!(nfs.validate().is_ok());
        let Some(vfs_request::Operation::Lookup(lookup)) = nfs.operation.as_mut() else {
            unreachable!();
        };
        lookup.parent_handle.push(1);
        assert_eq!(nfs.validate(), Err(ValidationError::Limit));

        let mut smb = request(vfs_request::Operation::Stat(StatRequest {
            drive_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            persistent_handle: vec![1],
        }));
        assert_eq!(smb.validate(), Err(ValidationError::Operation));
        let Some(vfs_request::Operation::Stat(stat)) = smb.operation.as_mut() else {
            unreachable!();
        };
        stat.persistent_handle.clear();
        assert!(smb.validate().is_ok());
    }

    #[test]
    fn nfs_hello_response_has_a_fixed_lease_and_sorted_manifest() {
        let request_id = Uuid::new_v4();
        let first_drive_id = Uuid::new_v4();
        let second_drive_id = Uuid::new_v4();
        let mut response = VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            error: VfsError::Ok as i32,
            gateway_epoch: 1,
            nfs_gateway_hello: Some(NfsGatewayHelloResponse {
                tenant_id: Uuid::new_v4().to_string(),
                feature_generation: 3,
                export_generation: 4,
                lease_seconds: NFS_GATEWAY_LEASE_SECONDS,
                active_exports: vec![
                    NfsExportManifestEntry {
                        export_id: 7,
                        drive_id: first_drive_id.to_string(),
                        export_path: format!("/filebelt/{first_drive_id}"),
                        generation: 3,
                        root_handle: vec![2; MAX_PERSISTENT_HANDLE_BYTES],
                        read_only: false,
                    },
                    NfsExportManifestEntry {
                        export_id: 8,
                        drive_id: second_drive_id.to_string(),
                        export_path: format!("/filebelt/{second_drive_id}"),
                        generation: 4,
                        root_handle: vec![3; 32],
                        read_only: true,
                    },
                ],
            }),
            ..VfsResponse::default()
        };
        assert!(response.validate_for(request_id).is_ok());
        response.error = VfsError::Unavailable as i32;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response.error = VfsError::Ok as i32;
        response.gateway_epoch = 0;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response.gateway_epoch = 1;
        response
            .nfs_gateway_hello
            .as_mut()
            .unwrap()
            .active_exports
            .swap(0, 1);
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_gateway_hello
            .as_mut()
            .unwrap()
            .active_exports
            .swap(0, 1);
        response.nfs_gateway_hello.as_mut().unwrap().lease_seconds += 1;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
    }

    #[test]
    fn nfs_auth_response_has_an_immutable_bounded_posix_projection() {
        let request_id = Uuid::new_v4();
        let mut response = VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            error: VfsError::Ok as i32,
            session_id: Uuid::new_v4().to_string(),
            credential_generation: 3,
            authorization_generation: 5,
            nfs_session_projection: Some(NfsSessionProjection {
                posix_name: "alice".into(),
                primary_group_name: "engineering".into(),
                projected_uid: 41_000,
                projected_gid: 42_000,
                mapping_generation: 7,
                feature_generation: 11,
                absolute_expires_at_unix_seconds: 1_900_000_000,
                allowed_export_ids: vec![4, 9],
            }),
            ..VfsResponse::default()
        };
        assert!(response.validate_for(request_id).is_ok());

        let projection = response.nfs_session_projection.as_mut().unwrap();
        projection.posix_name = "Alice".into();
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response.nfs_session_projection.as_mut().unwrap().posix_name = "alice".into();

        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .primary_group_name = "Engineering".into();
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .primary_group_name = "engineering".into();

        for invalid_uid in [0, NFS_NOBODY_PROJECTED_ID, MAX_PROJECTED_ID + 1] {
            response
                .nfs_session_projection
                .as_mut()
                .unwrap()
                .projected_uid = invalid_uid;
            assert_eq!(
                response.validate_for(request_id),
                Err(ValidationError::Envelope)
            );
        }
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .projected_uid = 41_000;

        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .projected_gid = NFS_NOBODY_PROJECTED_ID;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .projected_gid = 42_000;

        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .mapping_generation = 0;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .mapping_generation = 7;

        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .feature_generation = 0;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .feature_generation = 11;

        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .absolute_expires_at_unix_seconds = 0;
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .absolute_expires_at_unix_seconds = 1;
        assert!(response.validate_for(request_id).is_ok());

        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .allowed_export_ids
            .swap(0, 1);
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .allowed_export_ids = vec![4, 4];
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .allowed_export_ids = vec![0];
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
        response
            .nfs_session_projection
            .as_mut()
            .unwrap()
            .allowed_export_ids
            .clear();
        assert_eq!(
            response.validate_for(request_id),
            Err(ValidationError::Envelope)
        );
    }

    #[test]
    fn tagged_acl_setattr_and_symlink_attributes_are_bounded() {
        let mut setattr = nfs_request(
            vfs_request::Operation::SetAttributes(SetAttributesRequest {
                drive_id: Uuid::new_v4().to_string(),
                resource_id: Uuid::new_v4().to_string(),
                modified_at_unix_seconds: Some(1_800_000_000),
                accessed_at_unix_seconds: Some(1_799_999_999),
                read_only: None,
                size_bytes: Some(4_096),
                mode: Some(0o640),
                projected_uid: Some(1_000),
                projected_gid: Some(1_000),
                owner_name: Some("alice".into()),
                group_name: Some("users".into()),
                persistent_handle: vec![4; 32],
            }),
            true,
        );
        assert!(setattr.validate().is_ok());
        if let Some(vfs_request::Operation::SetAttributes(attributes)) = setattr.operation.as_mut()
        {
            attributes.mode = Some(0o4_640);
        }
        assert_eq!(setattr.validate(), Err(ValidationError::Operation));
        if let Some(vfs_request::Operation::SetAttributes(attributes)) = setattr.operation.as_mut()
        {
            attributes.mode = Some(0o640);
            attributes.owner_name = Some("Alice".into());
        }
        assert_eq!(setattr.validate(), Err(ValidationError::Operation));

        let acl = VfsAcl {
            representation: AclRepresentation::Tagged as i32,
            generation: 5,
            entries: vec![VfsAclEntry {
                entry_type: AclEntryType::Allow as i32,
                principal_kind: AclPrincipalKind::NamedUser as i32,
                principal: "alice@EXAMPLE.COM".into(),
                actions: vec![VfsAction::ReadMetadata as i32, VfsAction::Traverse as i32],
                inheritance: AclInheritance::ThisResource as i32,
                inherited: false,
            }],
        };
        let mut request = nfs_request(
            vfs_request::Operation::SetAcl(SetAclRequest {
                persistent_handle: vec![3; 32],
                acl: Some(acl.clone()),
                expected_acl_generation: 5,
            }),
            true,
        );
        assert!(request.validate().is_ok());
        let Some(vfs_request::Operation::SetAcl(set_acl)) = request.operation.as_mut() else {
            unreachable!();
        };
        set_acl.acl.as_mut().unwrap().entries[0].entry_type = AclEntryType::Deny as i32;
        assert_eq!(request.validate(), Err(ValidationError::Operation));

        let mut symlink = nfs_request(
            vfs_request::Operation::Symlink(SymlinkRequest {
                drive_id: Uuid::new_v4().to_string(),
                parent_id: Uuid::new_v4().to_string(),
                display_name: "link".into(),
                target: "../sibling".into(),
                expected_parent_generation: 3,
                parent_handle: vec![5; 32],
            }),
            true,
        );
        assert!(symlink.validate().is_ok());
        let Some(vfs_request::Operation::Symlink(symlink_request)) = symlink.operation.as_mut()
        else {
            unreachable!();
        };
        symlink_request.target = "/absolute/target".into();
        assert_eq!(symlink.validate(), Err(ValidationError::Name));

        let request_id = Uuid::new_v4();
        let response = VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            error: VfsError::Ok as i32,
            acl: Some(VfsAcl {
                representation: AclRepresentation::Synthesized as i32,
                ..acl
            }),
            attributes: Some(NodeAttributes {
                kind: NodeKind::Symlink as i32,
                namespace_generation: 1,
                acl_generation: 1,
                mode: 0o777,
                projected_uid: 1_000,
                projected_gid: 1_000,
                owner_name: "alice".into(),
                group_name: "users".into(),
                ..NodeAttributes::default()
            }),
            ..VfsResponse::default()
        };
        assert!(response.validate_for(request_id).is_ok());
    }
}

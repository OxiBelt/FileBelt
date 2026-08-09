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
        let tenant_id = uuid(&self.tenant_id)?;
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
        validate_operation(operation, protocol)?;
        let bootstrap = matches!(
            operation,
            vfs_request::Operation::Authenticate(_)
                | vfs_request::Operation::NfsAuthenticate(_)
                | vfs_request::Operation::GatewayHello(_)
        );
        if matches!(operation, vfs_request::Operation::GatewayHello(_)) != (self.gateway_epoch == 0)
        {
            return Err(ValidationError::Envelope);
        }
        let (session_id, credential_generation, authorization_generation) = if bootstrap {
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
        Ok(RequestFence {
            request_id,
            tenant_id,
            protocol,
            gateway_id: self.gateway_id.clone(),
            gateway_epoch: self.gateway_epoch as i64,
            session_id,
            credential_generation,
            authorization_generation,
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
            || self.xattr_value.len() > 65_536
            || self.xattr_names.len() > 256
            || self.symlink_target.len() > 4_096
            || self.symlink_target.as_bytes().contains(&0)
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
        ] {
            optional_uuid(identifier)?;
        }
        if error == VfsError::Ok && !self.reason_code.is_empty() {
            return Err(ValidationError::Envelope);
        }
        for entry in &self.entries {
            uuid(&entry.resource_id)?;
            validate_display_name(&entry.display_name)?;
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
            if protocol != MountProtocol::Nfs
                || !valid_kerberos_principal(&request.kerberos_principal)
                || request.gss_binding_digest.len() != 32
                || request.source_address.parse::<IpAddr>().is_err()
            {
                return Err(ValidationError::Operation);
            }
        }
        Operation::List(request) => {
            uuids(&[&request.drive_id, &request.directory_id])?;
            if !(1..=MAX_DIRECTORY_ENTRIES as u32).contains(&request.limit)
                || request.cursor.len() > 4_096
            {
                return Err(ValidationError::Limit);
            }
        }
        Operation::Stat(request) => uuids(&[&request.drive_id, &request.resource_id])?,
        Operation::Open(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            optional_uuid(&request.expected_version_id)?;
            validate_actions(&request.requested_actions)?;
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
        }
        Operation::Mkdir(request) => {
            uuids(&[&request.drive_id, &request.parent_id])?;
            validate_display_name(&request.display_name)?;
            positive(request.expected_parent_generation)?;
        }
        Operation::Rename(request) => {
            uuids(&[
                &request.drive_id,
                &request.resource_id,
                &request.target_parent_id,
            ])?;
            validate_display_name(&request.target_display_name)?;
            positive(request.expected_namespace_generation)?;
        }
        Operation::Remove(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            positive(request.expected_namespace_generation)?;
        }
        Operation::SetAttributes(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            if request.modified_at_unix_seconds.is_none()
                && request.accessed_at_unix_seconds.is_none()
                && request.read_only.is_none()
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
            if !stable_key(&request.shard_key, 255) {
                return Err(ValidationError::Operation);
            }
        }
        Operation::GetXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            validate_xattr_name(&request.name)?;
        }
        Operation::RemoveXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            validate_xattr_name(&request.name)?;
        }
        Operation::SetXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
            validate_xattr_name(&request.name)?;
            if request.value.len() > 65_536 || (request.create_only && request.replace_only) {
                return Err(ValidationError::Limit);
            }
        }
        Operation::ListXattr(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
        }
        Operation::Readlink(request) => {
            uuids(&[&request.drive_id, &request.resource_id])?;
        }
        Operation::Symlink(request) => {
            uuids(&[&request.drive_id, &request.parent_id])?;
            validate_display_name(&request.display_name)?;
            if request.target.is_empty()
                || request.target.len() > 4_096
                || request.target.as_bytes().contains(&0)
            {
                return Err(ValidationError::Name);
            }
            positive(request.expected_parent_generation)?;
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
    }
}

fn validate_actions(actions: &[i32]) -> Result<(), ValidationError> {
    if actions.is_empty() || actions.len() > 9 {
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
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\\' | b'\'' | b'"'))
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
            operation: Some(operation),
        }
    }

    #[test]
    fn ordinary_operations_require_a_complete_session_fence() {
        let request = request(vfs_request::Operation::Stat(StatRequest {
            drive_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
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
        }));
        assert_eq!(request.validate(), Err(ValidationError::Name));
        request.operation = Some(vfs_request::Operation::Read(ReadRequest {
            handle_id: Uuid::new_v4().to_string(),
            offset: u64::MAX,
            length: 2,
        }));
        assert_eq!(request.validate(), Err(ValidationError::Limit));
    }
}

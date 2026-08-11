// SPDX-License-Identifier: LGPL-3.0-or-later

//! Minimal adapter-local protobuf wrapper used by the C FSAL. The operation
//! payload is the canonical generated VFS operation message; the FSAL cannot
//! serialize envelope/session/generation authority.

use crate::control::ExportInstaller;
use crate::gateway::{Gateway, VfsExecutor};
use filebelt_vfs_protocol::vfs_request::Operation;
use filebelt_vfs_protocol::{
    AccessRequest, CloseRequest, CommitRequest, CreateRequest, ExportRootRequest,
    FilesystemInfoRequest, FlushRequest, GetAclRequest, GetXattrRequest, ListRequest,
    ListXattrRequest, LockRequest, MkdirRequest, MountProtocol, NfsAuthenticateRequest,
    NfsRequestContext, OpenRequest, OpenUnlinkedRequest, PROTOCOL_VERSION, ReadRequest,
    ReadlinkRequest, ReclaimRequest, RemoveRequest, RemoveXattrRequest, RenameRequest,
    ResolveHandleRequest, RpcsecGssProtection, SetAclRequest, SetAttributesRequest,
    SetXattrRequest, SparseControlRequest, SparseWriteRequest, StatRequest, SymlinkRequest,
    TestLockRequest, UnlockRequest, VfsError, VfsRequest, VfsResponse, WriteRequest,
};
use prost::Message;
use uuid::Uuid;

const FSAL_WIRE_FORMAT: u32 = 1;

#[derive(Clone, PartialEq, Message)]
pub struct FsalCall {
    #[prost(uint32, tag = "1")]
    pub format: u32,
    #[prost(message, optional, tag = "2")]
    pub authentication: Option<FsalAuthentication>,
    /// Stable field number of the VfsRequest oneof operation.
    #[prost(uint32, tag = "3")]
    pub operation_tag: u32,
    /// Canonical protobuf encoding of that operation message only.
    #[prost(bytes = "vec", tag = "4")]
    pub operation: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct FsalAuthentication {
    #[prost(string, tag = "1")]
    pub kerberos_principal: String,
    #[prost(bytes = "vec", tag = "2")]
    pub gss_binding_digest: Vec<u8>,
    #[prost(string, tag = "3")]
    pub source_address: String,
    #[prost(int64, tag = "4")]
    pub context_expires_at_unix_seconds: i64,
    #[prost(string, tag = "5")]
    pub client_id: String,
    #[prost(string, tag = "6")]
    pub nfs_session_id: String,
    #[prost(uint32, tag = "7")]
    pub slot_id: u32,
    #[prost(uint64, tag = "8")]
    pub sequence_id: u64,
    #[prost(uint32, tag = "9")]
    pub operation_index: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct FsalReply {
    /// Canonical generated VfsResponse bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub vfs_response: Vec<u8>,
    /// Exact immutable projection selected by Core for this bound session.
    #[prost(message, optional, tag = "2")]
    pub projection: Option<filebelt_vfs_protocol::NfsSessionProjection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Invalid,
}

pub fn execute<E, I>(gateway: &mut Gateway<E, I>, encoded: &[u8]) -> FsalReply
where
    E: VfsExecutor,
    I: ExportInstaller,
{
    let request_id = Uuid::new_v4();
    let Ok(call) = decode_exact::<FsalCall>(encoded) else {
        return reply(VfsResponse::failure(
            request_id,
            VfsError::InvalidRequest,
            "nfs_fsal_wire",
        ));
    };
    let Some(authentication) = call.authentication.as_ref() else {
        return reply(VfsResponse::failure(
            request_id,
            VfsError::Unauthenticated,
            "nfs_fsal_wire",
        ));
    };
    let Ok(operation) = decode_operation(call.operation_tag, &call.operation) else {
        return reply(VfsResponse::failure(
            request_id,
            VfsError::InvalidRequest,
            "nfs_fsal_wire",
        ));
    };
    if call.format != FSAL_WIRE_FORMAT
        || authentication.gss_binding_digest.len() != 32
        || authentication.kerberos_principal.is_empty()
        || authentication.source_address.is_empty()
        || authentication.context_expires_at_unix_seconds <= 0
        || authentication.client_id.is_empty()
        || authentication.nfs_session_id.is_empty()
        || authentication.slot_id > 1023
        || authentication.sequence_id == 0
        || authentication.operation_index > 63
    {
        return reply(VfsResponse::failure(
            request_id,
            VfsError::InvalidRequest,
            "nfs_fsal_wire",
        ));
    }

    let binding: [u8; 32] = authentication
        .gss_binding_digest
        .as_slice()
        .try_into()
        .expect("validated binding length");

    let mut response = gateway.handle(filesystem_request(authentication, operation.clone()));
    if response.error == VfsError::Unauthenticated as i32 {
        let authenticated = gateway.handle(authentication_request(authentication));
        if authenticated.error != VfsError::Ok as i32 {
            return reply(authenticated);
        }
        if gateway
            .bind_fsal_session(
                binding,
                &authentication.client_id,
                &authentication.nfs_session_id,
            )
            .is_err()
        {
            return reply(VfsResponse::failure(
                request_id,
                VfsError::Unauthenticated,
                "nfs_fsal_session_binding",
            ));
        }
        response = gateway.handle(filesystem_request(authentication, operation));
    }
    let projection = gateway.fsal_projection(
        binding,
        &authentication.client_id,
        &authentication.nfs_session_id,
    );
    FsalReply {
        vfs_response: response.encode_to_vec(),
        projection,
    }
}

fn reply(response: VfsResponse) -> FsalReply {
    FsalReply {
        vfs_response: response.encode_to_vec(),
        projection: None,
    }
}

fn filesystem_request(authentication: &FsalAuthentication, operation: Operation) -> VfsRequest {
    VfsRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: String::new(),
        tenant_id: String::new(),
        protocol: MountProtocol::Nfs as i32,
        gateway_id: String::new(),
        gateway_epoch: 0,
        session_id: String::new(),
        credential_generation: 0,
        authorization_generation: 0,
        nfs_context: Some(NfsRequestContext {
            gss_binding_digest: authentication.gss_binding_digest.clone(),
            client_id: authentication.client_id.clone(),
            nfs_session_id: authentication.nfs_session_id.clone(),
            slot_id: authentication.slot_id,
            sequence_id: authentication.sequence_id,
            operation_index: authentication.operation_index,
            request_digest: Vec::new(),
        }),
        operation: Some(operation),
    }
}

fn authentication_request(authentication: &FsalAuthentication) -> VfsRequest {
    VfsRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: String::new(),
        tenant_id: String::new(),
        protocol: MountProtocol::Nfs as i32,
        gateway_id: String::new(),
        gateway_epoch: 0,
        session_id: String::new(),
        credential_generation: 0,
        authorization_generation: 0,
        nfs_context: None,
        operation: Some(Operation::NfsAuthenticate(NfsAuthenticateRequest {
            kerberos_principal: authentication.kerberos_principal.clone(),
            gss_binding_digest: authentication.gss_binding_digest.clone(),
            source_address: authentication.source_address.clone(),
            protection: RpcsecGssProtection::Privacy as i32,
            context_expires_at_unix_seconds: authentication.context_expires_at_unix_seconds,
        })),
    }
}

fn decode_operation(tag: u32, payload: &[u8]) -> Result<Operation, WireError> {
    Ok(match tag {
        21 => Operation::List(decode_exact::<ListRequest>(payload)?),
        22 => Operation::Stat(decode_exact::<StatRequest>(payload)?),
        23 => Operation::Open(decode_exact::<OpenRequest>(payload)?),
        24 => Operation::Read(decode_exact::<ReadRequest>(payload)?),
        25 => Operation::Write(decode_exact::<WriteRequest>(payload)?),
        26 => Operation::Flush(decode_exact::<FlushRequest>(payload)?),
        27 => Operation::Commit(decode_exact::<CommitRequest>(payload)?),
        28 => Operation::Close(decode_exact::<CloseRequest>(payload)?),
        29 => Operation::Create(decode_exact::<CreateRequest>(payload)?),
        30 => Operation::Mkdir(decode_exact::<MkdirRequest>(payload)?),
        31 => Operation::Rename(decode_exact::<RenameRequest>(payload)?),
        32 => Operation::Remove(decode_exact::<RemoveRequest>(payload)?),
        33 => Operation::SetAttributes(decode_exact::<SetAttributesRequest>(payload)?),
        34 => Operation::Lock(decode_exact::<LockRequest>(payload)?),
        35 => Operation::Unlock(decode_exact::<UnlockRequest>(payload)?),
        42 => Operation::GetXattr(decode_exact::<GetXattrRequest>(payload)?),
        43 => Operation::SetXattr(decode_exact::<SetXattrRequest>(payload)?),
        44 => Operation::ListXattr(decode_exact::<ListXattrRequest>(payload)?),
        45 => Operation::RemoveXattr(decode_exact::<RemoveXattrRequest>(payload)?),
        46 => Operation::Readlink(decode_exact::<ReadlinkRequest>(payload)?),
        47 => Operation::Symlink(decode_exact::<SymlinkRequest>(payload)?),
        48 => Operation::SparseWrite(decode_exact::<SparseWriteRequest>(payload)?),
        49 => Operation::Reclaim(decode_exact::<ReclaimRequest>(payload)?),
        50 => Operation::OpenUnlinked(decode_exact::<OpenUnlinkedRequest>(payload)?),
        51 => Operation::ResolveHandle(decode_exact::<ResolveHandleRequest>(payload)?),
        52 => Operation::ExportRoot(decode_exact::<ExportRootRequest>(payload)?),
        53 => Operation::Lookup(decode_exact::<filebelt_vfs_protocol::LookupRequest>(
            payload,
        )?),
        54 => Operation::Access(decode_exact::<AccessRequest>(payload)?),
        55 => Operation::FilesystemInfo(decode_exact::<FilesystemInfoRequest>(payload)?),
        56 => Operation::GetAcl(decode_exact::<GetAclRequest>(payload)?),
        57 => Operation::SetAcl(decode_exact::<SetAclRequest>(payload)?),
        58 => Operation::SparseControl(decode_exact::<SparseControlRequest>(payload)?),
        61 => Operation::TestLock(decode_exact::<TestLockRequest>(payload)?),
        _ => return Err(WireError::Invalid),
    })
}

fn decode_exact<M>(encoded: &[u8]) -> Result<M, WireError>
where
    M: Message + Default,
{
    let message = M::decode(encoded).map_err(|_| WireError::Invalid)?;
    if message.encode_to_vec() != encoded {
        return Err(WireError::Invalid);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authentication() -> FsalAuthentication {
        FsalAuthentication {
            kerberos_principal: "alice@EXAMPLE.COM".into(),
            gss_binding_digest: vec![7; 32],
            source_address: "192.0.2.7".into(),
            context_expires_at_unix_seconds: 2_000_000_000,
            client_id: "0000000000000001".into(),
            nfs_session_id: "01010101010101010101010101010101".into(),
            slot_id: 1,
            sequence_id: 2,
            operation_index: 3,
        }
    }

    #[test]
    fn fsal_can_supply_only_authentication_replay_and_operation_fields() {
        let operation = filebelt_vfs_protocol::LookupRequest {
            parent_handle: vec![5; 101],
            display_name: "child".into(),
        };
        let decoded = decode_exact::<FsalCall>(
            &FsalCall {
                format: FSAL_WIRE_FORMAT,
                authentication: Some(authentication()),
                operation_tag: 53,
                operation: operation.encode_to_vec(),
            }
            .encode_to_vec(),
        )
        .expect("canonical call");
        let operation = decode_operation(decoded.operation_tag, &decoded.operation)
            .expect("supported operation");
        let request = filesystem_request(decoded.authentication.as_ref().unwrap(), operation);
        assert!(request.tenant_id.is_empty());
        assert!(request.gateway_id.is_empty());
        assert_eq!(request.gateway_epoch, 0);
        assert!(request.session_id.is_empty());
        assert_eq!(request.credential_generation, 0);
        assert_eq!(request.authorization_generation, 0);
    }

    #[test]
    fn bootstrap_auth_and_unknown_operations_cannot_cross_fsal_wire() {
        assert_eq!(decode_operation(41, &[]), Err(WireError::Invalid));
        assert_eq!(decode_operation(59, &[]), Err(WireError::Invalid));
        assert_eq!(decode_operation(60, &[]), Err(WireError::Invalid));
        let mut encoded = FsalCall {
            format: FSAL_WIRE_FORMAT,
            authentication: Some(authentication()),
            operation_tag: 53,
            operation: filebelt_vfs_protocol::LookupRequest {
                parent_handle: vec![1; 101],
                display_name: "child".into(),
            }
            .encode_to_vec(),
        }
        .encode_to_vec();
        encoded.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert_eq!(decode_exact::<FsalCall>(&encoded), Err(WireError::Invalid));
    }

    #[test]
    fn v42_sparse_and_recovery_operations_are_reachable() {
        let sparse = SparseWriteRequest {
            handle_id: Uuid::from_u128(1).to_string(),
            write_session_id: Uuid::from_u128(2).to_string(),
            fencing_token: 3,
            offset: 4,
            length: 5,
            data: Vec::new(),
            hole: true,
        };
        assert!(matches!(
            decode_operation(48, &sparse.encode_to_vec()),
            Ok(Operation::SparseWrite(_))
        ));
        let reclaim = ReclaimRequest {
            client_id: "0000000000000001".into(),
            state_id: Uuid::from_u128(6).to_string(),
            gateway_epoch: 7,
        };
        assert!(matches!(
            decode_operation(49, &reclaim.encode_to_vec()),
            Ok(Operation::Reclaim(_))
        ));
        let unlinked = OpenUnlinkedRequest {
            handle_id: Uuid::from_u128(8).to_string(),
            write_session_id: Uuid::from_u128(9).to_string(),
            fencing_token: 10,
        };
        assert!(matches!(
            decode_operation(50, &unlinked.encode_to_vec()),
            Ok(Operation::OpenUnlinked(_))
        ));
    }

    #[test]
    fn lock_test_is_a_distinct_read_only_wire_operation() {
        let request = TestLockRequest {
            handle_id: Uuid::from_u128(11).to_string(),
            owner_key: "nfs-client-1:01".into(),
            offset: 12,
            length: 0,
            exclusive: true,
            to_eof: true,
        };
        let decoded = decode_operation(61, &request.encode_to_vec()).expect("lock test");
        assert!(matches!(decoded, Operation::TestLock(_)));
        assert!(!super::super::gateway::operation_is_mutation(&decoded));
    }
}

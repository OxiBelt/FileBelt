// SPDX-License-Identifier: GPL-3.0-or-later
//! GPL bridge-side framing for the FileBelt SMB adapter.
//!
//! This crate intentionally has no Samba, database, payload-path, or Apache-core
//! dependency.  It validates the local VFS-module/bridge frame before an
//! integration-owned client translates it to the future protocol-neutral VFS RPC.

#![deny(unsafe_code)]

use std::io::{self, Read, Write};

use filebelt_vfs_protocol::vfs_request::Operation as VfsOperation;
use filebelt_vfs_protocol::{
    ListRequest, MountProtocol, PROTOCOL_VERSION, ReadRequest, StatRequest, VfsRequest,
};

/// The local module/bridge protocol version.
pub const LOCAL_PROTOCOL_VERSION: u16 = 1;
/// A frame payload is bounded before allocation or dispatch.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Stable FileBelt operations represented by the bridge boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    TreeConnect = 1,
    Lookup = 2,
    ListChildren = 3,
    OpenRead = 4,
    Read = 5,
    BeginWrite = 6,
    Write = 7,
    Flush = 8,
    Close = 9,
    CreateDirectory = 10,
    Rename = 11,
    Delete = 12,
    SetAttributes = 13,
    Lock = 14,
    Revalidate = 15,
}

impl TryFrom<u8> for Operation {
    type Error = FrameError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TreeConnect),
            2 => Ok(Self::Lookup),
            3 => Ok(Self::ListChildren),
            4 => Ok(Self::OpenRead),
            5 => Ok(Self::Read),
            6 => Ok(Self::BeginWrite),
            7 => Ok(Self::Write),
            8 => Ok(Self::Flush),
            9 => Ok(Self::Close),
            10 => Ok(Self::CreateDirectory),
            11 => Ok(Self::Rename),
            12 => Ok(Self::Delete),
            13 => Ok(Self::SetAttributes),
            14 => Ok(Self::Lock),
            15 => Ok(Self::Revalidate),
            _ => Err(FrameError::UnknownOperation),
        }
    }
}

/// Stable errors to be mapped by the VFS module to documented NTSTATUS values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FileBeltError {
    NotFound = 1,
    AccessDenied = 2,
    Conflict = 3,
    NameInvalid = 4,
    QuotaExceeded = 5,
    LockConflict = 6,
    SessionStale = 7,
    GatewayStale = 8,
    Unavailable = 9,
    Unsupported = 10,
    Internal = 11,
}

impl FileBeltError {
    /// The VFS module uses these symbolic values rather than guessing errno.
    #[must_use]
    pub const fn nt_status(self) -> &'static str {
        match self {
            Self::NotFound => "NT_STATUS_OBJECT_NAME_NOT_FOUND",
            Self::AccessDenied | Self::SessionStale | Self::GatewayStale => {
                "NT_STATUS_ACCESS_DENIED"
            }
            Self::Conflict | Self::LockConflict => "NT_STATUS_SHARING_VIOLATION",
            Self::NameInvalid => "NT_STATUS_OBJECT_NAME_INVALID",
            Self::QuotaExceeded => "NT_STATUS_DISK_FULL",
            Self::Unavailable => "NT_STATUS_IO_TIMEOUT",
            Self::Unsupported => "NT_STATUS_NOT_SUPPORTED",
            Self::Internal => "NT_STATUS_INTERNAL_ERROR",
        }
    }
}

/// Header common to every local request.  IDs are opaque 16-byte FileBelt IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub operation: Operation,
    pub mount_session_id: [u8; 16],
    pub handle_id: [u8; 16],
    pub gateway_epoch: u64,
    pub payload: Vec<u8>,
}

/// Authenticated, fenced context supplied by the Samba session bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeSession {
    pub request_id: String,
    pub tenant_id: String,
    pub gateway_id: String,
    pub gateway_epoch: u64,
    pub session_id: String,
    pub credential_generation: u64,
    pub authorization_generation: u64,
}

/// Converts a read-only SMB directory request into the Apache protocol-neutral VFS v1 envelope.
pub fn list_request(
    session: &BridgeSession,
    drive_id: String,
    directory_id: String,
    limit: u32,
) -> VfsRequest {
    envelope(
        session,
        VfsOperation::List(ListRequest {
            drive_id,
            directory_id,
            cursor: String::new(),
            limit,
        }),
    )
}

/// Converts a read-only SMB lookup without passing a Samba pathname or type.
pub fn stat_request(session: &BridgeSession, drive_id: String, resource_id: String) -> VfsRequest {
    envelope(
        session,
        VfsOperation::Stat(StatRequest {
            drive_id,
            resource_id,
        }),
    )
}

/// Converts a handle-bound SMB range read. The VFS validates range and grants.
pub fn vfs_read_request(
    session: &BridgeSession,
    handle_id: String,
    offset: u64,
    length: u64,
) -> VfsRequest {
    envelope(
        session,
        VfsOperation::Read(ReadRequest {
            handle_id,
            offset,
            length,
        }),
    )
}

fn envelope(session: &BridgeSession, operation: VfsOperation) -> VfsRequest {
    VfsRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: session.request_id.clone(),
        tenant_id: session.tenant_id.clone(),
        protocol: MountProtocol::Smb as i32,
        gateway_id: session.gateway_id.clone(),
        gateway_epoch: session.gateway_epoch,
        session_id: session.session_id.clone(),
        credential_generation: session.credential_generation,
        authorization_generation: session.authorization_generation,
        operation: Some(operation),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    Io,
    Oversize,
    Truncated,
    Version,
    UnknownOperation,
    InvalidVfsRequest,
}
impl From<io::Error> for FrameError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

/// Writes a length-prefixed frame. The payload is opaque to this boundary.
pub fn write_request(mut writer: impl Write, request: &Request) -> Result<(), FrameError> {
    if request.payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Oversize);
    }
    let body_len = 2 + 1 + 16 + 16 + 8 + request.payload.len();
    writer
        .write_all(&(u32::try_from(body_len).map_err(|_| FrameError::Oversize)?).to_be_bytes())?;
    writer.write_all(&LOCAL_PROTOCOL_VERSION.to_be_bytes())?;
    writer.write_all(&[request.operation as u8])?;
    writer.write_all(&request.mount_session_id)?;
    writer.write_all(&request.handle_id)?;
    writer.write_all(&request.gateway_epoch.to_be_bytes())?;
    writer.write_all(&request.payload)?;
    Ok(())
}

/// Reads and validates one bounded frame before it reaches adapter dispatch.
pub fn read_request(mut reader: impl Read) -> Result<Request, FrameError> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| FrameError::Oversize)?;
    const HEADER: usize = 2 + 1 + 16 + 16 + 8;
    if !(HEADER..=HEADER + MAX_FRAME_BYTES).contains(&length) {
        return Err(FrameError::Oversize);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    if u16::from_be_bytes([body[0], body[1]]) != LOCAL_PROTOCOL_VERSION {
        return Err(FrameError::Version);
    }
    let operation = Operation::try_from(body[2])?;
    let mut mount_session_id = [0; 16];
    mount_session_id.copy_from_slice(&body[3..19]);
    let mut handle_id = [0; 16];
    handle_id.copy_from_slice(&body[19..35]);
    let gateway_epoch =
        u64::from_be_bytes(body[35..43].try_into().map_err(|_| FrameError::Truncated)?);
    Ok(Request {
        operation,
        mount_session_id,
        handle_id,
        gateway_epoch,
        payload: body[43..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_round_trip_preserves_opaque_ids_and_fence() {
        let request = Request {
            operation: Operation::BeginWrite,
            mount_session_id: [1; 16],
            handle_id: [2; 16],
            gateway_epoch: 9,
            payload: vec![3; 9],
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request).unwrap();
        assert_eq!(read_request(bytes.as_slice()).unwrap(), request);
    }
    #[test]
    fn rejects_unknown_operation_before_dispatch() {
        let mut body = vec![0, 1, 99];
        body.extend([0; 40]);
        let mut bytes = (u32::try_from(body.len()).unwrap()).to_be_bytes().to_vec();
        bytes.extend(body);
        assert_eq!(
            read_request(bytes.as_slice()),
            Err(FrameError::UnknownOperation)
        );
    }
    #[test]
    fn stale_gateway_is_never_mapped_to_a_retryable_success() {
        assert_eq!(
            FileBeltError::GatewayStale.nt_status(),
            "NT_STATUS_ACCESS_DENIED"
        );
    }
    #[test]
    fn maps_list_to_valid_protocol_neutral_smb_request() {
        let session = BridgeSession {
            request_id: "11111111-1111-4111-8111-111111111111".into(),
            tenant_id: "22222222-2222-4222-8222-222222222222".into(),
            gateway_id: "smb-gateway-a".into(),
            gateway_epoch: 4,
            session_id: "33333333-3333-4333-8333-333333333333".into(),
            credential_generation: 2,
            authorization_generation: 9,
        };
        let request = list_request(
            &session,
            "44444444-4444-4444-8444-444444444444".into(),
            "55555555-5555-4555-8555-555555555555".into(),
            50,
        );
        let fence = request.validate().unwrap();
        assert_eq!(fence.protocol, MountProtocol::Smb);
        assert!(matches!(request.operation, Some(VfsOperation::List(_))));
    }
}

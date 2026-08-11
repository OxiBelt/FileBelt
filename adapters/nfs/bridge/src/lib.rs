// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bounded Unix-IPC framing between the NFS-Ganesha FSAL and its isolated
//! FileBelt VFS bridge. The payload is an opaque, generated VFS protobuf
//! envelope; this adapter crate deliberately has no Core database, payload,
//! capability-signing, or Kerberos dependency.

#![deny(unsafe_code)]

pub mod config;
pub mod control;
pub mod gateway;
pub mod ipc;
pub mod vfs;

/// Matches the Apache VFS envelope bound without importing Core implementation
/// types into the LGPL adapter workspace.
pub const MAX_VFS_FRAME_BYTES: usize = 1_114_112;
const PREFIX_BYTES: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameError {
    #[error("bridge frame exceeds its bound")]
    TooLarge,
    #[error("bridge frame is truncated")]
    Truncated,
    #[error("bridge frame has trailing bytes")]
    TrailingBytes,
}

/// Encodes one opaque VFS request or response for a `SOCK_SEQPACKET` bridge.
/// The FSAL authenticates the local peer separately; this framing is not an
/// authentication mechanism and never carries a keytab or raw GSS ticket.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_VFS_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    let mut frame = Vec::with_capacity(PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decodes exactly one complete bounded bridge frame.
pub fn decode_frame(frame: &[u8]) -> Result<&[u8], FrameError> {
    if frame.len() < PREFIX_BYTES {
        return Err(FrameError::Truncated);
    }
    let length = u32::from_be_bytes(frame[..PREFIX_BYTES].try_into().expect("prefix length"));
    let length = usize::try_from(length).map_err(|_| FrameError::TooLarge)?;
    if length > MAX_VFS_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let end = PREFIX_BYTES
        .checked_add(length)
        .ok_or(FrameError::TooLarge)?;
    if frame.len() < end {
        return Err(FrameError::Truncated);
    }
    if frame.len() != end {
        return Err(FrameError::TrailingBytes);
    }
    Ok(&frame[PREFIX_BYTES..])
}

#[cfg(test)]
mod tests {
    use super::{FrameError, MAX_VFS_FRAME_BYTES, decode_frame, encode_frame};

    #[test]
    fn bridge_frame_round_trips_without_reinterpreting_vfs_bytes() {
        let payload = [0x08, 0x01, 0x12, 0x02, 0xff, 0x00];
        let frame = encode_frame(&payload).expect("frame");
        assert_eq!(decode_frame(&frame), Ok(payload.as_slice()));
    }

    #[test]
    fn bridge_frame_rejects_truncation_trailing_bytes_and_oversize() {
        assert_eq!(decode_frame(&[0, 0, 0]), Err(FrameError::Truncated));
        assert_eq!(decode_frame(&[0, 0, 0, 2, 1]), Err(FrameError::Truncated));
        assert_eq!(
            decode_frame(&[0, 0, 0, 1, 1, 2]),
            Err(FrameError::TrailingBytes)
        );
        assert_eq!(
            encode_frame(&vec![0; MAX_VFS_FRAME_BYTES + 1]),
            Err(FrameError::TooLarge)
        );
    }
}

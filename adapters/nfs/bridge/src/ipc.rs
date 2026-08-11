// SPDX-License-Identifier: LGPL-3.0-or-later

//! Private, packet-preserving Unix IPC used by the FSAL.

use crate::{FrameError, MAX_VFS_FRAME_BYTES, decode_frame, encode_frame};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, SockFlag, SockType, UnixAddr, accept4, bind, connect, listen,
    recv, send, socket,
};
use nix::unistd::close;
use std::fs;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_PACKET_BYTES: usize = MAX_VFS_FRAME_BYTES + 4;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("Unix IPC socket setup failed")]
    Setup,
    #[error("Unix IPC operation failed")]
    Io,
    #[error(transparent)]
    Frame(#[from] FrameError),
}

pub struct SeqPacketListener {
    descriptor: OwnedFd,
    path: PathBuf,
}

impl SeqPacketListener {
    pub fn bind(path: &Path) -> Result<Self, IpcError> {
        let parent = path.parent().ok_or(IpcError::Setup)?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| IpcError::Setup)?;
        if !path.is_absolute()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o002 != 0
        {
            return Err(IpcError::Setup);
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                fs::remove_file(path).map_err(|_| IpcError::Setup)?;
            }
            Ok(_) => return Err(IpcError::Setup),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(IpcError::Setup),
        }
        let descriptor = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|_| IpcError::Setup)?;
        let address = UnixAddr::new(path).map_err(|_| IpcError::Setup)?;
        bind(descriptor.as_raw_fd(), &address).map_err(|_| IpcError::Setup)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| IpcError::Setup)?;
        listen(&descriptor, Backlog::new(64).map_err(|_| IpcError::Setup)?)
            .map_err(|_| IpcError::Setup)?;
        Ok(Self {
            descriptor,
            path: path.to_owned(),
        })
    }

    pub fn accept(&self) -> Result<SeqPacket, IpcError> {
        let descriptor = accept4(self.descriptor.as_raw_fd(), SockFlag::SOCK_CLOEXEC)
            .map_err(|_| IpcError::Io)?;
        Ok(SeqPacket(descriptor))
    }
}

impl Drop for SeqPacketListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub struct SeqPacket(RawFd);

impl SeqPacket {
    pub fn connect(path: &Path) -> Result<Self, IpcError> {
        if !path.is_absolute() {
            return Err(IpcError::Setup);
        }
        let descriptor = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|_| IpcError::Setup)?;
        let address = UnixAddr::new(path).map_err(|_| IpcError::Setup)?;
        connect(descriptor.as_raw_fd(), &address).map_err(|_| IpcError::Io)?;
        Ok(Self(descriptor.into_raw_fd()))
    }

    pub fn receive(&self) -> Result<Vec<u8>, IpcError> {
        let mut packet = vec![0_u8; MAX_PACKET_BYTES + 1];
        let received = recv(self.0, &mut packet, MsgFlags::MSG_TRUNC).map_err(|_| IpcError::Io)?;
        if received > MAX_PACKET_BYTES {
            return Err(IpcError::Frame(FrameError::TooLarge));
        }
        packet.truncate(received);
        Ok(decode_frame(&packet)?.to_vec())
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), IpcError> {
        let packet = encode_frame(payload)?;
        let written = send(self.0, &packet, MsgFlags::MSG_NOSIGNAL).map_err(|_| IpcError::Io)?;
        if written != packet.len() {
            return Err(IpcError::Io);
        }
        Ok(())
    }
}

impl Drop for SeqPacket {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::socketpair;
    use std::os::fd::IntoRawFd;

    #[test]
    fn seqpacket_preserves_one_bounded_frame() {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("socket pair");
        let left = SeqPacket(left.into_raw_fd());
        let right = SeqPacket(right.into_raw_fd());
        left.send(b"vfs").expect("send");
        assert_eq!(right.receive().expect("receive"), b"vfs");
    }
}

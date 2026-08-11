// SPDX-License-Identifier: LGPL-3.0-or-later

//! Private, packet-preserving Unix IPC used by the FSAL.

use crate::{FrameError, MAX_VFS_FRAME_BYTES, decode_frame, encode_frame};
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr, accept4,
    bind, connect, getsockopt, listen, recv, recvmsg, send, setsockopt, socket, sockopt,
};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::{close, getuid};
use std::fs;
use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
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
        setsockopt(&descriptor, sockopt::PassCred, &true).map_err(|_| IpcError::Setup)?;
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
        Ok(SeqPacket {
            descriptor,
            verify_peer_uid: true,
        })
    }
}

impl Drop for SeqPacketListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub struct SeqPacket {
    descriptor: RawFd,
    verify_peer_uid: bool,
}

impl SeqPacket {
    pub fn connect(path: &Path) -> Result<Self, IpcError> {
        if !path.is_absolute() {
            return Err(IpcError::Setup);
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| IpcError::Setup)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
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
        if getsockopt(&descriptor, sockopt::PeerCredentials)
            .map_err(|_| IpcError::Io)?
            .uid()
            != getuid().as_raw()
        {
            return Err(IpcError::Io);
        }
        let timeout = TimeVal::seconds(3);
        setsockopt(&descriptor, sockopt::ReceiveTimeout, &timeout).map_err(|_| IpcError::Setup)?;
        setsockopt(&descriptor, sockopt::SendTimeout, &timeout).map_err(|_| IpcError::Setup)?;
        Ok(Self {
            descriptor: descriptor.into_raw_fd(),
            verify_peer_uid: false,
        })
    }

    pub fn receive(&self) -> Result<Vec<u8>, IpcError> {
        let mut packet = vec![0_u8; MAX_PACKET_BYTES + 1];
        let received = if self.verify_peer_uid {
            let mut credentials = nix::cmsg_space!(nix::sys::socket::UnixCredentials);
            let mut slices = [IoSliceMut::new(&mut packet)];
            let message = recvmsg::<()>(
                self.descriptor,
                &mut slices,
                Some(&mut credentials),
                MsgFlags::MSG_TRUNC,
            )
            .map_err(|_| IpcError::Io)?;
            let same_uid = message.cmsgs().map_err(|_| IpcError::Io)?.any(|message| {
                matches!(message, ControlMessageOwned::ScmCredentials(credentials)
                        if credentials.uid() == getuid().as_raw())
            });
            if !same_uid {
                return Err(IpcError::Io);
            }
            message.bytes
        } else {
            recv(self.descriptor, &mut packet, MsgFlags::MSG_TRUNC).map_err(|_| IpcError::Io)?
        };
        if received > MAX_PACKET_BYTES {
            return Err(IpcError::Frame(FrameError::TooLarge));
        }
        packet.truncate(received);
        Ok(decode_frame(&packet)?.to_vec())
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), IpcError> {
        let packet = encode_frame(payload)?;
        let written =
            send(self.descriptor, &packet, MsgFlags::MSG_NOSIGNAL).map_err(|_| IpcError::Io)?;
        if written != packet.len() {
            return Err(IpcError::Io);
        }
        Ok(())
    }
}

impl Drop for SeqPacket {
    fn drop(&mut self) {
        let _ = close(self.descriptor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::socketpair;
    use std::os::fd::IntoRawFd;
    use uuid::Uuid;

    #[test]
    fn seqpacket_preserves_one_bounded_frame() {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("socket pair");
        let left = SeqPacket {
            descriptor: left.into_raw_fd(),
            verify_peer_uid: false,
        };
        let right = SeqPacket {
            descriptor: right.into_raw_fd(),
            verify_peer_uid: false,
        };
        left.send(b"vfs").expect("send");
        assert_eq!(right.receive().expect("receive"), b"vfs");
    }

    #[test]
    fn accepted_packet_requires_same_uid_credentials() {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("socket pair");
        setsockopt(&right, sockopt::PassCred, &true).expect("enable credentials");
        let left = SeqPacket {
            descriptor: left.into_raw_fd(),
            verify_peer_uid: false,
        };
        let right = SeqPacket {
            descriptor: right.into_raw_fd(),
            verify_peer_uid: true,
        };
        left.send(b"authenticated").expect("send");
        assert_eq!(right.receive().expect("same uid"), b"authenticated");
    }

    #[test]
    fn connected_packet_requires_private_same_uid_server() {
        let directory = std::env::temp_dir().join(format!("filebelt-nfs-ipc-{}", Uuid::new_v4()));
        fs::create_dir(&directory).expect("create socket directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("protect socket directory");
        let path = directory.join("control.sock");
        let listener = SeqPacketListener::bind(&path).expect("bind private listener");
        let client = SeqPacket::connect(&path).expect("connect to same uid");
        let server = listener.accept().expect("accept same uid");
        client.send(b"private").expect("send private frame");
        assert_eq!(server.receive().expect("receive private frame"), b"private");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))
            .expect("weaken socket mode for rejection test");
        assert!(matches!(SeqPacket::connect(&path), Err(IpcError::Setup)));
        drop(server);
        drop(client);
        drop(listener);
        fs::remove_dir(directory).expect("remove socket directory");
    }
}

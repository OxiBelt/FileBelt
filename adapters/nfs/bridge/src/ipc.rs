// SPDX-License-Identifier: LGPL-3.0-or-later

//! Private, packet-preserving Unix IPC used by the FSAL.

use crate::{FrameError, MAX_VFS_FRAME_BYTES, decode_frame, encode_frame};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, getsockopt, recv, recvmsg, send, sockopt};
use nix::unistd::{Gid, chown, getegid, geteuid};
use socket2::{Domain, SockAddr, Socket, Type};
use std::fs;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const MAX_PACKET_BYTES: usize = MAX_VFS_FRAME_BYTES + 4;

pub const BRIDGE_UID: u32 = 10_001;
pub const BRIDGE_GID: u32 = 10_001;
pub const GANESHA_UID: u32 = 10_002;
pub const GANESHA_GID: u32 = 10_002;
pub const IPC_GID: u32 = 10_003;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalIdentity {
    uid: u32,
    gid: u32,
}

const BRIDGE_IDENTITY: LocalIdentity = LocalIdentity {
    uid: BRIDGE_UID,
    gid: BRIDGE_GID,
};
const GANESHA_IDENTITY: LocalIdentity = LocalIdentity {
    uid: GANESHA_UID,
    gid: GANESHA_GID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectedPeer {
    pid: i32,
    identity: LocalIdentity,
}

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
    descriptor: Socket,
    path: PathBuf,
    expected_peer: LocalIdentity,
}

impl SeqPacketListener {
    pub fn bind(path: &Path) -> Result<Self, IpcError> {
        require_bridge_process_identity()?;
        Self::bind_for(path, BRIDGE_IDENTITY, IPC_GID, GANESHA_IDENTITY)
    }

    fn bind_for(
        path: &Path,
        owner: LocalIdentity,
        socket_gid: u32,
        expected_peer: LocalIdentity,
    ) -> Result<Self, IpcError> {
        let parent = path.parent().ok_or(IpcError::Setup)?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| IpcError::Setup)?;
        if !path.is_absolute()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o007 != 0
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
        let descriptor =
            Socket::new(Domain::UNIX, Type::SEQPACKET, None).map_err(|_| IpcError::Setup)?;
        descriptor.set_cloexec(true).map_err(|_| IpcError::Setup)?;
        descriptor
            .bind(&SockAddr::unix(path).map_err(|_| IpcError::Setup)?)
            .map_err(|_| IpcError::Setup)?;
        descriptor.set_passcred(true).map_err(|_| IpcError::Setup)?;
        chown(path, None, Some(Gid::from_raw(socket_gid))).map_err(|_| IpcError::Setup)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(|_| IpcError::Setup)?;
        require_socket_metadata(path, owner.uid, socket_gid)?;
        descriptor.listen(64).map_err(|_| IpcError::Setup)?;
        Ok(Self {
            descriptor,
            path: path.to_owned(),
            expected_peer,
        })
    }

    pub fn accept(&self) -> Result<SeqPacket, IpcError> {
        let (descriptor, _) = self.descriptor.accept().map_err(|_| IpcError::Io)?;
        descriptor.set_cloexec(true).map_err(|_| IpcError::Io)?;
        descriptor.set_passcred(true).map_err(|_| IpcError::Io)?;
        let peer = peer_credentials(&descriptor)?;
        if peer.identity != self.expected_peer {
            return Err(IpcError::Io);
        }
        Ok(SeqPacket {
            descriptor,
            expected_message_peer: Some(peer),
        })
    }
}

impl Drop for SeqPacketListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub struct SeqPacket {
    descriptor: Socket,
    expected_message_peer: Option<ConnectedPeer>,
}

impl SeqPacket {
    pub fn connect(path: &Path) -> Result<Self, IpcError> {
        require_bridge_process_identity()?;
        Self::connect_for(path, GANESHA_UID, IPC_GID, GANESHA_IDENTITY)
    }

    fn connect_for(
        path: &Path,
        socket_uid: u32,
        socket_gid: u32,
        expected_peer: LocalIdentity,
    ) -> Result<Self, IpcError> {
        if !path.is_absolute() {
            return Err(IpcError::Setup);
        }
        require_socket_metadata(path, socket_uid, socket_gid)?;
        let descriptor =
            Socket::new(Domain::UNIX, Type::SEQPACKET, None).map_err(|_| IpcError::Setup)?;
        descriptor.set_cloexec(true).map_err(|_| IpcError::Setup)?;
        descriptor.set_passcred(true).map_err(|_| IpcError::Setup)?;
        descriptor
            .connect(&SockAddr::unix(path).map_err(|_| IpcError::Setup)?)
            .map_err(|_| IpcError::Io)?;
        let peer = peer_credentials(&descriptor)?;
        if peer.identity != expected_peer {
            return Err(IpcError::Io);
        }
        let timeout = Some(Duration::from_secs(3));
        descriptor
            .set_read_timeout(timeout)
            .map_err(|_| IpcError::Setup)?;
        descriptor
            .set_write_timeout(timeout)
            .map_err(|_| IpcError::Setup)?;
        Ok(Self {
            descriptor,
            expected_message_peer: Some(peer),
        })
    }

    pub fn receive(&self) -> Result<Vec<u8>, IpcError> {
        let mut packet = vec![0_u8; MAX_PACKET_BYTES + 1];
        let received = if let Some(expected_peer) = self.expected_message_peer {
            let mut credentials = nix::cmsg_space!(nix::sys::socket::UnixCredentials);
            let mut slices = [IoSliceMut::new(&mut packet)];
            let message = recvmsg::<()>(
                self.descriptor.as_raw_fd(),
                &mut slices,
                Some(&mut credentials),
                MsgFlags::MSG_TRUNC,
            )
            .map_err(|_| IpcError::Io)?;
            let authenticated_peer = message.cmsgs().map_err(|_| IpcError::Io)?.any(|message| {
                matches!(message, ControlMessageOwned::ScmCredentials(credentials)
                if credentials_match(
                    credentials.pid(),
                    credentials.uid(),
                    credentials.gid(),
                    expected_peer,
                ))
            });
            if !authenticated_peer {
                return Err(IpcError::Io);
            }
            message.bytes
        } else {
            recv(
                self.descriptor.as_raw_fd(),
                &mut packet,
                MsgFlags::MSG_TRUNC,
            )
            .map_err(|_| IpcError::Io)?
        };
        if received > MAX_PACKET_BYTES {
            return Err(IpcError::Frame(FrameError::TooLarge));
        }
        packet.truncate(received);
        Ok(decode_frame(&packet)?.to_vec())
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), IpcError> {
        let packet = encode_frame(payload)?;
        let written = send(self.descriptor.as_raw_fd(), &packet, MsgFlags::MSG_NOSIGNAL)
            .map_err(|_| IpcError::Io)?;
        if written != packet.len() {
            return Err(IpcError::Io);
        }
        Ok(())
    }
}

pub fn require_bridge_process_identity() -> Result<(), IpcError> {
    require_effective_identity(BRIDGE_IDENTITY)
}

fn require_effective_identity(expected: LocalIdentity) -> Result<(), IpcError> {
    (LocalIdentity {
        uid: geteuid().as_raw(),
        gid: getegid().as_raw(),
    } == expected)
        .then_some(())
        .ok_or(IpcError::Setup)
}

fn require_socket_metadata(path: &Path, uid: u32, gid: u32) -> Result<(), IpcError> {
    socket_has_expected_metadata(path, uid, gid)
        .then_some(())
        .ok_or(IpcError::Setup)
}

pub(crate) fn socket_has_expected_metadata(path: &Path, uid: u32, gid: u32) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_socket()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.permissions().mode() & 0o777 == 0o660
}

fn peer_credentials(descriptor: &Socket) -> Result<ConnectedPeer, IpcError> {
    let credentials = getsockopt(descriptor, sockopt::PeerCredentials).map_err(|_| IpcError::Io)?;
    Ok(ConnectedPeer {
        pid: credentials.pid(),
        identity: LocalIdentity {
            uid: credentials.uid(),
            gid: credentials.gid(),
        },
    })
}

fn credentials_match(pid: i32, uid: u32, gid: u32, expected: ConnectedPeer) -> bool {
    pid == expected.pid && uid == expected.identity.uid && gid == expected.identity.gid
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, setsockopt, socketpair};
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
            descriptor: Socket::from(left),
            expected_message_peer: None,
        };
        let right = SeqPacket {
            descriptor: Socket::from(right),
            expected_message_peer: None,
        };
        left.send(b"vfs").expect("send");
        assert_eq!(right.receive().expect("receive"), b"vfs");
    }

    #[test]
    fn accepted_packet_requires_connection_bound_credentials() {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("socket pair");
        setsockopt(&right, sockopt::PassCred, &true).expect("enable credentials");
        let left = SeqPacket {
            descriptor: Socket::from(left),
            expected_message_peer: None,
        };
        let right = Socket::from(right);
        let right = SeqPacket {
            expected_message_peer: Some(peer_credentials(&right).expect("peer credentials")),
            descriptor: right,
        };
        left.send(b"authenticated").expect("send");
        assert_eq!(right.receive().expect("same uid"), b"authenticated");
    }

    fn receive_with_expected_credentials<F>(passcred: bool, alter: F) -> Result<Vec<u8>, IpcError>
    where
        F: FnOnce(&mut ConnectedPeer),
    {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("socket pair");
        if passcred {
            setsockopt(&right, sockopt::PassCred, &true).expect("enable credentials");
        }
        let left = SeqPacket {
            descriptor: Socket::from(left),
            expected_message_peer: None,
        };
        let right = Socket::from(right);
        let mut expected = peer_credentials(&right).expect("peer credentials");
        alter(&mut expected);
        let right = SeqPacket {
            descriptor: right,
            expected_message_peer: Some(expected),
        };
        left.send(b"authenticated").expect("send");
        right.receive()
    }

    #[test]
    fn received_packet_rejects_missing_or_wrong_credentials() {
        assert!(receive_with_expected_credentials(false, |_| {}).is_err());
        assert!(
            receive_with_expected_credentials(true, |peer| peer.pid = peer.pid.wrapping_add(1))
                .is_err()
        );
        assert!(
            receive_with_expected_credentials(true, |peer| {
                peer.identity.uid = peer.identity.uid.wrapping_add(1);
            })
            .is_err()
        );
        assert!(
            receive_with_expected_credentials(true, |peer| {
                peer.identity.gid = peer.identity.gid.wrapping_add(1);
            })
            .is_err()
        );
    }

    #[test]
    fn connected_packet_requires_exact_socket_and_peer_identity() {
        let directory = std::env::temp_dir().join(format!("filebelt-nfs-ipc-{}", Uuid::new_v4()));
        fs::create_dir(&directory).expect("create socket directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("protect socket directory");
        let path = directory.join("control.sock");
        let current = LocalIdentity {
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
        };
        let listener = SeqPacketListener::bind_for(&path, current, current.gid, current)
            .expect("bind exact listener");
        let client = SeqPacket::connect_for(&path, current.uid, current.gid, current)
            .expect("connect to exact peer");
        let server = listener.accept().expect("accept exact peer");
        client.send(b"private").expect("send private frame");
        assert_eq!(server.receive().expect("receive private frame"), b"private");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("weaken socket mode for rejection test");
        assert!(matches!(
            SeqPacket::connect_for(&path, current.uid, current.gid, current),
            Err(IpcError::Setup)
        ));
        drop(server);
        drop(client);
        drop(listener);
        fs::remove_dir(directory).expect("remove socket directory");
    }

    #[test]
    fn message_credentials_bind_pid_uid_and_primary_gid() {
        let expected = ConnectedPeer {
            pid: 41,
            identity: GANESHA_IDENTITY,
        };
        assert!(credentials_match(41, GANESHA_UID, GANESHA_GID, expected));
        assert!(!credentials_match(42, GANESHA_UID, GANESHA_GID, expected));
        assert!(!credentials_match(41, BRIDGE_UID, GANESHA_GID, expected));
        assert!(!credentials_match(41, GANESHA_UID, BRIDGE_GID, expected));
    }
}

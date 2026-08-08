// SPDX-License-Identifier: GPL-3.0-or-later

//! FileBelt's FTP/FTPS gateway policy boundary.
//!
//! This crate intentionally contains no FileBelt database, storage-path, HTTP
//! session, or adapter-external implementation type. A `libunftp` bridge must
//! translate its parser callbacks into these typed decisions and call the
//! Apache-2.0 VFS RPC client supplied by the eventual Phase 6 core contract.
//! The bridge must never implement a second ACL evaluator.

#![deny(unsafe_code)]

pub mod read_only;
pub mod vfs_contract;

#[cfg(test)]
mod libunftp_contract;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, SystemTime};

pub const MAX_AUTHORIZATION_LEASE: Duration = Duration::from_secs(60);
pub const DEFAULT_PASSIVE_ALLOCATION_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VfsAction {
    Mount,
    ReadMetadata,
    ListChildren,
    ReadContent,
    CreateChild,
    WriteContent,
    CreateVersion,
    Rename,
    Delete,
    SetAttributes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FtpCommand {
    Cwd,
    Pwd,
    List,
    Mlsd,
    Mlst,
    Nlst,
    Size,
    Retr,
    Stor { overwrite: bool },
    Mkd,
    Rnfr,
    Rnto { overwrite: bool },
    Dele,
    Rmd,
    Mfmt,
    RestDownload,
    RestUpload,
    Appe,
    Stou,
    ActiveMode,
    Fxp,
    Site,
}

pub fn actions_for(command: FtpCommand) -> Result<&'static [VfsAction], GatewayError> {
    match command {
        FtpCommand::Cwd | FtpCommand::Pwd => Ok(&[VfsAction::ReadMetadata]),
        FtpCommand::List | FtpCommand::Mlsd | FtpCommand::Mlst | FtpCommand::Nlst => {
            Ok(&[VfsAction::ReadMetadata, VfsAction::ListChildren])
        }
        FtpCommand::Size => Ok(&[VfsAction::ReadMetadata]),
        FtpCommand::Retr | FtpCommand::RestDownload => Ok(&[VfsAction::ReadContent]),
        FtpCommand::Stor { overwrite: false } => Ok(&[
            VfsAction::CreateChild,
            VfsAction::WriteContent,
            VfsAction::CreateVersion,
        ]),
        FtpCommand::Stor { overwrite: true } | FtpCommand::RestUpload => {
            Ok(&[VfsAction::WriteContent, VfsAction::CreateVersion])
        }
        FtpCommand::Mkd => Ok(&[VfsAction::CreateChild]),
        FtpCommand::Rnfr => Ok(&[VfsAction::Rename]),
        FtpCommand::Rnto { overwrite: false } => Ok(&[VfsAction::Rename, VfsAction::CreateChild]),
        FtpCommand::Rnto { overwrite: true } => {
            Ok(&[VfsAction::Rename, VfsAction::CreateChild, VfsAction::Delete])
        }
        FtpCommand::Dele | FtpCommand::Rmd => Ok(&[VfsAction::Delete]),
        FtpCommand::Mfmt => Ok(&[VfsAction::SetAttributes]),
        FtpCommand::Appe
        | FtpCommand::Stou
        | FtpCommand::ActiveMode
        | FtpCommand::Fxp
        | FtpCommand::Site => Err(GatewayError::UnsupportedCommand),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountSession {
    pub id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub credential_id: String,
    pub credential_generation: u64,
    pub device_id: Option<String>,
    pub gateway_epoch: u64,
    pub expires_at: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationProjection {
    pub user: u64,
    pub credential: u64,
    pub acl: u64,
    pub object: u64,
    pub gateway_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationLease {
    pub session_id: String,
    pub actions: BTreeSet<VfsAction>,
    pub projection: GenerationProjection,
    pub expires_at: SystemTime,
}

/// The only FileBelt-facing contract the FTP implementation may use.
///
/// Its concrete wire type belongs in the Apache `filebelt-vfs-protocol` once
/// that protocol has been approved. Methods deliberately carry FileBelt IDs,
/// typed actions, and generations rather than FTP commands or host paths.
pub trait VfsClient {
    fn begin_mount_session(
        &self,
        session: &MountSession,
    ) -> Result<AuthorizationLease, GatewayError>;
    fn authorize(
        &self,
        session: &MountSession,
        actions: &[VfsAction],
        resource_id: &str,
    ) -> Result<AuthorizationLease, GatewayError>;
    fn revalidate(&self, lease: &AuthorizationLease) -> Result<GenerationProjection, GatewayError>;
}

/// Credential verification and credential-to-principal mapping are Core-owned.
/// The gateway passes only the short-lived presentation over its protected
/// control channel and receives no verifier, password digest, database row, or
/// OIDC credential in return.
pub trait MountAuthenticator {
    fn authenticate_mount(
        &self,
        username: &str,
        secret: &[u8],
        observed_device_id: Option<&str>,
    ) -> Result<MountSession, GatewayError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySession {
    pub mount: MountSession,
    pub lease: AuthorizationLease,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionAdmission<'a> {
    pub ftps: FtpsState,
    pub policy: FtpsPolicy,
    pub username: &'a str,
    pub secret: &'a [u8],
    pub observed_device_id: Option<&'a str>,
    pub now: SystemTime,
}

/// Creates a mount session only after the explicit-FTPS control channel has
/// authenticated. A concrete `libunftp` authenticator must zeroize its command
/// buffer after this call and must never log the supplied secret.
pub fn admit_session(
    authenticator: &impl MountAuthenticator,
    vfs: &impl VfsClient,
    admission: SessionAdmission<'_>,
) -> Result<GatewaySession, GatewayError> {
    if !admission.ftps.accepts_authentication(admission.policy) {
        return Err(GatewayError::TlsRequired);
    }
    let mount = authenticator.authenticate_mount(
        admission.username,
        admission.secret,
        admission.observed_device_id,
    )?;
    if mount.expires_at <= admission.now {
        return Err(GatewayError::SessionRevoked);
    }
    let lease = vfs.begin_mount_session(&mount)?;
    if !lease.actions.contains(&VfsAction::Mount) {
        return Err(GatewayError::AuthorizationDenied);
    }
    revalidate_lease(vfs, &lease, admission.now)?;
    Ok(GatewaySession { mount, lease })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlProtection {
    Plain,
    Tls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataProtection {
    Unset,
    Private,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FtpsCommand {
    AuthTls,
    Pbsz(u32),
    ProtPrivate,
    ProtClear,
    Ccc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FtpsPolicy {
    pub minimum_tls_version: &'static str,
    pub require_data_tls: bool,
    pub allow_plaintext_ftp: bool,
}

impl Default for FtpsPolicy {
    fn default() -> Self {
        Self {
            minimum_tls_version: "TLS1.3",
            require_data_tls: true,
            allow_plaintext_ftp: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FtpsState {
    control: ControlProtection,
    data: DataProtection,
}

impl FtpsState {
    pub fn new() -> Self {
        Self {
            control: ControlProtection::Plain,
            data: DataProtection::Unset,
        }
    }

    pub fn apply(&mut self, policy: FtpsPolicy, command: FtpsCommand) -> Result<(), GatewayError> {
        match command {
            FtpsCommand::AuthTls if self.control == ControlProtection::Plain => {
                self.control = ControlProtection::Tls;
                Ok(())
            }
            FtpsCommand::AuthTls => Err(GatewayError::TlsRequired),
            FtpsCommand::Pbsz(0) if self.control == ControlProtection::Tls => Ok(()),
            FtpsCommand::Pbsz(_) => Err(GatewayError::TlsRequired),
            FtpsCommand::ProtPrivate if self.control == ControlProtection::Tls => {
                self.data = DataProtection::Private;
                Ok(())
            }
            FtpsCommand::ProtClear | FtpsCommand::Ccc if policy.require_data_tls => {
                Err(GatewayError::DataProtectionRequired)
            }
            _ => Err(GatewayError::TlsRequired),
        }
    }

    pub fn accepts_authentication(&self, policy: FtpsPolicy) -> bool {
        policy.allow_plaintext_ftp || self.control == ControlProtection::Tls
    }

    pub fn accepts_data_connection(&self, policy: FtpsPolicy) -> bool {
        self.control == ControlProtection::Tls
            && (!policy.require_data_tls || self.data == DataProtection::Private)
    }
}

impl Default for FtpsState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassiveBinding {
    pub port: u16,
    pub session_id: String,
    pub principal_id: String,
    pub device_id: Option<String>,
    pub transfer_id: String,
    pub expires_at: SystemTime,
}

/// A bounded, one-use passive listener allocator.
///
/// The networking layer must validate the TLS session/channel binding before it
/// calls `claim`; this type additionally rejects cross-session, cross-principal,
/// cross-device, duplicate, and expired data connections.
#[derive(Debug)]
pub struct PassivePortAllocator {
    start: u16,
    end: u16,
    next: u16,
    active: BTreeMap<u16, PassiveBinding>,
}

impl PassivePortAllocator {
    pub fn new(start: u16, end: u16) -> Result<Self, GatewayError> {
        if start == 0 || end < start {
            return Err(GatewayError::InvalidPassiveRange);
        }
        Ok(Self {
            start,
            end,
            next: start,
            active: BTreeMap::new(),
        })
    }

    pub fn allocate(
        &mut self,
        session: &MountSession,
        transfer_id: impl Into<String>,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<PassiveBinding, GatewayError> {
        self.reap(now);
        let width = u32::from(self.end) - u32::from(self.start) + 1;
        for _ in 0..width {
            let port = self.next;
            self.next = if port == self.end {
                self.start
            } else {
                port + 1
            };
            if self.active.contains_key(&port) {
                continue;
            }
            let binding = PassiveBinding {
                port,
                session_id: session.id.clone(),
                principal_id: session.principal_id.clone(),
                device_id: session.device_id.clone(),
                transfer_id: transfer_id.into(),
                expires_at: now
                    .checked_add(ttl)
                    .ok_or(GatewayError::InvalidPassiveRange)?,
            };
            self.active.insert(port, binding.clone());
            return Ok(binding);
        }
        Err(GatewayError::PassivePortsExhausted)
    }

    pub fn claim(
        &mut self,
        port: u16,
        session: &MountSession,
        transfer_id: &str,
        now: SystemTime,
    ) -> Result<PassiveBinding, GatewayError> {
        let binding = self
            .active
            .remove(&port)
            .ok_or(GatewayError::DataChannelRejected)?;
        if binding.expires_at <= now
            || binding.session_id != session.id
            || binding.principal_id != session.principal_id
            || binding.device_id != session.device_id
            || binding.transfer_id != transfer_id
        {
            return Err(GatewayError::DataChannelRejected);
        }
        Ok(binding)
    }

    pub fn reap(&mut self, now: SystemTime) {
        self.active.retain(|_, binding| binding.expires_at > now);
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    AuthenticationFailed,
    AuthorizationDenied,
    NotFound,
    Conflict,
    QuotaExceeded,
    InvalidRestartOffset,
    DataChannelRejected,
    PassivePortsExhausted,
    InvalidPassiveRange,
    TlsRequired,
    DataProtectionRequired,
    SessionRevoked,
    GatewayDraining,
    StorageUnavailable,
    UnsupportedCommand,
}

impl GatewayError {
    /// Intentionally avoids distinguishing an inaccessible node from a missing
    /// one; the VFS service is responsible for existence-hiding authorization.
    pub const fn ftp_reply(self) -> (u16, &'static str) {
        match self {
            Self::AuthenticationFailed => (530, "Authentication failed"),
            Self::AuthorizationDenied | Self::NotFound => (550, "File unavailable"),
            Self::Conflict => (450, "Version conflict; retry after refresh"),
            Self::QuotaExceeded => (552, "Quota exceeded"),
            Self::InvalidRestartOffset => (554, "Invalid restart offset"),
            Self::DataChannelRejected => (425, "Data connection rejected"),
            Self::PassivePortsExhausted => (421, "Passive ports unavailable"),
            Self::InvalidPassiveRange => (451, "Passive configuration unavailable"),
            Self::TlsRequired | Self::DataProtectionRequired => (534, "TLS protection required"),
            Self::SessionRevoked => (530, "Session revoked"),
            Self::GatewayDraining => (421, "Gateway draining"),
            Self::StorageUnavailable => (451, "Storage temporarily unavailable"),
            Self::UnsupportedCommand => (502, "Command not implemented"),
        }
    }
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.ftp_reply().1)
    }
}

impl std::error::Error for GatewayError {}

pub fn revalidate_lease(
    vfs: &impl VfsClient,
    lease: &AuthorizationLease,
    now: SystemTime,
) -> Result<(), GatewayError> {
    if lease.expires_at <= now {
        return Err(GatewayError::SessionRevoked);
    }
    let current = vfs.revalidate(lease)?;
    if current != lease.projection {
        return Err(GatewayError::SessionRevoked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeCore {
        projection: GenerationProjection,
    }

    impl VfsClient for FakeCore {
        fn begin_mount_session(
            &self,
            session: &MountSession,
        ) -> Result<AuthorizationLease, GatewayError> {
            Ok(AuthorizationLease {
                session_id: session.id.clone(),
                actions: BTreeSet::from([VfsAction::Mount]),
                projection: self.projection,
                expires_at: session.expires_at,
            })
        }

        fn authorize(
            &self,
            session: &MountSession,
            actions: &[VfsAction],
            _resource_id: &str,
        ) -> Result<AuthorizationLease, GatewayError> {
            Ok(AuthorizationLease {
                session_id: session.id.clone(),
                actions: actions.iter().copied().collect(),
                projection: self.projection,
                expires_at: session.expires_at,
            })
        }

        fn revalidate(
            &self,
            _lease: &AuthorizationLease,
        ) -> Result<GenerationProjection, GatewayError> {
            Ok(self.projection)
        }
    }

    struct FakeAuthenticator;

    impl MountAuthenticator for FakeAuthenticator {
        fn authenticate_mount(
            &self,
            username: &str,
            secret: &[u8],
            observed_device_id: Option<&str>,
        ) -> Result<MountSession, GatewayError> {
            if username != "user" || secret != b"credential" {
                return Err(GatewayError::AuthenticationFailed);
            }
            let mut result = session();
            result.device_id = observed_device_id.map(str::to_owned);
            Ok(result)
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000)
    }

    fn session() -> MountSession {
        MountSession {
            id: "session-a".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "principal-a".into(),
            credential_id: "credential-a".into(),
            credential_generation: 7,
            device_id: Some("device-a".into()),
            gateway_epoch: 3,
            expires_at: now() + Duration::from_secs(120),
        }
    }

    #[test]
    fn maps_mutations_to_independent_acl_actions() {
        assert_eq!(
            actions_for(FtpCommand::Stor { overwrite: false }).unwrap(),
            &[
                VfsAction::CreateChild,
                VfsAction::WriteContent,
                VfsAction::CreateVersion
            ]
        );
        assert_eq!(
            actions_for(FtpCommand::Rnto { overwrite: true }).unwrap(),
            &[VfsAction::Rename, VfsAction::CreateChild, VfsAction::Delete]
        );
    }

    #[test]
    fn rejects_unapproved_commands() {
        for command in [
            FtpCommand::Appe,
            FtpCommand::Stou,
            FtpCommand::ActiveMode,
            FtpCommand::Fxp,
            FtpCommand::Site,
        ] {
            assert_eq!(actions_for(command), Err(GatewayError::UnsupportedCommand));
        }
    }

    #[test]
    fn requires_explicit_tls_and_private_data_protection() {
        let policy = FtpsPolicy::default();
        let mut state = FtpsState::new();
        assert!(!state.accepts_authentication(policy));
        state.apply(policy, FtpsCommand::AuthTls).unwrap();
        assert!(!state.accepts_data_connection(policy));
        state.apply(policy, FtpsCommand::Pbsz(0)).unwrap();
        state.apply(policy, FtpsCommand::ProtPrivate).unwrap();
        assert!(state.accepts_data_connection(policy));
        assert_eq!(
            state.apply(policy, FtpsCommand::Ccc),
            Err(GatewayError::DataProtectionRequired)
        );
        assert_eq!(
            state.apply(policy, FtpsCommand::ProtClear),
            Err(GatewayError::DataProtectionRequired)
        );
    }

    #[test]
    fn rejects_nonzero_pbsz() {
        let policy = FtpsPolicy::default();
        let mut state = FtpsState::new();
        state.apply(policy, FtpsCommand::AuthTls).unwrap();
        assert_eq!(
            state.apply(policy, FtpsCommand::Pbsz(1)),
            Err(GatewayError::TlsRequired)
        );
    }

    #[test]
    fn allocates_within_a_bounded_range_and_consumes_once() {
        let mut allocator = PassivePortAllocator::new(41_000, 41_001).unwrap();
        let current = now();
        let binding = allocator
            .allocate(&session(), "transfer-a", current, Duration::from_secs(10))
            .unwrap();
        assert!((41_000..=41_001).contains(&binding.port));
        allocator
            .claim(binding.port, &session(), "transfer-a", current)
            .unwrap();
        assert_eq!(
            allocator.claim(binding.port, &session(), "transfer-a", current),
            Err(GatewayError::DataChannelRejected)
        );
    }

    #[test]
    fn rejects_passive_hijack_by_another_session_or_device() {
        let mut allocator = PassivePortAllocator::new(41_000, 41_000).unwrap();
        let current = now();
        let binding = allocator
            .allocate(&session(), "transfer-a", current, Duration::from_secs(10))
            .unwrap();
        let mut attacker = session();
        attacker.id = "session-b".into();
        assert_eq!(
            allocator.claim(binding.port, &attacker, "transfer-a", current),
            Err(GatewayError::DataChannelRejected)
        );
    }

    #[test]
    fn expires_and_reclaims_passive_ports() {
        let mut allocator = PassivePortAllocator::new(41_000, 41_000).unwrap();
        let current = now();
        allocator
            .allocate(&session(), "transfer-a", current, Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            allocator.allocate(&session(), "transfer-b", current, Duration::from_secs(1)),
            Err(GatewayError::PassivePortsExhausted)
        );
        let after_expiry = current + Duration::from_secs(2);
        assert!(
            allocator
                .allocate(
                    &session(),
                    "transfer-b",
                    after_expiry,
                    Duration::from_secs(1)
                )
                .is_ok()
        );
    }

    #[test]
    fn reply_mapping_hides_existence_and_classifies_errors() {
        assert_eq!(
            GatewayError::AuthorizationDenied.ftp_reply(),
            GatewayError::NotFound.ftp_reply()
        );
        assert_eq!(GatewayError::QuotaExceeded.ftp_reply().0, 552);
        assert_eq!(GatewayError::UnsupportedCommand.ftp_reply().0, 502);
    }

    #[test]
    fn refuses_credential_exchange_until_explicit_tls() {
        let core = FakeCore {
            projection: GenerationProjection {
                user: 1,
                credential: 7,
                acl: 1,
                object: 1,
                gateway_epoch: 3,
            },
        };
        assert_eq!(
            admit_session(
                &FakeAuthenticator,
                &core,
                SessionAdmission {
                    ftps: FtpsState::new(),
                    policy: FtpsPolicy::default(),
                    username: "user",
                    secret: b"credential",
                    observed_device_id: Some("device-a"),
                    now: now(),
                },
            ),
            Err(GatewayError::TlsRequired)
        );
    }

    #[test]
    fn admits_only_mount_authority_and_rejects_generation_revocation() {
        let projection = GenerationProjection {
            user: 1,
            credential: 7,
            acl: 1,
            object: 1,
            gateway_epoch: 3,
        };
        let core = FakeCore { projection };
        let mut ftps = FtpsState::new();
        ftps.apply(FtpsPolicy::default(), FtpsCommand::AuthTls)
            .unwrap();
        let admitted = admit_session(
            &FakeAuthenticator,
            &core,
            SessionAdmission {
                ftps,
                policy: FtpsPolicy::default(),
                username: "user",
                secret: b"credential",
                observed_device_id: Some("device-a"),
                now: now(),
            },
        )
        .unwrap();
        assert_eq!(admitted.mount.credential_generation, 7);
        let revoked = FakeCore {
            projection: GenerationProjection {
                credential: 8,
                ..projection
            },
        };
        assert_eq!(
            revalidate_lease(&revoked, &admitted.lease, now()),
            Err(GatewayError::SessionRevoked)
        );
    }
}

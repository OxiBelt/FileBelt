// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only explicit-FTPS bridge for the approved VFS read slice.
//!
//! FTP path names are resolved afresh, component by component, through VFS
//! `List` results. No UUID mapping is shared between sessions or retained past
//! a request, so a renamed or ACL-revoked child cannot remain reachable by a
//! stale FTP path cache.

use crate::GatewayError;
use crate::vfs_contract::{
    EphemeralPassword, GatewayIdentity, VfsRequestFactory, validate_response,
};
use async_trait::async_trait;
use filebelt_vfs_protocol::vfs_request::Operation;
use filebelt_vfs_protocol::{
    CloseRequest, ListRequest, MountProtocol, NodeAttributes, NodeKind, OpenRequest,
    PROTOCOL_VERSION, ReadRequest, StatRequest, VfsAction, VfsRequest, VfsResponse,
};
use libunftp::ServerBuilder;
use libunftp::options::{ActivePassiveMode, FtpsRequired, TlsFlags};
use prost::Message;
use reqwest::header::CONTENT_TYPE;
use reqwest::redirect::Policy;
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncRead;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;
use unftp_core::auth::{
    AuthenticationError, Authenticator, Credentials, Principal, UserDetail, UserDetailProvider,
};
use unftp_core::storage::{
    ErrorKind, FEATURE_RESTART, Fileinfo, Metadata, Result as StorageResult, StorageBackend,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";
const MAX_READ: u64 = 1_048_576;
const MAX_PENDING_SESSIONS: usize = 1_024;
const PENDING_SESSION_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct ReadOnlyGatewayConfig {
    pub identity: GatewayIdentity,
    pub shard_key: String,
    pub vfs_url: String,
    pub vfs_ca_pem: Vec<u8>,
    pub vfs_client_cert_pem: Vec<u8>,
    pub vfs_client_key_pem: Vec<u8>,
    pub drive_id: Uuid,
    pub root_node_id: Uuid,
    pub ftps_cert_path: PathBuf,
    pub ftps_key_path: PathBuf,
    pub bind_address: String,
    pub passive_host: String,
    pub passive_ports: std::ops::RangeInclusive<u16>,
}

#[derive(Clone, Debug)]
struct SessionFence {
    id: Uuid,
    credential_generation: u64,
    authorization_generation: u64,
    gateway_epoch: u64,
}

#[derive(Clone, Debug)]
struct VfsHttp {
    endpoint: reqwest::Url,
    client: reqwest::Client,
    identity: GatewayIdentity,
}

impl VfsHttp {
    fn new(config: &ReadOnlyGatewayConfig) -> Result<Self, GatewayError> {
        let endpoint =
            reqwest::Url::parse(&config.vfs_url).map_err(|_| GatewayError::StorageUnavailable)?;
        if endpoint.scheme() != "https"
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/internal/v1/vfs/execute"
        {
            return Err(GatewayError::TlsRequired);
        }
        let mut identity_pem = config.vfs_client_cert_pem.clone();
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&config.vfs_client_key_pem);
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&config.vfs_ca_pem)
                    .map_err(|_| GatewayError::StorageUnavailable)?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity_pem)
                    .map_err(|_| GatewayError::StorageUnavailable)?,
            )
            .build()
            .map_err(|_| GatewayError::StorageUnavailable)?;
        Ok(Self {
            endpoint,
            client,
            identity: config.identity.clone(),
        })
    }

    async fn execute(&self, request: &VfsRequest) -> Result<VfsResponse, GatewayError> {
        request
            .validate()
            .map_err(|_| GatewayError::StorageUnavailable)?;
        let encoded = Zeroizing::new(request.encode_to_vec());
        let body = bytes::Bytes::from_owner(encoded);
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)
            .body(body)
            .send()
            .await;
        let response = response.map_err(|_| GatewayError::StorageUnavailable)?;
        if !response.status().is_success()
            || response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                != Some(PROTOBUF_CONTENT_TYPE)
        {
            return Err(GatewayError::StorageUnavailable);
        }
        let mut body = response
            .bytes()
            .await
            .map_err(|_| GatewayError::StorageUnavailable)?
            .to_vec();
        let decoded =
            VfsResponse::decode(body.as_slice()).map_err(|_| GatewayError::StorageUnavailable);
        body.zeroize();
        let decoded = decoded?;
        validate_response(request, &decoded)?;
        Ok(decoded)
    }

    fn request(&self, fence: &SessionFence, operation: Operation) -> VfsRequest {
        VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            tenant_id: self.identity.tenant_id.to_string(),
            protocol: MountProtocol::Ftps as i32,
            gateway_id: self.identity.gateway_id.clone(),
            gateway_epoch: fence.gateway_epoch,
            session_id: fence.id.to_string(),
            credential_generation: fence.credential_generation,
            authorization_generation: fence.authorization_generation,
            operation: Some(operation),
        }
    }

    async fn hello(&self, shard_key: &str) -> Result<u64, GatewayError> {
        let request = self.identity.gateway_hello(shard_key);
        let response = self.execute(&request).await?;
        if response.gateway_epoch == 0 {
            Err(GatewayError::GatewayDraining)
        } else {
            Ok(response.gateway_epoch)
        }
    }
}

#[derive(Clone, Debug)]
struct GatewayUser(SessionFence);
impl Display for GatewayUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileBeltUser")
    }
}
impl UserDetail for GatewayUser {}

#[derive(Clone)]
struct PendingSessions(Arc<Mutex<HashMap<Uuid, PendingSession>>>);

#[derive(Clone, Debug)]
struct PendingSession {
    fence: SessionFence,
    expires_at: Instant,
}

impl PendingSessions {
    fn insert(&self, key: Uuid, fence: SessionFence) -> Result<(), ()> {
        let mut pending = self.0.lock().map_err(|_| ())?;
        let now = Instant::now();
        pending.retain(|_, session| session.expires_at > now);
        if pending.len() >= MAX_PENDING_SESSIONS {
            return Err(());
        }
        pending.insert(
            key,
            PendingSession {
                fence,
                expires_at: now + PENDING_SESSION_TTL,
            },
        );
        Ok(())
    }

    fn take(&self, key: Uuid) -> Result<SessionFence, ()> {
        let pending = self.0.lock().map_err(|_| ())?.remove(&key).ok_or(())?;
        (pending.expires_at > Instant::now())
            .then_some(pending.fence)
            .ok_or(())
    }
}

#[derive(Clone)]
struct VfsAuthenticator {
    vfs: Arc<VfsHttp>,
    pending: PendingSessions,
}
impl Debug for VfsAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VfsAuthenticator")
    }
}

#[async_trait]
impl Authenticator for VfsAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        creds: &Credentials,
    ) -> Result<Principal, AuthenticationError> {
        if !matches!(
            creds.command_channel_security,
            unftp_core::auth::ChannelEncryptionState::Tls
        ) {
            return Err(AuthenticationError::BadPassword);
        }
        let password = creds
            .password
            .as_deref()
            .ok_or(AuthenticationError::BadPassword)?;
        let mut raw = Zeroizing::new(password.as_bytes().to_vec());
        let password = EphemeralPassword::new(std::mem::take(raw.as_mut()))
            .map_err(|_| AuthenticationError::BadPassword)?;
        let factory = VfsRequestFactory::new(self.vfs.identity.clone())
            .map_err(|_| AuthenticationError::BadPassword)?;
        let mut request = factory
            .authenticate(username, password, creds.source_ip, None, Vec::new())
            .map_err(|_| AuthenticationError::BadPassword)?;
        let response = self.vfs.execute(request.request()).await;
        request.clear();
        let response = response.map_err(|_| AuthenticationError::BadPassword)?;
        let id =
            Uuid::parse_str(&response.session_id).map_err(|_| AuthenticationError::BadPassword)?;
        if response.credential_generation == 0
            || response.authorization_generation == 0
            || response.gateway_epoch == 0
        {
            return Err(AuthenticationError::BadPassword);
        }
        let key = Uuid::new_v4();
        self.pending
            .insert(
                key,
                SessionFence {
                    id,
                    credential_generation: response.credential_generation,
                    authorization_generation: response.authorization_generation,
                    gateway_epoch: response.gateway_epoch,
                },
            )
            .map_err(|_| AuthenticationError::BadPassword)?;
        Ok(Principal {
            username: format!("fb-session-{key}"),
        })
    }
}

#[derive(Clone)]
struct GatewayUserProvider {
    pending: PendingSessions,
}
impl Debug for GatewayUserProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayUserProvider")
    }
}
#[async_trait]
impl UserDetailProvider for GatewayUserProvider {
    type User = GatewayUser;
    async fn provide_user_detail(
        &self,
        principal: &Principal,
    ) -> Result<GatewayUser, unftp_core::auth::UserDetailError> {
        let key = principal
            .username
            .strip_prefix("fb-session-")
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| {
                unftp_core::auth::UserDetailError::Generic("invalid gateway session".into())
            })?;
        let fence = self.pending.take(key).map_err(|_| {
            unftp_core::auth::UserDetailError::Generic("session state unavailable".into())
        })?;
        Ok(GatewayUser(fence))
    }
}

#[derive(Clone, Debug)]
struct VfsMetadata(NodeAttributes);
impl Metadata for VfsMetadata {
    fn len(&self) -> u64 {
        self.0.size_bytes
    }
    fn is_dir(&self) -> bool {
        self.0.kind == NodeKind::Directory as i32
    }
    fn is_file(&self) -> bool {
        self.0.kind == NodeKind::File as i32
    }
    fn is_symlink(&self) -> bool {
        false
    }
    fn modified(&self) -> StorageResult<SystemTime> {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(
                self.0.modified_at_unix_seconds.max(0) as u64
            ))
            .ok_or_else(|| ErrorKind::LocalError.into())
    }
    fn gid(&self) -> u32 {
        0
    }
    fn uid(&self) -> u32 {
        0
    }
}

#[derive(Clone, Debug)]
struct Node {
    id: Uuid,
    attributes: NodeAttributes,
}

#[derive(Clone, Debug)]
struct ReadOnlyStorage {
    vfs: Arc<VfsHttp>,
    drive_id: Uuid,
    root_id: Uuid,
    session: Option<SessionFence>,
}
impl ReadOnlyStorage {
    fn new(vfs: Arc<VfsHttp>, drive_id: Uuid, root_id: Uuid) -> Self {
        Self {
            vfs,
            drive_id,
            root_id,
            session: None,
        }
    }
    fn fence(&self, user: &GatewayUser) -> StorageResult<&SessionFence> {
        self.session
            .as_ref()
            .filter(|f| f.id == user.0.id)
            .ok_or_else(|| ErrorKind::PermissionDenied.into())
    }
    fn clean(path: &Path) -> StorageResult<Vec<String>> {
        let mut output = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => output.push(
                    name.to_str()
                        .ok_or(ErrorKind::PermanentFileNotAvailable)?
                        .to_owned(),
                ),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(ErrorKind::PermanentFileNotAvailable.into());
                }
            }
        }
        Ok(output)
    }
    async fn list_node(&self, fence: &SessionFence, node: Uuid) -> StorageResult<VfsResponse> {
        self.call(
            fence,
            Operation::List(ListRequest {
                drive_id: self.drive_id.to_string(),
                directory_id: node.to_string(),
                cursor: String::new(),
                limit: 1000,
            }),
        )
        .await
    }
    async fn resolve(&self, user: &GatewayUser, path: &Path) -> StorageResult<Node> {
        let fence = self.fence(user)?.clone();
        let mut node = Node {
            id: self.root_id,
            attributes: self.stat(&fence, self.root_id).await?,
        };
        for component in Self::clean(path)? {
            if node.attributes.kind != NodeKind::Directory as i32 {
                return Err(ErrorKind::PermanentDirectoryNotAvailable.into());
            }
            let list = self.list_node(&fence, node.id).await?;
            let entry = list
                .entries
                .into_iter()
                .find(|entry| entry.display_name == component)
                .ok_or(ErrorKind::PermanentFileNotAvailable)?;
            let attributes = entry.attributes.ok_or(ErrorKind::LocalError)?;
            let id = Uuid::parse_str(&entry.resource_id).map_err(|_| ErrorKind::LocalError)?;
            node = Node { id, attributes };
        }
        Ok(node)
    }
    async fn stat(&self, fence: &SessionFence, id: Uuid) -> StorageResult<NodeAttributes> {
        self.call(
            fence,
            Operation::Stat(StatRequest {
                drive_id: self.drive_id.to_string(),
                resource_id: id.to_string(),
            }),
        )
        .await?
        .attributes
        .ok_or_else(|| ErrorKind::LocalError.into())
    }
    async fn call(&self, fence: &SessionFence, operation: Operation) -> StorageResult<VfsResponse> {
        self.vfs
            .execute(&self.vfs.request(fence, operation))
            .await
            .map_err(storage_error)
    }
}

fn storage_error(error: GatewayError) -> unftp_core::storage::Error {
    match error {
        GatewayError::AuthorizationDenied
        | GatewayError::NotFound
        | GatewayError::SessionRevoked => ErrorKind::PermissionDenied.into(),
        GatewayError::Conflict => ErrorKind::TransientFileNotAvailable.into(),
        GatewayError::QuotaExceeded => ErrorKind::ExceededStorageAllocationError.into(),
        GatewayError::UnsupportedCommand => ErrorKind::CommandNotImplemented.into(),
        _ => ErrorKind::LocalError.into(),
    }
}

#[async_trait]
impl StorageBackend<GatewayUser> for ReadOnlyStorage {
    type Metadata = VfsMetadata;
    fn enter(&mut self, user: &GatewayUser) -> io::Result<()> {
        if self.session.replace(user.0.clone()).is_some() {
            return Err(io::Error::other("storage session already entered"));
        }
        Ok(())
    }
    fn supported_features(&self) -> u32 {
        FEATURE_RESTART
    }
    async fn metadata<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &GatewayUser,
        path: P,
    ) -> StorageResult<Self::Metadata> {
        Ok(VfsMetadata(
            self.resolve(user, path.as_ref()).await?.attributes,
        ))
    }
    async fn list<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &GatewayUser,
        path: P,
    ) -> StorageResult<Vec<Fileinfo<PathBuf, Self::Metadata>>> {
        let node = self.resolve(user, path.as_ref()).await?;
        if node.attributes.kind != NodeKind::Directory as i32 {
            return Err(ErrorKind::PermanentDirectoryNotAvailable.into());
        }
        let fence = self.fence(user)?.clone();
        self.list_node(&fence, node.id)
            .await?
            .entries
            .into_iter()
            .map(|entry| {
                Ok(Fileinfo {
                    path: PathBuf::from(entry.display_name),
                    metadata: VfsMetadata(entry.attributes.ok_or(ErrorKind::LocalError)?),
                })
            })
            .collect()
    }
    async fn get<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &GatewayUser,
        path: P,
        start_pos: u64,
    ) -> StorageResult<Box<dyn AsyncRead + Send + Sync + Unpin>> {
        let node = self.resolve(user, path.as_ref()).await?;
        if node.attributes.kind != NodeKind::File as i32 || start_pos > node.attributes.size_bytes {
            return Err(ErrorKind::PermanentFileNotAvailable.into());
        }
        let fence = self.fence(user)?.clone();
        let open = self
            .call(
                &fence,
                Operation::Open(OpenRequest {
                    drive_id: self.drive_id.to_string(),
                    resource_id: node.id.to_string(),
                    expected_version_id: node.attributes.head_version_id.clone(),
                    requested_actions: vec![VfsAction::ReadContent as i32],
                    share_read: true,
                    share_write: false,
                    share_delete: false,
                }),
            )
            .await?;
        let handle = Uuid::parse_str(&open.handle_id).map_err(|_| ErrorKind::LocalError)?;
        let vfs = self.vfs.clone();
        let size = node.attributes.size_bytes;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            let mut offset = start_pos;
            while offset < size {
                let length = (size - offset).min(MAX_READ);
                let request = vfs.request(
                    &fence,
                    Operation::Read(ReadRequest {
                        handle_id: handle.to_string(),
                        offset,
                        length,
                    }),
                );
                let response = match vfs.execute(&request).await {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = sender.send(Err(io::Error::other("VFS read failed"))).await;
                        break;
                    }
                };
                let received = response.data.len() as u64;
                if received == 0 || received > length {
                    let _ = sender
                        .send(Err(io::Error::other("VFS returned an invalid read")))
                        .await;
                    break;
                }
                offset += received;
                if sender
                    .send(Ok(bytes::Bytes::from(response.data)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let request = vfs.request(
                &fence,
                Operation::Close(CloseRequest {
                    handle_id: handle.to_string(),
                }),
            );
            let _ = vfs.execute(&request).await;
        });
        Ok(Box::new(StreamReader::new(ReceiverStream::new(receiver))))
    }
    async fn put<P: AsRef<Path> + Send + Debug, R: AsyncRead + Send + Sync + Unpin + 'static>(
        &self,
        _: &GatewayUser,
        _: R,
        _: P,
        _: u64,
    ) -> StorageResult<u64> {
        Err(ErrorKind::CommandNotImplemented.into())
    }
    async fn del<P: AsRef<Path> + Send + Debug>(&self, _: &GatewayUser, _: P) -> StorageResult<()> {
        Err(ErrorKind::CommandNotImplemented.into())
    }
    async fn mkd<P: AsRef<Path> + Send + Debug>(&self, _: &GatewayUser, _: P) -> StorageResult<()> {
        Err(ErrorKind::CommandNotImplemented.into())
    }
    async fn rename<P: AsRef<Path> + Send + Debug>(
        &self,
        _: &GatewayUser,
        _: P,
        _: P,
    ) -> StorageResult<()> {
        Err(ErrorKind::CommandNotImplemented.into())
    }
    async fn rmd<P: AsRef<Path> + Send + Debug>(&self, _: &GatewayUser, _: P) -> StorageResult<()> {
        Err(ErrorKind::CommandNotImplemented.into())
    }
    async fn cwd<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &GatewayUser,
        path: P,
    ) -> StorageResult<()> {
        if self.resolve(user, path.as_ref()).await?.attributes.kind == NodeKind::Directory as i32 {
            Ok(())
        } else {
            Err(ErrorKind::PermanentDirectoryNotAvailable.into())
        }
    }
}

pub async fn serve(config: ReadOnlyGatewayConfig) -> Result<(), GatewayError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| GatewayError::StorageUnavailable)?;
    let vfs = Arc::new(VfsHttp::new(&config)?);
    let epoch = vfs.hello(&config.shard_key).await?;
    let mut identity = config.identity.clone();
    identity.gateway_epoch = epoch;
    let vfs = Arc::new(VfsHttp {
        identity,
        ..(*vfs).clone()
    });
    let pending = PendingSessions(Arc::new(Mutex::new(HashMap::new())));
    let authenticator = Arc::new(VfsAuthenticator {
        vfs: vfs.clone(),
        pending: pending.clone(),
    });
    let provider = Arc::new(GatewayUserProvider { pending });
    let drive_id = config.drive_id;
    let root_id = config.root_node_id;
    let provider: Arc<dyn UserDetailProvider<User = GatewayUser> + Send + Sync> = provider;
    let server = ServerBuilder::<ReadOnlyStorage, GatewayUser>::with_user_detail_provider(
        Box::new(move || ReadOnlyStorage::new(vfs.clone(), drive_id, root_id)),
        provider,
    )
    .authenticator(authenticator)
    .ftps(config.ftps_cert_path, config.ftps_key_path)
    .ftps_tls_flags(TlsFlags::V1_3)
    .ftps_required(FtpsRequired::All, FtpsRequired::All)
    .active_passive_mode(ActivePassiveMode::PassiveOnly)
    .passive_ports(config.passive_ports)
    .passive_host(config.passive_host.as_str())
    .build()
    .map_err(|_| GatewayError::StorageUnavailable)?;
    server
        .listen(config.bind_address)
        .await
        .map_err(|_| GatewayError::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PENDING_SESSIONS, PendingSession, PendingSessions, ReadOnlyStorage, SessionFence,
    };
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use unftp_core::storage::ErrorKind;
    use uuid::Uuid;

    #[test]
    fn virtual_path_normalization_rejects_parent_traversal() {
        assert_eq!(
            ReadOnlyStorage::clean(Path::new("/reports/2026")).unwrap(),
            vec!["reports", "2026"]
        );
        assert_eq!(
            ReadOnlyStorage::clean(Path::new("/reports/../private"))
                .unwrap_err()
                .kind(),
            ErrorKind::PermanentFileNotAvailable
        );
    }

    #[test]
    fn pending_session_handoff_is_single_use_and_bounded() {
        let sessions = PendingSessions(Arc::new(Mutex::new(HashMap::new())));
        let fence = SessionFence {
            id: Uuid::new_v4(),
            credential_generation: 1,
            authorization_generation: 1,
            gateway_epoch: 1,
        };
        let key = Uuid::new_v4();
        sessions.insert(key, fence.clone()).unwrap();
        assert_eq!(sessions.take(key).unwrap().id, fence.id);
        assert!(sessions.take(key).is_err());

        let mut full = HashMap::new();
        for _ in 0..MAX_PENDING_SESSIONS {
            full.insert(
                Uuid::new_v4(),
                PendingSession {
                    fence: fence.clone(),
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let sessions = PendingSessions(Arc::new(Mutex::new(full)));
        assert!(sessions.insert(Uuid::new_v4(), fence).is_err());
    }
}

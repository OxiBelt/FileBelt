// SPDX-License-Identifier: Apache-2.0

//! Protocol-neutral mount VFS and isolated credential-vault service.

#![deny(unsafe_code)]

mod nfs;
mod policy;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::hmac;
use aws_lc_rs::signature::Ed25519KeyPair;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand};
use filebelt_capability_keyset::MountStorageKeyset;
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::mount::{
    MountAuthenticationMaterial, MountSecretEnvelopeInput, MountSessionFence,
};
use filebelt_database::{Database, DatabaseError, NodeRecord};
use filebelt_domain::Action;
use filebelt_runtime::{
    MtlsListener, OperationsState, init_telemetry, install_crypto_provider, operations_router,
    trace_request, wait_for_shutdown,
};
use filebelt_secret_vault::{Keyring, SecretContext, SecretEnvelope, VaultProfile};
use filebelt_storage_protocol::{
    MountCapabilityClaims, MountCapabilityOperation, sign_mount_storage_read_capability,
    unix_time_now,
};
use filebelt_vfs_protocol::vfs_request::Operation;
use filebelt_vfs_protocol::{
    DirectoryEntry, MountProtocol, NodeAttributes, NodeKind, PROTOCOL_VERSION, RequestFence,
    VfsAction, VfsError, VfsRequest, VfsResponse,
};
use getrandom::fill as random_fill;
use md4::{Digest as _, Md4};
use prost::Message as _;
use reqwest::{Certificate, Client, Identity, Url};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const ROLE: &str = "filebelt-vfs";
const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";

#[derive(Debug, Parser)]
#[command(name = "filebelt-vfs", disable_version_flag = true)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/etc/filebelt/filebelt.toml")]
        config: PathBuf,
    },
}

#[derive(Clone)]
struct VfsState {
    database: Database,
    tenant_id: Uuid,
    keyring: Arc<Keyring>,
    key_generation: u32,
    io: MountIoClient,
    digest_key: [u8; 32],
}

#[derive(Clone)]
struct MountIoClient {
    http: Client,
    io_url: Url,
    signer: Arc<Ed25519KeyPair>,
    signing_generation: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCredentialRequest {
    principal_id: Uuid,
    protocol: String,
    read_only: bool,
    allowed_drive_ids: Vec<Uuid>,
    bound_device_id: Option<Uuid>,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct CreateCredentialResponse {
    credential_id: Uuid,
    protocol: String,
    username: String,
    password: String,
    expires_at: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--version" | "--build-info=json")
    ) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "VFS service stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    install_crypto_provider().map_err(|message| anyhow!(message))?;
    let Arguments {
        command: Command::Serve { config },
    } = Arguments::parse();
    let config = Config::load(&config)?;
    if !config.mounts.enabled {
        bail!("mount service is disabled");
    }
    let _telemetry = init_telemetry(&config.telemetry, ROLE).map_err(|message| anyhow!(message))?;
    let database_url = read_secret_string(
        config
            .mounts
            .database_url_file
            .as_ref()
            .ok_or_else(|| anyhow!("mount database URL file is absent"))?,
    )?;
    let database = Database::connect(&database_url, config.database.max_connections).await?;
    database.health().await?;
    let tenant_id = database.tenant_by_slug(&config.tenant.slug).await?;
    let keyring = Arc::new(Keyring::load(
        config
            .mounts
            .vault_keyring_file
            .as_ref()
            .ok_or_else(|| anyhow!("mount vault keyring file is absent"))?,
        VaultProfile::mount(),
    )?);
    let signing = config
        .mounts
        .capability_signing
        .as_ref()
        .ok_or_else(|| anyhow!("mount capability signing is absent"))?;
    let capability_private_key = std::fs::read(&signing.private_key_file)
        .context("cannot read mount capability private key")?;
    let capability_signer = Arc::new(
        Ed25519KeyPair::from_pkcs8(&capability_private_key)
            .map_err(|_| anyhow!("mount capability key is not Ed25519 PKCS#8"))?,
    );
    self_check_signer(
        &signing.public_keyset_file,
        signing.current_generation,
        &capability_signer,
    )?;
    let io = MountIoClient {
        http: mount_io_http_client(&config)?,
        io_url: config
            .mounts
            .io_url
            .clone()
            .ok_or_else(|| anyhow!("mount I/O URL is absent"))?,
        signer: capability_signer,
        signing_generation: signing.current_generation,
    };
    let digest_key_bytes =
        std::fs::read(&config.keys.digest_key_file).context("cannot read the mount digest key")?;
    let digest_key = digest_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("mount digest key must contain exactly 32 bytes"))?;
    let state = VfsState {
        database: database.clone(),
        tenant_id,
        keyring,
        key_generation: config.mounts.vault_key_generation,
        io,
        digest_key,
    };

    let gateway = Router::new()
        .route("/internal/v1/vfs/execute", post(execute))
        .layer(DefaultBodyLimit::max(
            filebelt_vfs_protocol::MAX_REQUEST_BYTES,
        ))
        .layer(middleware::from_fn(trace_request))
        .with_state(state.clone());
    let management = Router::new()
        .route("/internal/v1/mount/credentials", post(create_credential))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(trace_request))
        .with_state(state);

    let ready_database = database.clone();
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, move || {
        let database = ready_database.clone();
        async move { database.health().await.is_ok() }
    });
    policy::register_recursive_share_metrics(&operations);
    let operations_listener = tokio::net::TcpListener::bind(config.listeners.operations)
        .await
        .context("cannot bind VFS operations listener")?;
    let operations_state = operations.clone();
    let operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations_state))
            .await
            .map_err(anyhow::Error::from)
    });

    let gateway_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(config.listeners.vfs).await?;
            tokio::spawn(async move {
                axum::serve(listener, gateway)
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.vfs.as_ref())
                .ok_or_else(|| anyhow!("VFS backend TLS is absent"))?;
            let listener = MtlsListener::bind(config.listeners.vfs, tls)
                .await
                .map_err(|message| anyhow!(message))?;
            tokio::spawn(async move {
                axum::serve(listener, gateway)
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
    };
    let management_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(config.listeners.vfs_management).await?;
            tokio::spawn(async move {
                axum::serve(listener, management)
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.vfs_management.as_ref())
                .ok_or_else(|| anyhow!("VFS management backend TLS is absent"))?;
            let listener = MtlsListener::bind(config.listeners.vfs_management, tls)
                .await
                .map_err(|message| anyhow!(message))?;
            tokio::spawn(async move {
                axum::serve(listener, management)
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
    };
    info!(
        gateway = %config.listeners.vfs,
        management = %config.listeners.vfs_management,
        operations = %config.listeners.operations,
        "VFS listeners started"
    );
    tokio::select! {
        result = gateway_server => result??,
        result = management_server => result??,
        result = operations_server => result??,
        () = wait_for_shutdown() => {},
    }
    Ok(())
}

async fn execute(State(state): State<VfsState>, headers: HeaderMap, body: Bytes) -> Response {
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(PROTOBUF_CONTENT_TYPE)
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Ok(mut request) = VfsRequest::decode(body.as_ref()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(fence) = request.validate() else {
        return protobuf(VfsResponse::failure(
            Uuid::parse_str(&request.request_id).unwrap_or_else(|_| Uuid::nil()),
            VfsError::InvalidRequest,
            "vfs.invalid_request",
        ));
    };
    let response = dispatch(&state, &request, &fence).await;
    if let Some(Operation::Authenticate(authentication)) = request.operation.as_mut() {
        authentication.exchange.zeroize();
        authentication.channel_binding.zeroize();
    }
    protobuf(response)
}

async fn dispatch(state: &VfsState, request: &VfsRequest, fence: &RequestFence) -> VfsResponse {
    if fence.tenant_id != state.tenant_id {
        return denied(fence, "vfs.tenant_not_found");
    }
    let protocol = protocol_name(fence.protocol);
    let operation = request.operation.as_ref().expect("validated operation");
    if let Operation::GatewayHello(hello) = operation {
        return match state
            .database
            .claim_mount_gateway_epoch(
                fence.tenant_id,
                protocol,
                &hello.shard_key,
                &fence.gateway_id,
            )
            .await
        {
            Ok(epoch) => VfsResponse {
                protocol_version: PROTOCOL_VERSION,
                request_id: fence.request_id.to_string(),
                error: VfsError::Ok as i32,
                gateway_epoch: u64::try_from(epoch).unwrap_or_default(),
                ..VfsResponse::default()
            },
            Err(_) => unavailable(fence, "vfs.gateway_epoch_unavailable"),
        };
    }
    if let Operation::Authenticate(authentication) = operation {
        return authenticate(state, fence, authentication).await;
    }
    let session_id = fence.session_id.expect("validated session");
    let session = match state
        .database
        .admit_mount_session(
            fence.tenant_id,
            session_id,
            protocol,
            &fence.gateway_id,
            fence.gateway_epoch,
            fence.credential_generation.expect("validated generation"),
            fence
                .authorization_generation
                .expect("validated generation"),
        )
        .await
    {
        Ok(session) => session,
        Err(_) => return denied(fence, "vfs.session_fence_stale"),
    };
    match operation {
        Operation::List(list) if list.cursor.is_empty() => {
            list_directory(state, fence, &session, list).await
        }
        Operation::Stat(stat) => stat_node(state, fence, &session, stat).await,
        Operation::Open(open) => open_handle(state, fence, &session, open).await,
        Operation::Read(read) => read_handle(state, fence, &session, read).await,
        Operation::Close(close) => close_handle(state, fence, &session, close).await,
        Operation::Lock(lock) => lock_handle(state, fence, &session, lock).await,
        Operation::Unlock(unlock) => unlock_handle(state, fence, &session, unlock).await,
        Operation::Heartbeat(_) => ok(fence),
        Operation::EndSession(end) => match state
            .database
            .end_mount_session(&session, &end.reason_code)
            .await
        {
            Ok(()) => ok(fence),
            Err(_) => unavailable(fence, "vfs.session_close_failed"),
        },
        _ => VfsResponse::failure(
            fence.request_id,
            VfsError::NotSupported,
            "vfs.operation_not_supported",
        ),
    }
}

async fn open_handle(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    open: &filebelt_vfs_protocol::OpenRequest,
) -> VfsResponse {
    let (Ok(drive_id), Ok(resource_id)) = (
        Uuid::parse_str(&open.drive_id),
        Uuid::parse_str(&open.resource_id),
    ) else {
        return invalid(request);
    };
    if !session.allowed_drive_ids.contains(&drive_id) {
        return denied(request, "vfs.resource_not_found");
    }
    let expected_version_id = if open.expected_version_id.is_empty() {
        None
    } else {
        match Uuid::parse_str(&open.expected_version_id) {
            Ok(version_id) => Some(version_id),
            Err(_) => return invalid(request),
        }
    };
    let mut grant = None;
    let mut actions = Vec::with_capacity(open.requested_actions.len());
    for requested in &open.requested_actions {
        let Ok(requested) = VfsAction::try_from(*requested) else {
            return invalid(request);
        };
        let (action, persisted) = match requested {
            VfsAction::ReadMetadata => (Action::ReadMetadata, "READ_METADATA"),
            VfsAction::ReadContent => (Action::ReadContent, "READ_CONTENT"),
            // Lock ownership is internal handle state. In the initial
            // read-only slice, a shared lock is never broader than the
            // caller's common READ_CONTENT permission.
            VfsAction::ManageLock => (Action::ReadContent, "MANAGE_LOCK"),
            _ => {
                return VfsResponse::failure(
                    request.request_id,
                    VfsError::NotSupported,
                    "vfs.write_open_not_supported",
                );
            }
        };
        let authorized = match policy::authorize(
            &state.database,
            request.tenant_id,
            session.user_principal_id,
            drive_id,
            resource_id,
            action,
        )
        .await
        {
            Ok(authorized) => authorized,
            Err(()) => return denied(request, "vfs.resource_not_found"),
        };
        if grant.is_some_and(|existing| existing != authorized) {
            return VfsResponse::failure(
                request.request_id,
                VfsError::StaleGeneration,
                "vfs.authorization_changed",
            );
        }
        grant = Some(authorized);
        actions.push(persisted.to_owned());
    }
    let Some(grant) = grant else {
        return invalid(request);
    };
    match state
        .database
        .open_mount_handle(
            session,
            drive_id,
            resource_id,
            expected_version_id,
            &actions,
            open.share_read,
            open.share_write,
            open.share_delete,
            grant.drive_acl_generation,
            grant.namespace_generation,
            grant.resource_acl_generation,
        )
        .await
    {
        Ok(handle) => VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id.to_string(),
            error: VfsError::Ok as i32,
            handle_id: handle.id.to_string(),
            version_id: handle
                .version_id
                .map_or_else(String::new, |id| id.to_string()),
            ..VfsResponse::default()
        },
        Err(DatabaseError::NotFound) => denied(request, "vfs.resource_not_found"),
        Err(DatabaseError::Conflict) => VfsResponse::failure(
            request.request_id,
            VfsError::Conflict,
            "vfs.share_mode_conflict",
        ),
        Err(DatabaseError::StaleGeneration) => VfsResponse::failure(
            request.request_id,
            VfsError::StaleGeneration,
            "vfs.authorization_changed",
        ),
        Err(_) => unavailable(request, "vfs.handle_open_failed"),
    }
}

async fn read_handle(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    read: &filebelt_vfs_protocol::ReadRequest,
) -> VfsResponse {
    let Ok(handle_id) = Uuid::parse_str(&read.handle_id) else {
        return invalid(request);
    };
    let handle = match state
        .database
        .admit_mount_handle(session, handle_id, "READ_CONTENT")
        .await
    {
        Ok(handle) => handle,
        Err(_) => return denied(request, "vfs.handle_fence_stale"),
    };
    let Some(version_id) = handle.version_id else {
        return unavailable(request, "vfs.handle_version_missing");
    };
    let Some(range_end) = read.offset.checked_add(read.length - 1) else {
        return invalid(request);
    };
    let now = match unix_time_now() {
        Ok(now) => now,
        Err(_) => return unavailable(request, "vfs.clock_unavailable"),
    };
    let mut nonce = [0_u8; 32];
    if random_fill(&mut nonce).is_err() {
        return unavailable(request, "vfs.capability_generation_failed");
    }
    let claims = MountCapabilityClaims {
        capability_id: Uuid::new_v4().to_string(),
        audience: "filebelt-worker-io".to_owned(),
        operation: MountCapabilityOperation::Read as i32,
        tenant_id: request.tenant_id.to_string(),
        principal_id: session.user_principal_id.to_string(),
        mount_session_id: session.session_id.to_string(),
        credential_id: session.credential_id.to_string(),
        drive_id: handle.drive_id.to_string(),
        resource_id: handle.node_id.to_string(),
        version_id: version_id.to_string(),
        write_session_id: String::new(),
        range_start: read.offset,
        range_end,
        credential_generation: handle.credential_generation as u64,
        authorization_generation: handle.authorization_generation as u64,
        membership_generation: handle.membership_generation as u64,
        drive_acl_generation: handle.drive_acl_generation as u64,
        namespace_generation: handle.namespace_generation as u64,
        resource_acl_generation: handle.resource_acl_generation as u64,
        gateway_epoch: handle.gateway_epoch as u64,
        // Reads do not own a write lease. The v2 capability schema reserves
        // zero as invalid, so one is the stable read-only sentinel.
        fencing_token: 1,
        nonce: nonce.to_vec(),
        issued_at_unix_seconds: now,
        expires_at_unix_seconds: now + 15,
        grant_id: handle.id.to_string(),
    };
    let capability = match sign_mount_storage_read_capability(
        &claims,
        state.io.signing_generation,
        state.io.signer.as_ref(),
    ) {
        Ok(capability) => capability,
        Err(_) => return unavailable(request, "vfs.capability_generation_failed"),
    };
    let url = match state
        .io
        .io_url
        .join(&format!("io/v1/mount-reads/{handle_id}"))
    {
        Ok(url) => url,
        Err(_) => return unavailable(request, "vfs.io_url_invalid"),
    };
    let mut response = match state
        .io
        .http
        .get(url)
        .header(reqwest::header::AUTHORIZATION, capability)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return unavailable(request, "vfs.storage_unavailable"),
    };
    if matches!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        return denied(request, "vfs.handle_fence_stale");
    }
    if !response.status().is_success() {
        return unavailable(request, "vfs.storage_unavailable");
    }
    if response
        .content_length()
        .is_some_and(|length| length > read.length)
    {
        return unavailable(request, "vfs.storage_response_invalid");
    }
    let mut data = Vec::with_capacity(usize::try_from(read.length).unwrap_or_default());
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if data.len().saturating_add(chunk.len()) > read.length as usize {
                    return unavailable(request, "vfs.storage_response_invalid");
                }
                data.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return unavailable(request, "vfs.storage_unavailable"),
        }
    }
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.to_string(),
        error: VfsError::Ok as i32,
        data,
        version_id: version_id.to_string(),
        ..VfsResponse::default()
    }
}

async fn close_handle(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    close: &filebelt_vfs_protocol::CloseRequest,
) -> VfsResponse {
    let Ok(handle_id) = Uuid::parse_str(&close.handle_id) else {
        return invalid(request);
    };
    match state.database.close_mount_handle(session, handle_id).await {
        Ok(()) => ok(request),
        Err(DatabaseError::StaleGeneration | DatabaseError::NotFound) => {
            denied(request, "vfs.handle_not_found")
        }
        Err(_) => unavailable(request, "vfs.handle_close_failed"),
    }
}

async fn lock_handle(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    lock: &filebelt_vfs_protocol::LockRequest,
) -> VfsResponse {
    if lock.exclusive {
        return VfsResponse::failure(
            request.request_id,
            VfsError::NotSupported,
            "vfs.exclusive_lock_not_supported",
        );
    }
    let Ok(handle_id) = Uuid::parse_str(&lock.handle_id) else {
        return invalid(request);
    };
    let handle = match state
        .database
        .admit_mount_handle(session, handle_id, "MANAGE_LOCK")
        .await
    {
        Ok(handle) => handle,
        Err(_) => return denied(request, "vfs.handle_fence_stale"),
    };
    match state
        .database
        .acquire_mount_byte_lock(
            session,
            &handle,
            &lock.owner_key,
            lock.offset,
            lock.length,
            false,
        )
        .await
    {
        Ok(lock_id) => VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id.to_string(),
            error: VfsError::Ok as i32,
            lock_id: lock_id.to_string(),
            ..VfsResponse::default()
        },
        Err(DatabaseError::Conflict) => VfsResponse::failure(
            request.request_id,
            VfsError::LockConflict,
            "vfs.byte_range_lock_conflict",
        ),
        Err(_) => unavailable(request, "vfs.byte_range_lock_failed"),
    }
}

async fn unlock_handle(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    unlock: &filebelt_vfs_protocol::UnlockRequest,
) -> VfsResponse {
    let (Ok(handle_id), Ok(lock_id)) = (
        Uuid::parse_str(&unlock.handle_id),
        Uuid::parse_str(&unlock.lock_id),
    ) else {
        return invalid(request);
    };
    if state
        .database
        .admit_mount_handle(session, handle_id, "MANAGE_LOCK")
        .await
        .is_err()
    {
        return denied(request, "vfs.handle_fence_stale");
    }
    match state
        .database
        .release_mount_byte_lock(session, handle_id, lock_id)
        .await
    {
        Ok(()) => ok(request),
        Err(DatabaseError::NotFound) => denied(request, "vfs.lock_not_found"),
        Err(_) => unavailable(request, "vfs.byte_range_unlock_failed"),
    }
}

async fn authenticate(
    state: &VfsState,
    fence: &RequestFence,
    request: &filebelt_vfs_protocol::AuthenticateRequest,
) -> VfsResponse {
    if fence.protocol == MountProtocol::Smb {
        return VfsResponse::failure(
            fence.request_id,
            VfsError::NotSupported,
            "vfs.ntlm_exchange_not_implemented",
        );
    }
    let protocol = protocol_name(fence.protocol);
    let principal_key = authentication_index(&state.digest_key, b"principal", &request.username);
    let source_key = authentication_index(&state.digest_key, b"source", &request.source_address);
    match state
        .database
        .mount_authentication_throttled(fence.tenant_id, protocol, &principal_key, &source_key)
        .await
    {
        Ok(true) => {
            return VfsResponse::failure(
                fence.request_id,
                VfsError::RateLimited,
                "vfs.authentication_rate_limited",
            );
        }
        Ok(false) => {}
        Err(_) => return unavailable(fence, "vfs.authentication_state_unavailable"),
    }
    let device_id = if request.device_id.is_empty() {
        None
    } else {
        Uuid::parse_str(&request.device_id).ok()
    };
    let material = match state
        .database
        .mount_authentication_material(fence.tenant_id, protocol, &request.username, device_id)
        .await
    {
        Ok(material) => material,
        Err(DatabaseError::NotFound) => {
            if state
                .database
                .record_mount_authentication_failure(
                    fence.tenant_id,
                    protocol,
                    &principal_key,
                    &source_key,
                )
                .await
                .is_err()
            {
                return unavailable(fence, "vfs.authentication_state_unavailable");
            }
            return denied(fence, "vfs.authentication_failed");
        }
        Err(_) => return unavailable(fence, "vfs.authentication_state_unavailable"),
    };
    if !verify_ftps_password(state, &material, &request.exchange) {
        if state
            .database
            .record_mount_authentication_failure(
                fence.tenant_id,
                protocol,
                &principal_key,
                &source_key,
            )
            .await
            .is_err()
        {
            return unavailable(fence, "vfs.authentication_state_unavailable");
        }
        return denied(fence, "vfs.authentication_failed");
    }
    if state
        .database
        .clear_mount_authentication_failures(fence.tenant_id, protocol, &principal_key, &source_key)
        .await
        .is_err()
    {
        return unavailable(fence, "vfs.authentication_state_unavailable");
    }
    match state
        .database
        .create_mount_session(
            fence.tenant_id,
            material.credential.id,
            device_id,
            "ftps",
            &fence.gateway_id,
            fence.gateway_epoch,
            &request.source_address,
        )
        .await
    {
        Ok(session) => VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: fence.request_id.to_string(),
            error: VfsError::Ok as i32,
            session_id: session.session_id.to_string(),
            credential_generation: session.credential_generation as u64,
            authorization_generation: session.authorization_generation as u64,
            gateway_epoch: session.gateway_epoch as u64,
            ..VfsResponse::default()
        },
        Err(_) => denied(fence, "vfs.authentication_failed"),
    }
}

fn self_check_signer(
    path: &std::path::Path,
    generation: u32,
    signer: &Ed25519KeyPair,
) -> Result<()> {
    let source =
        std::fs::read_to_string(path).context("cannot read mount capability public keyset")?;
    let keyset = MountStorageKeyset::parse(&source)
        .map_err(|_| anyhow!("mount capability public keyset is invalid"))?;
    let probe = signer.sign(b"filebelt.mount.storage.keyset.self-check");
    keyset
        .verify(
            generation,
            b"filebelt.mount.storage.keyset.self-check",
            probe.as_ref(),
        )
        .map_err(|_| anyhow!("mount capability private key does not match the keyset"))
}

fn authentication_index(key: &[u8; 32], domain: &[u8], value: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"filebelt.mount.authentication-index.v1\0");
    hasher.update(
        &u32::try_from(domain.len())
            .expect("authentication index domain is bounded")
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        &u32::try_from(value.len())
            .expect("authentication index value is bounded")
            .to_be_bytes(),
    );
    hasher.update(value.as_bytes());
    *hasher.finalize().as_bytes()
}

fn verify_ftps_password(
    state: &VfsState,
    material: &MountAuthenticationMaterial,
    password: &[u8],
) -> bool {
    if material.credential.verifier_kind != "hmac_sha256" {
        return false;
    }
    let context = SecretContext {
        tenant_id: state.tenant_id,
        secret_id: material.credential.id,
        owner_principal_id: material.credential.principal_id,
        namespace: &material.credential.protocol,
        secret_kind: &material.credential.verifier_kind,
        credential_generation: material.credential.credential_generation,
    };
    if state.keyring.aad_digest(&context).ok().as_ref() != Some(&material.aad_digest) {
        return false;
    }
    let envelope = SecretEnvelope {
        ciphertext: material.ciphertext.clone(),
        nonce: material.nonce,
        wrapped_dek: material.wrapped_dek.clone(),
        wrap_nonce: material.wrap_nonce,
        kek_generation: material.kek_generation as u32,
        aad_version: material.aad_version as u32,
    };
    let Ok(secret) = state.keyring.decrypt(&context, &envelope) else {
        return false;
    };
    if secret.len() != 64 {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret[..32]);
    hmac::verify(&key, password, &secret[32..]).is_ok()
}

fn mount_io_http_client(config: &Config) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let mut identity_pem = std::fs::read(
            config
                .mounts
                .io_client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("mount I/O client certificate is absent"))?,
        )?;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&std::fs::read(
            config
                .mounts
                .io_client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("mount I/O client key is absent"))?,
        )?);
        let identity =
            Identity::from_pem(&identity_pem).context("mount I/O identity is invalid")?;
        let roots = Certificate::from_pem_bundle(&std::fs::read(
            config
                .mounts
                .io_server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("mount I/O CA is absent"))?,
        )?)
        .context("mount I/O CA is invalid")?;
        builder = builder.https_only(true).identity(identity);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    builder
        .build()
        .context("cannot initialize mount I/O client")
}

async fn list_directory(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    list: &filebelt_vfs_protocol::ListRequest,
) -> VfsResponse {
    let Ok(drive_id) = Uuid::parse_str(&list.drive_id) else {
        return invalid(request);
    };
    let Ok(directory_id) = Uuid::parse_str(&list.directory_id) else {
        return invalid(request);
    };
    if !session.allowed_drive_ids.contains(&drive_id) {
        return denied(request, "vfs.resource_not_found");
    }
    for action in directory_listing_actions() {
        if policy::authorize(
            &state.database,
            request.tenant_id,
            session.user_principal_id,
            drive_id,
            directory_id,
            action,
        )
        .await
        .is_err()
        {
            return denied(request, "vfs.resource_not_found");
        }
    }
    let Ok(children) = state
        .database
        .list_children(request.tenant_id, drive_id, directory_id)
        .await
    else {
        return unavailable(request, "vfs.database_unavailable");
    };
    let mut entries = Vec::new();
    for child in children {
        if entries.len() == list.limit as usize {
            break;
        }
        if policy::authorize(
            &state.database,
            request.tenant_id,
            session.user_principal_id,
            drive_id,
            child.id,
            Action::ReadMetadata,
        )
        .await
        .is_ok()
        {
            let attributes = match node_attributes(&child, session.read_only) {
                Ok(attributes) => attributes,
                Err(()) => return unavailable(request, "vfs.persisted_node_invalid"),
            };
            entries.push(DirectoryEntry {
                resource_id: child.id.to_string(),
                display_name: child.display_name,
                attributes: Some(attributes),
            });
        }
    }
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.to_string(),
        error: VfsError::Ok as i32,
        entries,
        ..VfsResponse::default()
    }
}

const fn directory_listing_actions() -> [Action; 2] {
    [Action::ReadMetadata, Action::ListChildren]
}

async fn stat_node(
    state: &VfsState,
    request: &RequestFence,
    session: &MountSessionFence,
    stat: &filebelt_vfs_protocol::StatRequest,
) -> VfsResponse {
    let (Ok(drive_id), Ok(resource_id)) = (
        Uuid::parse_str(&stat.drive_id),
        Uuid::parse_str(&stat.resource_id),
    ) else {
        return invalid(request);
    };
    if !session.allowed_drive_ids.contains(&drive_id)
        || policy::authorize(
            &state.database,
            request.tenant_id,
            session.user_principal_id,
            drive_id,
            resource_id,
            Action::ReadMetadata,
        )
        .await
        .is_err()
    {
        return denied(request, "vfs.resource_not_found");
    }
    match state
        .database
        .node(request.tenant_id, drive_id, resource_id)
        .await
    {
        Ok(node) => match node_attributes(&node, session.read_only) {
            Ok(attributes) => VfsResponse {
                protocol_version: PROTOCOL_VERSION,
                request_id: request.request_id.to_string(),
                error: VfsError::Ok as i32,
                attributes: Some(attributes),
                ..VfsResponse::default()
            },
            Err(()) => unavailable(request, "vfs.persisted_node_invalid"),
        },
        Err(DatabaseError::NotFound) => denied(request, "vfs.resource_not_found"),
        Err(_) => unavailable(request, "vfs.database_unavailable"),
    }
}

fn node_attributes(node: &NodeRecord, read_only: bool) -> Result<NodeAttributes, ()> {
    let modified = node.updated_at.parse::<jiff::Timestamp>().map_err(|_| ())?;
    let directory = node.kind == "directory";
    Ok(NodeAttributes {
        kind: match node.kind.as_str() {
            "file" => NodeKind::File as i32,
            "directory" => NodeKind::Directory as i32,
            _ => return Err(()),
        },
        size_bytes: u64::try_from(node.size_bytes.unwrap_or_default()).map_err(|_| ())?,
        head_version_id: node
            .head_version_id
            .map_or_else(String::new, |id| id.to_string()),
        namespace_generation: u64::try_from(node.namespace_generation).map_err(|_| ())?,
        acl_generation: u64::try_from(node.acl_generation).map_err(|_| ())?,
        modified_at_unix_seconds: modified.as_second(),
        read_only,
        mode: match (directory, read_only) {
            (true, true) => 0o555,
            (true, false) => 0o770,
            (false, true) => 0o444,
            (false, false) => 0o660,
        },
        projected_uid: 0,
        projected_gid: 0,
        link_count: if directory { 2 } else { 1 },
        sparse: false,
    })
}

async fn create_credential(
    State(state): State<VfsState>,
    Json(request): Json<CreateCredentialRequest>,
) -> Result<(StatusCode, Json<CreateCredentialResponse>), (StatusCode, &'static str)> {
    let expires_at = request
        .expires_at
        .parse::<jiff::Timestamp>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid mount credential request"))?;
    let now = jiff::Timestamp::now();
    let maximum_expiry = now
        .checked_add(jiff::SignedDuration::from_hours(7 * 24))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "credential clock failed"))?;
    if !matches!(request.protocol.as_str(), "smb" | "ftps")
        || !request.read_only
        || request.allowed_drive_ids.is_empty()
        || request.allowed_drive_ids.len() > 256
        || expires_at <= now
        || expires_at > maximum_expiry
    {
        return Err((StatusCode::BAD_REQUEST, "invalid mount credential request"));
    }
    let credential_id = Uuid::new_v4();
    let mut username_random = [0_u8; 12];
    let mut password_random = Zeroizing::new([0_u8; 32]);
    random_fill(&mut username_random).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential generation failed",
        )
    })?;
    random_fill(password_random.as_mut()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential generation failed",
        )
    })?;
    let username = format!("fb-{}", URL_SAFE_NO_PAD.encode(username_random));
    let password = Zeroizing::new(URL_SAFE_NO_PAD.encode(password_random.as_slice()));
    let verifier_kind = if request.protocol == "smb" {
        "ntlm_verifier"
    } else {
        "hmac_sha256"
    };
    let verifier = Zeroizing::new(if request.protocol == "smb" {
        let mut utf16 = Zeroizing::new(Vec::with_capacity(password.len() * 2));
        for code_unit in password.encode_utf16() {
            utf16.extend_from_slice(&code_unit.to_le_bytes());
        }
        Md4::digest(utf16.as_slice()).to_vec()
    } else {
        let mut pepper = Zeroizing::new([0_u8; 32]);
        random_fill(pepper.as_mut()).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential generation failed",
            )
        })?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, pepper.as_slice());
        let digest = hmac::sign(&key, password.as_bytes());
        [pepper.as_slice(), digest.as_ref()].concat()
    });
    let context = SecretContext {
        tenant_id: state.tenant_id,
        secret_id: credential_id,
        owner_principal_id: request.principal_id,
        namespace: &request.protocol,
        secret_kind: verifier_kind,
        credential_generation: 1,
    };
    let encrypted = state
        .keyring
        .encrypt(state.key_generation, &context, verifier.as_slice())
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential encryption failed",
            )
        })?;
    let aad_digest = state.keyring.aad_digest(&context).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential encryption failed",
        )
    })?;
    let record = state
        .database
        .create_mount_credential(
            state.tenant_id,
            request.principal_id,
            credential_id,
            &request.protocol,
            &username,
            verifier_kind,
            request.read_only,
            &request.allowed_drive_ids,
            request.bound_device_id,
            &request.expires_at,
            &MountSecretEnvelopeInput {
                ciphertext: &encrypted.ciphertext,
                nonce: &encrypted.nonce,
                wrapped_dek: &encrypted.wrapped_dek,
                wrap_nonce: &encrypted.wrap_nonce,
                kek_generation: encrypted.kek_generation as i32,
                aad_digest: &aad_digest,
                aad_version: encrypted.aad_version as i32,
            },
        )
        .await
        .map_err(|error| match error {
            DatabaseError::NotFound | DatabaseError::Conflict => {
                (StatusCode::CONFLICT, "mount policy rejected credential")
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential persistence failed",
            ),
        })?;
    Ok((
        StatusCode::CREATED,
        Json(CreateCredentialResponse {
            credential_id: record.id,
            protocol: record.protocol,
            username,
            password: password.to_string(),
            expires_at: record.expires_at,
        }),
    ))
}

fn protocol_name(protocol: MountProtocol) -> &'static str {
    match protocol {
        MountProtocol::Smb => "smb",
        MountProtocol::Ftps => "ftps",
        MountProtocol::Nfs => "nfs",
        MountProtocol::Unspecified => unreachable!("validated protocol"),
    }
}

fn protobuf(response: VfsResponse) -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)],
        response.encode_to_vec(),
    )
        .into_response()
}

fn ok(request: &RequestFence) -> VfsResponse {
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.to_string(),
        error: VfsError::Ok as i32,
        ..VfsResponse::default()
    }
}

fn invalid(request: &RequestFence) -> VfsResponse {
    VfsResponse::failure(
        request.request_id,
        VfsError::InvalidRequest,
        "vfs.invalid_request",
    )
}

fn denied(request: &RequestFence, reason: &str) -> VfsResponse {
    VfsResponse::failure(request.request_id, VfsError::NotFound, reason)
}

fn unavailable(request: &RequestFence, reason: &str) -> VfsResponse {
    VfsResponse::failure(request.request_id, VfsError::Unavailable, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntlm_verifier_is_the_standard_utf16le_md4_digest() {
        let password = "Password";
        let bytes = password
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Md4::digest(bytes)),
            "pPScQGUQvcq2gk7nww_YUg"
        );
    }

    #[test]
    fn gateway_error_responses_are_protocol_versioned() {
        let request = RequestFence {
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            protocol: MountProtocol::Ftps,
            gateway_id: "ftps-0".into(),
            gateway_epoch: 1,
            session_id: None,
            credential_generation: None,
            authorization_generation: None,
            operation: filebelt_vfs_protocol::OperationKind::Authenticate,
        };
        let response = denied(&request, "vfs.authentication_failed");
        assert_eq!(response.protocol_version, PROTOCOL_VERSION);
        assert_eq!(response.error, VfsError::NotFound as i32);
    }

    #[test]
    fn directory_listing_requires_metadata_and_child_discovery() {
        assert_eq!(
            directory_listing_actions(),
            [Action::ReadMetadata, Action::ListChildren]
        );
    }
}

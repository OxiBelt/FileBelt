// SPDX-License-Identifier: Apache-2.0

//! Protocol-neutral mount VFS and isolated credential-vault service.

#![deny(unsafe_code)]

mod gateway_identity;
mod nfs;
mod nfs_dispatch;
mod policy;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::signature::Ed25519KeyPair;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
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
    CreateNfsMountSessionInput, MountAuthenticationMaterial, MountSecretEnvelopeInput,
    MountSessionFence, NfsReplayContext, ReconcileNfsExportManifestInput,
    RecordNfsReplayReceiptInput,
};
use filebelt_database::{Database, DatabaseError, NodeRecord};
use filebelt_domain::Action;
use filebelt_runtime::{
    MtlsListener, OperationsState, VerifiedMtlsPeer, init_telemetry, install_crypto_provider,
    operations_router, trace_request, wait_for_shutdown,
};
use filebelt_secret_vault::{Keyring, SecretContext, SecretEnvelope, VaultProfile};
use filebelt_storage_protocol::{
    MountCapabilityClaims, MountCapabilityOperation, sign_mount_storage_read_capability,
    unix_time_now,
};
use filebelt_vfs_protocol::vfs_request::Operation;
use filebelt_vfs_protocol::{
    DirectoryEntry, GatewayDrainRequest, GatewayHelloRequest, GatewayReconcileRequest,
    MountProtocol, NFS_GATEWAY_LEASE_SECONDS, NfsAuthenticateRequest, NfsExportManifestEntry,
    NfsGatewayCompatibility, NfsGatewayFeature, NfsGatewayHelloResponse, NfsSessionProjection,
    NodeAttributes, NodeKind, PROTOCOL_VERSION, RequestFence, VfsAction, VfsError, VfsRequest,
    VfsResponse, canonical_nfs_request_digest,
};
use getrandom::fill as random_fill;
use md4::{Digest as _, Md4};
use prost::Message as _;
use reqwest::{Certificate, Client, Identity, Url};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::{Uuid, Variant};
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
    tenant_slug: String,
    keyring: Arc<Keyring>,
    key_generation: u32,
    io: MountIoClient,
    digest_key: [u8; 32],
    gateway_identities: Arc<gateway_identity::GatewayIdentityMap>,
    nfs: Option<Arc<NfsRuntime>>,
}

struct NfsRuntime {
    realm: String,
    handle_keyring: nfs::NfsHandleKeyring,
    release_revision: &'static str,
    backend_id: Uuid,
    chunk_size_bytes: u64,
    max_file_bytes: u64,
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
    operation_id: Uuid,
    operation_generation: i64,
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
    if !config.mounts.any_protocol_enabled() {
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
    let nfs = if config.mounts.nfs.enabled {
        let revision = filebelt_build_identity::CURRENT.revision;
        if filebelt_build_identity::CURRENT.dirty || revision == "unknown" || revision.len() < 7 {
            bail!("NFS requires a clean revision-bound FileBelt build");
        }
        let handle_keyring = nfs::NfsHandleKeyring::load(
            config
                .mounts
                .nfs
                .handle_keyring_file
                .as_deref()
                .ok_or_else(|| anyhow!("NFS handle keyset is absent"))?,
            config.mounts.nfs.handle_key_generation,
        )?;
        Some(Arc::new(NfsRuntime {
            realm: config
                .mounts
                .nfs
                .realm
                .clone()
                .ok_or_else(|| anyhow!("NFS Kerberos realm is absent"))?,
            handle_keyring,
            release_revision: revision,
            backend_id: config.storage.backend_id,
            chunk_size_bytes: config.limits.chunk_size_bytes,
            max_file_bytes: config.limits.max_file_bytes,
        }))
    } else {
        None
    };
    let state = VfsState {
        database: database.clone(),
        tenant_id,
        tenant_slug: config.tenant.slug.clone(),
        keyring,
        key_generation: config.mounts.vault_key_generation,
        io,
        digest_key,
        gateway_identities: Arc::new(gateway_identity::GatewayIdentityMap::from_mounts(
            &config.mounts,
        )),
        nfs,
    };

    let execute_route = match config.deployment.mode {
        DeploymentMode::Development => post(execute_development),
        DeploymentMode::Kubernetes => post(execute_mtls),
    };
    let gateway = Router::new()
        .route("/internal/v1/vfs/execute", execute_route)
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
                axum::serve(
                    listener,
                    gateway.into_make_service_with_connect_info::<VerifiedMtlsPeer>(),
                )
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

async fn execute_development(
    State(state): State<VfsState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute_inner(state, None, headers, body).await
}

async fn execute_mtls(
    ConnectInfo(peer): ConnectInfo<VerifiedMtlsPeer>,
    State(state): State<VfsState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute_inner(state, Some(peer), headers, body).await
}

async fn execute_inner(
    state: VfsState,
    peer: Option<VerifiedMtlsPeer>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
    if let Err(reason) = state
        .gateway_identities
        .authorize(peer.as_ref(), fence.protocol)
    {
        return protobuf(VfsResponse::failure(
            fence.request_id,
            VfsError::Unauthenticated,
            reason,
        ));
    }
    let response = dispatch(&state, &request, &fence).await;
    if let Some(Operation::Authenticate(authentication)) = request.operation.as_mut() {
        authentication.exchange.zeroize();
        authentication.channel_binding.zeroize();
    }
    if let Some(Operation::NfsAuthenticate(authentication)) = request.operation.as_mut() {
        authentication.gss_binding_digest.zeroize();
    }
    if let Some(context) = request.nfs_context.as_mut() {
        context.gss_binding_digest.zeroize();
        context.request_digest.zeroize();
    }
    protobuf(response)
}

async fn dispatch(state: &VfsState, request: &VfsRequest, fence: &RequestFence) -> VfsResponse {
    let protocol = protocol_name(fence.protocol);
    let operation = request.operation.as_ref().expect("validated operation");
    if let Operation::GatewayHello(hello) = operation {
        if fence.protocol == MountProtocol::Nfs {
            return nfs_gateway_hello(state, fence, hello).await;
        }
        if fence.tenant_id != state.tenant_id {
            return denied(fence, "vfs.tenant_not_found");
        }
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
    if fence.tenant_id != state.tenant_id {
        return denied(fence, "vfs.tenant_not_found");
    }
    if let Operation::NfsAuthenticate(authentication) = operation {
        return nfs_authenticate(state, fence, authentication).await;
    }
    if let Operation::GatewayReconcile(reconcile) = operation {
        return nfs_gateway_reconcile(state, fence, reconcile).await;
    }
    if let Operation::GatewayDrain(drain) = operation {
        return nfs_gateway_drain(state, fence, drain).await;
    }
    if let Operation::Authenticate(authentication) = operation {
        return authenticate(state, fence, authentication).await;
    }
    // NFS replay is part of dispatch because every ordinary retransmission
    // must re-enter current session and operation authorization. EndSession is
    // the sole exception: its fixed applied acknowledgement has a dedicated,
    // closed-session admission path in dispatch_nfs.
    if fence.protocol == MountProtocol::Nfs {
        return dispatch_nfs(state, request, fence, operation).await;
    }
    let Some(session_fence) = session_admission_fence(fence) else {
        return invalid(fence);
    };
    let session = match state
        .database
        .admit_mount_session(
            fence.tenant_id,
            session_fence.session_id,
            protocol,
            &fence.gateway_id,
            fence.gateway_epoch,
            session_fence.credential_generation,
            session_fence.authorization_generation,
            fence
                .nfs_context
                .as_ref()
                .map(|context| &context.gss_binding_digest),
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

async fn dispatch_nfs(
    state: &VfsState,
    request: &VfsRequest,
    fence: &RequestFence,
    operation: &Operation,
) -> VfsResponse {
    let canonical_digest = canonical_nfs_request_digest(request);
    let Some(context) = nfs_replay_context(fence, &canonical_digest) else {
        return invalid(fence);
    };
    let Some(session_fence) = session_admission_fence(fence) else {
        return invalid(fence);
    };
    let session = match state
        .database
        .admit_mount_session(
            fence.tenant_id,
            session_fence.session_id,
            protocol_name(MountProtocol::Nfs),
            &fence.gateway_id,
            fence.gateway_epoch,
            session_fence.credential_generation,
            session_fence.authorization_generation,
            fence
                .nfs_context
                .as_ref()
                .map(|context| &context.gss_binding_digest),
        )
        .await
    {
        Ok(session) => session,
        Err(_) => {
            if let Operation::EndSession(end) = operation {
                return match state
                    .database
                    .lookup_applied_nfs_end_session_replay(
                        &context,
                        &fence.gateway_id,
                        session_fence.credential_generation,
                        session_fence.authorization_generation,
                        fence
                            .nfs_context
                            .as_ref()
                            .map(|context| &context.gss_binding_digest),
                        &end.reason_code,
                    )
                    .await
                {
                    Ok(Some(receipt)) => decode_nfs_end_session_replay(fence, &receipt),
                    Ok(None) | Err(DatabaseError::StaleGeneration) => {
                        denied(fence, "vfs.session_fence_stale")
                    }
                    Err(DatabaseError::Conflict) => VfsResponse::failure(
                        fence.request_id,
                        VfsError::Conflict,
                        "vfs.nfs_replay_mismatch",
                    ),
                    Err(_) => unavailable(fence, "vfs.nfs_replay_unavailable"),
                };
            }
            return denied(fence, "vfs.session_fence_stale");
        }
    };

    let replay_candidate = match state.database.lookup_nfs_replay_candidate(&context).await {
        Ok(candidate) => candidate,
        Err(DatabaseError::Conflict) => {
            return VfsResponse::failure(
                fence.request_id,
                VfsError::Conflict,
                "vfs.nfs_replay_mismatch",
            );
        }
        Err(DatabaseError::StaleGeneration) => {
            return VfsResponse::failure(
                fence.request_id,
                VfsError::StaleGeneration,
                "vfs.nfs_replay_stale",
            );
        }
        Err(_) => return unavailable(fence, "vfs.nfs_replay_unavailable"),
    };
    if let Some(candidate) = replay_candidate {
        let replay = decode_nfs_replay(fence, &candidate);
        let admission = match nfs_dispatch::authorize_replay(
            state, fence, &session, operation, &replay,
        )
        .await
        {
            Ok(admission) => admission,
            Err(response) => return response,
        };
        return match state
            .database
            .select_authorized_nfs_replay_receipt(
                &session,
                match fence.nfs_context.as_ref() {
                    Some(context) => &context.gss_binding_digest,
                    None => return invalid(fence),
                },
                &context,
                &admission.authorizations,
                admission.handle.as_ref(),
            )
            .await
        {
            Ok(Some(receipt)) => decode_nfs_replay(fence, &receipt),
            Ok(None) | Err(DatabaseError::StaleGeneration) => {
                denied(fence, "vfs.session_fence_stale")
            }
            Err(DatabaseError::Conflict) => VfsResponse::failure(
                fence.request_id,
                VfsError::Conflict,
                "vfs.nfs_replay_mismatch",
            ),
            Err(_) => unavailable(fence, "vfs.nfs_replay_unavailable"),
        };
    }

    match nfs_dispatch::dispatch(state, fence, &session, &context, operation).await {
        nfs_dispatch::DispatchResult::Atomic(response) => response,
        nfs_dispatch::DispatchResult::Retryable(response) => response,
        nfs_dispatch::DispatchResult::ReadOnly(response) => {
            persist_nfs_read_only_receipt(state, fence, &session, context, operation, response)
                .await
        }
    }
}

fn nfs_not_qualified(fence: &RequestFence, operation: &str) -> VfsResponse {
    let reason = match operation {
        "list" => "vfs.nfs_list_not_qualified",
        "stat" => "vfs.nfs_stat_not_qualified",
        "open" => "vfs.nfs_open_not_qualified",
        "read" => "vfs.nfs_read_not_qualified",
        "write" => "vfs.nfs_write_not_qualified",
        "flush" => "vfs.nfs_flush_not_qualified",
        "commit" => "vfs.nfs_commit_not_qualified",
        "close" => "vfs.nfs_close_not_qualified",
        "create" => "vfs.nfs_create_not_qualified",
        "mkdir" => "vfs.nfs_mkdir_not_qualified",
        "rename" => "vfs.nfs_rename_not_qualified",
        "remove" => "vfs.nfs_remove_not_qualified",
        "set_attributes" => "vfs.nfs_set_attributes_not_qualified",
        "lock" => "vfs.nfs_lock_not_qualified",
        "unlock" => "vfs.nfs_unlock_not_qualified",
        "end_session" => "vfs.nfs_end_session_not_qualified",
        "get_xattr" => "vfs.nfs_get_xattr_not_qualified",
        "set_xattr" => "vfs.nfs_set_xattr_not_qualified",
        "list_xattr" => "vfs.nfs_list_xattr_not_qualified",
        "remove_xattr" => "vfs.nfs_remove_xattr_not_qualified",
        "readlink" => "vfs.nfs_readlink_not_qualified",
        "symlink" => "vfs.nfs_symlink_not_qualified",
        "sparse_write" => "vfs.nfs_sparse_write_not_qualified",
        "reclaim" => "vfs.nfs_reclaim_not_qualified",
        "open_unlinked" => "vfs.nfs_open_unlinked_not_qualified",
        "resolve_handle" => "vfs.nfs_resolve_handle_not_qualified",
        "export_root" => "vfs.nfs_export_root_not_qualified",
        "lookup" => "vfs.nfs_lookup_not_qualified",
        "access" => "vfs.nfs_access_not_qualified",
        "filesystem_info" => "vfs.nfs_filesystem_info_not_qualified",
        "get_acl" => "vfs.nfs_get_acl_not_qualified",
        "set_acl" => "vfs.nfs_set_acl_not_qualified",
        "sparse_control" => "vfs.nfs_sparse_control_not_qualified",
        _ => "vfs.nfs_operation_not_qualified",
    };
    VfsResponse::failure(fence.request_id, VfsError::NotSupported, reason)
}

fn nfs_not_supported(fence: &RequestFence, operation: &str) -> VfsResponse {
    let reason = match operation {
        "lease_acknowledge" => "vfs.nfs_delegations_not_supported",
        _ => "vfs.nfs_advanced_operation_not_supported",
    };
    VfsResponse::failure(fence.request_id, VfsError::NotSupported, reason)
}

fn nfs_replay_context<'a>(
    fence: &'a RequestFence,
    canonical_digest: &'a [u8; 32],
) -> Option<NfsReplayContext<'a>> {
    let session_id = fence.session_id?;
    let nfs = fence.nfs_context.as_ref()?;
    if let Some(supplied_digest) = nfs.request_digest.as_ref()
        && verify_slices_are_equal(supplied_digest, canonical_digest).is_err()
    {
        return None;
    }
    Some(NfsReplayContext {
        tenant_id: fence.tenant_id,
        mount_session_id: session_id,
        client_id: &nfs.client_id,
        nfs_session_id: &nfs.nfs_session_id,
        slot_id: i32::from(nfs.slot_id),
        sequence_id: nfs.sequence_id,
        operation_index: i32::from(nfs.operation_index),
        operation: nfs_operation_name(fence.operation),
        request_digest: canonical_digest,
        gateway_epoch: fence.gateway_epoch,
    })
}

const fn nfs_operation_name(operation: filebelt_vfs_protocol::OperationKind) -> &'static str {
    use filebelt_vfs_protocol::OperationKind;
    match operation {
        OperationKind::Authenticate => "authenticate",
        OperationKind::NfsAuthenticate => "nfs_authenticate",
        OperationKind::List => "list",
        OperationKind::Stat => "stat",
        OperationKind::Open => "open",
        OperationKind::Read => "read",
        OperationKind::Write => "write",
        OperationKind::Flush => "flush",
        OperationKind::Commit => "commit",
        OperationKind::Close => "close",
        OperationKind::Create => "create",
        OperationKind::Mkdir => "mkdir",
        OperationKind::Rename => "rename",
        OperationKind::Remove => "remove",
        OperationKind::SetAttributes => "set_attributes",
        OperationKind::Lock => "lock",
        OperationKind::TestLock => "test_lock",
        OperationKind::Unlock => "unlock",
        OperationKind::LeaseAcknowledge => "lease_acknowledge",
        OperationKind::AllocatePassivePort => "allocate_passive_port",
        OperationKind::Heartbeat => "heartbeat",
        OperationKind::EndSession => "end_session",
        OperationKind::GatewayHello => "gateway_hello",
        OperationKind::GetXattr => "get_xattr",
        OperationKind::SetXattr => "set_xattr",
        OperationKind::ListXattr => "list_xattr",
        OperationKind::RemoveXattr => "remove_xattr",
        OperationKind::Readlink => "readlink",
        OperationKind::Symlink => "symlink",
        OperationKind::SparseWrite => "sparse_write",
        OperationKind::Reclaim => "reclaim",
        OperationKind::OpenUnlinked => "open_unlinked",
        OperationKind::ResolveHandle => "resolve_handle",
        OperationKind::ExportRoot => "export_root",
        OperationKind::Lookup => "lookup",
        OperationKind::Access => "access",
        OperationKind::FilesystemInfo => "filesystem_info",
        OperationKind::GetAcl => "get_acl",
        OperationKind::SetAcl => "set_acl",
        OperationKind::SparseControl => "sparse_control",
        OperationKind::GatewayDrain => "gateway_drain",
        OperationKind::GatewayReconcile => "gateway_reconcile",
    }
}

fn decode_nfs_replay(
    fence: &RequestFence,
    receipt: &filebelt_database::mount::NfsReplayReceipt,
) -> VfsResponse {
    if blake3::hash(&receipt.response_bytes).as_bytes() != &receipt.response_digest {
        return unavailable(fence, "vfs.nfs_replay_corrupt");
    }
    match VfsResponse::decode(receipt.response_bytes.as_slice()) {
        Ok(mut response) if response.request_id.is_empty() => {
            response.request_id = fence.request_id.to_string();
            if response.validate_for(fence.request_id).is_ok() {
                response
            } else {
                unavailable(fence, "vfs.nfs_replay_corrupt")
            }
        }
        _ => unavailable(fence, "vfs.nfs_replay_corrupt"),
    }
}

fn decode_nfs_end_session_replay(
    fence: &RequestFence,
    receipt: &filebelt_database::mount::NfsReplayReceipt,
) -> VfsResponse {
    let expected = ok(fence);
    let mut template = expected.clone();
    template.request_id.clear();
    if receipt.mutation_outcome.as_deref() != Some("applied")
        || receipt.response_bytes != template.encode_to_vec()
    {
        return denied(fence, "vfs.session_fence_stale");
    }
    decode_nfs_replay(fence, receipt)
}

fn select_authorized_nfs_replay(
    fence: &RequestFence,
    receipt: &filebelt_database::mount::NfsReplayReceipt,
    current_response: VfsResponse,
) -> VfsResponse {
    let mut current_template = current_response.clone();
    current_template.request_id.clear();
    if receipt.response_bytes == current_template.encode_to_vec() {
        return decode_nfs_replay(fence, receipt);
    }
    if current_response.error != VfsError::Ok as i32 {
        return current_response;
    }
    VfsResponse::failure(
        fence.request_id,
        VfsError::StaleGeneration,
        "vfs.nfs_replay_authority_changed",
    )
}

async fn persist_nfs_read_only_receipt(
    state: &VfsState,
    fence: &RequestFence,
    session: &filebelt_database::mount::MountSessionFence,
    context: NfsReplayContext<'_>,
    operation: &Operation,
    response: VfsResponse,
) -> VfsResponse {
    let current_response = response;
    let mut response_template = current_response.clone();
    response_template.request_id.clear();
    let response_bytes = response_template.encode_to_vec();
    let response_digest = *blake3::hash(&response_bytes).as_bytes();
    match state
        .database
        .record_nfs_replay_receipt(&RecordNfsReplayReceiptInput {
            context: context.clone(),
            response_bytes: &response_bytes,
            response_digest: &response_digest,
        })
        .await
    {
        Ok(receipt) => {
            let replay = decode_nfs_replay(fence, &receipt);
            let admission =
                match nfs_dispatch::authorize_replay(state, fence, session, operation, &replay)
                    .await
                {
                    Ok(admission) => admission,
                    Err(response) => return response,
                };
            match state
                .database
                .select_authorized_nfs_replay_receipt(
                    session,
                    match fence.nfs_context.as_ref() {
                        Some(context) => &context.gss_binding_digest,
                        None => return invalid(fence),
                    },
                    &context,
                    &admission.authorizations,
                    admission.handle.as_ref(),
                )
                .await
            {
                Ok(Some(receipt)) => {
                    select_authorized_nfs_replay(fence, &receipt, current_response)
                }
                Ok(None) | Err(DatabaseError::StaleGeneration) => {
                    denied(fence, "vfs.session_fence_stale")
                }
                Err(_) => unavailable(fence, "vfs.nfs_replay_unavailable"),
            }
        }
        Err(DatabaseError::Conflict) => VfsResponse::failure(
            fence.request_id,
            VfsError::Conflict,
            "vfs.nfs_replay_mismatch",
        ),
        Err(DatabaseError::StaleGeneration) => VfsResponse::failure(
            fence.request_id,
            VfsError::StaleGeneration,
            "vfs.nfs_replay_stale",
        ),
        Err(_) => unavailable(fence, "vfs.nfs_replay_unavailable"),
    }
}

const NFS_GATEWAY_FEATURES: [i32; 6] = [
    NfsGatewayFeature::RpcsecGssPrivacy as i32,
    NfsGatewayFeature::PersistentHandles as i32,
    NfsGatewayFeature::Nfs4Acl as i32,
    NfsGatewayFeature::SparseFiles as i32,
    NfsGatewayFeature::Xattr as i32,
    NfsGatewayFeature::Symlink as i32,
];

fn nfs_gateway_compatible(compatibility: &NfsGatewayCompatibility, release_revision: &str) -> bool {
    compatibility.minimum_protocol_version == PROTOCOL_VERSION
        && compatibility.maximum_protocol_version == PROTOCOL_VERSION
        && compatibility.features == NFS_GATEWAY_FEATURES
        && compatibility.release_revision == release_revision
}

async fn nfs_gateway_hello(
    state: &VfsState,
    fence: &RequestFence,
    request: &GatewayHelloRequest,
) -> VfsResponse {
    let Some(runtime) = state.nfs.as_deref() else {
        return VfsResponse::failure(fence.request_id, VfsError::NotSupported, "vfs.nfs_disabled");
    };
    if request.tenant_slug != state.tenant_slug {
        return denied(fence, "vfs.tenant_not_found");
    }
    if request
        .nfs_compatibility
        .as_ref()
        .is_none_or(|compatibility| {
            !nfs_gateway_compatible(compatibility, runtime.release_revision)
        })
    {
        return VfsResponse::failure(
            fence.request_id,
            VfsError::NotSupported,
            "vfs.nfs_gateway_incompatible",
        );
    }
    let epoch = match state
        .database
        .claim_mount_gateway_epoch(state.tenant_id, "nfs", "nfs", &fence.gateway_id)
        .await
    {
        Ok(epoch) => epoch,
        Err(_) => return unavailable(fence, "vfs.gateway_epoch_unavailable"),
    };
    let Some(gateway_epoch) = positive_u64(epoch) else {
        return unavailable(fence, "vfs.gateway_epoch_unavailable");
    };
    let manifest = match state.database.nfs_export_manifest(state.tenant_id).await {
        Ok(manifest) => manifest,
        Err(DatabaseError::AdmissionLimited | DatabaseError::NotFound) => {
            return denied(fence, "vfs.nfs_feature_inactive");
        }
        Err(_) => return unavailable(fence, "vfs.nfs_manifest_unavailable"),
    };
    let Some(feature_generation) = positive_u64(manifest.feature_generation) else {
        return unavailable(fence, "vfs.nfs_manifest_invalid");
    };
    let Some(export_generation) = positive_u64(manifest.manifest_generation) else {
        return unavailable(fence, "vfs.nfs_manifest_invalid");
    };
    let Some(restore_generation) = positive_u64(manifest.restore_generation) else {
        return unavailable(fence, "vfs.nfs_manifest_invalid");
    };
    let mut active_exports = Vec::with_capacity(manifest.exports.len());
    for export in manifest.exports {
        let (Some(export_id), Some(export_generation), Some(root_node_generation)) = (
            positive_u64(export.export_id),
            positive_u64(export.export_generation),
            positive_u64(export.root_node_generation),
        ) else {
            return unavailable(fence, "vfs.nfs_manifest_invalid");
        };
        let root_handle = nfs::issue_handle(
            nfs::NfsHandleScope {
                tenant_id: state.tenant_id,
                export_id,
                node_id: export.root_node_id,
                export_generation,
                node_generation: root_node_generation,
                restore_generation,
            },
            runtime.handle_keyring.current(),
        );
        active_exports.push(NfsExportManifestEntry {
            export_id,
            drive_id: export.drive_id.to_string(),
            export_path: export.export_path,
            generation: export_generation,
            root_handle: root_handle.to_vec(),
            read_only: false,
        });
    }
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        gateway_epoch,
        nfs_gateway_hello: Some(NfsGatewayHelloResponse {
            tenant_id: state.tenant_id.to_string(),
            feature_generation,
            export_generation,
            lease_seconds: NFS_GATEWAY_LEASE_SECONDS,
            active_exports,
        }),
        ..VfsResponse::default()
    }
}

async fn nfs_gateway_reconcile(
    state: &VfsState,
    fence: &RequestFence,
    request: &GatewayReconcileRequest,
) -> VfsResponse {
    let Some(runtime) = state.nfs.as_deref() else {
        return VfsResponse::failure(fence.request_id, VfsError::NotSupported, "vfs.nfs_disabled");
    };
    let manifest = match state.database.nfs_export_manifest(state.tenant_id).await {
        Ok(manifest) => manifest,
        Err(DatabaseError::AdmissionLimited | DatabaseError::NotFound) => {
            return denied(fence, "vfs.nfs_feature_inactive");
        }
        Err(_) => return unavailable(fence, "vfs.nfs_manifest_unavailable"),
    };
    let (Some(feature_generation), Some(export_generation), Some(restore_generation)) = (
        positive_u64(manifest.feature_generation),
        positive_u64(manifest.manifest_generation),
        positive_u64(manifest.restore_generation),
    ) else {
        return unavailable(fence, "vfs.nfs_manifest_invalid");
    };
    let mut exports = Vec::with_capacity(manifest.exports.len());
    for export in &manifest.exports {
        let (Some(export_id), Some(generation), Some(node_generation)) = (
            positive_u64(export.export_id),
            positive_u64(export.export_generation),
            positive_u64(export.root_node_generation),
        ) else {
            return unavailable(fence, "vfs.nfs_manifest_invalid");
        };
        exports.push(NfsExportManifestEntry {
            export_id,
            drive_id: export.drive_id.to_string(),
            export_path: export.export_path.clone(),
            generation,
            root_handle: nfs::issue_handle(
                nfs::NfsHandleScope {
                    tenant_id: state.tenant_id,
                    export_id,
                    node_id: export.root_node_id,
                    export_generation: generation,
                    node_generation,
                    restore_generation,
                },
                runtime.handle_keyring.current(),
            )
            .to_vec(),
            read_only: false,
        });
    }
    let expected_digest = nfs::manifest_digest(
        state.tenant_id,
        feature_generation,
        export_generation,
        &exports,
    );
    if request.feature_generation != feature_generation
        || request.export_generation != export_generation
        || request.manifest_digest != expected_digest
        || request.applied_exports.len() != exports.len()
        || request
            .applied_exports
            .iter()
            .zip(&exports)
            .any(|(applied, expected)| {
                applied.export_id != expected.export_id
                    || applied.generation != expected.generation
                    || applied.root_handle_digest != nfs::root_handle_digest(&expected.root_handle)
            })
    {
        return VfsResponse::failure(
            fence.request_id,
            VfsError::StaleGeneration,
            "vfs.nfs_manifest_stale",
        );
    }
    let export_ids = request
        .applied_exports
        .iter()
        .map(|export| i64::try_from(export.export_id))
        .collect::<Result<Vec<_>, _>>();
    let export_generations = request
        .applied_exports
        .iter()
        .map(|export| i64::try_from(export.generation))
        .collect::<Result<Vec<_>, _>>();
    let root_handle_digests = request
        .applied_exports
        .iter()
        .map(|export| <[u8; 32]>::try_from(export.root_handle_digest.as_slice()))
        .collect::<Result<Vec<_>, _>>();
    let (Ok(export_ids), Ok(export_generations), Ok(root_handle_digests)) =
        (export_ids, export_generations, root_handle_digests)
    else {
        return invalid(fence);
    };
    let result = state
        .database
        .reconcile_nfs_export_manifest(&ReconcileNfsExportManifestInput {
            tenant_id: state.tenant_id,
            gateway_id: &fence.gateway_id,
            gateway_epoch: fence.gateway_epoch,
            feature_generation: manifest.feature_generation,
            manifest_generation: manifest.manifest_generation,
            manifest_digest: &expected_digest,
            export_ids: &export_ids,
            export_generations: &export_generations,
            root_handle_digests: &root_handle_digests,
        })
        .await;
    match result {
        Ok(applied)
            if applied.manifest_generation == manifest.manifest_generation
                && applied.manifest_digest == expected_digest
                && applied.gateway_id == fence.gateway_id
                && applied.gateway_epoch == fence.gateway_epoch =>
        {
            ok_with_gateway_epoch(fence)
        }
        Ok(_) | Err(DatabaseError::Conflict | DatabaseError::StaleGeneration) => {
            VfsResponse::failure(
                fence.request_id,
                VfsError::StaleGeneration,
                "vfs.nfs_manifest_stale",
            )
        }
        Err(_) => unavailable(fence, "vfs.nfs_manifest_reconcile_failed"),
    }
}

async fn nfs_gateway_drain(
    state: &VfsState,
    fence: &RequestFence,
    _request: &GatewayDrainRequest,
) -> VfsResponse {
    if state.nfs.is_none() {
        return VfsResponse::failure(fence.request_id, VfsError::NotSupported, "vfs.nfs_disabled");
    }
    match state
        .database
        .drain_mount_gateway_epoch(
            state.tenant_id,
            "nfs",
            "nfs",
            &fence.gateway_id,
            fence.gateway_epoch,
            "gateway_shutdown",
        )
        .await
    {
        Ok(()) => ok_with_gateway_epoch(fence),
        Err(DatabaseError::StaleGeneration) => VfsResponse::failure(
            fence.request_id,
            VfsError::StaleGeneration,
            "vfs.gateway_epoch_stale",
        ),
        Err(_) => unavailable(fence, "vfs.gateway_drain_failed"),
    }
}

async fn nfs_authenticate(
    state: &VfsState,
    fence: &RequestFence,
    request: &NfsAuthenticateRequest,
) -> VfsResponse {
    let Some(runtime) = state.nfs.as_deref() else {
        return VfsResponse::failure(fence.request_id, VfsError::NotSupported, "vfs.nfs_disabled");
    };
    if nfs::validate_authenticated_principal(&request.kerberos_principal, &runtime.realm).is_err() {
        return denied(fence, "vfs.authentication_failed");
    }
    let Ok(gss_binding_digest) = <[u8; 32]>::try_from(request.gss_binding_digest.as_slice()) else {
        return invalid(fence);
    };
    let projection = match state
        .database
        .create_nfs_mount_session(&CreateNfsMountSessionInput {
            tenant_id: state.tenant_id,
            kerberos_principal: &request.kerberos_principal,
            gss_binding_digest: &gss_binding_digest,
            gateway_id: &fence.gateway_id,
            gateway_epoch: fence.gateway_epoch,
            source_address: &request.source_address,
            gss_expires_at_unix_seconds: request.context_expires_at_unix_seconds,
        })
        .await
    {
        Ok(projection) => projection,
        Err(DatabaseError::NotFound | DatabaseError::AdmissionLimited) => {
            return denied(fence, "vfs.authentication_failed");
        }
        Err(_) => return unavailable(fence, "vfs.authentication_state_unavailable"),
    };
    let (Some(credential_generation), Some(authorization_generation), Some(gateway_epoch)) = (
        positive_u64(projection.session.credential_generation),
        positive_u64(projection.session.authorization_generation),
        positive_u64(projection.session.gateway_epoch),
    ) else {
        return unavailable(fence, "vfs.authentication_projection_invalid");
    };
    let (
        Some(projected_uid),
        Some(projected_gid),
        Some(mapping_generation),
        Some(feature_generation),
    ) = (
        positive_u64(projection.projected_uid),
        positive_u64(projection.projected_gid),
        positive_u64(projection.mapping_generation),
        positive_u64(projection.feature_generation),
    )
    else {
        return unavailable(fence, "vfs.authentication_projection_invalid");
    };
    let allowed_export_ids = projection
        .allowed_export_ids
        .iter()
        .copied()
        .map(positive_u64)
        .collect::<Option<Vec<_>>>();
    let Some(allowed_export_ids) = allowed_export_ids else {
        return unavailable(fence, "vfs.authentication_projection_invalid");
    };
    VfsResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: fence.request_id.to_string(),
        error: VfsError::Ok as i32,
        session_id: projection.session.session_id.to_string(),
        credential_generation,
        authorization_generation,
        gateway_epoch,
        nfs_session_projection: Some(NfsSessionProjection {
            posix_name: projection.posix_name,
            primary_group_name: projection.primary_group_name,
            projected_uid,
            projected_gid,
            mapping_generation,
            feature_generation,
            absolute_expires_at_unix_seconds: projection.absolute_expires_at_unix_seconds,
            allowed_export_ids,
        }),
        ..VfsResponse::default()
    }
}

fn positive_u64(value: i64) -> Option<u64> {
    u64::try_from(value).ok().filter(|value| *value > 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionAdmissionFence {
    session_id: Uuid,
    credential_generation: i64,
    authorization_generation: i64,
}

fn session_admission_fence(request: &RequestFence) -> Option<SessionAdmissionFence> {
    let (Some(session_id), Some(credential_generation), Some(authorization_generation)) = (
        request.session_id,
        request.credential_generation,
        request.authorization_generation,
    ) else {
        return None;
    };
    Some(SessionAdmissionFence {
        session_id,
        credential_generation,
        authorization_generation,
    })
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
        content_blake3: Vec::new(),
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
                persistent_handle: Vec::new(),
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
            // The common namespace may contain NFS-created symlinks. Generic
            // directory/stat projection must preserve their type instead of
            // treating valid persisted state as corruption. It does not grant
            // traversal: non-NFS Readlink/Symlink requests fail protocol
            // validation, and the generic handle-open SQL admits files only.
            "symlink" => NodeKind::Symlink as i32,
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
        accessed_at_unix_seconds: 0,
        created_at_unix_seconds: 0,
        changed_at_unix_seconds: 0,
        owner_name: String::new(),
        group_name: String::new(),
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
    if !valid_credential_operation_id(request.operation_id)
        || request.operation_generation <= 0
        || !matches!(request.protocol.as_str(), "smb" | "ftps")
        || !request.read_only
        || request.allowed_drive_ids.is_empty()
        || request.allowed_drive_ids.len() > 256
        || expires_at <= now
        || expires_at > maximum_expiry
    {
        return Err((StatusCode::BAD_REQUEST, "invalid mount credential request"));
    }
    let credential_id = request.operation_id;
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
            request.operation_generation,
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
            DatabaseError::StaleGeneration => (
                StatusCode::PRECONDITION_FAILED,
                "mount credential operation is stale",
            ),
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

fn valid_credential_operation_id(operation_id: Uuid) -> bool {
    operation_id.get_version_num() == 4 && operation_id.get_variant() == Variant::RFC4122
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

fn ok_with_gateway_epoch(request: &RequestFence) -> VfsResponse {
    match positive_u64(request.gateway_epoch) {
        Some(gateway_epoch) => VfsResponse {
            gateway_epoch,
            ..ok(request)
        },
        None => invalid(request),
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
    fn credential_operation_ids_require_rfc4122_uuid_v4() {
        assert!(valid_credential_operation_id(Uuid::new_v4()));
        for invalid in [
            Uuid::nil(),
            Uuid::parse_str("f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap(),
            Uuid::parse_str("00000000-0000-4000-0000-000000000001").unwrap(),
        ] {
            assert!(!valid_credential_operation_id(invalid));
        }
    }

    fn nfs_fence(operation: filebelt_vfs_protocol::OperationKind) -> RequestFence {
        RequestFence {
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            protocol: MountProtocol::Nfs,
            gateway_id: Uuid::new_v4().to_string(),
            gateway_epoch: 7,
            session_id: Some(Uuid::new_v4()),
            credential_generation: Some(2),
            authorization_generation: Some(3),
            nfs_context: Some(filebelt_vfs_protocol::ValidatedNfsContext {
                gss_binding_digest: [4; 32],
                client_id: "client-1".into(),
                nfs_session_id: "nfs-session-1".into(),
                slot_id: 5,
                sequence_id: 6,
                operation_index: 7,
                request_digest: Some([8; 32]),
            }),
            operation,
        }
    }

    fn nfs_request(operation: Operation, mutation: bool) -> VfsRequest {
        let mut request = VfsRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            protocol: MountProtocol::Nfs as i32,
            gateway_id: Uuid::new_v4().to_string(),
            gateway_epoch: 7,
            session_id: Uuid::new_v4().to_string(),
            credential_generation: 2,
            authorization_generation: 3,
            nfs_context: Some(filebelt_vfs_protocol::NfsRequestContext {
                gss_binding_digest: vec![4; 32],
                client_id: "client-1".into(),
                nfs_session_id: "nfs-session-1".into(),
                slot_id: 5,
                sequence_id: 6,
                operation_index: 7,
                request_digest: Vec::new(),
            }),
            operation: Some(operation),
        };
        if mutation {
            let digest = canonical_nfs_request_digest(&request);
            request.nfs_context.as_mut().unwrap().request_digest = digest.to_vec();
        }
        request
    }

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
            nfs_context: None,
            operation: filebelt_vfs_protocol::OperationKind::Authenticate,
        };
        let response = denied(&request, "vfs.authentication_failed");
        assert_eq!(response.protocol_version, PROTOCOL_VERSION);
        assert_eq!(response.error, VfsError::NotFound as i32);
    }

    #[test]
    fn nfs_gateway_compatibility_is_an_exact_release_contract() {
        let mut compatibility = NfsGatewayCompatibility {
            minimum_protocol_version: PROTOCOL_VERSION,
            maximum_protocol_version: PROTOCOL_VERSION,
            features: NFS_GATEWAY_FEATURES.to_vec(),
            release_revision: "abcdef1".into(),
            config_format: filebelt_vfs_protocol::NFS_CONFIG_FORMAT,
            authority_schema_revision: filebelt_vfs_protocol::NFS_AUTHORITY_SCHEMA_REVISION,
        };
        assert!(nfs_gateway_compatible(&compatibility, "abcdef1"));
        compatibility.release_revision = "abcdef2".into();
        assert!(!nfs_gateway_compatible(&compatibility, "abcdef1"));
        compatibility.release_revision = "abcdef1".into();
        compatibility.features.pop();
        assert!(!nfs_gateway_compatible(&compatibility, "abcdef1"));
        compatibility.features = NFS_GATEWAY_FEATURES.to_vec();
        compatibility.maximum_protocol_version += 1;
        assert!(!nfs_gateway_compatible(&compatibility, "abcdef1"));
    }

    #[test]
    fn session_admission_requires_a_complete_fence_without_panicking() {
        let session_id = Uuid::new_v4();
        let valid = RequestFence {
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            protocol: MountProtocol::Ftps,
            gateway_id: "ftps-0".into(),
            gateway_epoch: 1,
            session_id: Some(session_id),
            credential_generation: Some(2),
            authorization_generation: Some(3),
            nfs_context: None,
            operation: filebelt_vfs_protocol::OperationKind::Heartbeat,
        };
        assert_eq!(
            session_admission_fence(&valid),
            Some(SessionAdmissionFence {
                session_id,
                credential_generation: 2,
                authorization_generation: 3,
            })
        );

        let mut incomplete = valid;
        incomplete.session_id = None;
        assert_eq!(session_admission_fence(&incomplete), None);
        let response = invalid(&incomplete);
        assert_eq!(response.error, VfsError::InvalidRequest as i32);
        assert_eq!(response.reason_code, "vfs.invalid_request");
    }

    #[test]
    fn directory_listing_requires_metadata_and_child_discovery() {
        assert_eq!(
            directory_listing_actions(),
            [Action::ReadMetadata, Action::ListChildren]
        );
    }

    #[test]
    fn generic_metadata_projection_preserves_symlink_kind_without_traversing_it() {
        let node = NodeRecord {
            id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            parent_id: Some(Uuid::new_v4()),
            kind: "symlink".into(),
            display_name: "shortcut".into(),
            name_key: "shortcut".into(),
            head_version_id: None,
            namespace_generation: 4,
            acl_generation: 5,
            attribute_generation: 1,
            content_class_policy: "auto".into(),
            trashed: false,
            updated_at: "2026-08-11T00:00:00Z".into(),
            size_bytes: None,
            version_ordinal: None,
            head_media_type: None,
        };

        let attributes = node_attributes(&node, true).expect("valid symlink projection");
        assert_eq!(attributes.kind, NodeKind::Symlink as i32);
        assert_eq!(attributes.mode, 0o444);
        assert_eq!(attributes.link_count, 1);
        assert!(attributes.head_version_id.is_empty());
    }

    #[test]
    fn nfs_replay_context_binds_every_slot_and_operation_field() {
        let fence = nfs_fence(filebelt_vfs_protocol::OperationKind::Write);
        let digest = [8; 32];
        let context = nfs_replay_context(&fence, &digest).expect("complete NFS context");
        let nfs = fence.nfs_context.as_ref().unwrap();
        assert_eq!(context.tenant_id, fence.tenant_id);
        assert_eq!(context.mount_session_id, fence.session_id.unwrap());
        assert_eq!(context.client_id, nfs.client_id);
        assert_eq!(context.nfs_session_id, nfs.nfs_session_id);
        assert_eq!(context.slot_id, i32::from(nfs.slot_id));
        assert_eq!(context.sequence_id, nfs.sequence_id);
        assert_eq!(context.operation_index, i32::from(nfs.operation_index));
        assert_eq!(context.operation, "write");
        assert_eq!(context.request_digest, &[8; 32]);
        assert_eq!(context.gateway_epoch, fence.gateway_epoch);

        let mut read = nfs_fence(filebelt_vfs_protocol::OperationKind::Read);
        read.nfs_context.as_mut().unwrap().request_digest = None;
        let read_digest = [9; 32];
        assert_eq!(
            nfs_replay_context(&read, &read_digest)
                .unwrap()
                .request_digest,
            &read_digest,
            "read-only requests use their computed full-request digest"
        );
    }

    #[test]
    fn changed_nfs_read_arguments_produce_a_replay_mismatch_identity() {
        let request = nfs_request(
            Operation::Read(filebelt_vfs_protocol::ReadRequest {
                handle_id: Uuid::new_v4().to_string(),
                offset: 0,
                length: 64,
            }),
            false,
        );
        let fence = request.validate().expect("valid NFS read");
        let digest = canonical_nfs_request_digest(&request);
        let context = nfs_replay_context(&fence, &digest).expect("complete NFS replay context");

        let mut changed = request;
        let Some(Operation::Read(read)) = changed.operation.as_mut() else {
            unreachable!();
        };
        read.offset = 1;
        let changed_fence = changed.validate().expect("valid changed NFS read");
        let changed_digest = canonical_nfs_request_digest(&changed);
        let changed_context = nfs_replay_context(&changed_fence, &changed_digest)
            .expect("complete changed NFS replay context");

        assert_eq!(context.slot_id, changed_context.slot_id);
        assert_eq!(context.sequence_id, changed_context.sequence_id);
        assert_eq!(context.operation_index, changed_context.operation_index);
        assert_eq!(context.operation, changed_context.operation);
        assert_ne!(context.request_digest, changed_context.request_digest);
    }

    #[test]
    fn mutation_supplied_digest_must_match_the_canonical_request() {
        let request = nfs_request(
            Operation::Close(filebelt_vfs_protocol::CloseRequest {
                handle_id: Uuid::new_v4().to_string(),
            }),
            true,
        );
        let mut fence = request.validate().expect("valid NFS mutation");
        let canonical_digest = canonical_nfs_request_digest(&request);
        assert!(nfs_replay_context(&fence, &canonical_digest).is_some());

        fence.nfs_context.as_mut().unwrap().request_digest = Some([99; 32]);
        assert!(nfs_replay_context(&fence, &canonical_digest).is_none());
        let response = invalid(&fence);
        assert_eq!(response.error, VfsError::InvalidRequest as i32);
        assert_eq!(response.reason_code, "vfs.invalid_request");
    }

    #[test]
    fn nfs_exact_replay_uses_the_current_transport_uuid_and_rejects_corruption() {
        let fence = nfs_fence(filebelt_vfs_protocol::OperationKind::Heartbeat);
        let response = ok(&fence);
        let mut response_template = response.clone();
        response_template.request_id.clear();
        let response_bytes = response_template.encode_to_vec();
        let mut receipt = filebelt_database::mount::NfsReplayReceipt {
            response_digest: *blake3::hash(&response_bytes).as_bytes(),
            response_bytes,
            gateway_epoch: fence.gateway_epoch,
            expires_at_unix_seconds: 100,
            mutation_outcome: None,
        };
        assert_eq!(decode_nfs_replay(&fence, &receipt), response);

        receipt.response_digest[0] ^= 1;
        let corrupt = decode_nfs_replay(&fence, &receipt);
        assert_eq!(corrupt.error, VfsError::Unavailable as i32);
        assert_eq!(corrupt.reason_code, "vfs.nfs_replay_corrupt");

        receipt.response_digest = *blake3::hash(&receipt.response_bytes).as_bytes();
        let mut substituted = fence;
        substituted.request_id = Uuid::new_v4();
        let replay = decode_nfs_replay(&substituted, &receipt);
        assert_eq!(replay.error, response.error);
        assert_eq!(replay.reason_code, response.reason_code);
        assert_eq!(replay.request_id, substituted.request_id.to_string());

        receipt.response_bytes = response.encode_to_vec();
        receipt.response_digest = *blake3::hash(&receipt.response_bytes).as_bytes();
        let noncanonical = decode_nfs_replay(&substituted, &receipt);
        assert_eq!(noncanonical.error, VfsError::Unavailable as i32);
        assert_eq!(noncanonical.reason_code, "vfs.nfs_replay_corrupt");
    }

    #[test]
    fn nfs_replay_never_returns_cached_fields_after_live_result_changes() {
        let fence = nfs_fence(filebelt_vfs_protocol::OperationKind::Read);
        let cached = VfsResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: fence.request_id.to_string(),
            error: VfsError::Ok as i32,
            data: b"cached-secret".to_vec(),
            ..VfsResponse::default()
        };
        let mut cached_template = cached.clone();
        cached_template.request_id.clear();
        let response_bytes = cached_template.encode_to_vec();
        let receipt = filebelt_database::mount::NfsReplayReceipt {
            response_digest: *blake3::hash(&response_bytes).as_bytes(),
            response_bytes,
            gateway_epoch: fence.gateway_epoch,
            expires_at_unix_seconds: 100,
            mutation_outcome: None,
        };

        let denied = denied(&fence, "vfs.resource_not_found");
        let replay = select_authorized_nfs_replay(&fence, &receipt, denied.clone());
        assert_eq!(replay, denied);
        assert!(replay.data.is_empty());

        let changed = VfsResponse {
            data: b"changed-data".to_vec(),
            ..cached.clone()
        };
        let replay = select_authorized_nfs_replay(&fence, &receipt, changed);
        assert_eq!(replay.error, VfsError::StaleGeneration as i32);
        assert_eq!(replay.reason_code, "vfs.nfs_replay_authority_changed");
        assert!(replay.data.is_empty());

        assert_eq!(
            select_authorized_nfs_replay(&fence, &receipt, cached.clone()),
            cached
        );
    }

    #[test]
    fn nfs_end_session_replay_is_only_the_fixed_applied_acknowledgement() {
        let fence = nfs_fence(filebelt_vfs_protocol::OperationKind::EndSession);
        let mut response = ok(&fence);
        response.request_id.clear();
        let response_bytes = response.encode_to_vec();
        let mut receipt = filebelt_database::mount::NfsReplayReceipt {
            response_digest: *blake3::hash(&response_bytes).as_bytes(),
            response_bytes,
            gateway_epoch: fence.gateway_epoch,
            expires_at_unix_seconds: 100,
            mutation_outcome: Some("applied".into()),
        };
        assert_eq!(decode_nfs_end_session_replay(&fence, &receipt), ok(&fence));

        receipt.mutation_outcome = Some("conflict".into());
        assert_eq!(
            decode_nfs_end_session_replay(&fence, &receipt).error,
            VfsError::NotFound as i32
        );

        response.data = b"not-an-ack".to_vec();
        receipt.response_bytes = response.encode_to_vec();
        receipt.response_digest = *blake3::hash(&receipt.response_bytes).as_bytes();
        receipt.mutation_outcome = Some("applied".into());
        let replay = decode_nfs_end_session_replay(&fence, &receipt);
        assert_eq!(replay.error, VfsError::NotFound as i32);
        assert!(replay.data.is_empty());
    }

    #[test]
    fn nfs_replay_reenters_live_session_and_operation_admission() {
        let dispatch = include_str!("main.rs")
            .split_once("async fn dispatch_nfs(")
            .unwrap()
            .1
            .split_once("fn nfs_not_qualified(")
            .unwrap()
            .0;
        let session = dispatch.find("admit_mount_session").unwrap();
        let candidate = dispatch.find("lookup_nfs_replay_candidate").unwrap();
        let authorization = dispatch.find("authorize_replay").unwrap();
        let selection = dispatch
            .find("select_authorized_nfs_replay_receipt")
            .unwrap();
        assert!(session < candidate);
        assert!(candidate < authorization);
        assert!(authorization < selection);
        assert!(dispatch.contains("lookup_applied_nfs_end_session_replay"));
    }

    #[test]
    fn every_nfs_operation_has_an_exact_replay_identity_and_no_legacy_catch_all() {
        use filebelt_vfs_protocol::OperationKind;
        let operations = [
            (OperationKind::List, "list"),
            (OperationKind::Stat, "stat"),
            (OperationKind::Open, "open"),
            (OperationKind::Read, "read"),
            (OperationKind::Write, "write"),
            (OperationKind::Flush, "flush"),
            (OperationKind::Commit, "commit"),
            (OperationKind::Close, "close"),
            (OperationKind::Create, "create"),
            (OperationKind::Mkdir, "mkdir"),
            (OperationKind::Rename, "rename"),
            (OperationKind::Remove, "remove"),
            (OperationKind::SetAttributes, "set_attributes"),
            (OperationKind::Lock, "lock"),
            (OperationKind::Unlock, "unlock"),
            (OperationKind::LeaseAcknowledge, "lease_acknowledge"),
            (OperationKind::Heartbeat, "heartbeat"),
            (OperationKind::EndSession, "end_session"),
            (OperationKind::GetXattr, "get_xattr"),
            (OperationKind::SetXattr, "set_xattr"),
            (OperationKind::ListXattr, "list_xattr"),
            (OperationKind::RemoveXattr, "remove_xattr"),
            (OperationKind::Readlink, "readlink"),
            (OperationKind::Symlink, "symlink"),
            (OperationKind::SparseWrite, "sparse_write"),
            (OperationKind::Reclaim, "reclaim"),
            (OperationKind::OpenUnlinked, "open_unlinked"),
            (OperationKind::ResolveHandle, "resolve_handle"),
            (OperationKind::ExportRoot, "export_root"),
            (OperationKind::Lookup, "lookup"),
            (OperationKind::Access, "access"),
            (OperationKind::FilesystemInfo, "filesystem_info"),
            (OperationKind::GetAcl, "get_acl"),
            (OperationKind::SetAcl, "set_acl"),
            (OperationKind::SparseControl, "sparse_control"),
        ];
        for (operation, name) in operations {
            assert_eq!(nfs_operation_name(operation), name);
        }
        let dispatch = include_str!("main.rs")
            .split_once("async fn dispatch_nfs(")
            .unwrap()
            .1
            .split_once("fn nfs_not_qualified(")
            .unwrap()
            .0;
        assert!(!dispatch.contains("vfs.nfs_operation_not_implemented"));
    }
}

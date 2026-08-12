// SPDX-License-Identifier: Apache-2.0

//! Capability-limited FileBelt POSIX I/O worker.

#![deny(unsafe_code)]

use std::collections::{HashSet, VecDeque};
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path as FilePath, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{
    ACCEPT_RANGES, AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use filebelt_capability_keyset::{
    ApiStorageKeyset, CollaborationStorageKeyset, DocumentStorageKeyset, MountStorageKeyset,
    RevisionStorageKeyset, public_key_material_is_disjoint,
};
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::collaboration::{
    CollaborationAuthorizationContext, CollaborationAuthorizationGenerations,
    CollaborationObjectRecord,
};
use filebelt_database::mount::MountReadCapabilityFence;
use filebelt_database::mount::{
    BeginMountIoOperationInput, MountIoAdmission, MountIoCleanupRecord, MountIoCompletion,
    MountIoLookup, MountIoOperation, MountPayloadPartRecord, MountStagingCleanupJobRecord,
    MountWriteCapabilityFence, MountWriteChunkEvidence, MountWriteLockCleanupJobRecord,
    MountWriteRangeAdmission, MountWriteRangeOperation, MountWriteStorageRecord,
};
use filebelt_database::{Database, DatabaseError, UploadRecord};
use filebelt_runtime::{
    MtlsListener, OperationsState, certificate_not_after_unix_seconds, init_telemetry,
    install_crypto_provider, observe_request, operations_router, trace_request, wait_for_shutdown,
};
use filebelt_storage::{
    CowBaseChunk, CowLockGuard, CowManifest, DownloadSegment, REVISION_CHUNK_SIZE_BYTES,
    RevisionChunkLocator, StorageError, StorageLayout,
};
use filebelt_storage_protocol::{
    ApiStorageCapabilityUse, CapabilityClaims, CapabilityOperation,
    CollaborationStorageCapabilityUse, DocumentStorageCapabilityUse, MountCapabilityClaims,
    MountStorageCapabilityUse, RevisionStorageCapabilityUse, mount_capability_claims_digest,
    unix_time_now, verify_api_storage_capability, verify_collaboration_storage_capability,
    verify_document_storage_capability, verify_mount_storage_capability,
    verify_mount_storage_read_capability, verify_revision_storage_capability,
};
use futures_util::StreamExt as _;
use serde::Serialize;
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tracing::{error, info, warn};
use uuid::Uuid;

const ROLE: &str = "filebelt-worker-io";
const CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";
const CAPABILITY_COOKIE_NAMES: [&str; 2] = ["filebelt_capability", "filebelt-capability"];
const FINALIZATION_LEASE_SECONDS: i64 = 120;
const FINALIZATION_HEARTBEAT_SECONDS: u64 = 30;
const MOUNT_CLEANUP_HEARTBEAT_SECONDS: u64 = 10;
const MOUNT_WRITE_MODE_HEADER: &str = "x-filebelt-mount-write-mode";
const MAX_MOUNT_WRITE_BYTES: u64 = 1_048_576;
const REVISION_CHUNK_CAPABILITY_NONCE_BYTES: usize = 64;

#[derive(Debug, Parser)]
#[command(disable_version_flag = true)]
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
struct AppState {
    database: Database,
    storage: StorageLayout,
    api_storage_keys: Arc<ApiStorageKeyset>,
    collaboration_storage_keys: Option<Arc<CollaborationStorageKeyset>>,
    document_storage_keys: Option<Arc<DocumentStorageKeyset>>,
    revision_storage_keys: Option<Arc<RevisionStorageKeyset>>,
    mount_storage_keys: Option<Arc<MountStorageKeyset>>,
    generation_recheck: Duration,
    tenant_id: Uuid,
    backend_id: Uuid,
    worker_id: Uuid,
    chunk_size: u64,
    storage_ready: Arc<AtomicBool>,
}

#[derive(Debug)]
struct AuthorizedCapability {
    claims: CapabilityClaims,
    tenant_id: Uuid,
    session_id: Uuid,
    principal_id: Uuid,
    resource_id: Uuid,
    capability_id: Uuid,
}

#[derive(Debug)]
struct AuthorizedMountRead {
    claims: MountCapabilityClaims,
    fence: MountReadCapabilityFence,
}

#[derive(Debug)]
struct AuthorizedMountWrite {
    claims: MountCapabilityClaims,
    fence: MountWriteCapabilityFence,
}

#[derive(Debug)]
struct MountIoRequest {
    capability_id: Uuid,
    nonce_digest: [u8; 32],
    claims_digest: [u8; 32],
    operation: MountIoOperation,
    range_start: Option<i64>,
    range_end: Option<i64>,
    content_blake3: Option<[u8; 32]>,
}

impl MountIoRequest {
    fn from_claims(
        claims: &MountCapabilityClaims,
        operation: MountIoOperation,
    ) -> Result<Self, AppError> {
        let range_operation = matches!(
            operation,
            MountIoOperation::WriteData
                | MountIoOperation::HoleDeallocate
                | MountIoOperation::Allocate
                | MountIoOperation::SeekData
                | MountIoOperation::SeekHole
        );
        let content_blake3 = if operation == MountIoOperation::WriteData {
            Some(
                claims
                    .content_blake3
                    .as_slice()
                    .try_into()
                    .map_err(|_| AppError::Forbidden)?,
            )
        } else {
            None
        };
        let capability_id = parse_required_mount_uuid(&claims.capability_id)?;
        Ok(Self {
            capability_id,
            nonce_digest: nonce_digest(b"filebelt-mount-capability-nonce-v2\0", &claims.nonce),
            claims_digest: mount_capability_claims_digest(claims),
            operation,
            range_start: range_operation
                .then(|| i64::try_from(claims.range_start).map_err(|_| AppError::Forbidden))
                .transpose()?,
            range_end: range_operation
                .then(|| i64::try_from(claims.range_end).map_err(|_| AppError::Forbidden))
                .transpose()?,
            content_blake3,
        })
    }

    fn input<'a>(&'a self, authorized: &'a AuthorizedMountWrite) -> BeginMountIoOperationInput<'a> {
        BeginMountIoOperationInput {
            fence: &authorized.fence,
            capability_id: self.capability_id,
            nonce_digest: &self.nonce_digest,
            claims_digest: &self.claims_digest,
            operation: self.operation,
            range_start: self.range_start,
            range_end: self.range_end,
            content_blake3: self.content_blake3.as_ref(),
            expires_at_unix_seconds: authorized.claims.expires_at_unix_seconds,
        }
    }
}

#[derive(Debug)]
enum AppError {
    BadRequest(&'static str),
    NotFound(&'static str),
    Unauthorized,
    Forbidden,
    Conflict(&'static str),
    Range,
    Unavailable,
    Unsupported(&'static str),
    Internal,
}

#[derive(Serialize)]
struct Problem {
    r#type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
}

#[derive(Serialize)]
struct PartResult {
    upload_id: Uuid,
    part_number: i32,
    size_bytes: u64,
    blake3: String,
}

#[derive(Serialize)]
struct FinalizeResult {
    upload_id: Uuid,
    payload_id: Uuid,
    size_bytes: u64,
    blake3: String,
    state: &'static str,
}

#[derive(Serialize)]
struct CollaborationObjectResult {
    object_id: Uuid,
    payload_id: Uuid,
    size_bytes: u64,
    blake3: String,
    state: &'static str,
}

#[derive(Serialize)]
struct DocumentRevisionResult {
    revision_id: Uuid,
    payload_id: Uuid,
    size_bytes: u64,
    blake3: String,
    state: &'static str,
}

#[derive(Serialize)]
struct RevisionChunkResult {
    chunk_id: Uuid,
    drive_id: Uuid,
    size_bytes: u64,
    blake3: String,
    state: &'static str,
}

#[derive(Serialize)]
struct MountWriteResult {
    write_session_id: Uuid,
    logical_size_bytes: u64,
    reservation_delta_bytes: u64,
    state: &'static str,
}

#[derive(Serialize)]
struct MountSeekResult {
    offset: Option<u64>,
}

#[derive(Serialize)]
struct MountChunkResult {
    chunk_number: u64,
    size_bytes: u64,
    blake3: String,
}

#[derive(Serialize)]
struct MountManifestResult {
    write_session_id: Uuid,
    logical_size_bytes: u64,
    blake3: String,
    chunks: Vec<MountChunkResult>,
    state: &'static str,
}

#[derive(Serialize)]
struct MountStagingResult {
    write_session_id: Uuid,
    state: &'static str,
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    let raw_refs = raw.iter().map(String::as_str).collect::<Vec<_>>();
    if matches!(raw_refs.as_slice(), ["--version"] | ["--build-info=json"]) {
        return filebelt_deployment_diagnostics::run_probe(ROLE);
    }
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            let _ = error.print();
            return ExitCode::FAILURE;
        }
    };
    let result = match arguments.command {
        Command::Serve { config } => match Config::load(&config) {
            Ok(config) => match install_crypto_provider()
                .and_then(|()| init_telemetry(&config.telemetry, ROLE))
            {
                Ok(_guard) => serve(config).await,
                Err(error) => Err(error),
            },
            Err(error) => Err(error.to_string()),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!(error = %message, "I/O worker stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
    let database_url =
        read_secret_string(&config.database.url_file).map_err(|error| error.to_string())?;
    let database = Database::connect(&database_url, config.database.max_connections)
        .await
        .map_err(|error| error.to_string())?;
    database.health().await.map_err(|error| error.to_string())?;
    let tenant_id = database
        .tenant_by_slug(&config.tenant.slug)
        .await
        .map_err(|error| format!("configured tenant is unavailable: {error}"))?;
    let storage = StorageLayout::new(config.storage.root.clone());
    storage.probe().await.map_err(|error| error.to_string())?;
    if config.mounts.nfs.enabled {
        storage
            .probe_sparse_files()
            .await
            .map_err(|error| format!("NFS sparse-file probe failed: {error}"))?;
    }
    let (initial_total, initial_free) = report_capacity(
        &database,
        tenant_id,
        config.storage.backend_id,
        storage.root(),
        true,
    )
    .await?;
    let api_storage_keys = Arc::new(load_api_storage_keys(
        &config.keys.api_storage.public_keyset_file,
    )?);
    let collaboration_storage_keys = config
        .collaboration
        .capability_signing
        .as_ref()
        .map(|key| load_collaboration_storage_keys(&key.public_keyset_file).map(Arc::new))
        .transpose()?;
    let document_storage_keys = config
        .documents
        .capability_signing
        .as_ref()
        .map(|key| load_document_storage_keys(&key.public_keyset_file).map(Arc::new))
        .transpose()?;
    let revision_storage_keys = config
        .revisions
        .capability_signing
        .as_ref()
        .map(|key| load_revision_storage_keys(&key.public_keyset_file).map(Arc::new))
        .transpose()?;
    let mount_storage_keys = config
        .mounts
        .capability_signing
        .as_ref()
        .map(|key| load_mount_storage_keys(&key.public_keyset_file).map(Arc::new))
        .transpose()?;
    validate_storage_keyset_disjointness(
        &api_storage_keys,
        collaboration_storage_keys.as_deref(),
        document_storage_keys.as_deref(),
        revision_storage_keys.as_deref(),
        mount_storage_keys.as_deref(),
    )?;
    let storage_ready = Arc::new(AtomicBool::new(true));
    let state = AppState {
        database,
        storage,
        api_storage_keys,
        collaboration_storage_keys,
        document_storage_keys,
        revision_storage_keys,
        mount_storage_keys,
        generation_recheck: Duration::from_secs(config.limits.generation_recheck_seconds),
        tenant_id,
        backend_id: config.storage.backend_id,
        worker_id: Uuid::new_v4(),
        chunk_size: config.limits.chunk_size_bytes,
        storage_ready: storage_ready.clone(),
    };
    let ready_database = state.database.clone();
    let ready_storage = state.storage_ready.clone();
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, move || {
        let database = ready_database.clone();
        let storage = ready_storage.clone();
        async move { storage.load(Ordering::Acquire) && database.health().await.is_ok() }
    });
    let database_ready = operations.register_gauge(
        "database_ready",
        "Whether PostgreSQL is available to this role.",
    );
    database_ready.set(1);
    let observed_database = state.database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            database_ready.set(i64::from(observed_database.health().await.is_ok()));
        }
    });
    let storage_ready_metric = operations.register_gauge(
        "storage_ready",
        "Whether the payload storage probe is healthy.",
    );
    storage_ready_metric.set(1);
    let capacity = operations.register_gauge_family(
        "storage_capacity_bytes",
        "Last observed payload storage capacity.",
        "kind",
        &["total", "free"],
    );
    let capacity_total = capacity[0].clone();
    let capacity_free = capacity[1].clone();
    capacity_total.set(i64::try_from(initial_total).unwrap_or(i64::MAX));
    capacity_free.set(i64::try_from(initial_free).unwrap_or(i64::MAX));
    if let Some(tls) = config.backend_tls.as_ref() {
        operations
            .register_gauge(
                "tls_certificate_not_after_seconds",
                "Unix timestamp when the backend server certificate expires.",
            )
            .set(certificate_not_after_unix_seconds(&tls.io)?);
    }
    let application = Router::new()
        .route("/io/v1/uploads/{upload_id}/parts/{part}", put(upload_part))
        .route("/io/v1/uploads/{upload_id}/finalize", post(finalize_upload))
        .route("/io/v1/downloads/{grant_id}", get(download).head(download))
        .route(
            "/io/v1/revision-chunks/{chunk_id}",
            put(write_revision_chunk)
                .get(read_revision_chunk)
                .head(read_revision_chunk)
                .delete(delete_revision_chunk),
        )
        .route(
            "/io/v1/revision-legacy-payloads/{payload_id}",
            get(read_revision_legacy_payload).head(read_revision_legacy_payload),
        )
        .route(
            "/io/v1/documents/{session_id}/versions/{version_id}",
            get(read_document_version).head(read_document_version),
        )
        .route(
            "/io/v1/document-revisions/{revision_id}",
            put(write_document_revision),
        )
        .route(
            "/io/v1/document-revisions/{revision_id}/finalize",
            post(finalize_document_revision),
        )
        .route("/io/v1/mount-reads/{handle_id}", get(mount_download))
        .route(
            "/io/v1/mount-writes/{write_session_id}",
            put(mount_write_data),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/deallocate",
            post(deallocate_mount_write),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/allocate",
            post(allocate_mount_write),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/seek-data",
            get(seek_mount_data),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/seek-hole",
            get(seek_mount_hole),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/flush",
            post(flush_mount_write),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/finalize",
            post(finalize_mount_write),
        )
        .route(
            "/io/v1/mount-writes/{write_session_id}/abort",
            post(abort_mount_write),
        )
        .route(
            "/io/v1/mount-staging/{write_session_id}",
            axum::routing::delete(delete_mount_staging),
        )
        .route(
            "/io/v1/collaboration/{object_id}",
            put(write_collaboration_object)
                .get(read_collaboration_object)
                .head(read_collaboration_object),
        )
        .route(
            "/io/v1/collaboration/{object_id}/finalize",
            post(finalize_collaboration_object),
        )
        .fallback(not_found)
        .layer(axum::middleware::from_fn(trace_request))
        .layer(axum::middleware::from_fn_with_state(
            operations.clone(),
            observe_request,
        ))
        .with_state(state.clone());
    let operations_listener = tokio::net::TcpListener::bind(config.listeners.operations)
        .await
        .map_err(|error| format!("cannot bind operations listener: {error}"))?;
    let (operations_stop, operations_stopped) = tokio::sync::oneshot::channel();
    let operations_state = operations.clone();
    let operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations_state))
            .with_graceful_shutdown(async move {
                let _ = operations_stopped.await;
            })
            .await
            .map_err(|error| error.to_string())
    });
    let (application_stop, application_stopped) = tokio::sync::oneshot::channel();
    let mut application_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(config.listeners.io)
                .await
                .map_err(|error| error.to_string())?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .ok_or_else(|| "Kubernetes backend TLS configuration is absent".to_owned())?;
            let listener = MtlsListener::bind(config.listeners.io, &tls.io).await?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
    };
    info!(listener = %config.listeners.io, "I/O worker ready");
    let capacity_database = state.database.clone();
    let capacity_root = state.storage.root().to_path_buf();
    let capacity_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            match report_capacity(
                &capacity_database,
                tenant_id,
                config.storage.backend_id,
                &capacity_root,
                true,
            )
            .await
            {
                Ok((total, free)) => {
                    storage_ready.store(true, Ordering::Release);
                    storage_ready_metric.set(1);
                    capacity_total.set(i64::try_from(total).unwrap_or(i64::MAX));
                    capacity_free.set(i64::try_from(free).unwrap_or(i64::MAX));
                }
                Err(error) => {
                    storage_ready.store(false, Ordering::Release);
                    storage_ready_metric.set(0);
                    let _ = capacity_database
                        .mark_storage_unready(tenant_id, config.storage.backend_id)
                        .await;
                    warn!(code = "capacity_report_failed", %error);
                }
            }
        }
    });
    let result = tokio::select! {
        result = &mut application_server => result
            .map_err(|_| "I/O server task failed".to_owned())?,
        () = wait_for_shutdown() => {
            operations.begin_draining();
            let _ = application_stop.send(());
            if tokio::time::timeout(Duration::from_secs(75), &mut application_server).await.is_err() {
                application_server.abort();
            }
            Ok(())
        }
    };
    let _ = operations_stop.send(());
    operations_server
        .await
        .map_err(|_| "operations server task failed".to_owned())??;
    capacity_task.abort();
    result
}

async fn report_capacity(
    database: &Database,
    tenant_id: Uuid,
    backend_id: Uuid,
    root: &FilePath,
    ready: bool,
) -> Result<(u64, u64), String> {
    let root = root.to_path_buf();
    let (total, free) = tokio::task::spawn_blocking(move || {
        Ok::<_, std::io::Error>((fs2::total_space(&root)?, fs2::available_space(&root)?))
    })
    .await
    .map_err(|_| "capacity probe task failed".to_owned())?
    .map_err(|error| error.to_string())?;
    database
        .report_storage_capacity(
            tenant_id,
            backend_id,
            i64::try_from(total)
                .map_err(|_| "storage capacity exceeds supported range".to_owned())?,
            i64::try_from(free).map_err(|_| "free capacity exceeds supported range".to_owned())?,
            ready,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok((total, free))
}

async fn not_found() -> AppError {
    AppError::NotFound("route_not_found")
}

async fn upload_part(
    State(state): State<AppState>,
    Path((upload_id, part_number)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<PartResult>, AppError> {
    let upload_id =
        Uuid::parse_str(&upload_id).map_err(|_| AppError::BadRequest("invalid_upload_id"))?;
    let part_number = part_number
        .parse::<i32>()
        .map_err(|_| AppError::BadRequest("invalid_part_number"))?;
    if part_number < 0 {
        return Err(AppError::BadRequest("invalid_part_number"));
    }
    let authorized = authorize(&state, &headers, CapabilityOperation::UploadPart).await?;
    let claim_upload = parse_required_uuid(&authorized.claims.upload_id)?;
    let claim_payload = parse_required_uuid(&authorized.claims.payload_id)?;
    if claim_upload != upload_id
        || authorized.claims.part_number
            != u64::try_from(part_number)
                .map_err(|_| AppError::BadRequest("invalid_part_number"))?
    {
        return Err(AppError::Forbidden);
    }
    let upload = state
        .database
        .upload(authorized.tenant_id, upload_id)
        .await?;
    validate_upload_capability(&authorized, &upload, claim_payload, state.backend_id)?;
    check_generations(&state, &authorized, upload.drive_id).await?;
    let expected_size = expected_part_size(&upload, part_number)?;
    if authorized.claims.range_start != 0
        || (expected_size > 0 && authorized.claims.range_end != expected_size - 1)
        || (expected_size == 0 && authorized.claims.range_end != 0)
    {
        return Err(AppError::Forbidden);
    }
    if let Some(length) = headers.get(CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(AppError::BadRequest("invalid_content_length"))?;
        if length != expected_size {
            return Err(AppError::Conflict("part_size_mismatch"));
        }
    }
    let part = state
        .database
        .upload_part(authorized.tenant_id, upload_id, part_number)
        .await?;
    if upload.state != "open" || part.locator.is_nil() {
        return Err(AppError::Conflict("upload_not_open"));
    }
    consume_nonce(&state, &authorized, "upload_part").await?;
    let temporary = state
        .storage
        .staging_temporary_path(part.locator, authorized.capability_id)
        .map_err(storage_error)?;
    let (size, digest) = write_body(body, &temporary, expected_size).await?;
    let storage = state.storage.clone();
    let temporary_for_publish = temporary.clone();
    tokio::task::spawn_blocking(move || {
        storage.publish_staging_part(&temporary_for_publish, part.locator, size, &digest)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    state
        .database
        .mark_part_durable(
            authorized.tenant_id,
            upload_id,
            part_number,
            i64::try_from(authorized.claims.fencing_token).map_err(|_| AppError::Forbidden)?,
            i32::try_from(size).map_err(|_| AppError::Conflict("part_too_large"))?,
            &digest,
        )
        .await?;
    Ok(Json(PartResult {
        upload_id,
        part_number,
        size_bytes: size,
        blake3: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    }))
}

async fn finalize_upload(
    State(state): State<AppState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<FinalizeResult>, AppError> {
    let upload_id =
        Uuid::parse_str(&upload_id).map_err(|_| AppError::BadRequest("invalid_upload_id"))?;
    let authorized = authorize(&state, &headers, CapabilityOperation::FinalizeUpload).await?;
    let claim_upload = parse_required_uuid(&authorized.claims.upload_id)?;
    let claim_payload = parse_required_uuid(&authorized.claims.payload_id)?;
    if claim_upload != upload_id {
        return Err(AppError::Forbidden);
    }
    let upload = state
        .database
        .upload(authorized.tenant_id, upload_id)
        .await?;
    validate_upload_capability(&authorized, &upload, claim_payload, state.backend_id)?;
    check_generations(&state, &authorized, upload.drive_id).await?;
    consume_nonce(&state, &authorized, "finalize_upload").await?;
    let fencing_token =
        i64::try_from(authorized.claims.fencing_token).map_err(|_| AppError::Forbidden)?;
    state
        .database
        .claim_upload_finalization(
            authorized.tenant_id,
            upload_id,
            fencing_token,
            authorized.capability_id,
            FINALIZATION_LEASE_SECONDS,
        )
        .await?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = finish_upload_finalization(state, authorized, upload_id, fencing_token).await;
        let _ = sender.send(result);
    });
    receiver.await.map_err(|_| AppError::Internal)?.map(Json)
}

async fn finish_upload_finalization(
    state: AppState,
    authorized: AuthorizedCapability,
    upload_id: Uuid,
    fencing_token: i64,
) -> Result<FinalizeResult, AppError> {
    let result =
        finish_upload_finalization_inner(&state, &authorized, upload_id, fencing_token).await;
    if result.is_err()
        && let Err(error) = state
            .database
            .abort_upload_finalization(
                authorized.tenant_id,
                upload_id,
                fencing_token,
                authorized.capability_id,
            )
            .await
    {
        warn!(%upload_id, %error, "failed to release upload finalization lease");
    }
    result
}

async fn finish_upload_finalization_inner(
    state: &AppState,
    authorized: &AuthorizedCapability,
    upload_id: Uuid,
    fencing_token: i64,
) -> Result<FinalizeResult, AppError> {
    let upload = state
        .database
        .upload(authorized.tenant_id, upload_id)
        .await?;
    let parts = state
        .database
        .upload_parts(authorized.tenant_id, upload_id)
        .await?;
    let payload = state
        .database
        .payload(authorized.tenant_id, upload.payload_id)
        .await?;
    if upload.state != "finalizing"
        || upload.fencing_token != fencing_token
        || payload.state != "finalizing"
        || payload.backend_id != state.backend_id
    {
        return Err(AppError::Conflict("payload_not_finalizing"));
    }
    let storage = state.storage.clone();
    let upload_for_storage = upload.clone();
    let payload_for_storage = payload.clone();
    let parts_for_storage = parts.clone();
    let operation_id = authorized.capability_id;
    let work = tokio::task::spawn_blocking(move || {
        storage.finalize(
            &upload_for_storage,
            &payload_for_storage,
            &parts_for_storage,
            operation_id,
        )
    });
    tokio::pin!(work);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(FINALIZATION_HEARTBEAT_SECONDS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let finalized = loop {
        tokio::select! {
            result = &mut work => {
                break result.map_err(|_| AppError::Internal)?.map_err(storage_error)?;
            }
            _ = heartbeat.tick() => {
                if let Err(error) = state.database.heartbeat_upload_finalization(
                    authorized.tenant_id,
                    upload_id,
                    fencing_token,
                    authorized.capability_id,
                    FINALIZATION_LEASE_SECONDS,
                ).await {
                    warn!(%upload_id, %error, "upload finalization heartbeat failed");
                }
            }
        }
    };
    check_generations(state, authorized, upload.drive_id).await?;
    state
        .database
        .mark_upload_finalized(
            authorized.tenant_id,
            upload_id,
            fencing_token,
            authorized.capability_id,
            &finalized.digest,
        )
        .await?;
    let cleanup_storage = state.storage.clone();
    if let Err(error) =
        tokio::task::spawn_blocking(move || cleanup_storage.remove_staging_parts(&parts))
            .await
            .map_err(|_| StorageError::Join)
            .and_then(|result| result)
    {
        warn!(%upload_id, %error, "finalized upload staging cleanup deferred");
    } else if let Err(error) = state
        .database
        .mark_upload_staging_cleaned(authorized.tenant_id, upload_id)
        .await
    {
        warn!(%upload_id, %error, "finalized upload staging cleanup marker deferred");
    }
    Ok(FinalizeResult {
        upload_id,
        payload_id: upload.payload_id,
        size_bytes: finalized.size,
        blake3: finalized
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        state: "finalized",
    })
}

async fn download(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let grant_id =
        Uuid::parse_str(&grant_id).map_err(|_| AppError::BadRequest("invalid_grant_id"))?;
    let authorized = authorize(&state, &headers, CapabilityOperation::Download).await?;
    if parse_required_uuid(&authorized.claims.grant_id)? != grant_id {
        return Err(AppError::Forbidden);
    }
    let payload_id = parse_required_uuid(&authorized.claims.payload_id)?;
    let payload = state
        .database
        .payload(authorized.tenant_id, payload_id)
        .await?;
    if payload.state != "referenced" || payload.backend_id != state.backend_id {
        return Err(AppError::Conflict("payload_not_referenced"));
    }
    check_generations(&state, &authorized, payload.drive_id).await?;
    let upload = state
        .database
        .upload_for_payload(authorized.tenant_id, payload_id)
        .await?;
    let parts = state
        .database
        .upload_parts(authorized.tenant_id, upload.upload_id)
        .await?;
    let size = u64::try_from(payload.size_bytes).map_err(|_| AppError::Internal)?;
    let (start, end, partial) = requested_range(headers.get(RANGE), size, &authorized.claims)?;
    let storage = state.storage.clone();
    let payload_for_storage = payload.clone();
    let upload_for_storage = upload.clone();
    let segments = tokio::task::spawn_blocking(move || {
        storage.verified_download_segments(
            &upload_for_storage,
            &payload_for_storage,
            &parts,
            start,
            end,
        )
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    check_generations(&state, &authorized, payload.drive_id).await?;
    let response_length = if size == 0 { 0 } else { end - start + 1 };
    let mut builder = Response::builder()
        .status(if partial {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, response_length.to_string())
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff");
    if partial {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }
    let body = if request.method() == Method::HEAD || size == 0 {
        Body::empty()
    } else {
        Body::from_stream(download_stream(
            state.database.clone(),
            authorized,
            payload.drive_id,
            segments,
            state.generation_recheck,
        ))
    };
    builder.body(body).map_err(|_| AppError::Internal)
}

async fn write_revision_chunk(
    State(state): State<AppState>,
    Path(chunk_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<RevisionChunkResult>, AppError> {
    let chunk_id =
        Uuid::parse_str(&chunk_id).map_err(|_| AppError::BadRequest("invalid_chunk_id"))?;
    let authorized = authorize(&state, &headers, CapabilityOperation::WriteRevisionChunk).await?;
    let locator = revision_chunk_locator(&authorized, chunk_id)?;
    if let Some(length) = headers.get(CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(AppError::BadRequest("invalid_content_length"))?;
        if length != locator.size {
            return Err(AppError::Conflict("revision_chunk_size_mismatch"));
        }
    }
    consume_nonce(&state, &authorized, "revision_write_chunk").await?;
    let temporary = state
        .storage
        .revision_chunk_staging_path(locator.drive_id, authorized.capability_id)
        .map_err(storage_error)?;
    let (size, digest) = write_body(body, &temporary, locator.size).await?;
    if size != locator.size || digest != locator.digest {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(AppError::Conflict("revision_chunk_digest_mismatch"));
    }
    let storage = state.storage.clone();
    let temporary_for_publish = temporary.clone();
    tokio::task::spawn_blocking(move || {
        storage.publish_revision_chunk(&temporary_for_publish, locator)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    Ok(Json(RevisionChunkResult {
        chunk_id,
        drive_id: locator.drive_id,
        size_bytes: locator.size,
        blake3: hex_digest(&locator.digest),
        state: "durable",
    }))
}

async fn read_revision_chunk(
    State(state): State<AppState>,
    Path(chunk_id): Path<String>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let chunk_id =
        Uuid::parse_str(&chunk_id).map_err(|_| AppError::BadRequest("invalid_chunk_id"))?;
    let authorized = authorize(&state, &headers, CapabilityOperation::ReadRevisionChunk).await?;
    let locator = revision_chunk_locator(&authorized, chunk_id)?;
    let (start, end, partial) =
        requested_range(headers.get(RANGE), locator.size, &authorized.claims)?;
    let storage = state.storage.clone();
    let segment = tokio::task::spawn_blocking(move || {
        storage.verified_revision_chunk_segment(locator, start, end)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    binary_response(
        request.method(),
        locator.size,
        start,
        end,
        partial,
        vec![segment],
    )
}

async fn delete_revision_chunk(
    State(state): State<AppState>,
    Path(chunk_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let chunk_id =
        Uuid::parse_str(&chunk_id).map_err(|_| AppError::BadRequest("invalid_chunk_id"))?;
    let authorized = authorize(&state, &headers, CapabilityOperation::DeleteRevisionChunk).await?;
    let locator = revision_chunk_locator(&authorized, chunk_id)?;
    consume_nonce(&state, &authorized, "revision_delete_chunk").await?;
    let storage = state.storage.clone();
    let operation_id = authorized.capability_id;
    tokio::task::spawn_blocking(move || storage.delete_revision_chunk(locator, operation_id))
        .await
        .map_err(|_| AppError::Internal)?
        .map_err(storage_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn read_revision_legacy_payload(
    State(state): State<AppState>,
    Path(payload_id): Path<String>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let payload_id =
        Uuid::parse_str(&payload_id).map_err(|_| AppError::BadRequest("invalid_payload_id"))?;
    let authorized = authorize(
        &state,
        &headers,
        CapabilityOperation::ReadRevisionLegacyPayload,
    )
    .await?;
    validate_revision_legacy_payload_capability(&authorized, payload_id)?;
    let payload = state
        .database
        .payload(authorized.tenant_id, payload_id)
        .await?;
    if payload.state != "referenced" || payload.backend_id != state.backend_id {
        return Err(AppError::Conflict("legacy_payload_not_referenced"));
    }
    if payload.drive_id != authorized.resource_id {
        return Err(AppError::Forbidden);
    }
    let size = u64::try_from(payload.size_bytes).map_err(|_| AppError::Internal)?;
    validate_exact_range(&authorized, size)?;
    let (start, end, partial) = requested_range(headers.get(RANGE), size, &authorized.claims)?;
    let storage = state.storage.clone();
    let payload_for_storage = payload.clone();
    let parts = if payload.layout == "chunked" {
        state
            .database
            .payload_parts_for_mount_read(authorized.tenant_id, payload_id)
            .await?
    } else {
        Vec::new()
    };
    let segments = tokio::task::spawn_blocking(move || {
        if payload_for_storage.layout == "whole" {
            storage.verified_whole_object_segment(&payload_for_storage, start, end)
        } else {
            let chunks = parts
                .iter()
                .map(mount_base_chunk)
                .collect::<Result<Vec<_>, _>>()?;
            storage.verified_chunked_object_segments(&payload_for_storage, &chunks, start, end)
        }
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    binary_response(request.method(), size, start, end, partial, segments)
}

fn binary_response(
    method: &Method,
    size: u64,
    start: u64,
    end: u64,
    partial: bool,
    segments: Vec<DownloadSegment>,
) -> Result<Response, AppError> {
    let response_length = if size == 0 { 0 } else { end - start + 1 };
    let mut builder = Response::builder()
        .status(if partial {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, response_length.to_string())
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff");
    if partial {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }
    let body = if *method == Method::HEAD || size == 0 {
        Body::empty()
    } else {
        Body::from_stream(mount_download_stream(segments))
    };
    builder.body(body).map_err(|_| AppError::Internal)
}

async fn mount_download(
    State(state): State<AppState>,
    Path(handle_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let handle_id =
        Uuid::parse_str(&handle_id).map_err(|_| AppError::BadRequest("invalid_handle_id"))?;
    let authorized = authorize_mount_read(&state, &headers)?;
    if authorized.fence.handle_id != handle_id
        || parse_required_uuid(&authorized.claims.grant_id)? != handle_id
    {
        return Err(AppError::Forbidden);
    }
    consume_mount_nonce(
        &state,
        authorized.fence.tenant_id,
        &authorized.claims,
        "mount_read",
    )
    .await?;
    state
        .database
        .admit_mount_read_capability(&authorized.fence)
        .await?;
    let payload = state
        .database
        .payload_for_node(
            authorized.fence.tenant_id,
            authorized.fence.node_id,
            Some(authorized.fence.version_id),
        )
        .await?;
    if payload.state != "referenced"
        || payload.backend_id != state.backend_id
        || payload.drive_id != authorized.fence.drive_id
    {
        return Err(AppError::Conflict("payload_not_referenced"));
    }
    let size = u64::try_from(payload.size_bytes).map_err(|_| AppError::Internal)?;
    let start = authorized.claims.range_start;
    if size == 0 || start >= size {
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, "0")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .body(Body::empty())
            .map_err(|_| AppError::Internal);
    }
    let end = authorized.claims.range_end.min(size - 1);
    let parts = state
        .database
        .payload_parts_for_mount_read(authorized.fence.tenant_id, payload.payload_id)
        .await?;
    let storage = state.storage.clone();
    let payload_for_storage = payload.clone();
    let segments = tokio::task::spawn_blocking(move || {
        if payload_for_storage.layout == "whole" {
            storage.verified_whole_object_segment(&payload_for_storage, start, end)
        } else {
            let chunks = parts
                .iter()
                .map(mount_base_chunk)
                .collect::<Result<Vec<_>, _>>()?;
            storage.verified_chunked_object_segments(&payload_for_storage, &chunks, start, end)
        }
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    // Recheck after resolving physical payload metadata so generation changes
    // during admission fail before the first response byte is emitted.
    state
        .database
        .admit_mount_read_capability(&authorized.fence)
        .await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, (end - start + 1).to_string())
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from_stream(mount_download_stream(segments)))
        .map_err(|_| AppError::Internal)
}

async fn mount_write_data(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<MountWriteResult>, AppError> {
    reject_unsigned_mount_mode(&headers)?;
    require_mount_binary_content_type(&headers)?;
    mutate_mount_range(
        state,
        write_session_id,
        headers,
        body,
        MountStorageCapabilityUse::WriteData,
        MountWriteRangeOperation::WriteData,
        MountIoOperation::WriteData,
    )
    .await
}

async fn deallocate_mount_write(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<MountWriteResult>, AppError> {
    reject_unsigned_mount_mode(&headers)?;
    mutate_mount_range(
        state,
        write_session_id,
        headers,
        body,
        MountStorageCapabilityUse::Deallocate,
        MountWriteRangeOperation::HoleDeallocate,
        MountIoOperation::HoleDeallocate,
    )
    .await
}

async fn allocate_mount_write(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<MountWriteResult>, AppError> {
    reject_unsigned_mount_mode(&headers)?;
    mutate_mount_range(
        state,
        write_session_id,
        headers,
        body,
        MountStorageCapabilityUse::Allocate,
        MountWriteRangeOperation::Allocate,
        MountIoOperation::Allocate,
    )
    .await
}

async fn mutate_mount_range(
    state: AppState,
    write_session_id: String,
    headers: HeaderMap,
    body: Body,
    purpose: MountStorageCapabilityUse,
    operation: MountWriteRangeOperation,
    io_operation: MountIoOperation,
) -> Result<Json<MountWriteResult>, AppError> {
    let write_session_id = Uuid::parse_str(&write_session_id)
        .map_err(|_| AppError::BadRequest("invalid_write_session_id"))?;
    let authorized = authorize_mount_write(&state, &headers, purpose)?;
    if authorized.fence.write_session_id != write_session_id {
        return Err(AppError::Forbidden);
    }
    let length = mount_claim_range_length(&authorized.claims)?;
    if length > MAX_MOUNT_WRITE_BYTES {
        return Err(AppError::BadRequest("mount_write_too_large"));
    }
    let io_request = MountIoRequest::from_claims(&authorized.claims, io_operation)?;
    let capability_id = io_request.capability_id;
    let range_start = io_request.range_start.ok_or(AppError::Forbidden)?;
    let range_end = io_request.range_end.ok_or(AppError::Forbidden)?;
    let lookup = state
        .database
        .lookup_mount_io_completion(&io_request.input(&authorized))
        .await?;
    let initial_admission = match &lookup {
        MountIoLookup::Absent => {
            let admission = state
                .database
                .admit_mount_write_range(
                    &authorized.fence,
                    capability_id,
                    operation,
                    range_start,
                    range_end,
                )
                .await?;
            validate_mount_range_admission(
                &state,
                &authorized,
                &admission,
                operation,
                range_start,
                range_end,
            )?;
            Some(admission)
        }
        MountIoLookup::Pending | MountIoLookup::Completed(_) => None,
    };
    let bytes = if operation == MountWriteRangeOperation::WriteData {
        let bytes = read_mount_body_exact(body, length).await?;
        validate_mount_write_body_digest(&authorized.claims, &bytes)?;
        bytes
    } else {
        read_mount_body_exact(body, 0).await?;
        Vec::new()
    };
    if let MountIoLookup::Completed(completion) = lookup {
        return completed_mount_range_result(write_session_id, completion);
    }
    let initial_record = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            return completed_mount_range_result(write_session_id, completion);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &initial_record)?;
    let initial_admission = if let Some(admission) = initial_admission {
        admission
    } else {
        let admission = state
            .database
            .admit_mount_write_range(
                &authorized.fence,
                capability_id,
                operation,
                range_start,
                range_end,
            )
            .await?;
        validate_mount_range_admission(
            &state,
            &authorized,
            &admission,
            operation,
            range_start,
            range_end,
        )?;
        admission
    };
    let cow_lock = acquire_mount_cow_lock(state.storage.clone(), write_session_id).await?;
    // Admission is deliberately repeated after waiting for the cross-process
    // COW lock. A capability that became stale while another process flushed,
    // finalized, or aborted must fail before this process mutates bytes.
    match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => {
            validate_mount_storage_record(&state, &authorized, &record)?;
        }
        MountIoAdmission::Completed(completion) => {
            drop(cow_lock);
            return completed_mount_range_result(write_session_id, completion);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            drop(cow_lock);
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    }
    let record = state
        .database
        .admit_mount_write_range(
            &authorized.fence,
            capability_id,
            operation,
            range_start,
            range_end,
        )
        .await?;
    validate_mount_range_admission(
        &state,
        &authorized,
        &record,
        operation,
        range_start,
        range_end,
    )?;
    validate_mount_range_readmission(&initial_admission, &record)?;
    let storage = state.storage.clone();
    let chunk_size = state.chunk_size;
    let range_start = authorized.claims.range_start;
    let expected_logical_size = u64::try_from(record.resulting_logical_size)
        .map_err(|_| AppError::Conflict("mount_write_size_invalid"))?;
    let stable_operation_id = record.operation_id;
    let storage_record = record.storage;
    let (cow_lock, result) = tokio::task::spawn_blocking(move || {
        storage.recover_cow_under_lock(write_session_id)?;
        ensure_mount_cow(&storage, &storage_record, chunk_size)?;
        let current_size = storage.cow_logical_size(write_session_id, chunk_size)?;
        let planned_size = match operation {
            MountWriteRangeOperation::WriteData | MountWriteRangeOperation::Allocate => {
                current_size.max(
                    range_start
                        .checked_add(length)
                        .ok_or(StorageError::StateConflict)?,
                )
            }
            MountWriteRangeOperation::HoleDeallocate => current_size,
            MountWriteRangeOperation::SeekData | MountWriteRangeOperation::SeekHole => {
                return Err(StorageError::StateConflict);
            }
        };
        if planned_size != expected_logical_size {
            return Err(StorageError::StateConflict);
        }
        let result = match operation {
            MountWriteRangeOperation::WriteData => storage.write_cow_at(
                write_session_id,
                stable_operation_id,
                chunk_size,
                current_size,
                range_start,
                &bytes,
            ),
            MountWriteRangeOperation::HoleDeallocate => storage.deallocate_cow_range(
                write_session_id,
                stable_operation_id,
                chunk_size,
                current_size,
                range_start,
                length,
            ),
            MountWriteRangeOperation::Allocate => storage.allocate_cow_range(
                write_session_id,
                stable_operation_id,
                chunk_size,
                current_size,
                range_start,
                length,
            ),
            MountWriteRangeOperation::SeekData | MountWriteRangeOperation::SeekHole => {
                Err(StorageError::StateConflict)
            }
        }?;
        if result.logical_size != expected_logical_size {
            return Err(StorageError::StateConflict);
        }
        Ok::<_, StorageError>((cow_lock, result))
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let completion = MountIoCompletion::RangeMutation {
        logical_size_bytes: i64::try_from(result.logical_size)
            .map_err(|_| AppError::Conflict("mount_write_too_large"))?,
        reservation_delta_bytes: i64::try_from(result.reservation_delta)
            .map_err(|_| AppError::Conflict("mount_write_too_large"))?,
    };
    let completion = state
        .database
        .complete_mount_io_operation(&io_request.input(&authorized), &completion)
        .await?;
    drop(cow_lock);
    completed_mount_range_result(write_session_id, completion)
}

async fn seek_mount_data(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<MountSeekResult>, AppError> {
    reject_unsigned_mount_mode(&headers)?;
    seek_mount_range(
        state,
        write_session_id,
        headers,
        body,
        MountStorageCapabilityUse::SeekData,
        MountWriteRangeOperation::SeekData,
        MountIoOperation::SeekData,
    )
    .await
}

async fn seek_mount_hole(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<MountSeekResult>, AppError> {
    reject_unsigned_mount_mode(&headers)?;
    seek_mount_range(
        state,
        write_session_id,
        headers,
        body,
        MountStorageCapabilityUse::SeekHole,
        MountWriteRangeOperation::SeekHole,
        MountIoOperation::SeekHole,
    )
    .await
}

async fn seek_mount_range(
    state: AppState,
    write_session_id: String,
    headers: HeaderMap,
    body: Body,
    purpose: MountStorageCapabilityUse,
    operation: MountWriteRangeOperation,
    io_operation: MountIoOperation,
) -> Result<Json<MountSeekResult>, AppError> {
    let write_session_id = Uuid::parse_str(&write_session_id)
        .map_err(|_| AppError::BadRequest("invalid_write_session_id"))?;
    let authorized = authorize_mount_write(&state, &headers, purpose)?;
    if authorized.fence.write_session_id != write_session_id
        || authorized.claims.range_start != authorized.claims.range_end
    {
        return Err(AppError::Forbidden);
    }
    let io_request = MountIoRequest::from_claims(&authorized.claims, io_operation)?;
    let capability_id = io_request.capability_id;
    let range_start = io_request.range_start.ok_or(AppError::Forbidden)?;
    let lookup = state
        .database
        .lookup_mount_io_completion(&io_request.input(&authorized))
        .await?;
    let initial_admission = match &lookup {
        MountIoLookup::Absent => {
            let admission = state
                .database
                .admit_mount_write_range(
                    &authorized.fence,
                    capability_id,
                    operation,
                    range_start,
                    range_start,
                )
                .await?;
            validate_mount_range_admission(
                &state,
                &authorized,
                &admission,
                operation,
                range_start,
                range_start,
            )?;
            Some(admission)
        }
        MountIoLookup::Pending | MountIoLookup::Completed(_) => None,
    };
    read_mount_body_exact(body, 0).await?;
    if let MountIoLookup::Completed(completion) = lookup {
        return completed_mount_seek_result(completion);
    }
    let initial_record = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            return completed_mount_seek_result(completion);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &initial_record)?;
    let initial_admission = if let Some(admission) = initial_admission {
        admission
    } else {
        let admission = state
            .database
            .admit_mount_write_range(
                &authorized.fence,
                capability_id,
                operation,
                range_start,
                range_start,
            )
            .await?;
        validate_mount_range_admission(
            &state,
            &authorized,
            &admission,
            operation,
            range_start,
            range_start,
        )?;
        admission
    };
    let cow_lock = acquire_mount_cow_lock(state.storage.clone(), write_session_id).await?;
    match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => {
            validate_mount_storage_record(&state, &authorized, &record)?;
        }
        MountIoAdmission::Completed(completion) => {
            drop(cow_lock);
            return completed_mount_seek_result(completion);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            drop(cow_lock);
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    }
    let admitted = state
        .database
        .admit_mount_write_range(
            &authorized.fence,
            capability_id,
            operation,
            range_start,
            range_start,
        )
        .await?;
    validate_mount_range_admission(
        &state,
        &authorized,
        &admitted,
        operation,
        range_start,
        range_start,
    )?;
    validate_mount_range_readmission(&initial_admission, &admitted)?;
    let storage = state.storage.clone();
    let chunk_size = state.chunk_size;
    let logical_size = u64::try_from(admitted.resulting_logical_size)
        .map_err(|_| AppError::Conflict("mount_write_size_invalid"))?;
    let storage_record = admitted.storage;
    let offset = authorized.claims.range_start;
    let (cow_lock, result) = tokio::task::spawn_blocking(move || {
        storage.recover_cow_under_lock(write_session_id)?;
        ensure_mount_cow(&storage, &storage_record, chunk_size)?;
        if storage.cow_logical_size(write_session_id, chunk_size)? != logical_size {
            return Err(StorageError::StateConflict);
        }
        let result = match operation {
            MountWriteRangeOperation::SeekData => {
                storage.cow_next_data(write_session_id, chunk_size, logical_size, offset)
            }
            MountWriteRangeOperation::SeekHole => {
                storage.cow_next_hole(write_session_id, chunk_size, logical_size, offset)
            }
            _ => Err(StorageError::StateConflict),
        }?;
        Ok::<_, StorageError>((cow_lock, result))
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let completion = MountIoCompletion::Seek {
        offset: result
            .map(|offset| i64::try_from(offset).map_err(|_| AppError::Internal))
            .transpose()?,
    };
    let completion = state
        .database
        .complete_mount_io_operation(&io_request.input(&authorized), &completion)
        .await?;
    drop(cow_lock);
    completed_mount_seek_result(completion)
}

async fn flush_mount_write(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MountManifestResult>, AppError> {
    let write_session_id = Uuid::parse_str(&write_session_id)
        .map_err(|_| AppError::BadRequest("invalid_write_session_id"))?;
    let authorized = authorize_mount_write(&state, &headers, MountStorageCapabilityUse::Flush)?;
    if authorized.fence.write_session_id != write_session_id {
        return Err(AppError::Forbidden);
    }
    let io_request = MountIoRequest::from_claims(&authorized.claims, MountIoOperation::Flush)?;
    let record = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            return completed_mount_manifest_result(write_session_id, completion, false);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &record)?;
    let cow_lock = acquire_mount_cow_lock(state.storage.clone(), write_session_id).await?;
    let record = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            drop(cow_lock);
            return completed_mount_manifest_result(write_session_id, completion, false);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            drop(cow_lock);
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &record)?;
    let storage = state.storage.clone();
    let chunk_size = state.chunk_size;
    let storage_record = record;
    let (cow_lock, manifest) = tokio::task::spawn_blocking(move || {
        storage.recover_cow_under_lock(write_session_id)?;
        ensure_mount_cow(&storage, &storage_record, chunk_size)?;
        storage.sync_cow(write_session_id)?;
        let logical_size = storage.cow_logical_size(write_session_id, chunk_size)?;
        let manifest = storage.cow_manifest(write_session_id, chunk_size, logical_size)?;
        Ok::<_, StorageError>((cow_lock, manifest))
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let evidence = mount_chunk_evidence(&manifest)?;
    let logical_size_bytes = i64::try_from(manifest.logical_size)
        .map_err(|_| AppError::Conflict("mount_write_too_large"))?;
    let completion = state
        .database
        .complete_mount_io_flush(
            &io_request.input(&authorized),
            logical_size_bytes,
            &manifest.digest,
            &evidence,
        )
        .await?;
    drop(cow_lock);
    completed_mount_manifest_result(write_session_id, completion, false)
}

async fn finalize_mount_write(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MountManifestResult>, AppError> {
    let write_session_id = Uuid::parse_str(&write_session_id)
        .map_err(|_| AppError::BadRequest("invalid_write_session_id"))?;
    let authorized = authorize_mount_write(&state, &headers, MountStorageCapabilityUse::Finalize)?;
    if authorized.fence.write_session_id != write_session_id {
        return Err(AppError::Forbidden);
    }
    let io_request = MountIoRequest::from_claims(&authorized.claims, MountIoOperation::Finalize)?;
    let record = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            let cow_lock = acquire_mount_cow_lock(state.storage.clone(), write_session_id).await?;
            cleanup_mount_write_lock(
                &state,
                authorized.fence.tenant_id,
                write_session_id,
                None,
                cow_lock,
            )
            .await?;
            return completed_mount_manifest_result(write_session_id, completion, true);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &record)?;
    let cow_lock = acquire_mount_cow_lock(state.storage.clone(), write_session_id).await?;
    let record = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            cleanup_mount_write_lock(
                &state,
                authorized.fence.tenant_id,
                write_session_id,
                Some(record.staging_payload.payload_id),
                cow_lock,
            )
            .await?;
            return completed_mount_manifest_result(write_session_id, completion, true);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            drop(cow_lock);
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &record)?;
    let storage = state.storage.clone();
    let chunk_size = state.chunk_size;
    let staging_payload = record.staging_payload.clone();
    let staging_payload_id = staging_payload.payload_id;
    let logical_size = u64::try_from(record.logical_size_bytes)
        .map_err(|_| AppError::Conflict("mount_write_size_invalid"))?;
    let storage_record = record;
    let (cow_lock, manifest) = tokio::task::spawn_blocking(move || {
        storage.recover_cow_under_lock(write_session_id)?;
        ensure_mount_cow(&storage, &storage_record, chunk_size)?;
        let manifest = storage.cow_staging_manifest(
            write_session_id,
            &staging_payload,
            chunk_size,
            logical_size,
        )?;
        let mut expected_payload = staging_payload;
        expected_payload.size_bytes =
            i64::try_from(manifest.logical_size).map_err(|_| StorageError::StateConflict)?;
        expected_payload.blake3 = Some(manifest.digest.to_vec());
        storage.publish_cow(write_session_id, &expected_payload, chunk_size, &manifest)?;
        Ok::<_, StorageError>((cow_lock, manifest))
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let evidence = mount_chunk_evidence(&manifest)?;
    let logical_size_bytes = i64::try_from(manifest.logical_size)
        .map_err(|_| AppError::Conflict("mount_write_too_large"))?;
    let completion = state
        .database
        .complete_mount_io_finalize(
            &io_request.input(&authorized),
            logical_size_bytes,
            &manifest.digest,
            &evidence,
        )
        .await?;
    cleanup_mount_write_lock(
        &state,
        authorized.fence.tenant_id,
        write_session_id,
        Some(staging_payload_id),
        cow_lock,
    )
    .await?;
    completed_mount_manifest_result(write_session_id, completion, true)
}

async fn abort_mount_write(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MountStagingResult>, AppError> {
    let write_session_id = Uuid::parse_str(&write_session_id)
        .map_err(|_| AppError::BadRequest("invalid_write_session_id"))?;
    let authorized = authorize_mount_write(&state, &headers, MountStorageCapabilityUse::Abort)?;
    if authorized.fence.write_session_id != write_session_id {
        return Err(AppError::Forbidden);
    }
    let io_request = MountIoRequest::from_claims(&authorized.claims, MountIoOperation::Abort)?;
    let admitted = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            return completed_mount_staging_result(write_session_id, completion, false);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &admitted)?;
    let cow_lock = acquire_mount_cow_lock(state.storage.clone(), write_session_id).await?;
    let admitted = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            drop(cow_lock);
            return completed_mount_staging_result(write_session_id, completion, false);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            drop(cow_lock);
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &admitted)?;
    let storage = state.storage.clone();
    let (cow_lock, ()) = tokio::task::spawn_blocking(move || {
        storage.abort_cow(write_session_id)?;
        Ok::<_, StorageError>((cow_lock, ()))
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let completion = state
        .database
        .complete_mount_io_abort(&io_request.input(&authorized))
        .await?;
    remove_mount_cow_lock(state.storage.clone(), cow_lock).await?;
    completed_mount_staging_result(write_session_id, completion, false)
}

async fn delete_mount_staging(
    State(state): State<AppState>,
    Path(write_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MountStagingResult>, AppError> {
    let write_session_id = Uuid::parse_str(&write_session_id)
        .map_err(|_| AppError::BadRequest("invalid_write_session_id"))?;
    let authorized =
        authorize_mount_write(&state, &headers, MountStorageCapabilityUse::DeleteStaging)?;
    if authorized.fence.write_session_id != write_session_id {
        return Err(AppError::Forbidden);
    }
    let io_request =
        MountIoRequest::from_claims(&authorized.claims, MountIoOperation::DeleteStaging)?;
    let admitted = match state
        .database
        .begin_mount_io_operation(&io_request.input(&authorized))
        .await?
    {
        MountIoAdmission::Execute(record) => record,
        MountIoAdmission::Completed(completion) => {
            return completed_mount_staging_result(write_session_id, completion, true);
        }
        MountIoAdmission::CleanupRequired(cleanup) => {
            recover_expired_mount_io(&state, &authorized, cleanup).await?;
            return Err(AppError::Conflict("mount_io_recovered"));
        }
    };
    validate_mount_storage_record(&state, &authorized, &admitted)?;
    let cleanup = state
        .database
        .claim_mount_staging_cleanup(
            authorized.fence.tenant_id,
            admitted.staging_payload.backend_id,
            write_session_id,
            state.worker_id,
        )
        .await?;
    validate_mount_cleanup_job(
        &ExpectedMountCleanupJob {
            backend_id: state.backend_id,
            worker_id: state.worker_id,
            tenant_id: authorized.fence.tenant_id,
            write_session_id,
            payload: &admitted.staging_payload,
            source_nonce_digest: Some(io_request.nonce_digest),
            completion_kind: "delete_staging",
        },
        &cleanup,
    )?;
    cleanup_mount_staging_job(&state, cleanup).await?;
    let MountIoLookup::Completed(completion) = state
        .database
        .lookup_mount_io_completion(&io_request.input(&authorized))
        .await?
    else {
        return Err(AppError::Internal);
    };
    completed_mount_staging_result(write_session_id, completion, true)
}

async fn read_document_version(
    State(state): State<AppState>,
    Path((session_id, version_id)): Path<(String, String)>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let session_id =
        Uuid::parse_str(&session_id).map_err(|_| AppError::BadRequest("invalid_session_id"))?;
    let version_id =
        Uuid::parse_str(&version_id).map_err(|_| AppError::BadRequest("invalid_version_id"))?;
    let authorized = authorize(&state, &headers, CapabilityOperation::ReadDocumentVersion).await?;
    let row = sqlx::query(
        "SELECT s.drive_id,s.node_id,s.fencing_token,v.payload_id,v.size_bytes \
         FROM filebelt_document.sessions s JOIN file_versions v ON v.tenant_id=s.tenant_id \
           AND v.node_id=s.node_id AND v.id=$3 WHERE s.tenant_id=$1 AND s.id=$2 \
           AND s.state IN ('active','draining') AND s.absolute_expires_at>clock_timestamp()",
    )
    .bind(authorized.tenant_id)
    .bind(session_id)
    .bind(version_id)
    .fetch_optional(state.database.pool())
    .await
    .map_err(|_| AppError::Internal)?
    .ok_or(AppError::NotFound("document_version_not_found"))?;
    let payload_id: Uuid = row.get("payload_id");
    let drive_id: Uuid = row.get("drive_id");
    if parse_required_uuid(&authorized.claims.upload_id)? != session_id
        || parse_required_uuid(&authorized.claims.grant_id)? != version_id
        || parse_required_uuid(&authorized.claims.payload_id)? != payload_id
        || authorized.resource_id != row.get::<Uuid, _>("node_id")
        || i64::try_from(authorized.claims.fencing_token).map_err(|_| AppError::Forbidden)?
            != row.get::<i64, _>("fencing_token")
    {
        return Err(AppError::Forbidden);
    }
    check_generations(&state, &authorized, drive_id).await?;
    let payload = state
        .database
        .payload(authorized.tenant_id, payload_id)
        .await?;
    if !matches!(payload.state.as_str(), "finalized" | "referenced") {
        return Err(AppError::Conflict("payload_not_finalized"));
    }
    let size = u64::try_from(payload.size_bytes).map_err(|_| AppError::Internal)?;
    let (start, end, partial) = requested_range(headers.get(RANGE), size, &authorized.claims)?;
    let storage = state.storage.clone();
    let segments = tokio::task::spawn_blocking(move || {
        storage.verified_whole_object_segment(&payload, start, end)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    check_generations(&state, &authorized, drive_id).await?;
    let length = if size == 0 { 0 } else { end - start + 1 };
    let mut builder = Response::builder()
        .status(if partial {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, length.to_string())
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff");
    if partial {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }
    let body = if request.method() == Method::HEAD || size == 0 {
        Body::empty()
    } else {
        Body::from_stream(download_stream(
            state.database.clone(),
            authorized,
            drive_id,
            segments,
            state.generation_recheck,
        ))
    };
    builder.body(body).map_err(|_| AppError::Internal)
}

async fn write_document_revision(
    State(state): State<AppState>,
    Path(revision_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<DocumentRevisionResult>, AppError> {
    let revision_id =
        Uuid::parse_str(&revision_id).map_err(|_| AppError::BadRequest("invalid_revision_id"))?;
    let authorized =
        authorize(&state, &headers, CapabilityOperation::WriteDocumentRevision).await?;
    let context = state
        .database
        .document_revision_io_context(authorized.tenant_id, revision_id)
        .await?;
    validate_document_revision_capability(&authorized, revision_id, &context)?;
    if context.revision.state != "staging" {
        return Err(AppError::Conflict("document_revision_not_staging"));
    }
    let expected =
        u64::try_from(context.revision.reserved_bytes).map_err(|_| AppError::Internal)?;
    validate_exact_range(&authorized, expected)?;
    if let Some(length) = headers.get(CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(AppError::BadRequest("invalid_content_length"))?;
        if length != expected {
            return Err(AppError::Conflict("document_revision_size_mismatch"));
        }
    }
    check_generations(&state, &authorized, context.session.drive_id).await?;
    consume_nonce(&state, &authorized, "write_document_revision").await?;
    let temporary = state
        .storage
        .staging_temporary_path(context.revision.id, authorized.capability_id)
        .map_err(storage_error)?;
    let (size, digest) = write_body(body, &temporary, expected).await?;
    let storage = state.storage.clone();
    let locator = context.revision.payload_id.ok_or(AppError::Internal)?;
    let payload = state
        .database
        .payload(authorized.tenant_id, locator)
        .await?;
    let publish_path = temporary.clone();
    tokio::task::spawn_blocking(move || {
        storage.publish_staging_part(&publish_path, payload.locator, size, &digest)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    Ok(Json(DocumentRevisionResult {
        revision_id,
        payload_id: payload.payload_id,
        size_bytes: size,
        blake3: hex_digest(&digest),
        state: "staged",
    }))
}

async fn finalize_document_revision(
    State(state): State<AppState>,
    Path(revision_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DocumentRevisionResult>, AppError> {
    let revision_id =
        Uuid::parse_str(&revision_id).map_err(|_| AppError::BadRequest("invalid_revision_id"))?;
    let authorized = authorize(
        &state,
        &headers,
        CapabilityOperation::FinalizeDocumentRevision,
    )
    .await?;
    let context = state
        .database
        .document_revision_io_context(authorized.tenant_id, revision_id)
        .await?;
    validate_document_revision_capability(&authorized, revision_id, &context)?;
    if context.revision.state != "staging" {
        return Err(AppError::Conflict("document_revision_not_staging"));
    }
    let expected =
        u64::try_from(context.revision.reserved_bytes).map_err(|_| AppError::Internal)?;
    validate_exact_range(&authorized, expected)?;
    check_generations(&state, &authorized, context.session.drive_id).await?;
    consume_nonce(&state, &authorized, "finalize_document_revision").await?;
    let payload_id = context.revision.payload_id.ok_or(AppError::Internal)?;
    let payload = state
        .database
        .payload(authorized.tenant_id, payload_id)
        .await?;
    let storage = state.storage.clone();
    let staged = tokio::task::spawn_blocking(move || {
        storage.verify_staging_object(payload.locator, expected)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let storage = state.storage.clone();
    let payload_for_finalize = payload.clone();
    let finalized = tokio::task::spawn_blocking(move || {
        storage.finalize_whole_object(&payload_for_finalize, staged.size, &staged.digest)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    check_generations(&state, &authorized, context.session.drive_id).await?;
    let revision = match state
        .database
        .finalize_document_revision(
            authorized.tenant_id,
            revision_id,
            context.session.fencing_token,
            i64::try_from(finalized.size).map_err(|_| AppError::Internal)?,
            &finalized.digest,
            context
                .revision
                .media_type
                .as_deref()
                .ok_or(AppError::BadRequest("document_media_type_missing"))?,
        )
        .await
    {
        Ok(revision) => revision,
        Err(DatabaseError::StaleGeneration) => {
            return Err(AppError::Forbidden);
        }
        Err(error) => return Err(error.into()),
    };
    let storage = state.storage.clone();
    if let Err(error) =
        tokio::task::spawn_blocking(move || storage.remove_staging_locator(payload.locator))
            .await
            .map_err(|_| StorageError::Join)
            .and_then(|result| result)
    {
        warn!(%revision_id, %error, "document staging cleanup deferred");
    }
    Ok(Json(DocumentRevisionResult {
        revision_id,
        payload_id,
        size_bytes: finalized.size,
        blake3: hex_digest(&finalized.digest),
        state: if revision.state == "checkpoint" {
            "checkpoint"
        } else {
            "durable"
        },
    }))
}

fn validate_document_revision_capability(
    authorized: &AuthorizedCapability,
    revision_id: Uuid,
    context: &filebelt_database::document::DocumentIoContext,
) -> Result<(), AppError> {
    let payload_id = context.revision.payload_id.ok_or(AppError::Forbidden)?;
    if parse_required_uuid(&authorized.claims.grant_id)? != revision_id
        || parse_required_uuid(&authorized.claims.upload_id)? != context.session.id
        || parse_required_uuid(&authorized.claims.payload_id)? != payload_id
        || authorized.resource_id != context.session.node_id
        || authorized.principal_id != context.participant.user_principal_id
        || authorized.session_id != context.participant.api_session_id
        || i64::try_from(authorized.claims.fencing_token).map_err(|_| AppError::Forbidden)?
            != context.session.fencing_token
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn write_collaboration_object(
    State(state): State<AppState>,
    Path(object_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<CollaborationObjectResult>, AppError> {
    let object_id =
        Uuid::parse_str(&object_id).map_err(|_| AppError::BadRequest("invalid_object_id"))?;
    let authorized = authorize(
        &state,
        &headers,
        CapabilityOperation::WriteCollaborationObject,
    )
    .await?;
    let object = state
        .database
        .collaboration_object(authorized.tenant_id, object_id)
        .await?;
    validate_collaboration_capability(&authorized, &object, state.backend_id)?;
    check_generations(&state, &authorized, object.drive_id).await?;
    if object.state != "staging" {
        return Err(AppError::Conflict("collaboration_object_not_staging"));
    }
    let expected_size = u64::try_from(object.reserved_bytes).map_err(|_| AppError::Internal)?;
    validate_exact_range(&authorized, expected_size)?;
    if let Some(length) = headers.get(CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(AppError::BadRequest("invalid_content_length"))?;
        if length != expected_size {
            return Err(AppError::Conflict("object_size_mismatch"));
        }
    }
    consume_nonce(&state, &authorized, "write_collaboration_object").await?;
    let temporary = state
        .storage
        .staging_temporary_path(object.payload_locator, authorized.capability_id)
        .map_err(storage_error)?;
    let (size, digest) = write_body(body, &temporary, expected_size).await?;
    let storage = state.storage.clone();
    let publish_path = temporary.clone();
    tokio::task::spawn_blocking(move || {
        storage.publish_staging_part(&publish_path, object.payload_locator, size, &digest)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    Ok(Json(CollaborationObjectResult {
        object_id,
        payload_id: object.payload_id,
        size_bytes: size,
        blake3: hex_digest(&digest),
        state: "staged",
    }))
}

async fn finalize_collaboration_object(
    State(state): State<AppState>,
    Path(object_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CollaborationObjectResult>, AppError> {
    let object_id =
        Uuid::parse_str(&object_id).map_err(|_| AppError::BadRequest("invalid_object_id"))?;
    let authorized = authorize(
        &state,
        &headers,
        CapabilityOperation::FinalizeCollaborationObject,
    )
    .await?;
    let object = state
        .database
        .collaboration_object(authorized.tenant_id, object_id)
        .await?;
    validate_collaboration_capability(&authorized, &object, state.backend_id)?;
    check_generations(&state, &authorized, object.drive_id).await?;
    let expected_size = u64::try_from(object.reserved_bytes).map_err(|_| AppError::Internal)?;
    validate_exact_range(&authorized, expected_size)?;
    consume_nonce(&state, &authorized, "finalize_collaboration_object").await?;
    let verify_storage = state.storage.clone();
    let staged = tokio::task::spawn_blocking(move || {
        verify_storage.verify_staging_object(object.payload_locator, expected_size)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let payload = state
        .database
        .payload(authorized.tenant_id, object.payload_id)
        .await?;
    let storage = state.storage.clone();
    let finalized = tokio::task::spawn_blocking(move || {
        storage.finalize_whole_object(&payload, staged.size, &staged.digest)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    check_generations(&state, &authorized, object.drive_id).await?;
    state
        .database
        .collaboration_finalize_object(
            authorized.tenant_id,
            object_id,
            object.fencing_token,
            CollaborationAuthorizationContext {
                principal_id: authorized.principal_id,
                session_id: authorized.session_id,
                drive_id: object.drive_id,
                node_id: authorized.resource_id,
                generations: CollaborationAuthorizationGenerations {
                    membership: i64::try_from(authorized.claims.membership_generation)
                        .map_err(|_| AppError::Unauthorized)?,
                    drive_acl: i64::try_from(authorized.claims.drive_acl_generation)
                        .map_err(|_| AppError::Unauthorized)?,
                    namespace: i64::try_from(authorized.claims.namespace_generation)
                        .map_err(|_| AppError::Unauthorized)?,
                    resource_acl: i64::try_from(authorized.claims.resource_acl_generation)
                        .map_err(|_| AppError::Unauthorized)?,
                },
            },
            i64::try_from(finalized.size).map_err(|_| AppError::Internal)?,
            &finalized.digest,
        )
        .await?;
    let storage = state.storage.clone();
    if let Err(error) =
        tokio::task::spawn_blocking(move || storage.remove_staging_locator(object.payload_locator))
            .await
            .map_err(|_| StorageError::Join)
            .and_then(|result| result)
    {
        warn!(%object_id, %error, "collaboration staging cleanup deferred");
    }
    Ok(Json(CollaborationObjectResult {
        object_id,
        payload_id: object.payload_id,
        size_bytes: finalized.size,
        blake3: hex_digest(&finalized.digest),
        state: "durable",
    }))
}

async fn read_collaboration_object(
    State(state): State<AppState>,
    Path(object_id): Path<String>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let object_id =
        Uuid::parse_str(&object_id).map_err(|_| AppError::BadRequest("invalid_object_id"))?;
    let authorized = authorize(
        &state,
        &headers,
        CapabilityOperation::ReadCollaborationObject,
    )
    .await?;
    let object = state
        .database
        .collaboration_object(authorized.tenant_id, object_id)
        .await?;
    validate_collaboration_capability(&authorized, &object, state.backend_id)?;
    if object.state != "durable" {
        return Err(AppError::Conflict("collaboration_object_not_durable"));
    }
    check_generations(&state, &authorized, object.drive_id).await?;
    let payload = state
        .database
        .payload(authorized.tenant_id, object.payload_id)
        .await?;
    if !matches!(payload.state.as_str(), "finalized" | "referenced") {
        return Err(AppError::Conflict("payload_not_finalized"));
    }
    let size = u64::try_from(payload.size_bytes).map_err(|_| AppError::Internal)?;
    let (start, end, partial) = requested_range(headers.get(RANGE), size, &authorized.claims)?;
    let storage = state.storage.clone();
    let segments = tokio::task::spawn_blocking(move || {
        storage.verified_whole_object_segment(&payload, start, end)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)?;
    let response_length = if size == 0 { 0 } else { end - start + 1 };
    let mut builder = Response::builder()
        .status(if partial {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, response_length.to_string())
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff");
    if partial {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }
    let body = if request.method() == Method::HEAD || size == 0 {
        Body::empty()
    } else {
        Body::from_stream(download_stream(
            state.database.clone(),
            authorized,
            object.drive_id,
            segments,
            state.generation_recheck,
        ))
    };
    builder.body(body).map_err(|_| AppError::Internal)
}

fn download_stream(
    database: Database,
    authorized: AuthorizedCapability,
    drive_id: Uuid,
    segments: Vec<DownloadSegment>,
    recheck: Duration,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
    struct StreamState {
        database: Database,
        authorized: AuthorizedCapability,
        drive_id: Uuid,
        segments: VecDeque<DownloadSegment>,
        current: Option<(tokio::fs::File, u64)>,
        last_check: Instant,
        recheck: Duration,
        finished: bool,
    }
    futures_util::stream::unfold(
        StreamState {
            database,
            authorized,
            drive_id,
            segments: segments.into(),
            current: None,
            last_check: Instant::now(),
            recheck,
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }
            if state.last_check.elapsed() >= state.recheck {
                match generations_match(&state.database, &state.authorized, state.drive_id).await {
                    Ok(true) => state.last_check = Instant::now(),
                    Ok(false) | Err(_) => {
                        state.finished = true;
                        return Some((Err(io::Error::other("authorization changed")), state));
                    }
                }
            }
            if state.current.is_none() {
                let segment = state.segments.pop_front()?;
                match tokio::fs::File::open(&segment.path).await {
                    Ok(mut file) => {
                        if let Err(error) = file.seek(io::SeekFrom::Start(segment.offset)).await {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                        state.current = Some((file, segment.length));
                    }
                    Err(error) => {
                        state.finished = true;
                        return Some((Err(error), state));
                    }
                }
            }
            let (file, remaining) = state.current.as_mut().expect("current segment is set");
            let read_length =
                usize::try_from((*remaining).min(64 * 1024)).expect("bounded read length");
            let mut buffer = vec![0_u8; read_length];
            match file.read(&mut buffer).await {
                Ok(0) => {
                    state.finished = true;
                    Some((
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short stored payload",
                        )),
                        state,
                    ))
                }
                Ok(read) => {
                    buffer.truncate(read);
                    *remaining -= read as u64;
                    if *remaining == 0 {
                        state.current = None;
                    }
                    Some((Ok(Bytes::from(buffer)), state))
                }
                Err(error) => {
                    state.finished = true;
                    Some((Err(error), state))
                }
            }
        },
    )
}

fn mount_download_stream(
    segments: Vec<DownloadSegment>,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
    struct StreamState {
        segments: VecDeque<DownloadSegment>,
        current: Option<(tokio::fs::File, u64)>,
        finished: bool,
    }
    futures_util::stream::unfold(
        StreamState {
            segments: segments.into(),
            current: None,
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }
            if state.current.is_none() {
                let segment = state.segments.pop_front()?;
                match tokio::fs::File::open(&segment.path).await {
                    Ok(mut file) => {
                        if let Err(error) = file.seek(io::SeekFrom::Start(segment.offset)).await {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                        state.current = Some((file, segment.length));
                    }
                    Err(error) => {
                        state.finished = true;
                        return Some((Err(error), state));
                    }
                }
            }
            let (file, remaining) = state.current.as_mut().expect("current segment is set");
            let read_length =
                usize::try_from((*remaining).min(64 * 1024)).expect("bounded read length");
            let mut buffer = vec![0_u8; read_length];
            match file.read(&mut buffer).await {
                Ok(0) => {
                    state.finished = true;
                    Some((
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short stored payload",
                        )),
                        state,
                    ))
                }
                Ok(read) => {
                    buffer.truncate(read);
                    *remaining -= read as u64;
                    if *remaining == 0 {
                        state.current = None;
                    }
                    Some((Ok(Bytes::from(buffer)), state))
                }
                Err(error) => {
                    state.finished = true;
                    Some((Err(error), state))
                }
            }
        },
    )
}

fn authorize_mount_read(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthorizedMountRead, AppError> {
    let wire = mount_capability_wire(headers).ok_or(AppError::Unauthorized)?;
    let now = unix_time_now().map_err(|_| AppError::Unauthorized)?;
    let claims = verify_mount_storage_read_capability(
        &wire,
        state
            .mount_storage_keys
            .as_ref()
            .ok_or(AppError::Unauthorized)?,
        CAPABILITY_AUDIENCE,
        now,
    )
    .map_err(|_| AppError::Unauthorized)?
    .claims;
    let fence = MountReadCapabilityFence {
        tenant_id: parse_required_mount_uuid(&claims.tenant_id)?,
        principal_id: parse_required_mount_uuid(&claims.principal_id)?,
        mount_session_id: parse_required_mount_uuid(&claims.mount_session_id)?,
        credential_id: parse_required_mount_uuid(&claims.credential_id)?,
        handle_id: parse_required_mount_uuid(&claims.grant_id)?,
        drive_id: parse_required_mount_uuid(&claims.drive_id)?,
        node_id: parse_required_mount_uuid(&claims.resource_id)?,
        version_id: parse_required_mount_uuid(&claims.version_id)?,
        credential_generation: mount_generation(claims.credential_generation)?,
        authorization_generation: mount_generation(claims.authorization_generation)?,
        membership_generation: mount_generation(claims.membership_generation)?,
        drive_acl_generation: mount_generation(claims.drive_acl_generation)?,
        namespace_generation: mount_generation(claims.namespace_generation)?,
        resource_acl_generation: mount_generation(claims.resource_acl_generation)?,
        gateway_epoch: mount_generation(claims.gateway_epoch)?,
    };
    if fence.tenant_id != state.tenant_id {
        return Err(AppError::Forbidden);
    }
    Ok(AuthorizedMountRead { claims, fence })
}

fn authorize_mount_write(
    state: &AppState,
    headers: &HeaderMap,
    purpose: MountStorageCapabilityUse,
) -> Result<AuthorizedMountWrite, AppError> {
    let wire = mount_capability_wire(headers).ok_or(AppError::Unauthorized)?;
    let now = unix_time_now().map_err(|_| AppError::Unauthorized)?;
    let claims = verify_mount_storage_capability(
        &wire,
        state
            .mount_storage_keys
            .as_ref()
            .ok_or(AppError::Unauthorized)?,
        CAPABILITY_AUDIENCE,
        purpose,
        now,
    )
    .map_err(|_| AppError::Unauthorized)?
    .claims;
    let tenant_id = parse_required_mount_uuid(&claims.tenant_id)?;
    if tenant_id != state.tenant_id {
        return Err(AppError::Forbidden);
    }
    let fence = MountWriteCapabilityFence {
        tenant_id,
        principal_id: parse_required_mount_uuid(&claims.principal_id)?,
        mount_session_id: parse_required_mount_uuid(&claims.mount_session_id)?,
        credential_id: parse_required_mount_uuid(&claims.credential_id)?,
        handle_id: parse_required_mount_uuid(&claims.grant_id)?,
        drive_id: parse_required_mount_uuid(&claims.drive_id)?,
        node_id: parse_required_mount_uuid(&claims.resource_id)?,
        version_id: (!claims.version_id.is_empty())
            .then(|| parse_required_mount_uuid(&claims.version_id))
            .transpose()?,
        write_session_id: parse_required_mount_uuid(&claims.write_session_id)?,
        credential_generation: mount_generation(claims.credential_generation)?,
        authorization_generation: mount_generation(claims.authorization_generation)?,
        membership_generation: mount_generation(claims.membership_generation)?,
        drive_acl_generation: mount_generation(claims.drive_acl_generation)?,
        namespace_generation: mount_generation(claims.namespace_generation)?,
        resource_acl_generation: mount_generation(claims.resource_acl_generation)?,
        gateway_epoch: mount_generation(claims.gateway_epoch)?,
        fencing_token: mount_generation(claims.fencing_token)?,
    };
    Ok(AuthorizedMountWrite { claims, fence })
}

fn reject_unsigned_mount_mode(headers: &HeaderMap) -> Result<(), AppError> {
    if headers.contains_key(MOUNT_WRITE_MODE_HEADER) {
        Err(AppError::BadRequest("unsigned_mount_write_mode"))
    } else {
        Ok(())
    }
}

fn require_mount_binary_content_type(headers: &HeaderMap) -> Result<(), AppError> {
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        == Some("application/octet-stream")
    {
        Ok(())
    } else {
        Err(AppError::BadRequest("invalid_content_type"))
    }
}

fn mount_claim_range_length(claims: &MountCapabilityClaims) -> Result<u64, AppError> {
    claims
        .range_end
        .checked_sub(claims.range_start)
        .and_then(|difference| difference.checked_add(1))
        .ok_or(AppError::Forbidden)
}

async fn read_mount_body_exact(body: Body, expected_size: u64) -> Result<Vec<u8>, AppError> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::BadRequest("invalid_request_body"))?;
        let next = u64::try_from(bytes.len())
            .ok()
            .and_then(|size| size.checked_add(chunk.len() as u64))
            .ok_or(AppError::BadRequest("mount_write_too_large"))?;
        if next > expected_size {
            return Err(AppError::Conflict("mount_write_size_mismatch"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if u64::try_from(bytes.len()).ok() != Some(expected_size) {
        return Err(AppError::Conflict("mount_write_size_mismatch"));
    }
    Ok(bytes)
}

fn validate_mount_storage_record(
    state: &AppState,
    authorized: &AuthorizedMountWrite,
    record: &MountWriteStorageRecord,
) -> Result<(), AppError> {
    if record.write_session_id != authorized.fence.write_session_id
        || record.staging_payload.tenant_id != authorized.fence.tenant_id
        || record.staging_payload.drive_id != authorized.fence.drive_id
        || record.staging_payload.backend_id != state.backend_id
        || record.staging_payload.layout != "chunked"
        || record.base_payload.as_ref().is_some_and(|payload| {
            payload.tenant_id != authorized.fence.tenant_id
                || payload.drive_id != authorized.fence.drive_id
                || payload.backend_id != state.backend_id
                || payload.state != "referenced"
        })
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_mount_write_body_digest(
    claims: &MountCapabilityClaims,
    bytes: &[u8],
) -> Result<(), AppError> {
    let expected: [u8; 32] = claims
        .content_blake3
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Forbidden)?;
    if blake3::hash(bytes).as_bytes() != &expected {
        return Err(AppError::Conflict("mount_write_digest_mismatch"));
    }
    Ok(())
}

fn completed_mount_range_result(
    write_session_id: Uuid,
    completion: MountIoCompletion,
) -> Result<Json<MountWriteResult>, AppError> {
    if completion == MountIoCompletion::Cleanup {
        return Err(AppError::Conflict("mount_io_recovered"));
    }
    let MountIoCompletion::RangeMutation {
        logical_size_bytes,
        reservation_delta_bytes,
    } = completion
    else {
        return Err(AppError::Internal);
    };
    Ok(Json(MountWriteResult {
        write_session_id,
        logical_size_bytes: u64::try_from(logical_size_bytes).map_err(|_| AppError::Internal)?,
        reservation_delta_bytes: u64::try_from(reservation_delta_bytes)
            .map_err(|_| AppError::Internal)?,
        state: "staging",
    }))
}

fn completed_mount_seek_result(
    completion: MountIoCompletion,
) -> Result<Json<MountSeekResult>, AppError> {
    if completion == MountIoCompletion::Cleanup {
        return Err(AppError::Conflict("mount_io_recovered"));
    }
    let MountIoCompletion::Seek { offset } = completion else {
        return Err(AppError::Internal);
    };
    Ok(Json(MountSeekResult {
        offset: offset
            .map(|value| u64::try_from(value).map_err(|_| AppError::Internal))
            .transpose()?,
    }))
}

fn completed_mount_manifest_result(
    write_session_id: Uuid,
    completion: MountIoCompletion,
    finalized: bool,
) -> Result<Json<MountManifestResult>, AppError> {
    if completion == MountIoCompletion::Cleanup {
        return Err(AppError::Conflict("mount_io_recovered"));
    }
    let (logical_size_bytes, blake3, chunks) = match (finalized, completion) {
        (
            false,
            MountIoCompletion::Flush {
                logical_size_bytes,
                blake3,
                chunks,
            },
        )
        | (
            true,
            MountIoCompletion::Finalize {
                logical_size_bytes,
                blake3,
                chunks,
            },
        ) => (logical_size_bytes, blake3, chunks),
        _ => return Err(AppError::Internal),
    };
    Ok(Json(MountManifestResult {
        write_session_id,
        logical_size_bytes: u64::try_from(logical_size_bytes).map_err(|_| AppError::Internal)?,
        blake3: hex_digest(&blake3),
        chunks: chunks
            .into_iter()
            .map(|chunk| {
                Ok(MountChunkResult {
                    chunk_number: u64::try_from(chunk.chunk_number)
                        .map_err(|_| AppError::Internal)?,
                    size_bytes: u64::try_from(chunk.size_bytes).map_err(|_| AppError::Internal)?,
                    blake3: hex_digest(&chunk.blake3),
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?,
        state: if finalized { "finalized" } else { "flushed" },
    }))
}

fn completed_mount_staging_result(
    write_session_id: Uuid,
    completion: MountIoCompletion,
    deleted: bool,
) -> Result<Json<MountStagingResult>, AppError> {
    if completion == MountIoCompletion::Cleanup {
        return Err(AppError::Conflict("mount_io_recovered"));
    }
    if !matches!(
        (deleted, completion),
        (false, MountIoCompletion::Abort) | (true, MountIoCompletion::DeleteStaging)
    ) {
        return Err(AppError::Internal);
    }
    Ok(Json(MountStagingResult {
        write_session_id,
        state: if deleted { "deleted" } else { "aborted" },
    }))
}

async fn cleanup_mount_write_lock(
    state: &AppState,
    tenant_id: Uuid,
    write_session_id: Uuid,
    expected_staging_payload_id: Option<Uuid>,
    cow_lock: CowLockGuard,
) -> Result<(), AppError> {
    let cleanup = state
        .database
        .claim_mount_write_lock_cleanup(
            tenant_id,
            state.backend_id,
            write_session_id,
            state.worker_id,
        )
        .await?;
    validate_mount_write_lock_cleanup_job(
        state.backend_id,
        state.worker_id,
        tenant_id,
        write_session_id,
        expected_staging_payload_id,
        &cleanup,
    )?;
    if cleanup.job_state == "leased" {
        // The lock was held continuously through Finalize and the job claim,
        // but revalidate the short DB lease before unlinking its inode.
        state
            .database
            .heartbeat_mount_write_lock_cleanup(&cleanup)
            .await?;
    }
    remove_mount_cow_lock(state.storage.clone(), cow_lock).await?;
    if cleanup.job_state == "leased" {
        state
            .database
            .complete_mount_write_lock_cleanup(&cleanup)
            .await?;
    }
    Ok(())
}

fn validate_mount_write_lock_cleanup_job(
    backend_id: Uuid,
    worker_id: Uuid,
    tenant_id: Uuid,
    write_session_id: Uuid,
    expected_staging_payload_id: Option<Uuid>,
    job: &MountWriteLockCleanupJobRecord,
) -> Result<(), AppError> {
    if job.tenant_id != tenant_id
        || job.write_session_id != write_session_id
        || job.backend_id != backend_id
        || job.worker_id != worker_id
        || job.staging_payload_id.is_nil()
        || expected_staging_payload_id.is_some_and(|expected| expected != job.staging_payload_id)
        || job.job_fencing_token <= 0
        || !matches!(job.job_state.as_str(), "leased" | "completed")
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn recover_expired_mount_io(
    state: &AppState,
    authorized: &AuthorizedMountWrite,
    cleanup: MountIoCleanupRecord,
) -> Result<(), AppError> {
    if cleanup.tenant_id != authorized.fence.tenant_id
        || cleanup.write_session_id != authorized.fence.write_session_id
        || cleanup.fencing_token != authorized.fence.fencing_token
    {
        return Err(AppError::Forbidden);
    }
    validate_mount_storage_record(state, authorized, &cleanup.storage)?;
    let cleanup_job = state
        .database
        .claim_mount_staging_cleanup(
            cleanup.tenant_id,
            cleanup.storage.staging_payload.backend_id,
            cleanup.write_session_id,
            state.worker_id,
        )
        .await?;
    validate_mount_cleanup_job(
        &ExpectedMountCleanupJob {
            backend_id: state.backend_id,
            worker_id: state.worker_id,
            tenant_id: cleanup.tenant_id,
            write_session_id: cleanup.write_session_id,
            payload: &cleanup.storage.staging_payload,
            source_nonce_digest: Some(cleanup.nonce_digest),
            completion_kind: "cleanup",
        },
        &cleanup_job,
    )?;
    cleanup_mount_staging_job(state, cleanup_job).await
}

async fn cleanup_mount_staging_job(
    state: &AppState,
    cleanup: MountStagingCleanupJobRecord,
) -> Result<(), AppError> {
    let cow_lock = acquire_mount_cow_lock(state.storage.clone(), cleanup.write_session_id).await?;
    // A cleanup lease may expire while waiting on another process's flock.
    // Revalidate before authorizing any physical deletion.
    state
        .database
        .heartbeat_mount_staging_cleanup(&cleanup)
        .await?;
    let storage = state.storage.clone();
    let write_session_id = cleanup.write_session_id;
    let payload = cleanup.payload.clone();
    let deletion = tokio::task::spawn_blocking(move || {
        storage.delete_cow_staging(write_session_id, &payload)?;
        Ok::<_, StorageError>((storage, cow_lock))
    });
    tokio::pin!(deletion);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(MOUNT_CLEANUP_HEARTBEAT_SECONDS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let (storage, cow_lock) = loop {
        tokio::select! {
            result = &mut deletion => {
                break result
                    .map_err(|_| AppError::Internal)?
                    .map_err(storage_error)?;
            }
            _ = heartbeat.tick() => {
                if let Err(error) = state.database.heartbeat_mount_staging_cleanup(&cleanup).await {
                    // A blocking tree deletion cannot be cancelled safely. It
                    // retains the flock until completion, but stale authority
                    // must not advance or unlink the cleanup state machine.
                    let _ = (&mut deletion).await;
                    return Err(error.into());
                }
            }
        }
    };
    state
        .database
        .heartbeat_mount_staging_cleanup(&cleanup)
        .await?;
    state
        .database
        .mark_mount_staging_cleanup_physical_deleted(&cleanup)
        .await?;
    remove_mount_cow_lock(storage, cow_lock).await?;
    state
        .database
        .complete_mount_staging_cleanup(&cleanup)
        .await?;
    Ok(())
}

struct ExpectedMountCleanupJob<'a> {
    backend_id: Uuid,
    worker_id: Uuid,
    tenant_id: Uuid,
    write_session_id: Uuid,
    payload: &'a filebelt_database::PayloadRecord,
    source_nonce_digest: Option<[u8; 32]>,
    completion_kind: &'a str,
}

fn validate_mount_cleanup_job(
    expected: &ExpectedMountCleanupJob<'_>,
    job: &MountStagingCleanupJobRecord,
) -> Result<(), AppError> {
    let payload = &job.payload;
    if job.tenant_id != expected.tenant_id
        || job.write_session_id != expected.write_session_id
        || job.backend_id != expected.backend_id
        || job.worker_id != expected.worker_id
        || job.job_fencing_token <= 0
        || !matches!(job.job_state.as_str(), "leased" | "physical_deleted")
        || job.source_nonce_digest != expected.source_nonce_digest
        || job.completion_kind != expected.completion_kind
        || payload.tenant_id != expected.payload.tenant_id
        || payload.payload_id != expected.payload.payload_id
        || payload.drive_id != expected.payload.drive_id
        || payload.backend_id != expected.payload.backend_id
        || payload.locator != expected.payload.locator
        || payload.layout != expected.payload.layout
        || !matches!(
            expected.payload.state.as_str(),
            "staging" | "finalized" | "abandoned" | "deleting" | "deleted"
        )
        || !matches!(
            payload.state.as_str(),
            "staging" | "finalized" | "abandoned" | "deleting" | "deleted"
        )
        || payload.size_bytes != expected.payload.size_bytes
        || payload.blake3 != expected.payload.blake3
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_mount_range_admission(
    state: &AppState,
    authorized: &AuthorizedMountWrite,
    admission: &MountWriteRangeAdmission,
    operation: MountWriteRangeOperation,
    range_start: i64,
    range_end: i64,
) -> Result<(), AppError> {
    validate_mount_storage_record(state, authorized, &admission.storage)?;
    let signed_content_blake3 = if operation == MountWriteRangeOperation::WriteData {
        Some(
            authorized
                .claims
                .content_blake3
                .as_slice()
                .try_into()
                .map_err(|_| AppError::Forbidden)?,
        )
    } else {
        None
    };
    if admission.operation_id.is_nil()
        || admission.operation_ordinal <= 0
        || admission.operation != operation
        || admission.content_blake3 != signed_content_blake3
        || admission.range_start != range_start
        || admission.range_end != range_end
        || i64::try_from(authorized.claims.range_start).ok() != Some(range_start)
        || i64::try_from(authorized.claims.range_end).ok() != Some(range_end)
        || range_start < 0
        || range_end < range_start
        || admission.storage.reserved_bytes <= range_end
        || admission.resulting_logical_size < 0
        || admission.resulting_logical_size > admission.storage.reserved_bytes
        || admission.resulting_logical_size != admission.storage.logical_size_bytes
    {
        return Err(AppError::Forbidden);
    }
    validate_mount_chunk_plan(&admission.storage, state.chunk_size, range_end)?;
    Ok(())
}

fn validate_mount_chunk_plan(
    storage: &MountWriteStorageRecord,
    chunk_size: u64,
    range_end: i64,
) -> Result<(), AppError> {
    let mut planned_bytes = 0_i64;
    let mut locators = HashSet::with_capacity(storage.planned_chunks.len());
    for (index, chunk) in storage.planned_chunks.iter().enumerate() {
        let expected_number = i64::try_from(index).map_err(|_| AppError::Forbidden)?;
        let size = u64::try_from(chunk.size_bytes).map_err(|_| AppError::Forbidden)?;
        let source_pair_valid = match (chunk.source_payload_id, chunk.source_chunk_number) {
            (Some(payload_id), Some(source_chunk_number)) => {
                storage
                    .base_payload
                    .as_ref()
                    .is_some_and(|payload| payload.payload_id == payload_id)
                    && source_chunk_number == chunk.chunk_number
            }
            (None, None) => true,
            _ => false,
        };
        if chunk.chunk_number != expected_number
            || size == 0
            || size > chunk_size
            || (index + 1 < storage.planned_chunks.len() && size != chunk_size)
            || chunk.staging_locator.is_nil()
            || !locators.insert(chunk.staging_locator)
            || !source_pair_valid
        {
            return Err(AppError::Forbidden);
        }
        planned_bytes = planned_bytes
            .checked_add(chunk.size_bytes)
            .ok_or(AppError::Forbidden)?;
    }
    if planned_bytes != storage.reserved_bytes || storage.reserved_bytes <= range_end {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_mount_range_readmission(
    before: &MountWriteRangeAdmission,
    after: &MountWriteRangeAdmission,
) -> Result<(), AppError> {
    if before.operation_id != after.operation_id
        || before.operation_ordinal != after.operation_ordinal
        || before.operation != after.operation
        || before.content_blake3 != after.content_blake3
        || before.range_start != after.range_start
        || before.range_end != after.range_end
        || before.resulting_logical_size != after.resulting_logical_size
        || before.storage.reserved_bytes != after.storage.reserved_bytes
        || before.storage.logical_size_bytes != after.storage.logical_size_bytes
        || before.storage.planned_chunks != after.storage.planned_chunks
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn acquire_mount_cow_lock(
    storage: StorageLayout,
    write_session_id: Uuid,
) -> Result<CowLockGuard, AppError> {
    tokio::task::spawn_blocking(move || {
        let mut guard = storage.lock_cow(write_session_id)?;
        // A cancelled Tokio waiter does not cancel `spawn_blocking`. Arm the
        // returned guard so dropping a detached task result removes the exact
        // current inode under the shard coordinator instead of recreating a
        // terminal lock after its database cleanup has completed.
        guard.arm_remove_on_drop();
        Ok::<_, StorageError>(guard)
    })
    .await
    .map_err(|_| AppError::Internal)?
    .map_err(storage_error)
}

async fn remove_mount_cow_lock(
    storage: StorageLayout,
    guard: CowLockGuard,
) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || storage.remove_cow_lock(guard))
        .await
        .map_err(|_| AppError::Internal)?
        .map_err(storage_error)
}

fn ensure_mount_cow(
    storage: &StorageLayout,
    record: &MountWriteStorageRecord,
    chunk_size: u64,
) -> Result<(), StorageError> {
    storage.recover_cow_under_lock(record.write_session_id)?;
    match storage.cow_logical_size(record.write_session_id, chunk_size) {
        Ok(_) => Ok(()),
        Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            let base_chunks = record
                .base_parts
                .iter()
                .map(mount_base_chunk)
                .collect::<Result<Vec<_>, _>>()?;
            storage.begin_cow_write(
                record.write_session_id,
                chunk_size,
                record.base_payload.as_ref(),
                &base_chunks,
            )
        }
        Err(error) => Err(error),
    }
}

fn mount_base_chunk(part: &MountPayloadPartRecord) -> Result<CowBaseChunk, StorageError> {
    Ok(CowBaseChunk {
        chunk_number: u64::try_from(part.chunk_number).map_err(|_| StorageError::StateConflict)?,
        size: u64::try_from(part.size_bytes).map_err(|_| StorageError::StateConflict)?,
        digest: part.blake3,
    })
}

fn mount_chunk_evidence(manifest: &CowManifest) -> Result<Vec<MountWriteChunkEvidence>, AppError> {
    manifest
        .chunks
        .iter()
        .map(|chunk| {
            Ok(MountWriteChunkEvidence {
                chunk_number: i64::try_from(chunk.chunk_number)
                    .map_err(|_| AppError::Conflict("mount_write_too_large"))?,
                size_bytes: i64::try_from(chunk.size)
                    .map_err(|_| AppError::Conflict("mount_write_too_large"))?,
                blake3: chunk.digest,
            })
        })
        .collect()
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    operation: CapabilityOperation,
) -> Result<AuthorizedCapability, AppError> {
    let wire = capability_wire(headers).ok_or(AppError::Unauthorized)?;
    let now = unix_time_now().map_err(|_| AppError::Unauthorized)?;
    let claims = verify_capability_for_operation(
        &wire,
        operation,
        now,
        &state.api_storage_keys,
        state.collaboration_storage_keys.as_deref(),
        state.document_storage_keys.as_deref(),
        state.revision_storage_keys.as_deref(),
    )?;
    let tenant_id = parse_required_uuid(&claims.tenant_id)?;
    if tenant_id != state.tenant_id {
        return Err(AppError::Forbidden);
    }
    let principal_id = parse_required_uuid(&claims.principal_id)?;
    let resource_id = parse_required_uuid(&claims.resource_id)?;
    let capability_id = parse_required_uuid(&claims.capability_id)?;
    let session_id = parse_required_uuid(&claims.session_id)?;
    Ok(AuthorizedCapability {
        claims,
        tenant_id,
        session_id,
        principal_id,
        resource_id,
        capability_id,
    })
}

fn verify_capability_for_operation(
    wire: &str,
    operation: CapabilityOperation,
    now: i64,
    api_storage_keys: &ApiStorageKeyset,
    collaboration_storage_keys: Option<&CollaborationStorageKeyset>,
    document_storage_keys: Option<&DocumentStorageKeyset>,
    revision_storage_keys: Option<&RevisionStorageKeyset>,
) -> Result<CapabilityClaims, AppError> {
    match operation {
        CapabilityOperation::UploadPart => verify_api_storage_capability(
            wire,
            api_storage_keys,
            CAPABILITY_AUDIENCE,
            ApiStorageCapabilityUse::UploadPart,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::FinalizeUpload => verify_api_storage_capability(
            wire,
            api_storage_keys,
            CAPABILITY_AUDIENCE,
            ApiStorageCapabilityUse::FinalizeUpload,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::Download => verify_api_storage_capability(
            wire,
            api_storage_keys,
            CAPABILITY_AUDIENCE,
            ApiStorageCapabilityUse::Download,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::WriteCollaborationObject => verify_collaboration_storage_capability(
            wire,
            collaboration_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            CollaborationStorageCapabilityUse::WriteObject,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::FinalizeCollaborationObject => {
            verify_collaboration_storage_capability(
                wire,
                collaboration_storage_keys.ok_or(AppError::Unauthorized)?,
                CAPABILITY_AUDIENCE,
                CollaborationStorageCapabilityUse::FinalizeObject,
                now,
            )
            .map(|verified| verified.claims)
        }
        CapabilityOperation::ReadCollaborationObject => verify_collaboration_storage_capability(
            wire,
            collaboration_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            CollaborationStorageCapabilityUse::ReadObject,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::ReadDocumentVersion => verify_document_storage_capability(
            wire,
            document_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            DocumentStorageCapabilityUse::ReadVersion,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::WriteDocumentRevision => verify_document_storage_capability(
            wire,
            document_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            DocumentStorageCapabilityUse::WriteRevision,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::FinalizeDocumentRevision => verify_document_storage_capability(
            wire,
            document_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            DocumentStorageCapabilityUse::FinalizeRevision,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::WriteRevisionChunk => verify_revision_storage_capability(
            wire,
            revision_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            RevisionStorageCapabilityUse::WriteChunk,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::ReadRevisionChunk => verify_revision_storage_capability(
            wire,
            revision_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            RevisionStorageCapabilityUse::ReadChunk,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::DeleteRevisionChunk => verify_revision_storage_capability(
            wire,
            revision_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            RevisionStorageCapabilityUse::DeleteChunk,
            now,
        )
        .map(|verified| verified.claims),
        CapabilityOperation::ReadRevisionLegacyPayload => verify_revision_storage_capability(
            wire,
            revision_storage_keys.ok_or(AppError::Unauthorized)?,
            CAPABILITY_AUDIENCE,
            RevisionStorageCapabilityUse::ReadLegacyPayload,
            now,
        )
        .map(|verified| verified.claims),
        _ => return Err(AppError::Unauthorized),
    }
    .map_err(|_| AppError::Unauthorized)
}

fn mount_capability_wire(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    if value.starts_with("fbcap2.") {
        return Some(value.to_owned());
    }
    let (scheme, credential) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("fbcap2").then(|| {
        if credential.starts_with("fbcap2.") {
            credential.to_owned()
        } else {
            format!("fbcap2.{credential}")
        }
    })
}

fn mount_generation(value: u64) -> Result<i64, AppError> {
    i64::try_from(value).map_err(|_| AppError::Unauthorized)
}

fn capability_wire(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        if value.starts_with("fbcap1.") {
            return Some(value.to_owned());
        }
        if let Some((scheme, credential)) = value.split_once(' ')
            && scheme.eq_ignore_ascii_case("fbcap1")
        {
            return Some(if credential.starts_with("fbcap1.") {
                credential.to_owned()
            } else {
                format!("fbcap1.{credential}")
            });
        }
    }
    let cookies = headers.get("cookie")?.to_str().ok()?;
    cookies.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        CAPABILITY_COOKIE_NAMES
            .contains(&name)
            .then(|| value.to_owned())
    })
}

fn validate_upload_capability(
    authorized: &AuthorizedCapability,
    upload: &UploadRecord,
    claim_payload: Uuid,
    configured_backend_id: Uuid,
) -> Result<(), AppError> {
    if upload.tenant_id != authorized.tenant_id
        || upload.owner_principal_id != authorized.principal_id
        || upload.backend_id != configured_backend_id
        || upload.payload_id != claim_payload
        || upload.fencing_token
            != i64::try_from(authorized.claims.fencing_token).map_err(|_| AppError::Forbidden)?
        || authorized.resource_id != upload.node_id.unwrap_or(upload.parent_id)
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Decodes the revision coordinator's fixed chunk binding from a verified
/// purpose-scoped capability.  The nonce is intentionally 64 bytes: its first
/// 32 bytes are the immutable BLAKE3 locator and its random suffix preserves
/// one-time capability identity.  PostgreSQL persists the same
/// `(drive_id, digest, size)` tuple before it can issue the capability.
fn revision_chunk_locator(
    authorized: &AuthorizedCapability,
    expected_chunk_id: Uuid,
) -> Result<RevisionChunkLocator, AppError> {
    let _operation_id = parse_required_non_nil_uuid(&authorized.claims.upload_id)?;
    let _manifest_member_id = parse_required_non_nil_uuid(&authorized.claims.grant_id)?;
    if expected_chunk_id.is_nil()
        || parse_required_uuid(&authorized.claims.payload_id)? != expected_chunk_id
        || parse_required_non_nil_uuid(&authorized.claims.resource_id)? != authorized.resource_id
        || authorized.claims.range_start != 0
        || authorized.claims.nonce.len() != REVISION_CHUNK_CAPABILITY_NONCE_BYTES
        || authorized.claims.nonce[32..].iter().all(|byte| *byte == 0)
    {
        return Err(AppError::Forbidden);
    }
    let size = authorized
        .claims
        .range_end
        .checked_add(1)
        .ok_or(AppError::Forbidden)?;
    if size == 0 || size > REVISION_CHUNK_SIZE_BYTES {
        return Err(AppError::Forbidden);
    }
    let digest = authorized.claims.nonce[..32]
        .try_into()
        .map_err(|_| AppError::Forbidden)?;
    RevisionChunkLocator::new(authorized.resource_id, digest, size).map_err(|_| AppError::Forbidden)
}

fn validate_revision_legacy_payload_capability(
    authorized: &AuthorizedCapability,
    expected_payload_id: Uuid,
) -> Result<(), AppError> {
    let _operation_id = parse_required_non_nil_uuid(&authorized.claims.grant_id)?;
    let _drive_id = parse_required_non_nil_uuid(&authorized.claims.resource_id)?;
    let _operation_id = parse_required_non_nil_uuid(&authorized.claims.upload_id)?;
    if expected_payload_id.is_nil()
        || parse_required_uuid(&authorized.claims.payload_id)? != expected_payload_id
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_collaboration_capability(
    authorized: &AuthorizedCapability,
    object: &CollaborationObjectRecord,
    configured_backend_id: Uuid,
) -> Result<(), AppError> {
    if parse_required_uuid(&authorized.claims.grant_id)? != object.id
        || parse_required_uuid(&authorized.claims.upload_id)? != object.room_id
        || parse_required_uuid(&authorized.claims.payload_id)? != object.payload_id
        || authorized.resource_id != object.node_id
        || object.backend_id != configured_backend_id
        || object.fencing_token
            != i64::try_from(authorized.claims.fencing_token).map_err(|_| AppError::Forbidden)?
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_exact_range(
    authorized: &AuthorizedCapability,
    expected_size: u64,
) -> Result<(), AppError> {
    if authorized.claims.range_start != 0
        || (expected_size == 0 && authorized.claims.range_end != 0)
        || (expected_size > 0 && authorized.claims.range_end != expected_size - 1)
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn consume_nonce(
    state: &AppState,
    authorized: &AuthorizedCapability,
    operation: &str,
) -> Result<(), AppError> {
    let digest = nonce_digest(b"filebelt-capability-nonce-v1\0", &authorized.claims.nonce);
    state
        .database
        .consume_capability_nonce(
            authorized.tenant_id,
            &digest,
            operation,
            authorized.claims.expires_at_unix_seconds,
        )
        .await
        .map_err(|error| match error {
            DatabaseError::Conflict => AppError::Conflict("capability_replayed"),
            _ => AppError::Unavailable,
        })
}

async fn consume_mount_nonce(
    state: &AppState,
    tenant_id: Uuid,
    claims: &MountCapabilityClaims,
    operation: &str,
) -> Result<(), AppError> {
    let digest = nonce_digest(b"filebelt-mount-capability-nonce-v2\0", &claims.nonce);
    state
        .database
        .consume_capability_nonce(
            tenant_id,
            &digest,
            operation,
            claims.expires_at_unix_seconds,
        )
        .await
        .map_err(|error| match error {
            DatabaseError::Conflict => AppError::Conflict("capability_replayed"),
            _ => AppError::Unavailable,
        })
}

fn nonce_digest(domain: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

async fn check_generations(
    state: &AppState,
    authorized: &AuthorizedCapability,
    drive_id: Uuid,
) -> Result<(), AppError> {
    match generations_match(&state.database, authorized, drive_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError::Forbidden),
        Err(_) => Err(AppError::Unavailable),
    }
}

async fn generations_match(
    database: &Database,
    authorized: &AuthorizedCapability,
    drive_id: Uuid,
) -> Result<bool, DatabaseError> {
    database
        .authorization_generations_match(
            authorized.tenant_id,
            authorized.session_id,
            authorized.principal_id,
            drive_id,
            authorized.resource_id,
            i64::try_from(authorized.claims.membership_generation)
                .map_err(|_| DatabaseError::InvalidPersistedValue)?,
            i64::try_from(authorized.claims.drive_acl_generation)
                .map_err(|_| DatabaseError::InvalidPersistedValue)?,
            i64::try_from(authorized.claims.namespace_generation)
                .map_err(|_| DatabaseError::InvalidPersistedValue)?,
            i64::try_from(authorized.claims.resource_acl_generation)
                .map_err(|_| DatabaseError::InvalidPersistedValue)?,
        )
        .await
}

fn expected_part_size(upload: &UploadRecord, part_number: i32) -> Result<u64, AppError> {
    if part_number < 0 || part_number >= upload.part_count || upload.part_count <= 0 {
        return Err(AppError::BadRequest("invalid_part_number"));
    }
    let declared = u64::try_from(upload.declared_size_bytes).map_err(|_| AppError::Internal)?;
    let chunk = u64::try_from(upload.chunk_size_bytes).map_err(|_| AppError::Internal)?;
    let part =
        u64::try_from(part_number).map_err(|_| AppError::BadRequest("invalid_part_number"))?;
    if upload.part_count == 1 {
        return Ok(declared);
    }
    let offset = chunk.checked_mul(part).ok_or(AppError::Internal)?;
    let remaining = declared.checked_sub(offset).ok_or(AppError::Internal)?;
    if part_number + 1 == upload.part_count {
        Ok(remaining)
    } else if remaining >= chunk {
        Ok(chunk)
    } else {
        Err(AppError::Internal)
    }
}

async fn write_body(
    body: Body,
    path: &FilePath,
    expected_size: u64,
) -> Result<(u64, [u8; 32]), AppError> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(|_| AppError::Conflict("part_write_in_progress"))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|_| AppError::Internal)?;
    let mut stream = body.into_data_stream();
    let mut size = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let result = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| AppError::BadRequest("invalid_request_body"))?;
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or(AppError::BadRequest("part_too_large"))?;
            if size > expected_size {
                return Err(AppError::Conflict("part_size_mismatch"));
            }
            file.write_all(&chunk)
                .await
                .map_err(|_| AppError::Internal)?;
            hasher.update(&chunk);
        }
        if size != expected_size {
            return Err(AppError::Conflict("part_size_mismatch"));
        }
        file.sync_all().await.map_err(|_| AppError::Internal)?;
        Ok((size, *hasher.finalize().as_bytes()))
    }
    .await;
    drop(file);
    if result.is_err() {
        let _ = tokio::fs::remove_file(path).await;
    }
    result
}

fn requested_range(
    header: Option<&HeaderValue>,
    size: u64,
    claims: &CapabilityClaims,
) -> Result<(u64, u64, bool), AppError> {
    if size == 0 {
        if header.is_some() || claims.range_start != 0 || claims.range_end != 0 {
            return Err(AppError::Range);
        }
        return Ok((0, 0, false));
    }
    if claims.range_start > claims.range_end || claims.range_end >= size {
        return Err(AppError::Forbidden);
    }
    let Some(value) = header else {
        let partial = claims.range_start != 0 || claims.range_end != size - 1;
        return Ok((claims.range_start, claims.range_end, partial));
    };
    let value = value.to_str().map_err(|_| AppError::Range)?;
    let value = value.strip_prefix("bytes=").ok_or(AppError::Range)?;
    if value.contains(',') {
        return Err(AppError::Range);
    }
    let (start_text, end_text) = value.split_once('-').ok_or(AppError::Range)?;
    let (start, end) = if start_text.is_empty() {
        let suffix = end_text.parse::<u64>().map_err(|_| AppError::Range)?;
        if suffix == 0 {
            return Err(AppError::Range);
        }
        (size.saturating_sub(suffix), size - 1)
    } else {
        let start = start_text.parse::<u64>().map_err(|_| AppError::Range)?;
        let end = if end_text.is_empty() {
            size - 1
        } else {
            end_text
                .parse::<u64>()
                .map_err(|_| AppError::Range)?
                .min(size - 1)
        };
        (start, end)
    };
    if start > end || start < claims.range_start || end > claims.range_end {
        return Err(AppError::Range);
    }
    Ok((start, end, true))
}

fn parse_required_uuid(value: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(value).map_err(|_| AppError::Unauthorized)
}

fn parse_required_non_nil_uuid(value: &str) -> Result<Uuid, AppError> {
    let identifier = parse_required_uuid(value)?;
    if identifier.is_nil() {
        return Err(AppError::Unauthorized);
    }
    Ok(identifier)
}

fn parse_required_mount_uuid(value: &str) -> Result<Uuid, AppError> {
    let identifier = parse_required_uuid(value)?;
    if identifier.is_nil() {
        return Err(AppError::Unauthorized);
    }
    Ok(identifier)
}

fn keyset_source(path: &FilePath) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|_| "capability public keyset is invalid".to_owned())
}

fn load_api_storage_keys(path: &FilePath) -> Result<ApiStorageKeyset, String> {
    ApiStorageKeyset::parse(&keyset_source(path)?)
        .map_err(|_| "capability public keyset is invalid".to_owned())
}

fn load_collaboration_storage_keys(path: &FilePath) -> Result<CollaborationStorageKeyset, String> {
    CollaborationStorageKeyset::parse(&keyset_source(path)?)
        .map_err(|_| "capability public keyset is invalid".to_owned())
}

fn load_document_storage_keys(path: &FilePath) -> Result<DocumentStorageKeyset, String> {
    DocumentStorageKeyset::parse(&keyset_source(path)?)
        .map_err(|_| "capability public keyset is invalid".to_owned())
}

fn load_revision_storage_keys(path: &FilePath) -> Result<RevisionStorageKeyset, String> {
    RevisionStorageKeyset::parse(&keyset_source(path)?)
        .map_err(|_| "capability public keyset is invalid".to_owned())
}

fn load_mount_storage_keys(path: &FilePath) -> Result<MountStorageKeyset, String> {
    MountStorageKeyset::parse(&keyset_source(path)?)
        .map_err(|_| "capability public keyset is invalid".to_owned())
}

fn validate_storage_keyset_disjointness(
    api: &ApiStorageKeyset,
    collaboration: Option<&CollaborationStorageKeyset>,
    document: Option<&DocumentStorageKeyset>,
    revision: Option<&RevisionStorageKeyset>,
    mount: Option<&MountStorageKeyset>,
) -> Result<(), String> {
    let mut material = api.entries().map(|(_, key)| *key).collect::<Vec<_>>();
    if let Some(keys) = collaboration {
        material.extend(keys.entries().map(|(_, key)| *key));
    }
    if let Some(keys) = document {
        material.extend(keys.entries().map(|(_, key)| *key));
    }
    if let Some(keys) = revision {
        material.extend(keys.entries().map(|(_, key)| *key));
    }
    if let Some(keys) = mount {
        material.extend(keys.entries().map(|(_, key)| *key));
    }
    public_key_material_is_disjoint(material)
        .then_some(())
        .ok_or_else(|| "capability public key material is reused across purposes".to_owned())
}

fn storage_error(error: StorageError) -> AppError {
    match error {
        StorageError::StateConflict => AppError::Conflict("storage_state_conflict"),
        StorageError::CorruptObject | StorageError::UnsafeObject => {
            AppError::Conflict("storage_integrity_failure")
        }
        StorageError::InvalidContent => AppError::Conflict("content_profile_invalid"),
        StorageError::UnsupportedFilesystem => AppError::Unsupported("sparse_not_supported"),
        StorageError::Io(_) | StorageError::Join => AppError::Internal,
    }
}

impl From<DatabaseError> for AppError {
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::NotFound => Self::NotFound("object_not_found"),
            DatabaseError::Conflict => Self::Conflict("state_conflict"),
            DatabaseError::StaleGeneration => Self::Forbidden,
            DatabaseError::QuotaExceeded => Self::Conflict("quota_exceeded"),
            DatabaseError::AdmissionLimited | DatabaseError::SecurityAdmissionBlocked => {
                Self::Unavailable
            }
            DatabaseError::Sql(_) | DatabaseError::Migration(_) => Self::Unavailable,
            DatabaseError::StorageUnavailable => Self::Unavailable,
            DatabaseError::InvalidPersistedValue => Self::Internal,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, code) = match self {
            Self::BadRequest(code) => (StatusCode::BAD_REQUEST, "Request rejected", code),
            Self::NotFound(code) => (StatusCode::NOT_FOUND, "Object not found", code),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Capability required",
                "invalid_capability",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "Capability no longer authorized",
                "authorization_changed",
            ),
            Self::Conflict(code) => (StatusCode::CONFLICT, "Storage state conflict", code),
            Self::Range => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                "Range not satisfiable",
                "invalid_range",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authoritative state unavailable",
                "dependency_unavailable",
            ),
            Self::Unsupported(code) => (
                StatusCode::NOT_IMPLEMENTED,
                "Storage operation unsupported",
                code,
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage operation failed",
                "storage_failure",
            ),
        };
        let body = Json(Problem {
            r#type: "https://filebelt.dev/problems/storage",
            title,
            status: status.as_u16(),
            code,
        });
        let mut response = (status, body).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert("www-authenticate", HeaderValue::from_static("fbcap1"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

    const MOUNT_USES: [MountStorageCapabilityUse; 10] = [
        MountStorageCapabilityUse::Read,
        MountStorageCapabilityUse::WriteData,
        MountStorageCapabilityUse::Deallocate,
        MountStorageCapabilityUse::Allocate,
        MountStorageCapabilityUse::SeekData,
        MountStorageCapabilityUse::SeekHole,
        MountStorageCapabilityUse::Flush,
        MountStorageCapabilityUse::Finalize,
        MountStorageCapabilityUse::Abort,
        MountStorageCapabilityUse::DeleteStaging,
    ];

    fn claims(start: u64, end: u64) -> CapabilityClaims {
        CapabilityClaims {
            range_start: start,
            range_end: end,
            ..CapabilityClaims::default()
        }
    }

    fn valid_claims(operation: CapabilityOperation) -> CapabilityClaims {
        CapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: CAPABILITY_AUDIENCE.into(),
            operation: operation as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            upload_id: Uuid::new_v4().to_string(),
            payload_id: Uuid::new_v4().to_string(),
            part_number: 1,
            range_start: 0,
            range_end: 15,
            resource_acl_generation: 1,
            membership_generation: 1,
            namespace_generation: 1,
            fencing_token: 1,
            nonce: vec![7; 32],
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 160,
            drive_acl_generation: 1,
            grant_id: Uuid::new_v4().to_string(),
        }
    }

    fn mount_claims(purpose: MountStorageCapabilityUse) -> MountCapabilityClaims {
        let requires_version = matches!(
            purpose,
            MountStorageCapabilityUse::Read
                | MountStorageCapabilityUse::WriteData
                | MountStorageCapabilityUse::Deallocate
                | MountStorageCapabilityUse::Allocate
                | MountStorageCapabilityUse::SeekData
                | MountStorageCapabilityUse::SeekHole
                | MountStorageCapabilityUse::Flush
                | MountStorageCapabilityUse::Finalize
        );
        MountCapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: CAPABILITY_AUDIENCE.into(),
            operation: purpose.operation() as i32,
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: Uuid::new_v4().to_string(),
            mount_session_id: Uuid::new_v4().to_string(),
            credential_id: Uuid::new_v4().to_string(),
            drive_id: Uuid::new_v4().to_string(),
            resource_id: Uuid::new_v4().to_string(),
            version_id: if requires_version {
                Uuid::new_v4().to_string()
            } else {
                String::new()
            },
            write_session_id: if purpose == MountStorageCapabilityUse::Read {
                String::new()
            } else {
                Uuid::new_v4().to_string()
            },
            range_start: if matches!(
                purpose,
                MountStorageCapabilityUse::Read
                    | MountStorageCapabilityUse::WriteData
                    | MountStorageCapabilityUse::Deallocate
                    | MountStorageCapabilityUse::Allocate
                    | MountStorageCapabilityUse::SeekData
                    | MountStorageCapabilityUse::SeekHole
            ) {
                41
            } else {
                0
            },
            range_end: if matches!(
                purpose,
                MountStorageCapabilityUse::Read
                    | MountStorageCapabilityUse::WriteData
                    | MountStorageCapabilityUse::Deallocate
                    | MountStorageCapabilityUse::Allocate
                    | MountStorageCapabilityUse::SeekData
                    | MountStorageCapabilityUse::SeekHole
            ) {
                41
            } else {
                0
            },
            credential_generation: 1,
            authorization_generation: 2,
            membership_generation: 3,
            drive_acl_generation: 4,
            namespace_generation: 5,
            resource_acl_generation: 6,
            gateway_epoch: 7,
            fencing_token: 8,
            nonce: vec![9; 32],
            content_blake3: if purpose == MountStorageCapabilityUse::WriteData {
                vec![4; 32]
            } else {
                Vec::new()
            },
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 115,
            grant_id: Uuid::new_v4().to_string(),
        }
    }

    fn mount_handler_source<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing handler {start}"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("missing handler boundary {end}"))
            .0
    }

    #[test]
    fn range_must_be_attenuated_by_capability() {
        assert_eq!(
            requested_range(
                Some(&HeaderValue::from_static("bytes=12-19")),
                100,
                &claims(10, 20)
            )
            .unwrap(),
            (12, 19, true)
        );
        assert!(
            requested_range(
                Some(&HeaderValue::from_static("bytes=0-19")),
                100,
                &claims(10, 20)
            )
            .is_err()
        );
        assert!(
            requested_range(
                Some(&HeaderValue::from_static("bytes=12-30")),
                100,
                &claims(10, 20)
            )
            .is_err()
        );
    }

    #[test]
    fn keyset_parser_supports_rotation_file() {
        let temporary = tempfile::tempdir().expect("temporary key directory");
        let path = temporary.path().join("keys.pub");
        let keyset = filebelt_capability_keyset::encode_keyset(
            filebelt_capability_keyset::KeyPurpose::ApiStorage,
            &[(1, [1_u8; 32]), (2, [2_u8; 32])],
        )
        .expect("keyset");
        std::fs::write(&path, keyset).expect("write keyset");
        let keys = load_api_storage_keys(&path).expect("valid keyset");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_generation(2));
    }

    #[test]
    fn startup_rejects_public_key_reuse_across_storage_purposes() {
        let api = ApiStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::ApiStorage,
                &[(1, [7; 32])],
            )
            .unwrap(),
        )
        .unwrap();
        let collaboration = CollaborationStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::CollaborationStorage,
                &[(1, [7; 32])],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_storage_keyset_disjointness(&api, Some(&collaboration), None, None, None)
                .is_err()
        );
    }

    #[test]
    fn io_admission_rejects_foreign_signer_before_authoritative_state_access() {
        let retiring = Ed25519KeyPair::generate().unwrap();
        let current = Ed25519KeyPair::generate().unwrap();
        let foreign = Ed25519KeyPair::generate().unwrap();
        let api = ApiStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::ApiStorage,
                &[
                    (1, retiring.public_key().as_ref().try_into().unwrap()),
                    (2, current.public_key().as_ref().try_into().unwrap()),
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let collaboration = CollaborationStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::CollaborationStorage,
                &[(1, foreign.public_key().as_ref().try_into().unwrap())],
            )
            .unwrap(),
        )
        .unwrap();
        let claims = valid_claims(CapabilityOperation::UploadPart);

        for (generation, signer) in [(1, &retiring), (2, &current)] {
            let wire = filebelt_storage_protocol::sign_api_storage_capability(
                &claims,
                ApiStorageCapabilityUse::UploadPart,
                generation,
                signer,
            )
            .unwrap();
            assert!(
                verify_capability_for_operation(
                    &wire,
                    CapabilityOperation::UploadPart,
                    120,
                    &api,
                    Some(&collaboration),
                    None,
                    None,
                )
                .is_ok()
            );
        }

        let forged = filebelt_storage_protocol::sign_api_storage_capability(
            &claims,
            ApiStorageCapabilityUse::UploadPart,
            1,
            &foreign,
        )
        .unwrap();
        assert!(matches!(
            verify_capability_for_operation(
                &forged,
                CapabilityOperation::UploadPart,
                120,
                &api,
                Some(&collaboration),
                None,
                None,
            ),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn capability_transport_accepts_http_scheme_and_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("fbcap1 abc"));
        assert_eq!(capability_wire(&headers).as_deref(), Some("fbcap1.abc"));
        headers.remove(AUTHORIZATION);
        headers.insert(
            "cookie",
            HeaderValue::from_static("unrelated=x; filebelt_capability=fbcap1.cookie"),
        );
        assert_eq!(capability_wire(&headers).as_deref(), Some("fbcap1.cookie"));
    }

    #[test]
    fn mount_nonce_consumption_is_domain_separated() {
        let nonce = [7_u8; 32];
        assert_ne!(
            nonce_digest(b"filebelt-capability-nonce-v1\0", &nonce),
            nonce_digest(b"filebelt-mount-capability-nonce-v2\0", &nonce)
        );
    }

    #[test]
    fn mount_uuid_parser_rejects_nil_identifiers() {
        assert!(parse_required_mount_uuid(&Uuid::new_v4().to_string()).is_ok());
        assert!(matches!(
            parse_required_mount_uuid(&Uuid::nil().to_string()),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn revision_chunk_locator_requires_a_fixed_bound_digest_size_and_drive() {
        let chunk_id = Uuid::new_v4();
        let drive_id = Uuid::new_v4();
        let mut claims = valid_claims(CapabilityOperation::WriteRevisionChunk);
        claims.payload_id = chunk_id.to_string();
        claims.resource_id = drive_id.to_string();
        claims.range_start = 0;
        claims.range_end = 63;
        claims.nonce = vec![0x5a; REVISION_CHUNK_CAPABILITY_NONCE_BYTES];
        let authorized = AuthorizedCapability {
            tenant_id: Uuid::parse_str(&claims.tenant_id).unwrap(),
            session_id: Uuid::parse_str(&claims.session_id).unwrap(),
            principal_id: Uuid::parse_str(&claims.principal_id).unwrap(),
            resource_id: drive_id,
            capability_id: Uuid::parse_str(&claims.capability_id).unwrap(),
            claims,
        };
        let locator = revision_chunk_locator(&authorized, chunk_id).expect("bound revision chunk");
        assert_eq!(locator.drive_id, drive_id);
        assert_eq!(locator.size, 64);
        assert_eq!(locator.digest, [0x5a; 32]);

        let mut malformed = authorized.claims.clone();
        malformed.nonce.truncate(32);
        let malformed = AuthorizedCapability {
            claims: malformed,
            ..authorized
        };
        assert!(matches!(
            revision_chunk_locator(&malformed, chunk_id),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn revision_keyset_rejects_cross_operation_substitution() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let keyset = RevisionStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::RevisionStorage,
                &[(1, pair.public_key().as_ref().try_into().unwrap())],
            )
            .unwrap(),
        )
        .unwrap();
        let uses = [
            RevisionStorageCapabilityUse::WriteChunk,
            RevisionStorageCapabilityUse::ReadChunk,
            RevisionStorageCapabilityUse::DeleteChunk,
            RevisionStorageCapabilityUse::ReadLegacyPayload,
        ];
        for signed_use in uses {
            let operation = match signed_use {
                RevisionStorageCapabilityUse::WriteChunk => CapabilityOperation::WriteRevisionChunk,
                RevisionStorageCapabilityUse::ReadChunk => CapabilityOperation::ReadRevisionChunk,
                RevisionStorageCapabilityUse::DeleteChunk => {
                    CapabilityOperation::DeleteRevisionChunk
                }
                RevisionStorageCapabilityUse::ReadLegacyPayload => {
                    CapabilityOperation::ReadRevisionLegacyPayload
                }
            };
            let wire = filebelt_storage_protocol::sign_revision_storage_capability(
                &valid_claims(operation),
                signed_use,
                1,
                &pair,
            )
            .unwrap();
            for expected_use in uses {
                assert_eq!(
                    filebelt_storage_protocol::verify_revision_storage_capability(
                        &wire,
                        &keyset,
                        CAPABILITY_AUDIENCE,
                        expected_use,
                        120,
                    )
                    .is_ok(),
                    signed_use == expected_use,
                    "signed={signed_use:?} expected={expected_use:?}"
                );
            }
        }
    }

    #[test]
    fn every_worker_mount_operation_rejects_cross_operation_substitution() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let keyset = MountStorageKeyset::parse(
            &filebelt_capability_keyset::encode_keyset(
                filebelt_capability_keyset::KeyPurpose::MountStorage,
                &[(1, pair.public_key().as_ref().try_into().unwrap())],
            )
            .unwrap(),
        )
        .unwrap();
        for signed_purpose in MOUNT_USES {
            let claims = mount_claims(signed_purpose);
            let wire = filebelt_storage_protocol::sign_mount_storage_capability(
                &claims,
                signed_purpose,
                1,
                &pair,
            )
            .unwrap();
            for expected_purpose in MOUNT_USES {
                let verified = verify_mount_storage_capability(
                    &wire,
                    &keyset,
                    CAPABILITY_AUDIENCE,
                    expected_purpose,
                    110,
                );
                assert_eq!(
                    verified.is_ok(),
                    signed_purpose == expected_purpose,
                    "signed={signed_purpose:?} expected={expected_purpose:?}",
                );
            }
        }
    }

    #[test]
    fn unsigned_mount_modes_are_rejected_and_write_media_type_is_closed() {
        assert!(reject_unsigned_mount_mode(&HeaderMap::new()).is_ok());
        for value in ["data", "hole", "allocate", "anything"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                MOUNT_WRITE_MODE_HEADER,
                HeaderValue::from_str(value).unwrap(),
            );
            assert!(matches!(
                reject_unsigned_mount_mode(&headers),
                Err(AppError::BadRequest("unsigned_mount_write_mode"))
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert!(require_mount_binary_content_type(&headers).is_ok());
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream; charset=binary"),
        );
        assert!(matches!(
            require_mount_binary_content_type(&headers),
            Err(AppError::BadRequest("invalid_content_type"))
        ));
    }

    #[tokio::test]
    async fn mount_write_body_and_inclusive_range_are_exact_and_bounded() {
        let mut one_byte = mount_claims(MountStorageCapabilityUse::WriteData);
        one_byte.content_blake3 = blake3::hash(&[0x5a]).as_bytes().to_vec();
        assert_eq!(mount_claim_range_length(&one_byte).unwrap(), 1);
        assert_eq!(
            read_mount_body_exact(Body::from(vec![0x5a]), 1)
                .await
                .unwrap(),
            vec![0x5a]
        );
        assert!(validate_mount_write_body_digest(&one_byte, &[0x5a]).is_ok());
        assert!(matches!(
            validate_mount_write_body_digest(&one_byte, &[0x5b]),
            Err(AppError::Conflict("mount_write_digest_mismatch"))
        ));
        one_byte.content_blake3.pop();
        assert!(matches!(
            validate_mount_write_body_digest(&one_byte, &[0x5a]),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            read_mount_body_exact(Body::empty(), 1).await,
            Err(AppError::Conflict("mount_write_size_mismatch"))
        ));
        assert!(matches!(
            read_mount_body_exact(Body::from(vec![0; 2]), 1).await,
            Err(AppError::Conflict("mount_write_size_mismatch"))
        ));
        assert!(read_mount_body_exact(Body::empty(), 0).await.is_ok());
        assert!(matches!(
            read_mount_body_exact(Body::from(vec![1]), 0).await,
            Err(AppError::Conflict("mount_write_size_mismatch"))
        ));

        let mut maximum = one_byte.clone();
        maximum.range_start = 7;
        maximum.range_end = 7 + MAX_MOUNT_WRITE_BYTES - 1;
        assert_eq!(
            mount_claim_range_length(&maximum).unwrap(),
            MAX_MOUNT_WRITE_BYTES
        );
        maximum.range_end += 1;
        assert!(mount_claim_range_length(&maximum).unwrap() > MAX_MOUNT_WRITE_BYTES);
        maximum.range_start = u64::MAX;
        maximum.range_end = 0;
        assert!(matches!(
            mount_claim_range_length(&maximum),
            Err(AppError::Forbidden)
        ));
    }

    fn planned_mount_storage() -> MountWriteStorageRecord {
        let tenant_id = Uuid::new_v4();
        let drive_id = Uuid::new_v4();
        let backend_id = Uuid::new_v4();
        let payload = filebelt_database::PayloadRecord {
            tenant_id,
            payload_id: Uuid::new_v4(),
            backend_id,
            drive_id,
            locator: Uuid::new_v4(),
            layout: "chunked".into(),
            state: "staging".into(),
            size_bytes: 0,
            blake3: None,
        };
        MountWriteStorageRecord {
            write_session_id: Uuid::new_v4(),
            base_version_id: None,
            logical_size_bytes: 65_537,
            reserved_bytes: 65_537,
            state: "open".into(),
            staging_payload: payload,
            base_payload: None,
            base_parts: Vec::new(),
            planned_chunks: vec![
                filebelt_database::mount::MountWriteChunkPlan {
                    chunk_number: 0,
                    source_payload_id: None,
                    source_chunk_number: None,
                    staging_locator: Uuid::new_v4(),
                    size_bytes: 65_536,
                    dirty: true,
                },
                filebelt_database::mount::MountWriteChunkPlan {
                    chunk_number: 1,
                    source_payload_id: None,
                    source_chunk_number: None,
                    staging_locator: Uuid::new_v4(),
                    size_bytes: 1,
                    dirty: true,
                },
            ],
        }
    }

    #[test]
    fn mount_range_plan_rejects_reserved_unplanned_and_locator_substitution() {
        let valid = planned_mount_storage();
        assert!(validate_mount_chunk_plan(&valid, 65_536, 65_536).is_ok());
        assert!(matches!(
            validate_mount_chunk_plan(&valid, 65_536, 65_537),
            Err(AppError::Forbidden)
        ));

        let mut missing_tail = valid.clone();
        missing_tail.planned_chunks.pop();
        assert!(matches!(
            validate_mount_chunk_plan(&missing_tail, 65_536, 65_535),
            Err(AppError::Forbidden)
        ));

        let mut duplicate_locator = valid.clone();
        duplicate_locator.planned_chunks[1].staging_locator =
            duplicate_locator.planned_chunks[0].staging_locator;
        assert!(matches!(
            validate_mount_chunk_plan(&duplicate_locator, 65_536, 65_536),
            Err(AppError::Forbidden)
        ));

        let mut malformed_source = valid;
        malformed_source.planned_chunks[0].source_payload_id = Some(Uuid::new_v4());
        assert!(matches!(
            validate_mount_chunk_plan(&malformed_source, 65_536, 65_536),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn post_lock_range_readmission_rejects_every_authority_substitution() {
        let replaceable_capability_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        assert_ne!(replaceable_capability_id, operation_id);
        let before = MountWriteRangeAdmission {
            storage: planned_mount_storage(),
            operation_id,
            operation_ordinal: 1,
            operation: MountWriteRangeOperation::WriteData,
            content_blake3: Some([4; 32]),
            range_start: 65_536,
            range_end: 65_536,
            resulting_logical_size: 65_537,
        };
        let exact = before.clone();
        assert!(validate_mount_range_readmission(&before, &exact).is_ok());

        for substituted in [
            MountWriteRangeAdmission {
                operation_id: Uuid::new_v4(),
                ..exact.clone()
            },
            MountWriteRangeAdmission {
                operation_ordinal: 2,
                ..exact.clone()
            },
            MountWriteRangeAdmission {
                operation: MountWriteRangeOperation::Allocate,
                ..exact.clone()
            },
            MountWriteRangeAdmission {
                content_blake3: Some([5; 32]),
                ..exact.clone()
            },
            MountWriteRangeAdmission {
                range_start: 65_535,
                ..exact.clone()
            },
            MountWriteRangeAdmission {
                range_end: 65_535,
                ..exact.clone()
            },
            MountWriteRangeAdmission {
                resulting_logical_size: 65_536,
                ..exact.clone()
            },
        ] {
            assert!(matches!(
                validate_mount_range_readmission(&before, &substituted),
                Err(AppError::Forbidden)
            ));
        }

        let mut changed_plan = exact;
        changed_plan.storage.planned_chunks[1].staging_locator = Uuid::new_v4();
        assert!(matches!(
            validate_mount_range_readmission(&before, &changed_plan),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn cleanup_job_accepts_terminal_payload_crash_states_but_binds_identity() {
        let backend_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let mut storage = planned_mount_storage();
        storage.staging_payload.backend_id = backend_id;
        let cleanup = MountIoCleanupRecord {
            tenant_id: storage.staging_payload.tenant_id,
            write_session_id: storage.write_session_id,
            fencing_token: 9,
            storage: storage.clone(),
            nonce_digest: [3; 32],
            claims_digest: [4; 32],
            operation: MountIoOperation::WriteData,
            operation_id: Some(Uuid::new_v4()),
        };
        for (job_state, payload_state) in [
            ("leased", "staging"),
            ("leased", "deleting"),
            ("physical_deleted", "deleted"),
            ("physical_deleted", "abandoned"),
        ] {
            let mut payload = storage.staging_payload.clone();
            payload.state = payload_state.to_owned();
            let job = MountStagingCleanupJobRecord {
                tenant_id: cleanup.tenant_id,
                write_session_id: cleanup.write_session_id,
                backend_id,
                worker_id,
                payload,
                job_fencing_token: 10,
                job_state: job_state.to_owned(),
                reason: "pending_io_expired".to_owned(),
                completion_kind: "cleanup".to_owned(),
                source_nonce_digest: Some(cleanup.nonce_digest),
            };
            let expected_job = ExpectedMountCleanupJob {
                backend_id,
                worker_id,
                tenant_id: cleanup.tenant_id,
                write_session_id: cleanup.write_session_id,
                payload: &cleanup.storage.staging_payload,
                source_nonce_digest: Some(cleanup.nonce_digest),
                completion_kind: "cleanup",
            };
            assert!(validate_mount_cleanup_job(&expected_job, &job).is_ok());

            let mut substituted = job.clone();
            substituted.payload.locator = Uuid::new_v4();
            assert!(matches!(
                validate_mount_cleanup_job(&expected_job, &substituted),
                Err(AppError::Forbidden)
            ));
            let mut substituted_nonce = job;
            substituted_nonce.source_nonce_digest = Some([0x55; 32]);
            assert!(matches!(
                validate_mount_cleanup_job(&expected_job, &substituted_nonce),
                Err(AppError::Forbidden)
            ));
        }

        for job_state in ["leased", "completed"] {
            let lock_job = MountWriteLockCleanupJobRecord {
                tenant_id: cleanup.tenant_id,
                write_session_id: cleanup.write_session_id,
                backend_id,
                staging_payload_id: cleanup.storage.staging_payload.payload_id,
                worker_id,
                job_fencing_token: 11,
                job_state: job_state.to_owned(),
            };
            assert!(
                validate_mount_write_lock_cleanup_job(
                    backend_id,
                    worker_id,
                    cleanup.tenant_id,
                    cleanup.write_session_id,
                    Some(cleanup.storage.staging_payload.payload_id),
                    &lock_job,
                )
                .is_ok()
            );
            for substituted in [
                MountWriteLockCleanupJobRecord {
                    staging_payload_id: Uuid::new_v4(),
                    ..lock_job.clone()
                },
                MountWriteLockCleanupJobRecord {
                    backend_id: Uuid::new_v4(),
                    ..lock_job.clone()
                },
                MountWriteLockCleanupJobRecord {
                    worker_id: Uuid::new_v4(),
                    ..lock_job.clone()
                },
                MountWriteLockCleanupJobRecord {
                    job_state: "pending".to_owned(),
                    ..lock_job.clone()
                },
            ] {
                assert!(matches!(
                    validate_mount_write_lock_cleanup_job(
                        backend_id,
                        worker_id,
                        cleanup.tenant_id,
                        cleanup.write_session_id,
                        Some(cleanup.storage.staging_payload.payload_id),
                        &substituted,
                    ),
                    Err(AppError::Forbidden)
                ));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_waiting_cow_lock_does_not_leak_the_lock() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let storage = StorageLayout::new(root.path().join("payload"));
        storage.prepare().expect("prepare storage");
        let session = Uuid::new_v4();
        let first = storage.lock_cow(session).expect("hold first COW lock");
        let waiting_storage = storage.clone();
        let waiting =
            tokio::spawn(async move { acquire_mount_cow_lock(waiting_storage, session).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        waiting.abort();
        drop(first);

        let hexadecimal = session.simple().to_string();
        let lock_path = root
            .path()
            .join("payload/staging")
            .join(&hexadecimal[0..2])
            .join(&hexadecimal[2..4])
            .join(format!(".{session}.cow.lock"));
        tokio::time::timeout(Duration::from_secs(2), async {
            while lock_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled stale waiter removed its recreated lock inode");

        let recovered = tokio::time::timeout(
            Duration::from_secs(2),
            acquire_mount_cow_lock(storage.clone(), session),
        )
        .await
        .expect("cancelled blocking task eventually released its guard")
        .expect("reacquire COW lock");
        drop(recovered);
        assert!(
            !lock_path.exists(),
            "normal guard drop removes its lock inode"
        );
    }

    #[test]
    fn mount_replay_identity_is_shared_across_all_operations() {
        let nonce = [13_u8; 32];
        let digest = nonce_digest(b"filebelt-mount-capability-nonce-v2\0", &nonce);
        for operation in [
            "mount_write_data",
            "mount_deallocate",
            "mount_allocate",
            "mount_seek_data",
            "mount_seek_hole",
            "mount_flush",
            "mount_finalize",
            "mount_abort",
            "mount_delete_staging",
        ] {
            // The operation is audit metadata, not part of the unique nonce
            // identity, so reusing one nonce for another operation conflicts.
            assert_eq!(
                digest,
                nonce_digest(b"filebelt-mount-capability-nonce-v2\0", &nonce),
                "operation={operation}",
            );
        }
    }

    #[test]
    fn worker_receipt_identity_binds_full_claims_and_write_content_digest() {
        let claims = mount_claims(MountStorageCapabilityUse::WriteData);
        let request = MountIoRequest::from_claims(&claims, MountIoOperation::WriteData).unwrap();
        assert_eq!(
            request.capability_id,
            parse_required_mount_uuid(&claims.capability_id).unwrap()
        );
        assert_eq!(request.range_start, i64::try_from(claims.range_start).ok());
        assert_eq!(request.range_end, i64::try_from(claims.range_end).ok());
        assert_eq!(request.content_blake3, Some([4; 32]));

        for changed in [
            {
                let mut changed = claims.clone();
                changed.content_blake3[0] ^= 1;
                changed
            },
            {
                let mut changed = claims.clone();
                changed.range_end += 1;
                changed
            },
            {
                let mut changed = claims.clone();
                changed.fencing_token += 1;
                changed
            },
        ] {
            let changed = MountIoRequest::from_claims(&changed, MountIoOperation::WriteData)
                .expect("locally well-formed changed receipt identity");
            assert_ne!(request.claims_digest, changed.claims_digest);
        }

        for (purpose, operation) in [
            (MountStorageCapabilityUse::Flush, MountIoOperation::Flush),
            (
                MountStorageCapabilityUse::Finalize,
                MountIoOperation::Finalize,
            ),
            (MountStorageCapabilityUse::Abort, MountIoOperation::Abort),
            (
                MountStorageCapabilityUse::DeleteStaging,
                MountIoOperation::DeleteStaging,
            ),
        ] {
            let claims = mount_claims(purpose);
            let request = MountIoRequest::from_claims(&claims, operation).unwrap();
            assert_eq!(
                request.capability_id,
                parse_required_mount_uuid(&claims.capability_id).unwrap()
            );
            assert_eq!(request.range_start, None);
            assert_eq!(request.range_end, None);
        }
    }

    #[test]
    fn private_mount_routes_and_responses_are_exact() {
        let source = include_str!("main.rs");
        for route in [
            "\"/io/v1/mount-writes/{write_session_id}\",\n            put(mount_write_data)",
            "\"/io/v1/mount-writes/{write_session_id}/deallocate\",\n            post(deallocate_mount_write)",
            "\"/io/v1/mount-writes/{write_session_id}/allocate\",\n            post(allocate_mount_write)",
            "\"/io/v1/mount-writes/{write_session_id}/seek-data\",\n            get(seek_mount_data)",
            "\"/io/v1/mount-writes/{write_session_id}/seek-hole\",\n            get(seek_mount_hole)",
            "\"/io/v1/mount-writes/{write_session_id}/flush\",\n            post(flush_mount_write)",
            "\"/io/v1/mount-writes/{write_session_id}/finalize\",\n            post(finalize_mount_write)",
            "\"/io/v1/mount-writes/{write_session_id}/abort\",\n            post(abort_mount_write)",
            "\"/io/v1/mount-staging/{write_session_id}\",\n            axum::routing::delete(delete_mount_staging)",
        ] {
            assert!(source.contains(route), "missing exact route {route}");
        }
        let write_session_id = Uuid::new_v4();
        assert_eq!(
            completed_mount_range_result(
                write_session_id,
                MountIoCompletion::RangeMutation {
                    logical_size_bytes: 1,
                    reservation_delta_bytes: 1,
                },
            )
            .unwrap()
            .0
            .state,
            "staging"
        );
        assert_eq!(
            completed_mount_manifest_result(
                write_session_id,
                MountIoCompletion::Flush {
                    logical_size_bytes: 0,
                    blake3: [0; 32],
                    chunks: Vec::new(),
                },
                false,
            )
            .unwrap()
            .0
            .state,
            "flushed"
        );
        assert_eq!(
            completed_mount_manifest_result(
                write_session_id,
                MountIoCompletion::Finalize {
                    logical_size_bytes: 0,
                    blake3: [0; 32],
                    chunks: Vec::new(),
                },
                true,
            )
            .unwrap()
            .0
            .state,
            "finalized"
        );
        assert_eq!(
            completed_mount_staging_result(write_session_id, MountIoCompletion::Abort, false)
                .unwrap()
                .0
                .state,
            "aborted"
        );
        assert_eq!(
            completed_mount_staging_result(
                write_session_id,
                MountIoCompletion::DeleteStaging,
                true,
            )
            .unwrap()
            .0
            .state,
            "deleted"
        );
        assert!(source.contains("struct MountSeekResult {\n    offset: Option<u64>"));
    }

    #[test]
    fn completed_mount_receipts_are_typed_and_cleanup_replays_stable_conflict() {
        let write_session_id = Uuid::new_v4();
        assert!(
            completed_mount_range_result(
                write_session_id,
                MountIoCompletion::Seek { offset: Some(1) }
            )
            .is_err()
        );
        assert!(
            completed_mount_seek_result(MountIoCompletion::RangeMutation {
                logical_size_bytes: 1,
                reservation_delta_bytes: 0,
            })
            .is_err()
        );
        assert!(
            completed_mount_manifest_result(
                write_session_id,
                MountIoCompletion::Finalize {
                    logical_size_bytes: 0,
                    blake3: [0; 32],
                    chunks: Vec::new(),
                },
                false,
            )
            .is_err()
        );
        assert!(
            completed_mount_staging_result(write_session_id, MountIoCompletion::Abort, true,)
                .is_err()
        );
        for result in [
            completed_mount_range_result(write_session_id, MountIoCompletion::Cleanup).map(|_| ()),
            completed_mount_seek_result(MountIoCompletion::Cleanup).map(|_| ()),
            completed_mount_manifest_result(write_session_id, MountIoCompletion::Cleanup, false)
                .map(|_| ()),
            completed_mount_staging_result(write_session_id, MountIoCompletion::Cleanup, false)
                .map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(AppError::Conflict("mount_io_recovered"))
            ));
        }
    }

    #[test]
    fn mount_mutations_revalidate_under_the_cross_process_lock() {
        let source = include_str!("main.rs");
        for (start, end, range_admission, physical, completion) in [
            (
                "async fn mutate_mount_range(",
                "async fn seek_mount_data(",
                true,
                "storage.write_cow_at(",
                ".complete_mount_io_operation(",
            ),
            (
                "async fn seek_mount_range(",
                "async fn flush_mount_write(",
                true,
                "storage.cow_next_data(",
                ".complete_mount_io_operation(",
            ),
            (
                "async fn flush_mount_write(",
                "async fn finalize_mount_write(",
                false,
                "storage.sync_cow(",
                ".complete_mount_io_flush(",
            ),
            (
                "async fn finalize_mount_write(",
                "async fn abort_mount_write(",
                false,
                "storage.publish_cow(",
                ".complete_mount_io_finalize(",
            ),
            (
                "async fn abort_mount_write(",
                "async fn delete_mount_staging(",
                false,
                "storage.abort_cow(",
                ".complete_mount_io_abort(",
            ),
        ] {
            let handler = mount_handler_source(source, start, end);
            let lock = handler.find("acquire_mount_cow_lock(").unwrap();
            let receipts = handler
                .match_indices(".begin_mount_io_operation(")
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            assert_eq!(receipts.len(), 2, "handler={start}");
            let physical = handler.find(physical).unwrap();
            assert!(receipts[0] < lock, "handler={start}");
            assert!(
                lock < receipts[1] && receipts[1] < physical,
                "handler={start}"
            );
            if range_admission {
                let admissions = handler
                    .match_indices(".admit_mount_write_range(")
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                assert_eq!(admissions.len(), 3, "handler={start}");
                assert!(admissions[0] < receipts[0] && receipts[0] < lock);
                assert!(receipts[0] < admissions[1] && admissions[1] < lock);
                assert!(receipts[1] < admissions[2] && admissions[2] < physical);
            }
            assert!(
                physical < handler.find(completion).unwrap(),
                "the DB transition and receipt must complete after physical I/O: {start}"
            );
        }
        let write = mount_handler_source(
            source,
            "async fn mutate_mount_range(",
            "async fn seek_mount_data(",
        );
        assert!(
            write.find("validate_mount_write_body_digest(").unwrap()
                < write.find(".begin_mount_io_operation(").unwrap(),
            "WriteData body verification must precede pending receipt creation"
        );
        assert!(
            write.find(".admit_mount_write_range(").unwrap()
                < write.find("read_mount_body_exact(").unwrap(),
            "authoritative range/plan admission must precede body allocation"
        );
        assert!(write.contains("MountIoLookup::Pending"));
        assert!(write.contains("MountIoLookup::Completed"));
        assert!(write.contains("let capability_id = io_request.capability_id;"));
        assert!(write.contains("let stable_operation_id = record.operation_id;"));
        assert!(write.contains("write_session_id,\n                stable_operation_id,"));

        for (start, end, legacy) in [
            (
                "async fn flush_mount_write(",
                "async fn finalize_mount_write(",
                ".mark_mount_write_flushed(",
            ),
            (
                "async fn finalize_mount_write(",
                "async fn abort_mount_write(",
                ".finalize_mount_write(",
            ),
            (
                "async fn abort_mount_write(",
                "async fn delete_mount_staging(",
                ".begin_mount_write_abort(",
            ),
        ] {
            let handler = mount_handler_source(source, start, end);
            assert!(
                !handler.contains(legacy),
                "legacy split transition: {start}"
            );
            assert!(!handler.contains(".complete_mount_io_operation("));
        }
        let abort = mount_handler_source(
            source,
            "async fn abort_mount_write(",
            "async fn delete_mount_staging(",
        );
        assert!(!abort.contains(".finish_mount_write_abort("));

        let finalize = mount_handler_source(
            source,
            "async fn finalize_mount_write(",
            "async fn abort_mount_write(",
        );
        let completed = finalize.find(".complete_mount_io_finalize(").unwrap();
        let terminal_lock_removal = finalize
            .rfind("cleanup_mount_write_lock(")
            .expect("Finalize enters its leased terminal lock cleanup");
        assert!(
            completed < terminal_lock_removal,
            "Finalize must retain the COW lock through the atomic DB transition"
        );
        assert_eq!(
            finalize.matches("cleanup_mount_write_lock(").count(),
            3,
            "normal completion and both completed-retry paths repair terminal lock state"
        );
        let lock_cleanup = mount_handler_source(
            source,
            "async fn cleanup_mount_write_lock(",
            "fn validate_mount_write_lock_cleanup_job(",
        );
        let claimed = lock_cleanup
            .find(".claim_mount_write_lock_cleanup(")
            .unwrap();
        let heartbeat = lock_cleanup
            .find(".heartbeat_mount_write_lock_cleanup(")
            .unwrap();
        let removed = lock_cleanup.find("remove_mount_cow_lock(").unwrap();
        let acknowledged = lock_cleanup
            .find(".complete_mount_write_lock_cleanup(")
            .unwrap();
        assert!(claimed < heartbeat && heartbeat < removed && removed < acknowledged);
        assert!(!lock_cleanup.contains("delete_cow_staging"));
    }

    #[test]
    fn request_cleanup_uses_the_authoritative_two_phase_job_machine() {
        let source = include_str!("main.rs");
        let recovery = mount_handler_source(
            source,
            "async fn recover_expired_mount_io(",
            "fn validate_mount_range_admission(",
        );
        let claim = recovery
            .find(".claim_mount_staging_cleanup(")
            .expect("exact cleanup claim");
        let revalidate = recovery
            .find(".heartbeat_mount_staging_cleanup(")
            .expect("post-wait lease revalidation");
        let deleted = recovery
            .find("storage.delete_cow_staging(")
            .expect("dual physical deletion");
        let marked = recovery
            .find(".mark_mount_staging_cleanup_physical_deleted(")
            .expect("nonterminal physical marker");
        let unlocked = recovery
            .find("remove_mount_cow_lock(")
            .expect("verified lock removal");
        let completed = recovery
            .find(".complete_mount_staging_cleanup(")
            .expect("terminal completion");
        assert!(claim < revalidate && revalidate < deleted);
        assert!(deleted < marked && marked < unlocked && unlocked < completed);
        assert!(!recovery.contains("complete_mount_io_cleanup"));
    }

    #[test]
    fn ordinary_delete_staging_uses_the_same_leased_two_phase_job() {
        let source = include_str!("main.rs");
        let deletion = mount_handler_source(
            source,
            "async fn delete_mount_staging(",
            "async fn read_document_version(",
        );
        let begin = deletion
            .find(".begin_mount_io_operation(")
            .expect("exact pending receipt");
        let claim = deletion
            .find(".claim_mount_staging_cleanup(")
            .expect("leased cleanup claim");
        let validated = deletion
            .find("validate_mount_cleanup_job(")
            .expect("exact job identity");
        let cleanup = deletion
            .find("cleanup_mount_staging_job(")
            .expect("two-phase physical cleanup");
        let lookup = deletion
            .find(".lookup_mount_io_completion(")
            .expect("stored typed outcome");
        assert!(begin < claim && claim < validated && validated < cleanup && cleanup < lookup);
        assert!(deletion.contains("\"delete_staging\""));
        assert!(!deletion.contains("claim_mount_staging_deletion"));
        assert!(!deletion.contains("complete_mount_staging_deletion"));
        assert!(!deletion.contains("storage.delete_cow_staging"));
        assert!(!deletion.contains("complete_mount_io_operation"));
    }

    #[tokio::test]
    async fn sparse_unsupported_error_is_stable() {
        let response = storage_error(StorageError::UnsupportedFilesystem).into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("sparse_not_supported")
        );
    }

    #[test]
    fn finalization_claim_precedes_detached_filesystem_work() {
        let source = include_str!("main.rs");
        let handler = source
            .split_once("async fn finalize_upload")
            .expect("finalize handler exists")
            .1
            .split_once("async fn download")
            .expect("download follows finalize helpers")
            .0;
        let claim = handler
            .find(".claim_upload_finalization(")
            .expect("database claim exists");
        let detached = handler
            .find("tokio::spawn(async move")
            .expect("detached orchestration exists");
        let filesystem = handler
            .find("storage.finalize(")
            .expect("filesystem finalization exists");
        assert!(claim < detached && detached < filesystem);
        assert!(handler.contains("heartbeat_upload_finalization("));
        assert!(handler.contains("abort_upload_finalization("));
    }

    #[test]
    fn document_finalize_removes_only_the_redundant_staging_link_after_db_success() {
        let source = include_str!("main.rs");
        let handler = source
            .split_once("async fn finalize_document_revision")
            .expect("document finalize handler exists")
            .1
            .split_once("fn validate_document_revision_capability")
            .expect("capability validation follows document finalize")
            .0;
        let finalized = handler
            .find(".finalize_document_revision(")
            .expect("database finalization exists");
        let cleanup = handler
            .find("storage.remove_staging_locator(payload.locator)")
            .expect("staging link cleanup exists");
        assert!(finalized < cleanup);
        assert!(handler.contains("document staging cleanup deferred"));
    }
}

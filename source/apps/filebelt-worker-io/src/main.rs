// SPDX-License-Identifier: Apache-2.0

//! Capability-limited FileBelt POSIX I/O worker.

#![deny(unsafe_code)]

use std::collections::VecDeque;
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
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::collaboration::{
    CollaborationAuthorizationContext, CollaborationAuthorizationGenerations,
    CollaborationObjectRecord,
};
use filebelt_database::mount::MountReadCapabilityFence;
use filebelt_database::{Database, DatabaseError, UploadRecord};
use filebelt_runtime::{
    MtlsListener, OperationsState, certificate_not_after_unix_seconds, init_telemetry,
    install_crypto_provider, observe_request, operations_router, trace_request, wait_for_shutdown,
};
use filebelt_storage::{DownloadSegment, StorageError, StorageLayout};
use filebelt_storage_protocol::{
    CapabilityClaims, CapabilityOperation, MountCapabilityClaims, MountCapabilityOperation,
    VerificationKey, unix_time_now, verify_capability, verify_mount_capability,
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
    keys: Arc<Vec<VerificationKey>>,
    generation_recheck: Duration,
    tenant_id: Uuid,
    backend_id: Uuid,
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
enum AppError {
    BadRequest(&'static str),
    NotFound(&'static str),
    Unauthorized,
    Forbidden,
    Conflict(&'static str),
    Range,
    Unavailable,
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
    let (initial_total, initial_free) = report_capacity(
        &database,
        tenant_id,
        config.storage.backend_id,
        storage.root(),
        true,
    )
    .await?;
    let keys = load_verification_keys(
        &config.keys.capability_public_key_file,
        config.keys.current_generation,
    )?;
    let storage_ready = Arc::new(AtomicBool::new(true));
    let state = AppState {
        database,
        storage,
        keys: Arc::new(keys),
        generation_recheck: Duration::from_secs(config.limits.generation_recheck_seconds),
        tenant_id,
        backend_id: config.storage.backend_id,
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
    consume_mount_nonce(&state, &authorized).await?;
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
    let upload = state
        .database
        .upload_for_payload(authorized.fence.tenant_id, payload.payload_id)
        .await?;
    let parts = state
        .database
        .upload_parts(authorized.fence.tenant_id, upload.upload_id)
        .await?;
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
    let claims = verify_mount_capability(
        &wire,
        &state.keys,
        CAPABILITY_AUDIENCE,
        MountCapabilityOperation::Read,
        now,
    )
    .map_err(|_| AppError::Unauthorized)?;
    let fence = MountReadCapabilityFence {
        tenant_id: parse_required_uuid(&claims.tenant_id)?,
        principal_id: parse_required_uuid(&claims.principal_id)?,
        mount_session_id: parse_required_uuid(&claims.mount_session_id)?,
        credential_id: parse_required_uuid(&claims.credential_id)?,
        handle_id: parse_required_uuid(&claims.grant_id)?,
        drive_id: parse_required_uuid(&claims.drive_id)?,
        node_id: parse_required_uuid(&claims.resource_id)?,
        version_id: parse_required_uuid(&claims.version_id)?,
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

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    operation: CapabilityOperation,
) -> Result<AuthorizedCapability, AppError> {
    let wire = capability_wire(headers).ok_or(AppError::Unauthorized)?;
    let now = unix_time_now().map_err(|_| AppError::Unauthorized)?;
    let claims = verify_capability(&wire, &state.keys, CAPABILITY_AUDIENCE, operation, now)
        .map_err(|_| AppError::Unauthorized)?;
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
    authorized: &AuthorizedMountRead,
) -> Result<(), AppError> {
    let digest = nonce_digest(
        b"filebelt-mount-capability-nonce-v2\0",
        &authorized.claims.nonce,
    );
    state
        .database
        .consume_capability_nonce(
            authorized.fence.tenant_id,
            &digest,
            "mount_read",
            authorized.claims.expires_at_unix_seconds,
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

fn load_verification_keys(
    path: &FilePath,
    current_generation: u32,
) -> Result<Vec<VerificationKey>, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() == 32 {
        return Ok(vec![VerificationKey {
            generation: current_generation,
            public_key: bytes,
        }]);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "capability public keyset is invalid".to_owned())?;
    let mut lines = text.lines();
    if lines.next() != Some("filebelt-capability-keyset-v1") {
        return Err("capability public keyset header is invalid".into());
    }
    let mut keys = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (generation, encoded) = line
            .split_once(':')
            .ok_or_else(|| "capability public key entry is invalid".to_owned())?;
        let generation = generation
            .parse::<u32>()
            .map_err(|_| "capability public key generation is invalid".to_owned())?;
        let public_key = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "capability public key is invalid".to_owned())?;
        if generation == 0
            || public_key.len() != 32
            || keys
                .iter()
                .any(|key: &VerificationKey| key.generation == generation)
        {
            return Err("capability public key entry is invalid".into());
        }
        keys.push(VerificationKey {
            generation,
            public_key,
        });
    }
    if keys.is_empty() || !keys.iter().any(|key| key.generation == current_generation) {
        return Err("current capability key generation is absent".into());
    }
    Ok(keys)
}

fn storage_error(error: StorageError) -> AppError {
    match error {
        StorageError::StateConflict => AppError::Conflict("storage_state_conflict"),
        StorageError::CorruptObject | StorageError::UnsafeObject => {
            AppError::Conflict("storage_integrity_failure")
        }
        StorageError::InvalidContent => AppError::Conflict("content_profile_invalid"),
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
            DatabaseError::AdmissionLimited => Self::Unavailable,
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

    fn claims(start: u64, end: u64) -> CapabilityClaims {
        CapabilityClaims {
            range_start: start,
            range_end: end,
            ..CapabilityClaims::default()
        }
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
        std::fs::write(
            &path,
            format!(
                "filebelt-capability-keyset-v1\n1:{}\n2:{}\n",
                URL_SAFE_NO_PAD.encode([1_u8; 32]),
                URL_SAFE_NO_PAD.encode([2_u8; 32])
            ),
        )
        .expect("write keyset");
        let keys = load_verification_keys(&path, 2).expect("valid keyset");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[1].generation, 2);
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

// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-authoritative coordinator for immutable text and binary revisions.
//!
//! The coordinator never accepts browser traffic or a payload mount.  It
//! rechecks the API's session-bound Virtual ACL generation fence, then is the
//! sole Apache component permitted to use the isolated Git adapter protocol.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::signature::Ed25519KeyPair;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::post};
use clap::{Parser, Subcommand};
use filebelt_capability_keyset::RevisionStorageKeyset;
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::Database;
use filebelt_revision_protocol::{
    CompareRevisionCommits, RevisionComparisonKind, RevisionErrorCode, RevisionExecuteRequest,
    RevisionExecuteResponse, RevisionLineKind, revision_execute_request, revision_execute_response,
    validate_request, validate_response,
};
use filebelt_runtime::{
    MtlsListener, OperationsState, certificate_not_after_unix_seconds, init_telemetry,
    install_crypto_provider, operations_router, trace_request, wait_for_shutdown,
};
use filebelt_storage_protocol::{
    CapabilityClaims, CapabilityOperation, RevisionStorageCapabilityUse,
    sign_revision_storage_capability, unix_time_now,
};
use getrandom::fill as random_fill;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prost::Message as _;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;
use uuid::Uuid;

const ROLE: &str = "filebelt-revision";
const CONTENT_TYPE: &str = "application/json";
const ADAPTER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ADAPTER_RESPONSE_BYTES: usize = filebelt_revision_protocol::MAX_FRAME_BYTES;
const BACKFILL_LEASE_SECONDS: i64 = 90;
const BACKFILL_INTERVAL: Duration = Duration::from_secs(2);
const IO_RESPONSE_LIMIT: usize = 512 * 1024 * 1024;
const CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";

#[derive(Debug, Parser)]
#[command(name = ROLE, disable_version_flag = true)]
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
    tenant_id: Uuid,
    adapter: AdapterClient,
    io: IoClient,
    signer: Arc<Ed25519KeyPair>,
    signing_generation: u32,
    worker_id: Uuid,
    comparison_admission: Arc<ComparisonAdmission>,
}

struct ComparisonAdmission {
    global: Arc<Semaphore>,
    users: Mutex<HashMap<Uuid, Weak<Semaphore>>>,
    per_user: usize,
    active: Gauge,
    rejections: Counter,
}

struct ComparisonPermits {
    _global: OwnedSemaphorePermit,
    _user: OwnedSemaphorePermit,
    active: Gauge,
}

#[derive(Clone)]
struct AdapterClient {
    endpoint: String,
    server_name: ServerName<'static>,
    connector: TlsConnector,
}

#[derive(Clone)]
struct IoClient {
    client: reqwest::Client,
    base: Url,
}

/// The API performs the Virtual ACL decision and persists this exact fence.
/// No caller-controlled identity is accepted by the adapter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompareCommand {
    tenant_id: Uuid,
    user_id: Uuid,
    principal_id: Uuid,
    session_id: Uuid,
    drive_id: Uuid,
    node_id: Uuid,
    base_version_id: Uuid,
    target_version_id: Uuid,
    membership_generation: i64,
    drive_acl_generation: i64,
    namespace_generation: i64,
    resource_acl_generation: i64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparisonResponse {
    algorithm: &'static str,
    context_lines: u8,
    base_version_id: Uuid,
    target_version_id: Uuid,
    base_final_newline: bool,
    target_final_newline: bool,
    hunks: Vec<DiffHunk>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DiffHunk {
    base_start: u64,
    base_lines: u64,
    target_start: u64,
    target_lines: u64,
    lines: Vec<DiffLine>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DiffLine {
    kind: &'static str,
    base_line: Option<u64>,
    target_line: Option<u64>,
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    code: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceError {
    Forbidden,
    NotFound,
    TooLarge,
    Unavailable,
    Integrity,
    AdmissionLimited,
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(raw.as_slice(), [argument] if argument == "--version" || argument == "--build-info=json")
    {
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
                Err(error) => Err(anyhow!(error)),
            },
            Err(error) => Err(anyhow!(error)),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "revision coordinator stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<()> {
    if !config.revisions.enabled {
        bail!("revision coordinator is disabled");
    }
    let database_url = read_secret_string(
        config
            .revisions
            .database_url_file
            .as_ref()
            .ok_or_else(|| anyhow!("revision database URL is absent"))?,
    )?;
    let database = Database::connect(&database_url, config.database.max_connections).await?;
    database.health().await?;
    let tenant_id = database.tenant_by_slug(&config.tenant.slug).await?;
    let signing = config
        .revisions
        .capability_signing
        .as_ref()
        .ok_or_else(|| anyhow!("revision capability signing is absent"))?;
    let signer = Arc::new(
        Ed25519KeyPair::from_pkcs8(&std::fs::read(&signing.private_key_file)?)
            .map_err(|_| anyhow!("revision capability key is not Ed25519 PKCS#8"))?,
    );
    let keyset =
        RevisionStorageKeyset::parse(&std::fs::read_to_string(&signing.public_keyset_file)?)
            .map_err(|_| anyhow!("revision capability public keyset is invalid"))?;
    let probe = signer.sign(b"filebelt.revision.storage.keyset.self-check");
    keyset
        .verify(
            signing.current_generation,
            b"filebelt.revision.storage.keyset.self-check",
            probe.as_ref(),
        )
        .map_err(|_| anyhow!("revision capability private key does not match the keyset"))?;
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, {
        let database = database.clone();
        move || {
            let database = database.clone();
            async move { database.health().await.is_ok() }
        }
    });
    let comparison_admission = Arc::new(ComparisonAdmission::new(
        config.revisions.limits.global_comparisons,
        config.revisions.limits.per_user_comparisons,
        operations.register_gauge(
            "revision_comparisons_active",
            "Revision comparisons currently holding global and per-user admission slots.",
        ),
        operations.register_counter(
            "revision_comparison_admission_rejections",
            "Revision comparisons rejected by coordinator or adapter capacity admission.",
        ),
    ));
    let state = AppState {
        database: database.clone(),
        tenant_id,
        adapter: adapter_client(&config)?,
        io: io_client(&config)?,
        signer,
        signing_generation: signing.current_generation,
        worker_id: Uuid::new_v4(),
        comparison_admission,
    };
    let backfill_state = state.clone();
    tokio::spawn(async move {
        backfill_loop(backfill_state).await;
    });
    let application = Router::new()
        .route("/internal/v1/revision/compare", post(compare))
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::from_fn(trace_request))
        .with_state(state);
    let operations_listener = tokio::net::TcpListener::bind(config.listeners.operations).await?;
    let (operations_stop, operations_stopped) = tokio::sync::oneshot::channel();
    let operations_server = tokio::spawn(async move {
        axum::serve(operations_listener, operations_router(operations))
            .with_graceful_shutdown(async move {
                let _ = operations_stopped.await;
            })
            .await
            .map_err(anyhow::Error::from)
    });
    let listener = config.listeners.revision;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(listener).await?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.revision.as_ref())
                .ok_or_else(|| anyhow!("revision backend TLS is absent"))?;
            let listener = MtlsListener::bind(listener, tls)
                .await
                .map_err(anyhow::Error::msg)?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
    };
    if let Some(tls) = config
        .backend_tls
        .as_ref()
        .and_then(|tls| tls.revision.as_ref())
    {
        let _ = certificate_not_after_unix_seconds(tls).map_err(anyhow::Error::msg)?;
    }
    tracing::info!(%listener, "revision coordinator ready");
    let result = tokio::select! {
        result = &mut server => result.context("revision coordinator server task failed")?,
        () = wait_for_shutdown() => {
            let _ = stop.send(());
            if timeout(Duration::from_secs(45), &mut server).await.is_err() { server.abort(); }
            Ok(())
        }
    };
    let _ = operations_stop.send(());
    operations_server
        .await
        .context("revision operations server task failed")??;
    result
}

async fn compare(State(state): State<AppState>, Json(command): Json<CompareCommand>) -> Response {
    let result = compare_inner(&state, command).await;
    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error(error),
    }
}

impl ComparisonAdmission {
    fn new(global: u32, per_user: u32, active: Gauge, rejections: Counter) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global as usize)),
            users: Mutex::new(HashMap::new()),
            per_user: per_user as usize,
            active,
            rejections,
        }
    }

    fn try_acquire(&self, user_id: Uuid) -> Result<ComparisonPermits, ServiceError> {
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| self.rejected("global"))?;
        let user = {
            let mut users = self
                .users
                .lock()
                .expect("revision comparison admission lock poisoned");
            users.retain(|_, semaphore| semaphore.strong_count() != 0);
            if let Some(semaphore) = users.get(&user_id).and_then(Weak::upgrade) {
                semaphore
            } else {
                let semaphore = Arc::new(Semaphore::new(self.per_user));
                users.insert(user_id, Arc::downgrade(&semaphore));
                semaphore
            }
        };
        let user = user
            .try_acquire_owned()
            .map_err(|_| self.rejected("per_user"))?;
        self.active.inc();
        Ok(ComparisonPermits {
            _global: global,
            _user: user,
            active: self.active.clone(),
        })
    }

    fn record_adapter_rejection(&self) {
        let _ = self.rejected("git_process");
    }

    fn rejected(&self, scope: &'static str) -> ServiceError {
        self.rejections.inc();
        tracing::warn!(scope, "revision comparison admission limited");
        ServiceError::AdmissionLimited
    }
}

impl Drop for ComparisonPermits {
    fn drop(&mut self) {
        self.active.dec();
    }
}

async fn compare_inner(
    state: &AppState,
    command: CompareCommand,
) -> Result<ComparisonResponse, ServiceError> {
    if command.tenant_id != state.tenant_id {
        return Err(ServiceError::Forbidden);
    }
    let _permits = state.comparison_admission.try_acquire(command.user_id)?;
    let permitted = state
        .database
        .revision_authorization_fence_matches(
            command.tenant_id,
            command.session_id,
            command.user_id,
            command.principal_id,
            command.drive_id,
            command.node_id,
            command.membership_generation,
            command.drive_acl_generation,
            command.namespace_generation,
            command.resource_acl_generation,
        )
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    if !permitted {
        return Err(ServiceError::Forbidden);
    }
    let preference = state
        .database
        .text_preferences(command.tenant_id, command.user_id)
        .await
        .map_err(|_| ServiceError::Forbidden)?;
    let record = state
        .database
        .revision_comparison(
            command.tenant_id,
            command.drive_id,
            command.node_id,
            command.base_version_id,
            command.target_version_id,
        )
        .await
        .map_err(|error| match error {
            filebelt_database::DatabaseError::NotFound => ServiceError::NotFound,
            filebelt_database::DatabaseError::InvalidPersistedValue => ServiceError::Integrity,
            _ => ServiceError::Unavailable,
        })?;
    if record.base_size_bytes > preference.inline_limit_bytes
        || record.target_size_bytes > preference.inline_limit_bytes
    {
        return Err(ServiceError::TooLarge);
    }
    let request = RevisionExecuteRequest {
        request_id: Uuid::new_v4().hyphenated().to_string(),
        operation: Some(revision_execute_request::Operation::CompareCommits(
            CompareRevisionCommits {
                repository_id: record.repository_id.hyphenated().to_string(),
                base_commit_oid: record.base_commit_oid.clone(),
                target_commit_oid: record.target_commit_oid.clone(),
                kind: RevisionComparisonKind::LineDiff as i32,
            },
        )),
    };
    // The deadline covers every adapter round trip; no partial comparison can escape it.
    timeout(ADAPTER_TIMEOUT, async {
        let comparison = state.adapter.execute(request).await.inspect_err(|error| {
            if *error == ServiceError::AdmissionLimited {
                state.comparison_admission.record_adapter_rejection();
            }
        })?;
        comparison_response(command, comparison, &record)
    })
    .await
    .map_err(|_| ServiceError::Unavailable)?
}

async fn backfill_loop(state: AppState) {
    let mut interval = tokio::time::interval(BACKFILL_INTERVAL);
    loop {
        interval.tick().await;
        match state
            .database
            .lease_revision_backfill(state.tenant_id, state.worker_id, BACKFILL_LEASE_SECONDS)
            .await
        {
            Ok(Some(lease)) => {
                if let Err((code, detail)) = backfill_one(&state, &lease).await {
                    tracing::warn!(content_id=%lease.content_id, %code, "revision backfill item held");
                    let _ = state
                        .database
                        .hold_revision_backfill(
                            state.tenant_id,
                            lease.content_id,
                            lease.lease_owner,
                            lease.fencing_token,
                            code,
                            &detail,
                        )
                        .await;
                }
            }
            Ok(None) => {
                let _ = state
                    .database
                    .mark_revision_ready_if_complete(state.tenant_id)
                    .await;
            }
            Err(error) => tracing::warn!(%error, "revision backfill lease failed"),
        }
    }
}

async fn backfill_one(
    state: &AppState,
    lease: &filebelt_database::revision::RevisionBackfillLease,
) -> Result<(), (&'static str, String)> {
    let bytes = state
        .io
        .read_legacy(state, lease)
        .await
        .map_err(|error| ("legacy_payload_read", error))?;
    let digest = blake3::hash(&bytes);
    if lease.blake3.as_slice() != digest.as_bytes()
        || usize::try_from(lease.size_bytes).ok() != Some(bytes.len())
    {
        return Err((
            "legacy_payload_digest",
            "legacy payload digest or size does not match the immutable version".into(),
        ));
    }
    let class = classify(lease, &bytes);
    if class == "text" {
        if bytes.len() > filebelt_revision_protocol::MAX_TEXT_BYTES {
            return Err((
                "text_size_limit",
                "validated text exceeds the 100 MiB Git revision limit".into(),
            ));
        }
        // The node UUID is a stable, tenant-scoped repository identity. It
        // prevents a crash before the PostgreSQL projection from allocating
        // an unbounded sequence of orphan Git repositories on retry.
        let repository_id = lease.repository_id.unwrap_or(lease.node_id);
        let final_newline = bytes.last() == Some(&b'\n');
        let request = RevisionExecuteRequest {
            request_id: Uuid::new_v4().to_string(),
            operation: Some(revision_execute_request::Operation::PrepareCommit(
                filebelt_revision_protocol::PrepareRevisionCommit {
                    repository_id: repository_id.to_string(),
                    version_id: lease.version_id.to_string(),
                    ordinal: u64::try_from(lease.ordinal)
                        .map_err(|_| ("version_ordinal", "version ordinal is invalid".into()))?,
                    committed_at_unix_seconds: lease.created_at_unix_seconds,
                    content: bytes,
                    expected_old_commit_oid: lease.expected_head_oid.clone().unwrap_or_default(),
                    migration_import: true,
                },
            )),
        };
        let prepared = state.adapter.execute(request).await.map_err(|_| {
            (
                "git_prepare",
                "Git adapter could not prepare the immutable commit".into(),
            )
        })?;
        let revision_execute_response::Result::PreparedCommit(prepared) = prepared else {
            return Err((
                "git_prepare",
                "Git adapter returned an invalid prepare result".into(),
            ));
        };
        let reconcile = RevisionExecuteRequest {
            request_id: Uuid::new_v4().to_string(),
            operation: Some(revision_execute_request::Operation::ReconcileRef(
                filebelt_revision_protocol::ReconcileRevisionRef {
                    repository_id: repository_id.to_string(),
                    expected_old_commit_oid: lease.expected_head_oid.clone().unwrap_or_default(),
                    new_commit_oid: prepared.commit_oid.clone(),
                },
            )),
        };
        let reconciled = state.adapter.execute(reconcile).await.map_err(|_| {
            (
                "git_reconcile",
                "Git adapter could not reconcile the projected ref".into(),
            )
        })?;
        let revision_execute_response::Result::ReconcileResult(result) = reconciled else {
            return Err((
                "git_reconcile",
                "Git adapter returned an invalid reconciliation result".into(),
            ));
        };
        // A retry after ref publication but before the PostgreSQL commit sees
        // the desired ref already installed. Treat that exact observation as
        // success; any other head remains a conflict.
        if result.observed_commit_oid != prepared.commit_oid {
            return Err((
                "git_ref_conflict",
                "Git ref did not advance from the PostgreSQL-projected head".into(),
            ));
        }
        state
            .database
            .commit_git_backfill(
                lease,
                &prepared.commit_oid,
                &prepared.tree_oid,
                &prepared.blob_oid,
                final_newline,
                i64::try_from(prepared.repository_size_kib)
                    .ok()
                    .and_then(|size| size.checked_mul(1024))
                    .ok_or(("git_size", "Git repository size is invalid".into()))?,
            )
            .await
            .map_err(|_| {
                (
                    "git_commit",
                    "PostgreSQL rejected the fenced Git projection".into(),
                )
            })?;
        return Ok(());
    }
    let chunks = bytes
        .chunks(16 * 1024 * 1024)
        .map(|part| {
            (
                blake3::hash(part).as_bytes().to_vec(),
                i32::try_from(part.len()).unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let evidence = state
        .database
        .reserve_revision_chunks(lease, &chunks)
        .await
        .map_err(|_| {
            (
                "chunk_reserve",
                "PostgreSQL could not reserve shared chunks".into(),
            )
        })?;
    for (chunk, evidence) in bytes.chunks(16 * 1024 * 1024).zip(&evidence) {
        if evidence.newly_allocated {
            state
                .io
                .write_chunk(state, lease, evidence, chunk)
                .await
                .map_err(|error| ("chunk_publish", error))?;
        }
    }
    state
        .database
        .commit_chunk_backfill(lease, class, &evidence)
        .await
        .map_err(|_| {
            (
                "chunk_commit",
                "PostgreSQL rejected the fenced shared-chunk manifest".into(),
            )
        })
}

fn classify(
    lease: &filebelt_database::revision::RevisionBackfillLease,
    bytes: &[u8],
) -> &'static str {
    if is_office(lease.media_type.as_deref(), &lease.display_name) {
        return "office";
    }
    if lease.content_class_policy == "binary" {
        return "binary";
    }
    let intent = text_intent(lease.media_type.as_deref(), &lease.display_name);
    if intent && !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
        "text"
    } else {
        "binary"
    }
}

fn text_intent(media_type: Option<&str>, name: &str) -> bool {
    matches!(
        media_type,
        Some(
            "text/plain"
                | "text/markdown"
                | "text/csv"
                | "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-yaml"
        )
    ) || [
        "md", "markdown", "txt", "rst", "csv", "json", "yaml", "yml", "toml", "xml", "html", "css",
        "js", "ts", "rs", "py", "go", "java", "c", "h", "sh", "sql", "ini", "conf",
    ]
    .iter()
    .any(|extension| {
        name.rsplit('.')
            .next()
            .is_some_and(|value| value.eq_ignore_ascii_case(extension))
    })
}

fn is_office(media_type: Option<&str>, name: &str) -> bool {
    matches!(
        media_type,
        Some(
            "application/vnd.oasis.opendocument.text"
                | "application/vnd.oasis.opendocument.spreadsheet"
                | "application/vnd.oasis.opendocument.presentation"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        )
    ) || ["odt", "ods", "odp", "docx", "xlsx", "pptx"]
        .iter()
        .any(|extension| {
            name.rsplit('.')
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
        })
}

fn comparison_response(
    command: CompareCommand,
    comparison: revision_execute_response::Result,
    record: &filebelt_database::revision::RevisionComparisonRecord,
) -> Result<ComparisonResponse, ServiceError> {
    let revision_execute_response::Result::Comparison(comparison) = comparison else {
        return Err(ServiceError::Integrity);
    };
    if RevisionComparisonKind::try_from(comparison.kind).ok()
        != Some(RevisionComparisonKind::LineDiff)
    {
        return Err(ServiceError::Integrity);
    }
    if comparison.line_diff.len() > filebelt_revision_protocol::MAX_LINE_DIFF_HUNKS {
        return Err(ServiceError::TooLarge);
    }
    let mut total_lines = 0_usize;
    let mut hunks = Vec::with_capacity(comparison.line_diff.len());
    for hunk in comparison.line_diff {
        let mut base_line = hunk.old_start;
        let mut target_line = hunk.new_start;
        let mut lines = Vec::with_capacity(hunk.lines.len());
        for line in hunk.lines {
            total_lines = total_lines.checked_add(1).ok_or(ServiceError::TooLarge)?;
            if total_lines > filebelt_revision_protocol::MAX_LINE_DIFF_LINES {
                return Err(ServiceError::TooLarge);
            }
            let (kind, at_base, at_target) = match RevisionLineKind::try_from(line.kind).ok() {
                Some(RevisionLineKind::Context) => {
                    let result = ("context", Some(base_line), Some(target_line));
                    base_line += 1;
                    target_line += 1;
                    result
                }
                Some(RevisionLineKind::Deleted) => {
                    let result = ("delete", Some(base_line), None);
                    base_line += 1;
                    result
                }
                Some(RevisionLineKind::Added) => {
                    let result = ("add", None, Some(target_line));
                    target_line += 1;
                    result
                }
                _ => return Err(ServiceError::Integrity),
            };
            if line.text.len() > 1_048_576 {
                return Err(ServiceError::TooLarge);
            }
            lines.push(DiffLine {
                kind,
                base_line: at_base,
                target_line: at_target,
                text: line.text,
            });
        }
        hunks.push(DiffHunk {
            base_start: hunk.old_start,
            base_lines: hunk.old_lines,
            target_start: hunk.new_start,
            target_lines: hunk.new_lines,
            lines,
        });
    }
    let encoded = serde_json_size(&hunks)?;
    if encoded > filebelt_revision_protocol::MAX_LINE_DIFF_OUTPUT_BYTES {
        return Err(ServiceError::TooLarge);
    }
    Ok(ComparisonResponse {
        algorithm: "git-histogram-v1",
        context_lines: 3,
        base_version_id: command.base_version_id,
        target_version_id: command.target_version_id,
        base_final_newline: record.base_final_newline,
        target_final_newline: record.target_final_newline,
        hunks,
    })
}

fn serde_json_size<T: Serialize>(value: &T) -> Result<usize, ServiceError> {
    serde_json::to_vec(value)
        .map(|value| value.len())
        .map_err(|_| ServiceError::Integrity)
}

impl AdapterClient {
    async fn execute(
        &self,
        request: RevisionExecuteRequest,
    ) -> Result<revision_execute_response::Result, ServiceError> {
        validate_request(&request).map_err(|_| ServiceError::Integrity)?;
        let body = request.encode_to_vec();
        if body.len() > filebelt_revision_protocol::MAX_FRAME_BYTES {
            return Err(ServiceError::TooLarge);
        }
        let tcp = TcpStream::connect(&self.endpoint)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        let mut stream = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        stream
            .write_all(
                &(u32::try_from(body.len()).map_err(|_| ServiceError::TooLarge)?).to_be_bytes(),
            )
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        stream
            .write_all(&body)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        stream
            .flush()
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        let mut prefix = [0_u8; 4];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_ADAPTER_RESPONSE_BYTES {
            return Err(ServiceError::TooLarge);
        }
        let mut body = vec![0_u8; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        let response = RevisionExecuteResponse::decode(body.as_slice())
            .map_err(|_| ServiceError::Integrity)?;
        validate_response(&request, &response).map_err(|_| ServiceError::Integrity)?;
        adapter_result(response.result)
    }
}

fn adapter_result(
    result: Option<revision_execute_response::Result>,
) -> Result<revision_execute_response::Result, ServiceError> {
    match result.ok_or(ServiceError::Integrity)? {
        revision_execute_response::Result::Error(error) => {
            match RevisionErrorCode::try_from(error.code).ok() {
                Some(RevisionErrorCode::NotFound) => Err(ServiceError::NotFound),
                Some(RevisionErrorCode::ResourceExhausted) => Err(ServiceError::TooLarge),
                Some(RevisionErrorCode::IntegrityFailure) => Err(ServiceError::Integrity),
                Some(RevisionErrorCode::AdmissionLimited) => Err(ServiceError::AdmissionLimited),
                _ => Err(ServiceError::Unavailable),
            }
        }
        result => Ok(result),
    }
}

fn adapter_client(config: &Config) -> Result<AdapterClient> {
    let revision = &config.revisions;
    let endpoint = revision
        .adapter_url
        .as_ref()
        .ok_or_else(|| anyhow!("revision adapter URL is absent"))?;
    let (host, port) = host_port(endpoint)?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(
        revision
            .adapter_server_ca_file
            .as_ref()
            .ok_or_else(|| anyhow!("revision adapter CA is absent"))?,
    )? {
        roots
            .add(certificate?)
            .map_err(|_| anyhow!("revision adapter CA is invalid"))?;
    }
    let certificates = CertificateDer::pem_file_iter(
        revision
            .adapter_client_certificate_chain_file
            .as_ref()
            .ok_or_else(|| anyhow!("revision adapter client certificate is absent"))?,
    )?
    .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        bail!("revision adapter client certificate chain is empty");
    }
    let private_key = PrivateKeyDer::from_pem_file(
        revision
            .adapter_client_private_key_file
            .as_ref()
            .ok_or_else(|| anyhow!("revision adapter client key is absent"))?,
    )?;
    let client = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| anyhow!(error))?
    .with_root_certificates(roots)
    .with_client_auth_cert(certificates, private_key)
    .map_err(|error| anyhow!(error))?;
    Ok(AdapterClient {
        endpoint: format!("{host}:{port}"),
        server_name: ServerName::try_from(host)
            .map_err(|_| anyhow!("revision adapter TLS server name is invalid"))?,
        connector: TlsConnector::from(Arc::new(client)),
    })
}

fn io_client(config: &Config) -> Result<IoClient> {
    let revision = &config.revisions;
    let base = revision
        .io_url
        .clone()
        .ok_or_else(|| anyhow!("revision I/O URL is absent"))?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(90));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let certificate = std::fs::read(
            revision
                .io_client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("revision I/O client certificate is absent"))?,
        )?;
        let key = std::fs::read(
            revision
                .io_client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("revision I/O client key is absent"))?,
        )?;
        let mut identity = certificate;
        identity.extend_from_slice(b"\n");
        identity.extend_from_slice(&key);
        builder = builder
            .https_only(true)
            .tls_built_in_root_certs(false)
            .identity(reqwest::Identity::from_pem(&identity)?);
        for certificate in reqwest::Certificate::from_pem_bundle(&std::fs::read(
            revision
                .io_server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("revision I/O CA is absent"))?,
        )?)? {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(IoClient {
        client: builder.build()?,
        base,
    })
}

impl IoClient {
    async fn read_legacy(
        &self,
        state: &AppState,
        lease: &filebelt_database::revision::RevisionBackfillLease,
    ) -> Result<Vec<u8>, String> {
        if lease.size_bytes < 0
            || usize::try_from(lease.size_bytes)
                .ok()
                .is_none_or(|size| size > IO_RESPONSE_LIMIT)
        {
            return Err("legacy payload exceeds the coordinator process bound".into());
        }
        let capability = revision_capability(
            state,
            lease,
            RevisionStorageCapabilityUse::ReadLegacyPayload,
            lease.legacy_payload_id,
            u64::try_from(lease.size_bytes).map_err(|_| "legacy size invalid")?,
            &[],
        )?;
        let url = self
            .base
            .join(&format!(
                "io/v1/revision-legacy-payloads/{}",
                lease.legacy_payload_id
            ))
            .map_err(|_| "invalid revision I/O legacy URL")?;
        let response = self
            .client
            .get(url)
            .header("authorization", format!("fbcap1 {capability}"))
            .send()
            .await
            .map_err(|_| "revision I/O legacy request failed")?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > IO_RESPONSE_LIMIT as u64)
        {
            return Err("revision I/O legacy request rejected".into());
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "revision I/O legacy body failed")?;
        if bytes.len() > IO_RESPONSE_LIMIT {
            return Err("revision I/O legacy response exceeds process bound".into());
        }
        Ok(bytes.to_vec())
    }

    async fn write_chunk(
        &self,
        state: &AppState,
        lease: &filebelt_database::revision::RevisionBackfillLease,
        evidence: &filebelt_database::revision::RevisionChunkEvidence,
        body: &[u8],
    ) -> Result<(), String> {
        let mut nonce = evidence.blake3.clone();
        let mut suffix = [0_u8; 32];
        random_fill(&mut suffix).map_err(|_| "random capability nonce failed")?;
        nonce.extend_from_slice(&suffix);
        let capability = revision_capability(
            state,
            lease,
            RevisionStorageCapabilityUse::WriteChunk,
            evidence.id,
            u64::try_from(evidence.size_bytes).map_err(|_| "chunk size invalid")?,
            &nonce,
        )?;
        let url = self
            .base
            .join(&format!("io/v1/revision-chunks/{}", evidence.id))
            .map_err(|_| "invalid revision I/O chunk URL")?;
        let response = self
            .client
            .put(url)
            .header("authorization", format!("fbcap1 {capability}"))
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| "revision I/O chunk publish failed")?;
        if !response.status().is_success() {
            return Err("revision I/O chunk publish rejected".into());
        }
        Ok(())
    }
}

fn revision_capability(
    state: &AppState,
    lease: &filebelt_database::revision::RevisionBackfillLease,
    use_case: RevisionStorageCapabilityUse,
    payload_id: Uuid,
    size: u64,
    nonce: &[u8],
) -> Result<String, String> {
    let now = unix_time_now().map_err(|_| "clock is invalid")?;
    let mut random = [0_u8; 32];
    random_fill(&mut random).map_err(|_| "random capability nonce failed")?;
    let nonce = if nonce.is_empty() {
        random.to_vec()
    } else {
        nonce.to_vec()
    };
    sign_revision_storage_capability(
        &CapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: CAPABILITY_AUDIENCE.into(),
            operation: match use_case {
                RevisionStorageCapabilityUse::WriteChunk => {
                    CapabilityOperation::WriteRevisionChunk as i32
                }
                RevisionStorageCapabilityUse::ReadChunk => {
                    CapabilityOperation::ReadRevisionChunk as i32
                }
                RevisionStorageCapabilityUse::DeleteChunk => {
                    CapabilityOperation::DeleteRevisionChunk as i32
                }
                RevisionStorageCapabilityUse::ReadLegacyPayload => {
                    CapabilityOperation::ReadRevisionLegacyPayload as i32
                }
            },
            tenant_id: lease.tenant_id.to_string(),
            principal_id: lease.created_by.to_string(),
            session_id: Uuid::new_v4().to_string(),
            resource_id: lease.drive_id.to_string(),
            upload_id: lease.version_id.to_string(),
            payload_id: payload_id.to_string(),
            part_number: 0,
            range_start: 0,
            range_end: size.saturating_sub(1),
            resource_acl_generation: 0,
            membership_generation: 0,
            namespace_generation: 0,
            fencing_token: u64::try_from(lease.fencing_token).map_err(|_| "fence invalid")?,
            nonce,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now + 60,
            drive_acl_generation: 0,
            grant_id: lease.content_id.to_string(),
        },
        use_case,
        state.signing_generation,
        &state.signer,
    )
    .map_err(|_| "revision capability signing failed".to_owned())
}

fn host_port(url: &Url) -> Result<(String, u16)> {
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        bail!("revision adapter URL must not contain a path, query, or fragment");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("revision adapter URL has no host"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("revision adapter URL has no port"))?;
    Ok((host, port))
}

fn service_error(error: ServiceError) -> Response {
    let (status, code, retry_after) = match error {
        ServiceError::Forbidden => (StatusCode::FORBIDDEN, "revision.authorization_stale", false),
        ServiceError::NotFound => (StatusCode::NOT_FOUND, "revision.not_found", false),
        ServiceError::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "revision.limit_exceeded",
            false,
        ),
        ServiceError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "revision.unavailable",
            false,
        ),
        ServiceError::Integrity => (
            StatusCode::SERVICE_UNAVAILABLE,
            "revision.integrity_failure",
            false,
        ),
        ServiceError::AdmissionLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "revision.admission_limited",
            true,
        ),
    };
    let mut response = (
        status,
        [(header::CONTENT_TYPE, CONTENT_TYPE)],
        Json(ErrorResponse { code }),
    )
        .into_response();
    if retry_after {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("5"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use filebelt_revision_protocol::{RevisionError, RevisionLine, RevisionLineDiffHunk};

    #[test]
    fn comparison_admission_bounds_both_scopes_and_recovers() {
        let active = Gauge::default();
        let rejections = Counter::default();
        let admission = ComparisonAdmission::new(2, 1, active.clone(), rejections.clone());
        let first_user = Uuid::new_v4();
        let second_user = Uuid::new_v4();
        let third_user = Uuid::new_v4();

        let first = admission.try_acquire(first_user).unwrap();
        assert_eq!(active.get(), 1);
        assert!(matches!(
            admission.try_acquire(first_user),
            Err(ServiceError::AdmissionLimited)
        ));
        let second = admission.try_acquire(second_user).unwrap();
        assert_eq!(active.get(), 2);
        assert!(matches!(
            admission.try_acquire(third_user),
            Err(ServiceError::AdmissionLimited)
        ));
        assert_eq!(rejections.get(), 2);

        drop(first);
        drop(second);
        assert_eq!(active.get(), 0);
        assert!(admission.try_acquire(first_user).is_ok());
    }

    #[test]
    fn adapter_admission_and_size_errors_remain_distinct() {
        let error = |code| {
            Some(revision_execute_response::Result::Error(RevisionError {
                code: code as i32,
                message: "bounded adapter error".into(),
                retry_after_millis: if code == RevisionErrorCode::AdmissionLimited {
                    5_000
                } else {
                    0
                },
            }))
        };
        assert_eq!(
            adapter_result(error(RevisionErrorCode::AdmissionLimited)),
            Err(ServiceError::AdmissionLimited)
        );
        assert_eq!(
            adapter_result(error(RevisionErrorCode::ResourceExhausted)),
            Err(ServiceError::TooLarge)
        );

        let response = service_error(ServiceError::AdmissionLimited);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("5"))
        );
        assert_eq!(
            service_error(ServiceError::TooLarge).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn typed_lines_preserve_per_side_coordinates() {
        let command = CompareCommand {
            tenant_id: Uuid::nil(),
            user_id: Uuid::nil(),
            principal_id: Uuid::nil(),
            session_id: Uuid::nil(),
            drive_id: Uuid::nil(),
            node_id: Uuid::nil(),
            base_version_id: Uuid::nil(),
            target_version_id: Uuid::nil(),
            membership_generation: 1,
            drive_acl_generation: 1,
            namespace_generation: 1,
            resource_acl_generation: 1,
        };
        let comparison = revision_execute_response::Result::Comparison(
            filebelt_revision_protocol::RevisionComparison {
                kind: RevisionComparisonKind::LineDiff as i32,
                histogram: None,
                line_diff: vec![RevisionLineDiffHunk {
                    old_start: 3,
                    old_lines: 2,
                    new_start: 3,
                    new_lines: 2,
                    lines: vec![
                        RevisionLine {
                            kind: RevisionLineKind::Deleted as i32,
                            text: "old".into(),
                        },
                        RevisionLine {
                            kind: RevisionLineKind::Added as i32,
                            text: "new".into(),
                        },
                    ],
                }],
            },
        );
        let record = filebelt_database::revision::RevisionComparisonRecord {
            repository_id: Uuid::new_v4(),
            base_commit_oid: "a".repeat(64),
            target_commit_oid: "b".repeat(64),
            base_size_bytes: 3,
            target_size_bytes: 4,
            base_final_newline: false,
            target_final_newline: true,
        };
        let result = comparison_response(command, comparison, &record).unwrap();
        assert_eq!(result.hunks[0].lines[0].base_line, Some(3));
        assert_eq!(result.hunks[0].lines[1].target_line, Some(3));
        assert!(result.target_final_newline);
    }

    #[test]
    fn office_and_binary_policy_never_enter_git() {
        let lease = |name: &str, policy: &str, media_type: Option<&str>| {
            filebelt_database::revision::RevisionBackfillLease {
                tenant_id: Uuid::new_v4(),
                content_id: Uuid::new_v4(),
                version_id: Uuid::new_v4(),
                drive_id: Uuid::new_v4(),
                node_id: Uuid::new_v4(),
                created_by: Uuid::new_v4(),
                legacy_payload_id: Uuid::new_v4(),
                size_bytes: 1,
                blake3: vec![0; 32],
                media_type: media_type.map(str::to_owned),
                display_name: name.into(),
                content_class_policy: policy.into(),
                ordinal: 1,
                created_at_unix_seconds: 1,
                fencing_token: 2,
                lease_owner: Uuid::new_v4(),
                repository_id: None,
                expected_head_oid: None,
            }
        };
        assert_eq!(
            classify(&lease("report.odt", "auto", None), b"ordinary text"),
            "office"
        );
        assert_eq!(
            classify(&lease("notes.md", "binary", None), b"ordinary text"),
            "binary"
        );
        assert_eq!(
            classify(&lease("notes.md", "auto", None), b"bad\0text"),
            "binary"
        );
        assert_eq!(
            classify(&lease("notes.md", "auto", None), b"valid text"),
            "text"
        );
    }
}

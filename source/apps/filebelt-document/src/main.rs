// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral external-document coordinator.
//!
//! This role accepts deterministic Protobuf control messages only on its
//! isolated backend listener. It owns no payload mount: immutable reads and
//! revision writes are admitted through short-lived scoped I/O capabilities.

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use aws_lc_rs::signature::Ed25519KeyPair;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::post};
use clap::{Parser, Subcommand};
use filebelt_capability_keyset::DocumentStorageKeyset;
use filebelt_control_protocol::{Config, DeploymentMode, read_secret_string};
use filebelt_database::document::{
    BeginDocumentRevisionInput, CreateDocumentSessionInput, DocumentAuthorizationGenerations,
    DocumentCommitResult, DocumentLaunchIoContext, DocumentLaunchRecord,
    ForceCloseDocumentSessionInput, ListDocumentSessionsForNodeInput, ReceiveDocumentCallbackInput,
};
use filebelt_database::{Database, DatabaseError};
use filebelt_document_protocol::{
    BeginDocumentRevisionCommand, CommitDocumentRevisionCommand, CreateDocumentConflictCopyCommand,
    CreateDocumentSessionCommand, DocumentAuthorizationGenerations as WireGenerations,
    DocumentCallbackKind, DocumentCommitOutcome, DocumentCommitState, DocumentConflictCopy,
    DocumentExecuteRequest, DocumentExecuteResponse, DocumentLaunch, DocumentLaunchGrant,
    DocumentParticipant, DocumentParticipantActivity, DocumentRevisionAdmission,
    DocumentRevisionKind, DocumentSession, DocumentSessionDetail, DocumentSessionError,
    DocumentSessionErrorCode, DocumentSessionMode, DocumentSessionPage, DocumentSessionPageAnchor,
    DocumentSessionState, ForceCloseDocumentSessionCommand, IssueDocumentLaunchGrantCommand,
    ListDocumentSessionsCommand, RedeemDocumentLaunchCommand, document_execute_request,
    document_execute_response,
};
use filebelt_runtime::{
    MtlsListener, OperationsState, certificate_not_after_unix_seconds, init_telemetry,
    install_crypto_provider, operations_router, trace_request, wait_for_shutdown,
};
use filebelt_storage_protocol::{
    CapabilityClaims, CapabilityOperation, DocumentStorageCapabilityUse,
    sign_document_storage_capability, unix_time_now,
};
use getrandom::fill as random_fill;
use prost::Message as _;
use sqlx::Row as _;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

const ROLE: &str = "filebelt-document";
const CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";
const CAPABILITY_NONCE_BYTES: usize = 32;
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const RECONCILIATION_LEASE_SECONDS: i64 = 30;

#[derive(Debug, Parser)]
#[command(name = "filebelt-document", disable_version_flag = true)]
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
    signer: Arc<Ed25519KeyPair>,
    signing_generation: u32,
    max_active_tabs: i64,
    max_document_bytes: i64,
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
            error!(%error, "document service stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<()> {
    if !config.documents.enabled {
        bail!("document service is disabled");
    }
    let database_url = read_secret_string(
        config
            .documents
            .database_url_file
            .as_ref()
            .ok_or_else(|| anyhow!("document database URL is absent"))?,
    )?;
    let database = Database::connect(&database_url, config.database.max_connections).await?;
    database.health().await?;
    let tenant_id = database.tenant_by_slug(&config.tenant.slug).await?;
    let signing = config
        .documents
        .capability_signing
        .as_ref()
        .ok_or_else(|| anyhow!("document capability signing is absent"))?;
    let private_key = std::fs::read(&signing.private_key_file)?;
    let signer = Arc::new(
        Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| anyhow!("document capability key is not Ed25519 PKCS#8"))?,
    );
    self_check_signer(
        &signing.public_keyset_file,
        signing.current_generation,
        &signer,
    )?;
    let state = AppState {
        database: database.clone(),
        tenant_id,
        signer,
        signing_generation: signing.current_generation,
        max_active_tabs: i64::from(config.documents.max_active_tabs),
        max_document_bytes: i64::try_from(config.documents.max_document_bytes)
            .map_err(|_| anyhow!("document max bytes is invalid"))?,
    };
    let (stop_reconciliation, reconciliation_stopped) = watch::channel(false);
    let reconciliation_state = state.clone();
    tokio::spawn(async move {
        reconciliation_loop(reconciliation_state, reconciliation_stopped).await;
    });
    let application = Router::new()
        .route("/internal/v1/document/execute", post(execute_api))
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn(trace_request))
        .with_state(state.clone());
    let adapter_application = Router::new()
        .route("/internal/v1/document/execute", post(execute_adapter))
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn(trace_request))
        .with_state(state);
    let ready_database = database.clone();
    let operations = OperationsState::new(ROLE, config.telemetry.prometheus_enabled, move || {
        let database = ready_database.clone();
        async move { database.health().await.is_ok() }
    });
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
    let listener = config.listeners.document;
    let adapter_listener = config.listeners.document_adapter;
    let (application_stop, application_stopped) = tokio::sync::oneshot::channel();
    let mut application_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(listener).await?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.document.as_ref())
                .ok_or_else(|| anyhow!("document backend TLS is absent"))?;
            let listener = MtlsListener::bind(listener, tls)
                .await
                .map_err(|error| anyhow!(error))?;
            tokio::spawn(async move {
                axum::serve(listener, application)
                    .with_graceful_shutdown(async move {
                        let _ = application_stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
    };
    let (adapter_stop, adapter_stopped) = tokio::sync::oneshot::channel();
    let mut adapter_server = match config.deployment.mode {
        DeploymentMode::Development => {
            let listener = tokio::net::TcpListener::bind(adapter_listener).await?;
            tokio::spawn(async move {
                axum::serve(listener, adapter_application)
                    .with_graceful_shutdown(async move {
                        let _ = adapter_stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
        DeploymentMode::Kubernetes => {
            let tls = config
                .backend_tls
                .as_ref()
                .and_then(|tls| tls.document_adapter.as_ref())
                .ok_or_else(|| anyhow!("document adapter backend TLS is absent"))?;
            let listener = MtlsListener::bind(adapter_listener, tls)
                .await
                .map_err(|error| anyhow!(error))?;
            tokio::spawn(async move {
                axum::serve(listener, adapter_application)
                    .with_graceful_shutdown(async move {
                        let _ = adapter_stopped.await;
                    })
                    .await
                    .map_err(anyhow::Error::from)
            })
        }
    };
    if let Some(tls) = config
        .backend_tls
        .as_ref()
        .and_then(|tls| tls.document.as_ref())
    {
        let _ = certificate_not_after_unix_seconds(tls).map_err(|error| anyhow!(error))?;
    }
    info!(%listener, "document service ready");
    let result = tokio::select! {
        result = &mut application_server => result.context("document API server task failed")?,
        result = &mut adapter_server => result.context("document adapter server task failed")?,
        () = wait_for_shutdown() => {
            let _ = application_stop.send(());
            let _ = adapter_stop.send(());
            let _ = stop_reconciliation.send(true);
            if tokio::time::timeout(Duration::from_secs(75), &mut application_server).await.is_err() { application_server.abort(); }
            if tokio::time::timeout(Duration::from_secs(75), &mut adapter_server).await.is_err() { adapter_server.abort(); }
            Ok(())
        }
    };
    let _ = operations_stop.send(());
    operations_server
        .await
        .context("operations server task failed")??;
    result
}

async fn execute_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    execute_filtered(state, headers, body, false).await
}

async fn execute_adapter(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    execute_filtered(state, headers, body, true).await
}

async fn execute_filtered(
    state: AppState,
    headers: axum::http::HeaderMap,
    body: Bytes,
    adapter: bool,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/x-protobuf")
    {
        return response_error(
            String::new(),
            DocumentSessionErrorCode::ProtocolViolation,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        );
    }
    let request = match DocumentExecuteRequest::decode(body) {
        Ok(request) if valid_request_id(&request.request_id) => request,
        _ => {
            return response_error(
                String::new(),
                DocumentSessionErrorCode::ProtocolViolation,
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let request_id = request.request_id.clone();
    let permitted = matches!(
        &request.command,
        Some(
            document_execute_request::Command::RedeemLaunch(_)
                | document_execute_request::Command::BeginRevision(_)
                | document_execute_request::Command::CommitRevision(_)
                | document_execute_request::Command::ReceiveCallback(_)
                | document_execute_request::Command::RefreshSource(_)
        )
    );
    if permitted != adapter {
        return response_error(
            request_id,
            DocumentSessionErrorCode::AuthenticationRequired,
            StatusCode::FORBIDDEN,
        );
    }
    let result = match request.command {
        Some(command) => dispatch(&state, command).await,
        None => Err(DocumentSessionErrorCode::ProtocolViolation),
    };
    match result {
        Ok(result) => response_ok(request_id, result),
        Err(code) => response_error(request_id, code, status_for(code)),
    }
}

async fn dispatch(
    state: &AppState,
    command: document_execute_request::Command,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    match command {
        document_execute_request::Command::CreateSession(command) => {
            create_session(state, command).await
        }
        document_execute_request::Command::ListSessions(command) => {
            list_sessions(state, command).await
        }
        document_execute_request::Command::GetSession(command) => {
            get_session(
                state,
                command.tenant_id,
                command.actor_principal_id,
                command.document_session_id,
            )
            .await
        }
        document_execute_request::Command::RevokeSession(command) => {
            revoke_session(
                state,
                command.tenant_id,
                command.actor_principal_id,
                command.participant_id,
                command.reason,
            )
            .await
        }
        document_execute_request::Command::ForceCloseSession(command) => {
            force_close_session(state, command).await
        }
        document_execute_request::Command::CreateConflictCopy(command) => {
            create_conflict_copy(state, command).await
        }
        document_execute_request::Command::IssueLaunchGrant(command) => {
            issue_launch_grant(state, command).await
        }
        document_execute_request::Command::RedeemLaunch(command) => {
            redeem_launch(state, command).await
        }
        document_execute_request::Command::BeginRevision(command) => {
            begin_revision(state, command).await
        }
        document_execute_request::Command::ReceiveCallback(command) => {
            receive_callback(state, command).await
        }
        document_execute_request::Command::RefreshSource(command) => {
            refresh_source(state, command).await
        }
        document_execute_request::Command::CommitRevision(command) => {
            commit_revision(state, command).await
        }
    }
}

async fn create_session(
    state: &AppState,
    command: CreateDocumentSessionCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let tenant_id = tenant(state, &command.tenant_id)?;
    let mode = mode_name(command.mode)?;
    let operation_digest = exact_digest(&command.operation_digest)?;
    let request_fingerprint = exact_digest(&command.request_fingerprint)?;
    let launch = state
        .database
        .create_document_session(&CreateDocumentSessionInput {
            tenant_id,
            actor_principal_id: parse_uuid(&command.actor_principal_id)?,
            api_session_id: parse_uuid(&command.api_session_id)?,
            drive_id: parse_uuid(&command.drive_id)?,
            node_id: parse_uuid(&command.node_id)?,
            base_version_id: parse_uuid(&command.base_version_id)?,
            provider_id: &command.provider_id,
            mode,
            generations: generations(command.generations)?,
            maximum_active_participants: state.max_active_tabs,
            maximum_document_bytes: state.max_document_bytes,
            operation_digest: &operation_digest,
            request_fingerprint: &request_fingerprint,
        })
        .await
        .map_err(database_error)?;
    Ok(document_execute_response::Result::Session(detail(&launch)))
}

async fn issue_launch_grant(
    state: &AppState,
    command: IssueDocumentLaunchGrantCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let mut token = [0_u8; 32];
    random_fill(&mut token).map_err(|_| DocumentSessionErrorCode::Unavailable)?;
    let expires_at_unix_seconds = state
        .database
        .issue_document_launch_grant(
            tenant(state, &command.tenant_id)?,
            parse_uuid(&command.document_session_id)?,
            parse_uuid(&command.actor_principal_id)?,
            parse_uuid(&command.api_session_id)?,
            blake3::hash(&token).as_bytes(),
        )
        .await
        .map_err(database_error)?;
    Ok(document_execute_response::Result::LaunchGrant(
        DocumentLaunchGrant {
            launch_token: token.to_vec(),
            expires_at_unix_seconds,
        },
    ))
}

async fn create_conflict_copy(
    state: &AppState,
    command: CreateDocumentConflictCopyCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let operation_digest = exact_digest(&command.operation_digest)?;
    let request_fingerprint = exact_digest(&command.request_fingerprint)?;
    let copy = state
        .database
        .create_document_conflict_copy(
            tenant(state, &command.tenant_id)?,
            parse_uuid(&command.document_session_id)?,
            parse_uuid(&command.actor_principal_id)?,
            parse_uuid(&command.api_session_id)?,
            parse_uuid(&command.target_parent_id)?,
            i64::try_from(command.expected_parent_namespace_generation)
                .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?,
            generations(command.generations)?,
            &command.display_name,
            &operation_digest,
            &request_fingerprint,
        )
        .await
        .map_err(database_error)?;
    Ok(document_execute_response::Result::ConflictCopy(
        DocumentConflictCopy {
            drive_id: copy.drive_id.to_string(),
            node_id: copy.node_id.to_string(),
            version_id: copy.version_id.to_string(),
            display_name: copy.display_name,
            media_type: copy.media_type,
            size_bytes: u64::try_from(copy.size_bytes)
                .map_err(|_| DocumentSessionErrorCode::Internal)?,
            blake3: copy.blake3,
        },
    ))
}

async fn list_sessions(
    state: &AppState,
    command: ListDocumentSessionsCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let tenant_id = tenant(state, &command.tenant_id)?;
    let launches = match (command.drive_id.is_empty(), command.node_id.is_empty()) {
        (true, true) => {
            let _ = parse_uuid(&command.api_session_id)?;
            state
                .database
                .list_document_sessions_for_principal(
                    tenant_id,
                    parse_uuid(&command.actor_principal_id)?,
                    command.limit,
                    page_anchor(command.anchor)?,
                )
                .await
        }
        (false, false) => {
            state
                .database
                .list_document_sessions_for_node(&ListDocumentSessionsForNodeInput {
                    tenant_id,
                    actor_principal_id: parse_uuid(&command.actor_principal_id)?,
                    api_session_id: parse_uuid(&command.api_session_id)?,
                    drive_id: parse_uuid(&command.drive_id)?,
                    node_id: parse_uuid(&command.node_id)?,
                    generations: generations(command.generations)?,
                    limit: command.limit,
                    anchor: page_anchor(command.anchor)?,
                })
                .await
        }
        _ => return Err(DocumentSessionErrorCode::ProtocolViolation),
    }
    .map_err(database_error)?;
    Ok(document_execute_response::Result::Sessions(
        DocumentSessionPage {
            sessions: grouped_details(launches.launches),
            next_anchor: launches.next_anchor.map(|value| DocumentSessionPageAnchor {
                created_at_unix_microseconds: value.created_at_unix_microseconds,
                session_id: value.session_id.to_string(),
            }),
        },
    ))
}

async fn get_session(
    state: &AppState,
    tenant_wire: String,
    principal_wire: String,
    session_wire: String,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let session_id = parse_uuid(&session_wire)?;
    let launches = state
        .database
        .document_session_for_principal(
            tenant(state, &tenant_wire)?,
            parse_uuid(&principal_wire)?,
            session_id,
        )
        .await
        .map_err(database_error)?;
    grouped_details(launches)
        .into_iter()
        .next()
        .map(document_execute_response::Result::Session)
        .ok_or(DocumentSessionErrorCode::SessionNotOwner)
}

async fn revoke_session(
    state: &AppState,
    tenant_wire: String,
    actor_wire: String,
    participant_wire: String,
    reason: String,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let changed = state
        .database
        .revoke_document_participant(
            tenant(state, &tenant_wire)?,
            parse_uuid(&participant_wire)?,
            parse_uuid(&actor_wire)?,
            &reason,
        )
        .await
        .map_err(database_error)?;
    if !changed {
        return Err(DocumentSessionErrorCode::SessionNotOwner);
    }
    Ok(document_execute_response::Result::Session(
        DocumentSessionDetail {
            session: None,
            participants: Vec::new(),
        },
    ))
}

async fn force_close_session(
    state: &AppState,
    command: ForceCloseDocumentSessionCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let changed = state
        .database
        .force_close_document_session(&ForceCloseDocumentSessionInput {
            tenant_id: tenant(state, &command.tenant_id)?,
            session_id: parse_uuid(&command.document_session_id)?,
            actor_principal_id: parse_uuid(&command.actor_principal_id)?,
            api_session_id: parse_uuid(&command.api_session_id)?,
            drive_id: parse_uuid(&command.drive_id)?,
            node_id: parse_uuid(&command.node_id)?,
            generations: generations(command.generations)?,
            reason: &command.reason,
        })
        .await
        .map_err(database_error)?;
    if !changed {
        return Err(DocumentSessionErrorCode::SessionNotOwner);
    }
    Ok(document_execute_response::Result::Session(
        DocumentSessionDetail {
            session: None,
            participants: Vec::new(),
        },
    ))
}

async fn redeem_launch(
    state: &AppState,
    command: RedeemDocumentLaunchCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    if command.launch_token.len() != 32 {
        return Err(DocumentSessionErrorCode::AuthenticationRequired);
    }
    let token_digest = *blake3::hash(&command.launch_token).as_bytes();
    let launch = state
        .database
        .consume_document_launch_grant(tenant(state, &command.tenant_id)?, &token_digest)
        .await
        .map_err(database_error)?;
    let context = state
        .database
        .document_launch_io_context(state.tenant_id, launch.session.id, launch.participant.id)
        .await
        .map_err(database_error)?;
    let source_read_capability = mint_source_read(state, &context)?;
    Ok(document_execute_response::Result::Launch(DocumentLaunch {
        detail: Some(detail(&launch)),
        source_read_capability,
        display_name: context.source_display_name.clone(),
        media_type: context.base_media_type.clone(),
        size_bytes: u64::try_from(context.base_size_bytes)
            .map_err(|_| DocumentSessionErrorCode::Internal)?,
        base_version_id: context.session.base_version_id.to_string(),
    }))
}

async fn begin_revision(
    state: &AppState,
    command: BeginDocumentRevisionCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    if command.reserved_bytes > 104_857_600 {
        return Err(DocumentSessionErrorCode::ProtocolViolation);
    }
    let received = state
        .database
        .received_document_revision(
            tenant(state, &command.tenant_id)?,
            parse_uuid(&command.revision_id)?,
        )
        .await
        .map_err(database_error)?;
    let digest: [u8; 32] = received
        .provider_event_digest
        .as_slice()
        .try_into()
        .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?;
    let allocation = state
        .database
        .begin_document_revision(&BeginDocumentRevisionInput {
            tenant_id: tenant(state, &command.tenant_id)?,
            document_session_id: received.document_session_id,
            participant_id: received.participant_id,
            provider_event_digest: &digest,
            kind: &received.kind,
            reserved_bytes: i64::try_from(command.reserved_bytes)
                .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?,
            media_type: &received.media_type,
        })
        .await
        .map_err(database_error)?;
    let context = state
        .database
        .document_revision_io_context(state.tenant_id, allocation.revision.id)
        .await
        .map_err(database_error)?;
    let staged_write_capability =
        mint_revision_capability(state, &context, CapabilityOperation::WriteDocumentRevision)?;
    let finalize_capability = mint_revision_capability(
        state,
        &context,
        CapabilityOperation::FinalizeDocumentRevision,
    )?;
    Ok(document_execute_response::Result::RevisionAdmission(
        DocumentRevisionAdmission {
            revision_id: allocation.revision.id.to_string(),
            staged_write_capability,
            finalize_capability,
        },
    ))
}

async fn receive_callback(
    state: &AppState,
    command: filebelt_document_protocol::ReceiveDocumentCallbackCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    if command.provider_event_digest.len() != 32 {
        return Err(DocumentSessionErrorCode::ProtocolViolation);
    };
    let digest: [u8; 32] = command
        .provider_event_digest
        .as_slice()
        .try_into()
        .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?;
    let receipt = state
        .database
        .receive_document_callback(&ReceiveDocumentCallbackInput {
            tenant_id: tenant(state, &command.tenant_id)?,
            document_session_id: parse_uuid(&command.document_session_id)?,
            participant_id: parse_uuid(&command.participant_id)?,
            provider_event_digest: &digest,
            callback_kind: callback_kind(command.callback_kind)?,
            revision_kind: revision_kind_for_callback(
                command.callback_kind,
                command.revision_kind,
            )?,
            activity: callback_activity(command.callback_kind, command.activity)?,
            output_file_type: document_file_type(&command.output_file_type)?,
        })
        .await
        .map_err(database_error)?;
    Ok(document_execute_response::Result::CallbackReceipt(
        filebelt_document_protocol::DocumentCallbackReceipt {
            revision_id: receipt
                .revision
                .as_ref()
                .map_or_else(String::new, |revision| revision.id.to_string()),
            state: receipt.revision.as_ref().map_or(
                filebelt_document_protocol::DocumentCallbackState::NoOp as i32,
                |revision| callback_state(&revision.state),
            ),
            event_id: receipt.event_id.to_string(),
        },
    ))
}

fn document_file_type(value: &str) -> Result<&str, DocumentSessionErrorCode> {
    matches!(value, "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp")
        .then_some(value)
        .ok_or(DocumentSessionErrorCode::ProtocolViolation)
}

async fn refresh_source(
    state: &AppState,
    command: filebelt_document_protocol::RefreshDocumentSourceCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let context = state
        .database
        .document_launch_io_context(
            tenant(state, &command.tenant_id)?,
            parse_uuid(&command.document_session_id)?,
            parse_uuid(&command.participant_id)?,
        )
        .await
        .map_err(database_error)?;
    let capability = mint_source_read(state, &context)?;
    Ok(document_execute_response::Result::Launch(DocumentLaunch {
        detail: None,
        source_read_capability: capability,
        display_name: context.source_display_name,
        media_type: context.base_media_type,
        size_bytes: u64::try_from(context.base_size_bytes)
            .map_err(|_| DocumentSessionErrorCode::Internal)?,
        base_version_id: context.session.base_version_id.to_string(),
    }))
}

async fn commit_revision(
    state: &AppState,
    command: CommitDocumentRevisionCommand,
) -> Result<document_execute_response::Result, DocumentSessionErrorCode> {
    let tenant_id = tenant(state, &command.tenant_id)?;
    let revision_id = parse_uuid(&command.revision_id)?;
    let outcome = match state
        .database
        .commit_document_revision(tenant_id, revision_id)
        .await
    {
        Ok(outcome) => outcome,
        Err(DatabaseError::StaleGeneration) => {
            state
                .database
                .reject_document_revision_for_authorization_change(tenant_id, revision_id)
                .await
                .map_err(database_error)?;
            return Err(DocumentSessionErrorCode::AuthorizationChanged);
        }
        Err(error) => return Err(database_error(error)),
    };
    Ok(document_execute_response::Result::Commit(commit_outcome(
        outcome,
    )))
}

fn detail(launch: &DocumentLaunchRecord) -> DocumentSessionDetail {
    DocumentSessionDetail {
        session: Some(wire_session(launch)),
        participants: vec![wire_participant(launch)],
    }
}

fn grouped_details(launches: Vec<DocumentLaunchRecord>) -> Vec<DocumentSessionDetail> {
    let mut positions = BTreeMap::<Uuid, usize>::new();
    let mut grouped = Vec::<DocumentSessionDetail>::new();
    for launch in launches {
        let index = if let Some(index) = positions.get(&launch.session.id) {
            *index
        } else {
            let index = grouped.len();
            positions.insert(launch.session.id, index);
            grouped.push(DocumentSessionDetail {
                session: Some(wire_session(&launch)),
                participants: Vec::new(),
            });
            index
        };
        grouped[index].participants.push(wire_participant(&launch));
    }
    grouped
}

fn wire_session(launch: &DocumentLaunchRecord) -> DocumentSession {
    let session = &launch.session;
    let participant = &launch.participant;
    let generations = participant.generations;
    DocumentSession {
        session_id: session.id.to_string(),
        tenant_id: String::new(),
        drive_id: session.drive_id.to_string(),
        node_id: session.node_id.to_string(),
        base_version_id: session.base_version_id.to_string(),
        principal_id: participant.user_principal_id.to_string(),
        api_session_id: participant.api_session_id.to_string(),
        mode: wire_mode(&participant.mode),
        state: wire_state(&session.state),
        session_epoch: u64::try_from(session.fencing_token).unwrap_or(0),
        resource_acl_generation: u64::try_from(generations.resource_acl).unwrap_or(0),
        drive_acl_generation: u64::try_from(generations.drive_acl).unwrap_or(0),
        membership_generation: u64::try_from(generations.membership).unwrap_or(0),
        namespace_generation: u64::try_from(generations.namespace).unwrap_or(0),
        created_at_unix_seconds: unix_timestamp(&session.created_at),
        last_activity_at_unix_seconds: unix_timestamp(&participant.last_activity_at),
        expires_at_unix_seconds: unix_timestamp(&session.absolute_expires_at),
        closed_at_unix_seconds: session.closed_at.as_deref().map_or(0, unix_timestamp),
        conflict_head_version_id: session
            .conflict_head_version_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    }
}

fn wire_participant(launch: &DocumentLaunchRecord) -> DocumentParticipant {
    let participant = &launch.participant;
    DocumentParticipant {
        participant_id: participant.id.to_string(),
        principal_id: participant.user_principal_id.to_string(),
        mode: wire_mode(&participant.mode),
        joined_at_unix_seconds: unix_timestamp(&participant.created_at),
        last_activity_at_unix_seconds: unix_timestamp(&participant.last_activity_at),
        active: matches!(participant.state.as_str(), "active" | "disconnected"),
        display_name: participant.display_name.clone(),
    }
}

fn unix_timestamp(value: &str) -> i64 {
    value
        .parse::<jiff::Timestamp>()
        .map(|timestamp| timestamp.as_second())
        .unwrap_or(0)
}

fn mint_source_read(
    state: &AppState,
    context: &DocumentLaunchIoContext,
) -> Result<String, DocumentSessionErrorCode> {
    mint_capability(
        state,
        &context.session,
        &context.participant,
        context.base_payload_id,
        context.session.base_version_id,
        u64::try_from(context.base_size_bytes).map_err(|_| DocumentSessionErrorCode::Internal)?,
        CapabilityOperation::ReadDocumentVersion,
    )
}

fn mint_revision_capability(
    state: &AppState,
    context: &filebelt_database::document::DocumentIoContext,
    operation: CapabilityOperation,
) -> Result<String, DocumentSessionErrorCode> {
    let payload_id = context
        .revision
        .payload_id
        .ok_or(DocumentSessionErrorCode::Internal)?;
    mint_capability(
        state,
        &context.session,
        &context.participant,
        payload_id,
        context.revision.id,
        u64::try_from(context.revision.reserved_bytes)
            .map_err(|_| DocumentSessionErrorCode::Internal)?,
        operation,
    )
}

fn mint_capability(
    state: &AppState,
    session: &filebelt_database::document::DocumentSessionRecord,
    participant: &filebelt_database::document::DocumentParticipantRecord,
    payload_id: Uuid,
    grant_id: Uuid,
    size: u64,
    operation: CapabilityOperation,
) -> Result<String, DocumentSessionErrorCode> {
    let now = unix_time_now().map_err(|_| DocumentSessionErrorCode::Unavailable)?;
    let mut nonce = [0_u8; CAPABILITY_NONCE_BYTES];
    random_fill(&mut nonce).map_err(|_| DocumentSessionErrorCode::Unavailable)?;
    let generations = participant.generations;
    let use_case = match operation {
        CapabilityOperation::ReadDocumentVersion => DocumentStorageCapabilityUse::ReadVersion,
        CapabilityOperation::WriteDocumentRevision => DocumentStorageCapabilityUse::WriteRevision,
        CapabilityOperation::FinalizeDocumentRevision => {
            DocumentStorageCapabilityUse::FinalizeRevision
        }
        _ => return Err(DocumentSessionErrorCode::Internal),
    };
    sign_document_storage_capability(
        &CapabilityClaims {
            capability_id: Uuid::new_v4().to_string(),
            audience: CAPABILITY_AUDIENCE.into(),
            operation: operation as i32,
            tenant_id: state.tenant_id.to_string(),
            principal_id: participant.user_principal_id.to_string(),
            session_id: participant.api_session_id.to_string(),
            resource_id: session.node_id.to_string(),
            upload_id: session.id.to_string(),
            payload_id: payload_id.to_string(),
            part_number: 0,
            range_start: 0,
            range_end: size.saturating_sub(1),
            resource_acl_generation: u64::try_from(generations.resource_acl)
                .map_err(|_| DocumentSessionErrorCode::Internal)?,
            membership_generation: u64::try_from(generations.membership)
                .map_err(|_| DocumentSessionErrorCode::Internal)?,
            namespace_generation: u64::try_from(generations.namespace)
                .map_err(|_| DocumentSessionErrorCode::Internal)?,
            fencing_token: u64::try_from(session.fencing_token)
                .map_err(|_| DocumentSessionErrorCode::Internal)?,
            nonce: nonce.to_vec(),
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now + 60,
            drive_acl_generation: u64::try_from(generations.drive_acl)
                .map_err(|_| DocumentSessionErrorCode::Internal)?,
            grant_id: grant_id.to_string(),
        },
        use_case,
        state.signing_generation,
        &state.signer,
    )
    .map_err(|_| DocumentSessionErrorCode::Internal)
}

fn self_check_signer(
    path: &std::path::Path,
    generation: u32,
    signer: &Ed25519KeyPair,
) -> Result<()> {
    let source =
        std::fs::read_to_string(path).context("cannot read document capability public keyset")?;
    let keyset = DocumentStorageKeyset::parse(&source)
        .map_err(|_| anyhow!("document capability public keyset is invalid"))?;
    let probe = signer.sign(b"filebelt.document.storage.keyset.self-check");
    keyset
        .verify(
            generation,
            b"filebelt.document.storage.keyset.self-check",
            probe.as_ref(),
        )
        .map_err(|_| anyhow!("document capability private key does not match the keyset"))
}

fn commit_outcome(outcome: DocumentCommitResult) -> DocumentCommitOutcome {
    match outcome {
        DocumentCommitResult::Committed { version_id } => DocumentCommitOutcome {
            state: DocumentCommitState::Committed as i32,
            version_id: version_id.to_string(),
            retained_until_unix_seconds: 0,
        },
        DocumentCommitResult::NoOp { version_id } => DocumentCommitOutcome {
            state: DocumentCommitState::NoOp as i32,
            version_id: version_id.to_string(),
            retained_until_unix_seconds: 0,
        },
        DocumentCommitResult::Conflict { retained_until } => DocumentCommitOutcome {
            state: DocumentCommitState::Conflict as i32,
            version_id: String::new(),
            retained_until_unix_seconds: unix_timestamp(&retained_until),
        },
    }
}

fn tenant(state: &AppState, value: &str) -> Result<Uuid, DocumentSessionErrorCode> {
    let value = parse_uuid(value)?;
    if value == state.tenant_id {
        Ok(value)
    } else {
        Err(DocumentSessionErrorCode::AuthenticationRequired)
    }
}
fn parse_uuid(value: &str) -> Result<Uuid, DocumentSessionErrorCode> {
    Uuid::parse_str(value).map_err(|_| DocumentSessionErrorCode::ProtocolViolation)
}

fn exact_digest(value: &[u8]) -> Result<[u8; 32], DocumentSessionErrorCode> {
    value
        .try_into()
        .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)
}

fn page_anchor(
    value: Option<DocumentSessionPageAnchor>,
) -> Result<Option<filebelt_database::document::DocumentSessionPageAnchor>, DocumentSessionErrorCode>
{
    value
        .map(|value| {
            if value.created_at_unix_microseconds <= 0 {
                return Err(DocumentSessionErrorCode::ProtocolViolation);
            }
            Ok(filebelt_database::document::DocumentSessionPageAnchor {
                created_at_unix_microseconds: value.created_at_unix_microseconds,
                session_id: parse_uuid(&value.session_id)?,
            })
        })
        .transpose()
}
fn generations(
    value: Option<WireGenerations>,
) -> Result<DocumentAuthorizationGenerations, DocumentSessionErrorCode> {
    let value = value.ok_or(DocumentSessionErrorCode::ProtocolViolation)?;
    let values = [
        value.membership_generation,
        value.drive_acl_generation,
        value.namespace_generation,
        value.resource_acl_generation,
    ];
    if values.contains(&0) {
        return Err(DocumentSessionErrorCode::ProtocolViolation);
    }
    Ok(DocumentAuthorizationGenerations {
        membership: i64::try_from(value.membership_generation)
            .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?,
        drive_acl: i64::try_from(value.drive_acl_generation)
            .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?,
        namespace: i64::try_from(value.namespace_generation)
            .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?,
        resource_acl: i64::try_from(value.resource_acl_generation)
            .map_err(|_| DocumentSessionErrorCode::ProtocolViolation)?,
    })
}
fn mode_name(value: i32) -> Result<&'static str, DocumentSessionErrorCode> {
    match DocumentSessionMode::try_from(value).ok() {
        Some(DocumentSessionMode::View) => Ok("view"),
        Some(DocumentSessionMode::Comment) => Ok("comment"),
        Some(DocumentSessionMode::Review) => Ok("review"),
        Some(DocumentSessionMode::Edit) => Ok("edit"),
        _ => Err(DocumentSessionErrorCode::ModeUnauthorized),
    }
}
fn revision_kind(value: i32) -> Result<&'static str, DocumentSessionErrorCode> {
    match DocumentRevisionKind::try_from(value).ok() {
        Some(DocumentRevisionKind::Checkpoint) => Ok("checkpoint"),
        Some(DocumentRevisionKind::UserSave) => Ok("user_save"),
        Some(DocumentRevisionKind::FinalSave) => Ok("final_save"),
        _ => Err(DocumentSessionErrorCode::ProtocolViolation),
    }
}

fn callback_kind(value: i32) -> Result<&'static str, DocumentSessionErrorCode> {
    match DocumentCallbackKind::try_from(value).ok() {
        Some(DocumentCallbackKind::Editing) => Ok("editing"),
        Some(DocumentCallbackKind::OutputRequired) => Ok("output_required"),
        Some(DocumentCallbackKind::Corrupted) => Ok("corrupted"),
        Some(DocumentCallbackKind::ClosedNoChanges) => Ok("closed_no_changes"),
        Some(DocumentCallbackKind::ForceSaveError) => Ok("force_save_error"),
        _ => Err(DocumentSessionErrorCode::ProtocolViolation),
    }
}

fn revision_kind_for_callback(
    callback_kind_value: i32,
    revision_kind_value: i32,
) -> Result<Option<&'static str>, DocumentSessionErrorCode> {
    match DocumentCallbackKind::try_from(callback_kind_value).ok() {
        Some(DocumentCallbackKind::OutputRequired) => revision_kind(revision_kind_value).map(Some),
        Some(_) if revision_kind_value == DocumentRevisionKind::Unspecified as i32 => Ok(None),
        _ => Err(DocumentSessionErrorCode::ProtocolViolation),
    }
}

fn callback_activity(
    callback_kind_value: i32,
    activity_value: i32,
) -> Result<Option<&'static str>, DocumentSessionErrorCode> {
    match (
        DocumentCallbackKind::try_from(callback_kind_value).ok(),
        DocumentParticipantActivity::try_from(activity_value).ok(),
    ) {
        (Some(DocumentCallbackKind::Editing), Some(DocumentParticipantActivity::Connected)) => {
            Ok(Some("connected"))
        }
        (Some(DocumentCallbackKind::Editing), Some(DocumentParticipantActivity::Disconnected)) => {
            Ok(Some("disconnected"))
        }
        (Some(DocumentCallbackKind::Editing), _) => {
            Err(DocumentSessionErrorCode::ProtocolViolation)
        }
        (Some(_), Some(DocumentParticipantActivity::Unspecified)) => Ok(None),
        _ => Err(DocumentSessionErrorCode::ProtocolViolation),
    }
}

fn callback_state(value: &str) -> i32 {
    use filebelt_document_protocol::DocumentCallbackState;
    match value {
        "received" => DocumentCallbackState::Received as i32,
        "staging" => DocumentCallbackState::Staging as i32,
        "staged" => DocumentCallbackState::Staged as i32,
        "committed" => DocumentCallbackState::Committed as i32,
        "checkpoint" => DocumentCallbackState::Checkpoint as i32,
        "no_op" => DocumentCallbackState::NoOp as i32,
        "conflict" => DocumentCallbackState::Conflict as i32,
        "rejected" => DocumentCallbackState::Rejected as i32,
        "failed" => DocumentCallbackState::Failed as i32,
        _ => DocumentCallbackState::Unspecified as i32,
    }
}
fn wire_mode(value: &str) -> i32 {
    match value {
        "view" => DocumentSessionMode::View as i32,
        "comment" => DocumentSessionMode::Comment as i32,
        "review" => DocumentSessionMode::Review as i32,
        "edit" => DocumentSessionMode::Edit as i32,
        _ => DocumentSessionMode::Unspecified as i32,
    }
}
fn wire_state(value: &str) -> i32 {
    match value {
        "active" | "draining" => DocumentSessionState::Active as i32,
        "conflict" => DocumentSessionState::Conflicted as i32,
        "revoked" => DocumentSessionState::Revoked as i32,
        "expired" => DocumentSessionState::Expired as i32,
        _ => DocumentSessionState::Closed as i32,
    }
}
fn valid_request_id(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn database_error(error: DatabaseError) -> DocumentSessionErrorCode {
    match error {
        DatabaseError::NotFound => DocumentSessionErrorCode::SessionNotFound,
        DatabaseError::StaleGeneration => DocumentSessionErrorCode::AuthorizationChanged,
        DatabaseError::AdmissionLimited => DocumentSessionErrorCode::Unavailable,
        DatabaseError::QuotaExceeded => DocumentSessionErrorCode::WriteAuthorizationRequired,
        DatabaseError::StorageUnavailable => DocumentSessionErrorCode::Unavailable,
        DatabaseError::Conflict => DocumentSessionErrorCode::BaseVersionConflict,
        DatabaseError::InvalidPersistedValue => DocumentSessionErrorCode::ProtocolViolation,
        _ => DocumentSessionErrorCode::Internal,
    }
}
fn status_for(code: DocumentSessionErrorCode) -> StatusCode {
    match code {
        DocumentSessionErrorCode::AuthenticationRequired => StatusCode::UNAUTHORIZED,
        DocumentSessionErrorCode::AuthorizationChanged
        | DocumentSessionErrorCode::SessionNotOwner
        | DocumentSessionErrorCode::ModeUnauthorized
        | DocumentSessionErrorCode::WriteAuthorizationRequired
        | DocumentSessionErrorCode::VersionAuthorizationRequired => StatusCode::FORBIDDEN,
        DocumentSessionErrorCode::SessionNotFound => StatusCode::NOT_FOUND,
        DocumentSessionErrorCode::BaseVersionConflict
        | DocumentSessionErrorCode::ConflictCopyRequired => StatusCode::CONFLICT,
        DocumentSessionErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}
fn response_ok(request_id: String, result: document_execute_response::Result) -> Response {
    response(request_id, result, StatusCode::OK)
}
fn response_error(
    request_id: String,
    code: DocumentSessionErrorCode,
    status: StatusCode,
) -> Response {
    response(
        request_id,
        document_execute_response::Result::Error(DocumentSessionError {
            code: code as i32,
            message: code.as_str_name().to_ascii_lowercase(),
            retry_after_millis: 0,
        }),
        status,
    )
}
fn response(
    request_id: String,
    result: document_execute_response::Result,
    status: StatusCode,
) -> Response {
    let body = DocumentExecuteResponse {
        request_id,
        result: Some(result),
    }
    .encode_to_vec();
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-protobuf"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body,
    )
        .into_response()
}

async fn reconciliation_loop(state: AppState, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(RECONCILIATION_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => { if let Err(error) = reconcile_one(&state).await { warn!(%error, "document revision reconciliation failed"); } },
            changed = stop.changed() => { if changed.is_err() || *stop.borrow() { return; } },
        }
    }
}

async fn reconcile_one(state: &AppState) -> Result<(), sqlx::Error> {
    let mut transaction = state.database.pool().begin().await?;
    sqlx::query("UPDATE filebelt_document.reconciliation_jobs SET state='terminal',last_error_code='attempts_exhausted',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND lease_expires_at<=clock_timestamp() AND attempt_count>=8").bind(state.tenant_id).execute(&mut *transaction).await?;
    let row = sqlx::query("SELECT j.revision_id FROM filebelt_document.reconciliation_jobs j WHERE j.tenant_id=$1 AND j.attempt_count<8 AND ((j.state IN ('queued','retry_wait') AND j.available_at<=clock_timestamp()) OR (j.state='running' AND j.lease_expires_at<=clock_timestamp())) ORDER BY j.available_at,j.revision_id FOR UPDATE OF j SKIP LOCKED LIMIT 1").bind(state.tenant_id).fetch_optional(&mut *transaction).await?;
    let Some(row) = row else {
        transaction.commit().await?;
        return Ok(());
    };
    let revision_id: Uuid = row.get("revision_id");
    let owner = Uuid::new_v4();
    let fence: i64 = sqlx::query_scalar("UPDATE filebelt_document.reconciliation_jobs SET state='running',attempt_count=attempt_count+1,lease_owner=$3,lease_expires_at=clock_timestamp()+make_interval(secs=>$4),fencing_token=fencing_token+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2 RETURNING fencing_token").bind(state.tenant_id).bind(revision_id).bind(owner).bind(RECONCILIATION_LEASE_SECONDS).fetch_one(&mut *transaction).await?;
    transaction.commit().await?;
    match state
        .database
        .commit_document_revision(state.tenant_id, revision_id)
        .await
    {
        Ok(_) => {
            sqlx::query("UPDATE filebelt_document.reconciliation_jobs SET state='complete',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2 AND state='running' AND lease_owner=$3 AND fencing_token=$4").bind(state.tenant_id).bind(revision_id).bind(owner).bind(fence).execute(state.database.pool()).await?;
        }
        Err(DatabaseError::StaleGeneration) => {
            match state
                .database
                .reject_document_revision_for_authorization_change(state.tenant_id, revision_id)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    warn!(%revision_id, %error, "document authorization rejection deferred");
                    sqlx::query("UPDATE filebelt_document.reconciliation_jobs SET state=CASE WHEN attempt_count>=8 THEN 'terminal' ELSE 'retry_wait' END,last_error_code='authorization_rejection_failed',available_at=clock_timestamp()+interval '30 seconds',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2 AND state='running' AND lease_owner=$3 AND fencing_token=$4").bind(state.tenant_id).bind(revision_id).bind(owner).bind(fence).execute(state.database.pool()).await?;
                }
            }
        }
        Err(error) => {
            warn!(%revision_id, %error, "document revision commit deferred");
            sqlx::query("UPDATE filebelt_document.reconciliation_jobs SET state=CASE WHEN attempt_count>=8 THEN 'terminal' ELSE 'retry_wait' END,last_error_code='commit_failed',available_at=clock_timestamp()+interval '30 seconds',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision_id=$2 AND state='running' AND lease_owner=$3 AND fencing_token=$4").bind(state.tenant_id).bind(revision_id).bind(owner).bind(fence).execute(state.database.pool()).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use filebelt_database::document::{DocumentParticipantRecord, DocumentSessionRecord};

    fn launch(conflict_head_version_id: Option<Uuid>) -> DocumentLaunchRecord {
        DocumentLaunchRecord {
            grant_id: Uuid::nil(),
            expires_at: "2026-01-01T00:00:00Z".into(),
            session: DocumentSessionRecord {
                id: Uuid::new_v4(),
                session_principal_id: Uuid::new_v4(),
                drive_id: Uuid::new_v4(),
                node_id: Uuid::new_v4(),
                base_version_id: Uuid::new_v4(),
                expected_head_version_id: Uuid::new_v4(),
                provider_id: "onlyoffice".into(),
                state: if conflict_head_version_id.is_some() {
                    "conflict".into()
                } else {
                    "active".into()
                },
                fencing_token: 1,
                created_at: "2026-01-01T00:00:00Z".into(),
                created_at_unix_microseconds: 1_767_225_600_000_000,
                absolute_expires_at: "2026-01-02T00:00:00Z".into(),
                reconnect_until: "2026-01-01T00:30:00Z".into(),
                closed_at: None,
                close_reason: None,
                conflict_head_version_id,
            },
            participant: DocumentParticipantRecord {
                id: Uuid::new_v4(),
                document_session_id: Uuid::new_v4(),
                user_principal_id: Uuid::new_v4(),
                api_session_id: Uuid::new_v4(),
                mode: "edit".into(),
                state: "active".into(),
                display_name: "Ada".into(),
                created_at: "2026-01-01T00:00:01Z".into(),
                last_activity_at: "2026-01-01T00:00:00Z".into(),
                disconnected_until: None,
                generations: DocumentAuthorizationGenerations {
                    membership: 1,
                    drive_acl: 1,
                    namespace: 1,
                    resource_acl: 1,
                },
            },
        }
    }

    #[test]
    fn conflicted_session_exposes_authoritative_head() {
        let head = Uuid::new_v4();
        assert_eq!(
            wire_session(&launch(Some(head))).conflict_head_version_id,
            head.to_string()
        );
    }

    #[test]
    fn non_conflicted_session_omits_head() {
        assert!(
            wire_session(&launch(None))
                .conflict_head_version_id
                .is_empty()
        );
    }

    #[test]
    fn conflict_commit_outcome_exposes_its_retention_deadline() {
        let outcome = commit_outcome(DocumentCommitResult::Conflict {
            retained_until: "2026-01-02T03:04:05Z".into(),
        });
        assert_eq!(outcome.state, DocumentCommitState::Conflict as i32);
        assert_eq!(outcome.retained_until_unix_seconds, 1_767_323_045);
    }

    #[test]
    fn checkpoint_callback_receipt_is_explicit_and_terminal() {
        assert_eq!(
            callback_state("checkpoint"),
            filebelt_document_protocol::DocumentCallbackState::Checkpoint as i32
        );
    }
}

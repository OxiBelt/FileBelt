// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral document-session HTTP controls.
//!
//! This module deliberately has no dependency on a provider adapter or the
//! `filebelt_document` database schema. The API authorizes a request with the
//! common Virtual ACL model and then uses the deterministic Protobuf contract
//! at the document-service mTLS boundary.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_control_protocol::{Config, DeploymentMode};
use filebelt_document_protocol::{
    CreateDocumentConflictCopyCommand, CreateDocumentSessionCommand,
    DocumentAuthorizationGenerations, DocumentExecuteRequest, DocumentExecuteResponse,
    DocumentParticipant, DocumentSession, DocumentSessionDetail, DocumentSessionErrorCode,
    DocumentSessionMode, DocumentSessionPage, DocumentSessionPageAnchor,
    ForceCloseDocumentSessionCommand, GetDocumentSessionCommand, IssueDocumentLaunchGrantCommand,
    ListDocumentSessionsCommand, RevokeDocumentSessionCommand, document_execute_request,
    document_execute_response,
};
use filebelt_domain::{Action, NormalizedName};
use jiff::Timestamp;
use prost::Message as _;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{AuthenticatedSession, authenticate, authenticate_mutation};
use crate::error::ApiError;
use crate::policy::{AuthorizationGrant, authorize_session_bound};
use crate::resources::{NodeResponse, VersionResponse};

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const DOCUMENT_OPERATION_DIGEST_DOMAIN: &[u8] = b"filebelt.document.operation.v1\0";
const EXECUTE_CONTENT_TYPE: &str = "application/x-protobuf";
const MAX_EXECUTE_RESPONSE_BYTES: u64 = 1_048_576;

pub(crate) struct DocumentApiState {
    execute: Client,
    execute_url: Url,
    launch_action: Url,
    provider_origin: String,
}

pub(crate) fn initialize(config: &Config) -> Result<Option<Arc<DocumentApiState>>> {
    if !config.documents.enabled {
        return Ok(None);
    }
    let execute_url = config
        .documents
        .url
        .clone()
        .ok_or_else(|| anyhow!("document service URL is absent"))?
        .join("internal/v1/document/execute")
        .context("document execute URL is invalid")?;
    let launch_action = config
        .documents
        .launch_action
        .clone()
        .ok_or_else(|| anyhow!("document launch action is absent"))?;
    let provider_origin = config
        .documents
        .provider_origin
        .as_ref()
        .ok_or_else(|| anyhow!("document provider origin is absent"))?
        .origin()
        .ascii_serialization();
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let certificate = std::fs::read(
            config
                .documents
                .client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("document client certificate is absent"))?,
        )?;
        let private_key = std::fs::read(
            config
                .documents
                .client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("document client key is absent"))?,
        )?;
        let mut identity_pem = certificate;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&private_key);
        let identity =
            Identity::from_pem(&identity_pem).context("document client identity is invalid")?;
        let ca = std::fs::read(
            config
                .documents
                .server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("document service CA is absent"))?,
        )?;
        let certificates =
            Certificate::from_pem_bundle(&ca).context("document service CA is invalid")?;
        builder = builder
            .https_only(true)
            .tls_built_in_root_certs(false)
            .identity(identity);
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(Some(Arc::new(DocumentApiState {
        execute: builder
            .build()
            .context("cannot initialize document client")?,
        execute_url,
        launch_action,
        provider_origin,
    })))
}

impl DocumentApiState {
    async fn execute(
        &self,
        command: document_execute_request::Command,
    ) -> Result<document_execute_response::Result, ApiError> {
        let request_id = Uuid::new_v4().hyphenated().to_string();
        let body = DocumentExecuteRequest {
            request_id: request_id.clone(),
            command: Some(command),
        }
        .encode_to_vec();
        let response = self
            .execute
            .post(self.execute_url.clone())
            .header(header::CONTENT_TYPE, EXECUTE_CONTENT_TYPE)
            .header(header::ACCEPT, EXECUTE_CONTENT_TYPE)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "document service request failed");
                unavailable()
            })?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_EXECUTE_RESPONSE_BYTES)
        {
            return Err(unavailable());
        }
        let bytes = response.bytes().await.map_err(|_| unavailable())?;
        if u64::try_from(bytes.len()).map_err(|_| unavailable())? > MAX_EXECUTE_RESPONSE_BYTES {
            return Err(unavailable());
        }
        let decoded = DocumentExecuteResponse::decode(bytes.as_ref()).map_err(|_| unavailable())?;
        if !bool::from(decoded.request_id.as_bytes().ct_eq(request_id.as_bytes())) {
            return Err(unavailable());
        }
        match decoded.result.ok_or_else(unavailable)? {
            document_execute_response::Result::Error(error) => Err(document_error(error.code)),
            result => Ok(result),
        }
    }
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/document-sessions", routing::get(list_own_sessions))
        .route(
            "/document-sessions/{document_session_id}",
            routing::get(get_own_session).delete(revoke_own_session),
        )
        .route(
            "/document-sessions/{document_session_id}/conflict-copy",
            routing::post(create_conflict_copy),
        )
        .route(
            "/document-sessions/{document_session_id}/handoff",
            routing::post(redeem_launch_handoff),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/document-sessions",
            routing::get(list_node_sessions).post(create_session),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}",
            routing::delete(force_close_session),
        )
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionRequest {
    base_version_id: String,
    mode: DocumentMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DocumentMode {
    View,
    Comment,
    Review,
    Edit,
}

impl DocumentMode {
    const fn protocol(self) -> DocumentSessionMode {
        match self {
            Self::View => DocumentSessionMode::View,
            Self::Comment => DocumentSessionMode::Comment,
            Self::Review => DocumentSessionMode::Review,
            Self::Edit => DocumentSessionMode::Edit,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConflictCopyRequest {
    target_parent_id: String,
    target_name: String,
    expected_parent_generation: i64,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    #[serde(default = "default_page_limit")]
    limit: usize,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SessionResponse {
    id: Uuid,
    drive_id: Uuid,
    node_id: Uuid,
    base_version_id: Uuid,
    mode: String,
    state: String,
    created_at: String,
    last_activity_at: String,
    expires_at: String,
    closed_at: Option<String>,
    conflict_head_version_id: Option<Uuid>,
    participant_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ParticipantResponse {
    principal_id: Uuid,
    display_name: String,
    mode: String,
    active: bool,
    joined_at: String,
    last_activity_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DetailResponse {
    session: SessionResponse,
    participants: Vec<ParticipantResponse>,
    provider_origin: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct LaunchHandoffResponse {
    session_id: Uuid,
    action: String,
    grant: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConflictCopyResponse {
    node: NodeResponse,
    version: VersionResponse,
}

async fn list_own_sessions(
    State(state): State<AppState>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<Page<SessionResponse>>, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate(&state, &headers).await?;
    let limit = validated_limit(page.limit)?;
    let anchor = page
        .cursor
        .as_deref()
        .map(decode_session_cursor)
        .transpose()?;
    let result = documents
        .execute(document_execute_request::Command::ListSessions(
            ListDocumentSessionsCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                api_session_id: session.record.session_id.to_string(),
                drive_id: String::new(),
                node_id: String::new(),
                limit: u32::try_from(limit).map_err(|_| ApiError::internal())?,
                anchor,
                generations: None,
            },
        ))
        .await?;
    Ok(Json(session_page_response(expect_sessions(result)?)?))
}

async fn get_own_session(
    State(state): State<AppState>,
    Path(document_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DetailResponse>, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate(&state, &headers).await?;
    let document_session_id = parse_uuid_v4(&document_session_id)?;
    let detail = get_owned_detail(documents, &state, &session, document_session_id).await?;
    Ok(Json(detail_response(&documents.provider_origin, &detail)?))
}

async fn revoke_own_session(
    State(state): State<AppState>,
    Path(document_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let document_session_id = parse_uuid_v4(&document_session_id)?;
    let fingerprint = fingerprint(&(document_session_id, "owner_revoke"))?;
    let operation_digest = document_operation_digest(
        &state,
        &session,
        "DELETE /api/v1/document-sessions/{document_session_id}",
        key,
    );
    if replay_no_content(
        &state,
        &session,
        "DELETE /api/v1/document-sessions/{document_session_id}",
        key,
        &fingerprint,
    )
    .await?
    {
        return Ok(StatusCode::NO_CONTENT);
    }
    let detail = get_owned_detail(documents, &state, &session, document_session_id).await?;
    let participant_id = own_participant_id(&detail, session.record.principal_id)?;
    let result = documents
        .execute(document_execute_request::Command::RevokeSession(
            RevokeDocumentSessionCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                participant_id: participant_id.to_string(),
                reason: "owner_revoke".into(),
                operation_digest: operation_digest.to_vec(),
                request_fingerprint: fingerprint.to_vec(),
            },
        ))
        .await?;
    let _ = expect_detail(result)?;
    store_no_content(
        &state,
        &session,
        "DELETE /api/v1/document-sessions/{document_session_id}",
        key,
        &fingerprint,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_node_sessions(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<Page<SessionResponse>>, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let limit = validated_limit(page.limit)?;
    let anchor = page
        .cursor
        .as_deref()
        .map(decode_session_cursor)
        .transpose()?;
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ManageAcl,
    )
    .await?;
    let result = documents
        .execute(document_execute_request::Command::ListSessions(
            ListDocumentSessionsCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                api_session_id: session.record.session_id.to_string(),
                drive_id: drive_id.to_string(),
                node_id: node_id.to_string(),
                limit: u32::try_from(limit).map_err(|_| ApiError::internal())?,
                anchor,
                generations: Some(generations(grant)),
            },
        ))
        .await?;
    Ok(Json(session_page_response(expect_sessions(result)?)?))
}

async fn create_session(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Response, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let base_version_id = parse_uuid_v4(&request.base_version_id)?;
    let fingerprint = fingerprint(&(drive_id, node_id, base_version_id, request.mode))?;
    let operation_digest = document_operation_digest(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions",
        key,
    );
    if let Some(response) = replay::<DetailResponse>(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions",
        key,
        &fingerprint,
    )
    .await?
    {
        return response_with_status(response.0, response.1);
    }
    let grant = authorize_document_mode(&state, &session, drive_id, node_id, request.mode).await?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    if node.head_version_id != Some(base_version_id) {
        return Err(ApiError::conflict(
            "document.base_version_conflict",
            "The requested document base is no longer the current file head",
        ));
    }
    let result = documents
        .execute(document_execute_request::Command::CreateSession(
            CreateDocumentSessionCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                api_session_id: session.record.session_id.to_string(),
                drive_id: drive_id.to_string(),
                node_id: node_id.to_string(),
                base_version_id: base_version_id.to_string(),
                provider_id: state.config.documents.provider_id.clone(),
                mode: request.mode.protocol() as i32,
                generations: Some(generations(grant)),
                operation_digest: operation_digest.to_vec(),
                request_fingerprint: fingerprint.to_vec(),
            },
        ))
        .await?;
    let response = detail_response(&documents.provider_origin, &expect_detail(result)?)?;
    let stored = store_idempotent(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    response_with_status(StatusCode::CREATED.as_u16(), stored)
}

async fn force_close_session(
    State(state): State<AppState>,
    Path((drive_id, node_id, document_session_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let document_session_id = parse_uuid_v4(&document_session_id)?;
    let fingerprint = fingerprint(&(drive_id, node_id, document_session_id, "force_close"))?;
    let operation_digest = document_operation_digest(
        &state,
        &session,
        "DELETE /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}",
        key,
    );
    if replay_no_content(
        &state,
        &session,
        "DELETE /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}",
        key,
        &fingerprint,
    )
    .await?
    {
        return Ok(StatusCode::NO_CONTENT);
    }
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ManageAcl,
    )
    .await?;
    let result = documents
        .execute(document_execute_request::Command::ForceCloseSession(
            ForceCloseDocumentSessionCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                document_session_id: document_session_id.to_string(),
                reason: "manager_force_close".into(),
                api_session_id: session.record.session_id.to_string(),
                drive_id: drive_id.to_string(),
                node_id: node_id.to_string(),
                generations: Some(generations(grant)),
                operation_digest: operation_digest.to_vec(),
                request_fingerprint: fingerprint.to_vec(),
            },
        ))
        .await?;
    let _ = expect_detail(result)?;
    store_no_content(
        &state,
        &session,
        "DELETE /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}",
        key,
        &fingerprint,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_conflict_copy(
    State(state): State<AppState>,
    Path(document_session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ConflictCopyRequest>,
) -> Result<Response, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let document_session_id = parse_uuid_v4(&document_session_id)?;
    let target_parent_id = parse_uuid_v4(&request.target_parent_id)?;
    if request.expected_parent_generation <= 0 {
        return Err(ApiError::bad_request(
            "generation.invalid",
            "The expected parent generation must be positive",
        ));
    }
    let name = NormalizedName::new(&request.target_name).map_err(|error| {
        ApiError::bad_request(error.code(), "The conflict-copy name is invalid")
    })?;
    let fingerprint = fingerprint(&(
        document_session_id,
        target_parent_id,
        name.display(),
        request.expected_parent_generation,
    ))?;
    let operation_digest = document_operation_digest(
        &state,
        &session,
        "POST /api/v1/document-sessions/{document_session_id}/conflict-copy",
        key,
    );
    if let Some(response) = replay::<ConflictCopyResponse>(
        &state,
        &session,
        "POST /api/v1/document-sessions/{document_session_id}/conflict-copy",
        key,
        &fingerprint,
    )
    .await?
    {
        return response_with_status(response.0, response.1);
    }
    let detail = get_owned_detail(documents, &state, &session, document_session_id).await?;
    let stored = detail.session.as_ref().ok_or_else(ApiError::internal)?;
    let drive_id = parse_uuid_v4(&stored.drive_id)?;
    let node_id = parse_uuid_v4(&stored.node_id)?;
    if DocumentSessionStateView::from(stored)? != DocumentSessionStateView::Conflicted {
        return Err(ApiError::conflict(
            "document.conflict_copy_required",
            "A conflict copy can only be created from a conflicted document session",
        ));
    }
    let source = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    if source.parent_id != Some(target_parent_id) {
        return Err(ApiError::bad_request(
            "document.conflict_copy_parent_invalid",
            "The conflict copy must be created beside the source file",
        ));
    }
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        target_parent_id,
        Action::CreateChild,
    )
    .await?;
    let result = documents
        .execute(document_execute_request::Command::CreateConflictCopy(
            CreateDocumentConflictCopyCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                document_session_id: document_session_id.to_string(),
                display_name: name.display().to_owned(),
                target_parent_id: target_parent_id.to_string(),
                expected_parent_namespace_generation: u64::try_from(
                    request.expected_parent_generation,
                )
                .map_err(|_| ApiError::internal())?,
                api_session_id: session.record.session_id.to_string(),
                generations: Some(generations(grant)),
                operation_digest: operation_digest.to_vec(),
                request_fingerprint: fingerprint.to_vec(),
            },
        ))
        .await?;
    let copy = expect_conflict_copy(result)?;
    let copy_drive_id = parse_uuid_v4(&copy.drive_id)?;
    let copy_node_id = parse_uuid_v4(&copy.node_id)?;
    let copy_version_id = parse_uuid_v4(&copy.version_id)?;
    if copy_drive_id != drive_id {
        return Err(ApiError::internal());
    }
    let node = state
        .database
        .node(state.tenant_id, copy_drive_id, copy_node_id)
        .await?;
    let version = state
        .database
        .list_file_versions(state.tenant_id, copy_drive_id, copy_node_id)
        .await?
        .into_iter()
        .find(|version| version.id == copy_version_id)
        .ok_or_else(ApiError::internal)?;
    let response = ConflictCopyResponse {
        node: NodeResponse::try_from(node)?,
        version: VersionResponse::try_from(version)?,
    };
    let stored = store_idempotent(
        &state,
        &session,
        "POST /api/v1/document-sessions/{document_session_id}/conflict-copy",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    response_with_status(StatusCode::CREATED.as_u16(), stored)
}

async fn redeem_launch_handoff(
    State(state): State<AppState>,
    Path(document_session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let documents = require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    let document_session_id = parse_uuid_v4(&document_session_id)?;
    let _ = get_owned_detail(documents, &state, &session, document_session_id).await?;
    let result = documents
        .execute(document_execute_request::Command::IssueLaunchGrant(
            IssueDocumentLaunchGrantCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                api_session_id: session.record.session_id.to_string(),
                document_session_id: document_session_id.to_string(),
            },
        ))
        .await?;
    let launch = expect_launch_grant(result)?;
    if launch.launch_token.is_empty() {
        return Err(ApiError::internal());
    }
    let grant = URL_SAFE_NO_PAD.encode(launch.launch_token);
    if !(32..=4096).contains(&grant.len()) {
        return Err(ApiError::internal());
    }
    let response = LaunchHandoffResponse {
        session_id: document_session_id,
        action: documents.launch_action.to_string(),
        grant,
        expires_at: format_timestamp(launch.expires_at_unix_seconds)?,
    };
    response_with_status(StatusCode::CREATED.as_u16(), response)
}

async fn get_owned_detail(
    documents: &DocumentApiState,
    state: &AppState,
    session: &AuthenticatedSession,
    document_session_id: Uuid,
) -> Result<DocumentSessionDetail, ApiError> {
    let result = documents
        .execute(document_execute_request::Command::GetSession(
            GetDocumentSessionCommand {
                tenant_id: state.tenant_id.to_string(),
                actor_principal_id: session.record.principal_id.to_string(),
                document_session_id: document_session_id.to_string(),
            },
        ))
        .await?;
    let detail = expect_detail(result)?;
    let stored = detail.session.as_ref().ok_or_else(ApiError::internal)?;
    if parse_uuid_v4(&stored.session_id)? != document_session_id
        || parse_uuid_v4(&stored.principal_id)? != session.record.principal_id
    {
        return Err(ApiError::not_found());
    }
    Ok(detail)
}

async fn authorize_document_mode(
    state: &AppState,
    session: &AuthenticatedSession,
    drive_id: Uuid,
    node_id: Uuid,
    mode: DocumentMode,
) -> Result<AuthorizationGrant, ApiError> {
    let mut grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    for action in document_mode_actions(mode) {
        let candidate = authorize_session_bound(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            node_id,
            *action,
        )
        .await?;
        if candidate != grant {
            return Err(ApiError::conflict(
                "authorization.generation_changed",
                "Authorization changed while the request was being evaluated",
            ));
        }
        grant = candidate;
    }
    Ok(grant)
}

fn document_mode_actions(mode: DocumentMode) -> &'static [Action] {
    match mode {
        DocumentMode::View => &[Action::UseExternalEditor],
        DocumentMode::Comment => &[
            Action::UseExternalEditor,
            Action::WriteContent,
            Action::CreateVersion,
            Action::Comment,
        ],
        DocumentMode::Review => &[
            Action::UseExternalEditor,
            Action::WriteContent,
            Action::CreateVersion,
            Action::Review,
        ],
        DocumentMode::Edit => &[
            Action::UseExternalEditor,
            Action::WriteContent,
            Action::CreateVersion,
        ],
    }
}

fn generations(grant: AuthorizationGrant) -> DocumentAuthorizationGenerations {
    DocumentAuthorizationGenerations {
        membership_generation: grant.membership_generation,
        drive_acl_generation: grant.drive_acl_generation,
        namespace_generation: grant.namespace_generation,
        resource_acl_generation: grant.resource_acl_generation,
    }
}

fn session_response(detail: &DocumentSessionDetail) -> Result<SessionResponse, ApiError> {
    let session = detail.session.as_ref().ok_or_else(ApiError::internal)?;
    Ok(SessionResponse {
        id: parse_uuid_v4(&session.session_id)?,
        drive_id: parse_uuid_v4(&session.drive_id)?,
        node_id: parse_uuid_v4(&session.node_id)?,
        base_version_id: parse_uuid_v4(&session.base_version_id)?,
        mode: mode_name(session.mode)?.into(),
        state: DocumentSessionStateView::from(session)?.as_str().into(),
        created_at: format_timestamp(session.created_at_unix_seconds)?,
        last_activity_at: format_timestamp(session.last_activity_at_unix_seconds)?,
        expires_at: format_timestamp(session.expires_at_unix_seconds)?,
        closed_at: (session.closed_at_unix_seconds > 0)
            .then(|| format_timestamp(session.closed_at_unix_seconds))
            .transpose()?,
        conflict_head_version_id: (!session.conflict_head_version_id.is_empty())
            .then(|| parse_uuid_v4(&session.conflict_head_version_id))
            .transpose()?,
        participant_count: detail.participants.len(),
    })
}

fn detail_response(
    provider_origin: &str,
    detail: &DocumentSessionDetail,
) -> Result<DetailResponse, ApiError> {
    Ok(DetailResponse {
        session: session_response(detail)?,
        participants: detail
            .participants
            .iter()
            .map(participant_response)
            .collect::<Result<Vec<_>, _>>()?,
        provider_origin: provider_origin.into(),
    })
}

fn participant_response(
    participant: &DocumentParticipant,
) -> Result<ParticipantResponse, ApiError> {
    Ok(ParticipantResponse {
        principal_id: parse_uuid_v4(&participant.principal_id)?,
        display_name: participant_display_name(participant)?,
        mode: mode_name(participant.mode)?.into(),
        active: participant.active,
        joined_at: format_timestamp(participant.joined_at_unix_seconds)?,
        last_activity_at: format_timestamp(participant.last_activity_at_unix_seconds)?,
    })
}

fn participant_display_name(participant: &DocumentParticipant) -> Result<String, ApiError> {
    let display_name = participant.display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 120 {
        return Err(ApiError::internal());
    }
    Ok(display_name.to_owned())
}

fn own_participant_id(
    detail: &DocumentSessionDetail,
    principal_id: Uuid,
) -> Result<Uuid, ApiError> {
    detail
        .participants
        .iter()
        .find(|participant| participant.principal_id == principal_id.to_string())
        .map(|participant| parse_uuid_v4(&participant.participant_id))
        .transpose()?
        .ok_or_else(ApiError::not_found)
}

fn expect_detail(
    result: document_execute_response::Result,
) -> Result<DocumentSessionDetail, ApiError> {
    match result {
        document_execute_response::Result::Session(detail) => Ok(detail),
        _ => Err(ApiError::internal()),
    }
}

fn expect_sessions(
    result: document_execute_response::Result,
) -> Result<DocumentSessionPage, ApiError> {
    match result {
        document_execute_response::Result::Sessions(page) => Ok(page),
        _ => Err(ApiError::internal()),
    }
}

fn expect_launch_grant(
    result: document_execute_response::Result,
) -> Result<filebelt_document_protocol::DocumentLaunchGrant, ApiError> {
    match result {
        document_execute_response::Result::LaunchGrant(grant) => Ok(grant),
        _ => Err(ApiError::internal()),
    }
}

fn expect_conflict_copy(
    result: document_execute_response::Result,
) -> Result<filebelt_document_protocol::DocumentConflictCopy, ApiError> {
    match result {
        document_execute_response::Result::ConflictCopy(copy) => Ok(copy),
        _ => Err(ApiError::internal()),
    }
}

fn mode_name(value: i32) -> Result<&'static str, ApiError> {
    match DocumentSessionMode::try_from(value).map_err(|_| ApiError::internal())? {
        DocumentSessionMode::View => Ok("view"),
        DocumentSessionMode::Comment => Ok("comment"),
        DocumentSessionMode::Review => Ok("review"),
        DocumentSessionMode::Edit => Ok("edit"),
        DocumentSessionMode::Unspecified => Err(ApiError::internal()),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DocumentSessionStateView {
    Active,
    Conflicted,
    Revoked,
    Closed,
    Expired,
}

impl DocumentSessionStateView {
    fn from(session: &DocumentSession) -> Result<Self, ApiError> {
        match filebelt_document_protocol::DocumentSessionState::try_from(session.state)
            .map_err(|_| ApiError::internal())?
        {
            filebelt_document_protocol::DocumentSessionState::Active => Ok(Self::Active),
            filebelt_document_protocol::DocumentSessionState::Conflicted => Ok(Self::Conflicted),
            filebelt_document_protocol::DocumentSessionState::Revoked => Ok(Self::Revoked),
            filebelt_document_protocol::DocumentSessionState::Closed => Ok(Self::Closed),
            filebelt_document_protocol::DocumentSessionState::Expired => Ok(Self::Expired),
            filebelt_document_protocol::DocumentSessionState::Unspecified => {
                Err(ApiError::internal())
            }
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Conflicted => "conflicted",
            Self::Revoked => "revoked",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }
}

fn format_timestamp(seconds: i64) -> Result<String, ApiError> {
    Timestamp::new(seconds, 0)
        .map(|timestamp| timestamp.to_string())
        .map_err(|_| ApiError::internal())
}

fn document_error(code: i32) -> ApiError {
    match DocumentSessionErrorCode::try_from(code) {
        Ok(DocumentSessionErrorCode::AuthenticationRequired) => ApiError::unauthorized(),
        Ok(
            DocumentSessionErrorCode::AuthorizationChanged
            | DocumentSessionErrorCode::ModeUnauthorized
            | DocumentSessionErrorCode::WriteAuthorizationRequired
            | DocumentSessionErrorCode::VersionAuthorizationRequired
            | DocumentSessionErrorCode::BaseVersionConflict
            | DocumentSessionErrorCode::ConflictCopyRequired,
        ) => ApiError::conflict(
            "document.conflict",
            "The document session conflicts with current state",
        ),
        Ok(
            DocumentSessionErrorCode::SessionNotFound | DocumentSessionErrorCode::SessionNotOwner,
        ) => ApiError::not_found(),
        Ok(DocumentSessionErrorCode::SessionNotActive) => ApiError::conflict(
            "document.session_not_active",
            "The document session is no longer active",
        ),
        Ok(
            DocumentSessionErrorCode::ConflictCopyInvalid
            | DocumentSessionErrorCode::ProtocolViolation,
        ) => ApiError::bad_request(
            "document.request_invalid",
            "The document request is invalid",
        ),
        Ok(DocumentSessionErrorCode::Unavailable) => unavailable(),
        Ok(DocumentSessionErrorCode::Internal | DocumentSessionErrorCode::Unspecified) | Err(_) => {
            ApiError::internal()
        }
    }
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "document.unavailable",
        "The document service is unavailable",
    )
}

fn require_enabled(state: &AppState) -> Result<&DocumentApiState, ApiError> {
    state.documents.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "document.disabled",
            "Document editing is not enabled for this deployment",
        )
    })
}

fn default_page_limit() -> usize {
    100
}

fn validated_limit(limit: usize) -> Result<usize, ApiError> {
    if !(1..=200).contains(&limit) {
        return Err(ApiError::bad_request(
            "pagination.limit_invalid",
            "The page limit must be between 1 and 200",
        ));
    }
    Ok(limit)
}

fn session_page_response(page: DocumentSessionPage) -> Result<Page<SessionResponse>, ApiError> {
    let items = page
        .sessions
        .iter()
        .map(session_response)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = page
        .next_anchor
        .as_ref()
        .map(encode_session_cursor)
        .transpose()?;
    Ok(Page { items, next_cursor })
}

fn encode_session_cursor(anchor: &DocumentSessionPageAnchor) -> Result<String, ApiError> {
    if anchor.created_at_unix_microseconds <= 0 {
        return Err(ApiError::internal());
    }
    let session_id = parse_uuid_v4(&anchor.session_id).map_err(|_| ApiError::internal())?;
    Ok(URL_SAFE_NO_PAD.encode(format!(
        "document-session-v1\0{}\0{session_id}",
        anchor.created_at_unix_microseconds
    )))
}

fn decode_session_cursor(value: &str) -> Result<DocumentSessionPageAnchor, ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let value = String::from_utf8(bytes).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let mut fields = value.split('\0');
    let kind = fields.next().unwrap_or_default();
    let created_at_unix_microseconds = fields.next().unwrap_or_default().parse::<i64>().ok();
    let session_id = fields.next().unwrap_or_default();
    if kind != "document-session-v1" || fields.next().is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let created_at_unix_microseconds = created_at_unix_microseconds
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
        })?;
    let session_id = parse_uuid_v4(session_id).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    Ok(DocumentSessionPageAnchor {
        created_at_unix_microseconds,
        session_id: session_id.to_string(),
    })
}

fn parse_uuid_v4(value: &str) -> Result<Uuid, ApiError> {
    let id = Uuid::parse_str(value).map_err(|_| {
        ApiError::bad_request("id.invalid", "The identifier is not a canonical UUIDv4")
    })?;
    if id.get_version_num() != 4 || id.hyphenated().to_string() != value {
        return Err(ApiError::bad_request(
            "id.invalid",
            "The identifier is not a canonical UUIDv4",
        ));
    }
    Ok(id)
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        })
        .ok_or_else(|| {
            ApiError::bad_request(
                "idempotency.key_invalid",
                "A valid Idempotency-Key header is required",
            )
        })
}

fn fingerprint<T: Serialize>(request: &T) -> Result<[u8; 32], ApiError> {
    let bytes = serde_json::to_vec(request).map_err(|_| ApiError::internal())?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Binds the internal operation receipt to one authenticated browser session
/// and public idempotency route without transmitting or persisting the raw
/// client idempotency key outside the API idempotency record.
fn document_operation_digest(
    state: &AppState,
    session: &AuthenticatedSession,
    route: &str,
    idempotency_key: &str,
) -> [u8; 32] {
    let binding = document_operation_material(
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        route,
        idempotency_key,
    );
    state.digest(DOCUMENT_OPERATION_DIGEST_DOMAIN, &binding)
}

fn document_operation_material(
    tenant_id: Uuid,
    principal_id: Uuid,
    api_session_id: Uuid,
    route: &str,
    idempotency_key: &str,
) -> Vec<u8> {
    let mut binding = Vec::with_capacity(16 * 3 + 2 + route.len() + idempotency_key.len());
    binding.extend_from_slice(tenant_id.as_bytes());
    binding.extend_from_slice(principal_id.as_bytes());
    binding.extend_from_slice(api_session_id.as_bytes());
    append_operation_field(&mut binding, route);
    append_operation_field(&mut binding, idempotency_key);
    binding
}

fn append_operation_field(binding: &mut Vec<u8>, value: &str) {
    debug_assert!(value.len() <= u8::MAX.into());
    binding.push(u8::try_from(value.len()).expect("bounded operation field"));
    binding.extend_from_slice(value.as_bytes());
}

async fn replay<T: serde::de::DeserializeOwned>(
    state: &AppState,
    session: &AuthenticatedSession,
    route: &str,
    key: &str,
    fingerprint: &[u8; 32],
) -> Result<Option<(u16, T)>, ApiError> {
    let Some(record) = state
        .database
        .idempotency_record(state.tenant_id, session.record.principal_id, route, key)
        .await?
    else {
        return Ok(None);
    };
    if !bool::from(
        record
            .request_fingerprint
            .as_slice()
            .ct_eq(fingerprint.as_slice()),
    ) {
        return Err(ApiError::conflict(
            "idempotency.key_reused",
            "The idempotency key was used for a different request",
        ));
    }
    let status = u16::try_from(record.response_status).map_err(|_| ApiError::internal())?;
    let body = serde_json::from_value(record.response_body).map_err(|_| ApiError::internal())?;
    Ok(Some((status, body)))
}

async fn store_idempotent<T: serde::de::DeserializeOwned + Serialize>(
    state: &AppState,
    session: &AuthenticatedSession,
    route: &str,
    key: &str,
    fingerprint: &[u8; 32],
    status: StatusCode,
    body: &T,
) -> Result<T, ApiError> {
    let body = serde_json::to_value(body).map_err(|_| ApiError::internal())?;
    let stored = state
        .database
        .store_idempotency_response(
            state.tenant_id,
            session.record.principal_id,
            route,
            key,
            fingerprint,
            i32::from(status.as_u16()),
            &body,
        )
        .await?;
    if !bool::from(
        stored
            .request_fingerprint
            .as_slice()
            .ct_eq(fingerprint.as_slice()),
    ) {
        return Err(ApiError::conflict(
            "idempotency.key_reused",
            "The idempotency key was used for a different request",
        ));
    }
    serde_json::from_value(stored.response_body).map_err(|_| ApiError::internal())
}

async fn replay_no_content(
    state: &AppState,
    session: &AuthenticatedSession,
    route: &str,
    key: &str,
    fingerprint: &[u8; 32],
) -> Result<bool, ApiError> {
    let replayed: Option<(u16, ())> = replay(state, session, route, key, fingerprint).await?;
    let Some((status, ())) = replayed else {
        return Ok(false);
    };
    if status != StatusCode::NO_CONTENT.as_u16() {
        return Err(ApiError::internal());
    }
    Ok(true)
}

async fn store_no_content(
    state: &AppState,
    session: &AuthenticatedSession,
    route: &str,
    key: &str,
    fingerprint: &[u8; 32],
) -> Result<(), ApiError> {
    let _: () = store_idempotent(
        state,
        session,
        route,
        key,
        fingerprint,
        StatusCode::NO_CONTENT,
        &(),
    )
    .await?;
    Ok(())
}

fn response_with_status<T: Serialize>(status: u16, body: T) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(status).map_err(|_| ApiError::internal())?;
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{
        DocumentMode, decode_session_cursor, detail_response, document_mode_actions,
        document_operation_material, encode_session_cursor, format_timestamp,
        session_page_response,
    };
    use filebelt_document_protocol::{
        DocumentSession, DocumentSessionDetail, DocumentSessionMode, DocumentSessionPage,
        DocumentSessionPageAnchor, DocumentSessionState,
    };
    use filebelt_domain::Action;
    use uuid::Uuid;

    #[test]
    fn mutating_document_modes_require_version_authority() {
        assert_eq!(
            document_mode_actions(DocumentMode::View),
            &[Action::UseExternalEditor]
        );
        for mode in [
            DocumentMode::Comment,
            DocumentMode::Review,
            DocumentMode::Edit,
        ] {
            assert!(document_mode_actions(mode).contains(&Action::WriteContent));
            assert!(document_mode_actions(mode).contains(&Action::CreateVersion));
        }
    }

    #[test]
    fn unix_timestamps_are_rfc3339() {
        assert_eq!(format_timestamp(0).unwrap(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn session_detail_discloses_the_configured_provider_origin() {
        let identifier = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let detail = DocumentSessionDetail {
            session: Some(DocumentSession {
                session_id: identifier.to_string(),
                tenant_id: identifier.to_string(),
                drive_id: identifier.to_string(),
                node_id: identifier.to_string(),
                base_version_id: identifier.to_string(),
                principal_id: identifier.to_string(),
                api_session_id: identifier.to_string(),
                mode: DocumentSessionMode::View as i32,
                state: DocumentSessionState::Active as i32,
                session_epoch: 1,
                resource_acl_generation: 1,
                drive_acl_generation: 1,
                membership_generation: 1,
                namespace_generation: 1,
                created_at_unix_seconds: 0,
                last_activity_at_unix_seconds: 0,
                expires_at_unix_seconds: 1,
                closed_at_unix_seconds: 0,
                conflict_head_version_id: String::new(),
            }),
            participants: Vec::new(),
        };

        assert_eq!(
            detail_response("https://documentserver.example.test", &detail)
                .unwrap()
                .provider_origin,
            "https://documentserver.example.test"
        );
    }

    #[test]
    fn document_session_page_preserves_the_service_anchor_as_an_opaque_cursor() {
        let anchor = DocumentSessionPageAnchor {
            created_at_unix_microseconds: 1_754_726_400_123_456,
            session_id: "00000000-0000-4000-8000-000000000001".into(),
        };
        let page = session_page_response(DocumentSessionPage {
            sessions: Vec::new(),
            next_anchor: Some(anchor.clone()),
        })
        .unwrap();
        let cursor = page.next_cursor.unwrap();
        assert!(!cursor.contains(&anchor.session_id));
        assert_eq!(decode_session_cursor(&cursor).unwrap(), anchor);
    }

    #[test]
    fn document_session_cursor_rejects_malformed_or_unordered_anchor() {
        assert!(decode_session_cursor("not-a-cursor").is_err());
        assert!(
            encode_session_cursor(&DocumentSessionPageAnchor {
                created_at_unix_microseconds: 0,
                session_id: "00000000-0000-4000-8000-000000000001".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn document_operation_material_binds_the_authenticated_session_and_route() {
        let tenant = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let principal = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        let api_session = Uuid::parse_str("00000000-0000-4000-8000-000000000003").unwrap();
        let material =
            document_operation_material(tenant, principal, api_session, "POST /one", "key");

        assert_ne!(
            material,
            document_operation_material(tenant, principal, api_session, "POST /two", "key")
        );
        assert_ne!(
            material,
            document_operation_material(tenant, principal, api_session, "POST /one", "other")
        );
        assert_ne!(
            material,
            document_operation_material(tenant, principal, tenant, "POST /one", "key")
        );
        assert_ne!(
            document_operation_material(tenant, principal, api_session, "ab", "c"),
            document_operation_material(tenant, principal, api_session, "a", "bc")
        );

        assert_ne!(
            document_operation_material(
                tenant,
                principal,
                api_session,
                "DELETE /api/v1/document-sessions/{document_session_id}",
                "key",
            ),
            document_operation_material(
                tenant,
                principal,
                api_session,
                "DELETE /api/v1/drives/{drive_id}/nodes/{node_id}/document-sessions/{document_session_id}",
                "key",
            )
        );
    }

    #[test]
    fn close_handlers_forward_coordinator_receipts_before_finalizing_http_receipts() {
        let source = include_str!("documents.rs");
        for (start, end) in [
            ("async fn revoke_own_session", "async fn list_node_sessions"),
            (
                "async fn force_close_session",
                "async fn create_conflict_copy",
            ),
        ] {
            let handler = source
                .split_once(start)
                .expect("document close handler exists")
                .1
                .split_once(end)
                .expect("document close handler has a bounded source section")
                .0;
            assert!(handler.contains("document_operation_digest("));
            assert!(handler.contains("operation_digest: operation_digest.to_vec()"));
            assert!(handler.contains("request_fingerprint: fingerprint.to_vec()"));
            let execute = handler.find(".execute(").expect("coordinator mutation");
            let finalize = handler
                .find("store_no_content(")
                .expect("public receipt finalization");
            assert!(execute < finalize);
        }
    }
}

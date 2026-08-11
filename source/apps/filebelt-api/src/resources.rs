// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_collaboration_protocol::{
    CollaborationGrantClaims, PresenceMode, grant_digest, sign_collaboration_grant,
};
use filebelt_database::collaboration::{
    CollaborationAuthorizationContext, CollaborationAuthorizationGenerations,
    CollaborationImportIntentInput,
};
use filebelt_database::{
    AdvancedAclEntryInput, AdvancedAclEntryRecord, AdvancedAclReplacementPreflight, DatabaseError,
    DirectShareRecord, DriveRecord, FileVersionRecord, NodeRecord, UploadRecord,
};
use filebelt_domain::{Action, NormalizedName};
use filebelt_storage_protocol::{
    ApiStorageCapabilityUse, CapabilityClaims, CapabilityOperation,
    MAX_CAPABILITY_LIFETIME_SECONDS, sign_api_storage_capability,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{AuthenticatedSession, authenticate, authenticate_mutation, postgres_timestamp};
use crate::error::ApiError;
use crate::policy::{AuthorizationGrant, authorize, authorize_capability, authorize_session_bound};

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/drives", routing::get(list_drives))
        .route("/drives/{drive_id}", routing::get(get_drive))
        .route("/drives/{drive_id}/nodes/{node_id}", routing::get(get_node))
        .route(
            "/drives/{drive_id}/nodes/{node_id}/collaboration",
            routing::get(get_collaboration_summary).delete(discard_collaboration),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/collaboration-grants",
            routing::post(create_collaboration_grant),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/markdown-import-intents",
            routing::post(create_markdown_import_intent),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/children",
            routing::get(list_children),
        )
        .route(
            "/drives/{drive_id}/nodes/{parent_id}/directories",
            routing::post(create_directory),
        )
        .route("/drives/{drive_id}/uploads", routing::post(begin_upload))
        .route("/uploads/{upload_id}", routing::get(get_upload))
        .route("/uploads/{upload_id}/commit", routing::post(commit_upload))
        .route(
            "/drives/{drive_id}/nodes/{node_id}/download-grants",
            routing::post(create_download_grant),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/versions",
            routing::get(list_versions),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/versions/{version_id}/restore",
            routing::post(restore_version),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/shares",
            routing::get(list_shares).post(create_share),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/shares/{principal_id}",
            routing::delete(revoke_share),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/acl",
            routing::get(list_acl).put(replace_acl),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/trash",
            routing::post(trash_node),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/restore",
            routing::post(restore_node),
        )
        .route("/drives/{drive_id}/trash", routing::get(list_trash))
        .route("/shared", routing::get(list_shared))
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

#[derive(Debug, Serialize)]
struct DriveResponse {
    id: Uuid,
    kind: String,
    display_name: String,
    owner_display_name: String,
    root_id: Uuid,
    namespace_generation: i64,
    acl_generation: i64,
    quota_bytes: i64,
    used_physical_bytes: i64,
    reserved_bytes: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct NodeResponse {
    id: Uuid,
    drive_id: Uuid,
    parent_id: Option<Uuid>,
    kind: String,
    display_name: String,
    head_version_id: Option<Uuid>,
    namespace_generation: i64,
    acl_generation: i64,
    trashed: bool,
    updated_at: String,
    size_bytes: Option<i64>,
    version_ordinal: Option<i64>,
    head_media_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CollaborationSummaryResponse {
    active: bool,
    room_id: Option<Uuid>,
    codec: Option<String>,
    room_epoch: Option<i64>,
    durable_sequence: Option<i64>,
    base_version_id: Option<Uuid>,
    current_head_version_id: Option<Uuid>,
    dirty_expires_at: Option<String>,
    warning_at: Option<String>,
    frozen: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateCollaborationGrantRequest {
    transport: CollaborationTransport,
    client_id: String,
    presence_mode: CollaborationPresenceMode,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollaborationPresenceMode {
    Pseudonym,
    DisplayName,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollaborationTransport {
    Websocket,
    Webtransport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CollaborationGrantResponse {
    grant_id: Uuid,
    authorization: String,
    expires_at: String,
    codec: String,
    protocol_version: u8,
    presence_label: String,
    room: CollaborationSummaryResponse,
    endpoints: Vec<CollaborationEndpointResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CollaborationEndpointResponse {
    transport: String,
    url: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateMarkdownImportIntentRequest {
    source_version_id: String,
    target_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MarkdownImportIntentResponse {
    id: Uuid,
    source_drive_id: Uuid,
    source_node_id: Uuid,
    source_version_id: Uuid,
    target_parent_id: Uuid,
    target_name: String,
    target_media_type: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateDirectoryRequest {
    name: String,
    expected_parent_generation: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct BeginUploadRequest {
    parent_id: String,
    node_id: Option<String>,
    expected_head_version_id: Option<String>,
    expected_parent_generation: Option<i64>,
    name: String,
    declared_size_bytes: u64,
    declared_media_type: Option<String>,
    collaboration_checkpoint_id: Option<String>,
    import_intent_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CommitUploadRequest {
    expected_fencing_token: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UploadAllocationResponse {
    upload_id: Uuid,
    drive_id: Uuid,
    parent_id: Uuid,
    node_id: Option<Uuid>,
    payload_id: Uuid,
    declared_size_bytes: i64,
    chunk_size_bytes: i32,
    part_count: i32,
    fencing_token: i64,
    state: String,
    grants_url: String,
}

#[derive(Debug, Serialize)]
struct UploadGrantResponse {
    upload: UploadAllocationResponse,
    parts: Vec<ByteGrant>,
    next_cursor: Option<String>,
    finalize: ByteGrant,
}

#[derive(Debug, Serialize)]
struct ByteGrant {
    method: &'static str,
    path: String,
    authorization_scheme: &'static str,
    authorization: String,
    expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CommitUploadResponse {
    node_id: Uuid,
    version_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct DownloadGrantRequest {
    version_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct DownloadGrantResponse {
    grant_id: Uuid,
    method: &'static str,
    path: String,
    authorization_scheme: &'static str,
    authorization: String,
    expires_at: String,
    size_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct VersionResponse {
    id: Uuid,
    node_id: Uuid,
    ordinal: i64,
    size_bytes: i64,
    created_by: Uuid,
    restored_from_version_id: Option<Uuid>,
    created_at: String,
    current: bool,
    media_type: String,
    provenance: VersionProvenanceResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct VersionProvenanceResponse {
    origin: String,
    source_version_id: Option<Uuid>,
    creator_display_name: String,
    mcp_assisted: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct RestoreVersionRequest {
    expected_head_version_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ShareKind {
    Direct,
    Group,
    Link,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SharePreset {
    Viewer,
    Contributor,
    Manager,
}

impl SharePreset {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Contributor => "contributor",
            Self::Manager => "manager",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ShareInheritance {
    #[serde(rename = "self")]
    ThisResource,
    SelfAndDescendants,
}

impl ShareInheritance {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ThisResource => "self",
            Self::SelfAndDescendants => "self_and_descendants",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateShareRequest {
    kind: ShareKind,
    verified_email: Option<String>,
    preset: SharePreset,
    inheritance: ShareInheritance,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectShareResponse {
    kind: String,
    principal_id: Uuid,
    display_name: String,
    verified_email: String,
    preset: String,
    inheritance: String,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AclPrincipalSelector {
    kind: String,
    verified_email: Option<String>,
    group_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AclEntryMutation {
    action: String,
    effect: String,
    inheritance: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplaceAclRequest {
    principal: AclPrincipalSelector,
    entries: Vec<AclEntryMutation>,
}

#[derive(Debug, Serialize)]
struct AclEntryResponse {
    principal_id: Uuid,
    principal_kind: String,
    display_name: String,
    verified_email: Option<String>,
    action: String,
    effect: String,
    inheritance: String,
    source: String,
}

#[derive(Debug, Serialize)]
struct AclCollectionResponse {
    supported_actions: Vec<&'static str>,
    entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
struct NamespaceMutationRequest {
    expected_namespace_generation: i64,
}

async fn list_drives(
    State(state): State<AppState>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<Page<DriveResponse>>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let limit = validated_limit(page.limit)?;
    let cursor = page
        .cursor
        .as_deref()
        .map(decode_drive_cursor)
        .transpose()?;
    let candidates = state
        .database
        .list_drives(state.tenant_id, session.record.principal_id)
        .await?;
    let mut items = Vec::new();
    for drive in candidates {
        if authorize(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            drive.id,
            drive.root_id,
            Action::ReadMetadata,
        )
        .await
        .is_ok()
        {
            items.push(drive);
        }
    }
    if let Some(cursor) = cursor {
        let position = items
            .iter()
            .position(|drive| {
                drive.id == cursor.id
                    && drive.kind == cursor.kind
                    && drive.display_name == cursor.display_name
            })
            .ok_or_else(|| {
                ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
            })?;
        items = items.split_off(position + 1);
    }
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(encode_drive_cursor)
    } else {
        None
    };
    Ok(Json(Page {
        items: items.into_iter().map(DriveResponse::from).collect(),
        next_cursor,
    }))
}

async fn get_drive(
    State(state): State<AppState>,
    Path(drive_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let drive = state
        .database
        .list_drives(state.tenant_id, session.record.principal_id)
        .await?
        .into_iter()
        .find(|drive| drive.id == drive_id)
        .ok_or_else(ApiError::not_found)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive.id,
        drive.root_id,
        Action::ReadMetadata,
    )
    .await?;
    let etag = drive_etag(drive_id, drive.namespace_generation, drive.acl_generation);
    json_with_etag(StatusCode::OK, &DriveResponse::from(drive), etag)
}

async fn get_node(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::ReadMetadata,
    )
    .await?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    json_with_etag(
        StatusCode::OK,
        &NodeResponse::try_from(node.clone())?,
        node_etag(&node),
    )
}

async fn list_children(
    State(state): State<AppState>,
    Path((drive_id, parent_id)): Path<(String, String)>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let parent_id = parse_uuid_v4(&parent_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        parent_id,
        Action::ListChildren,
    )
    .await?;
    let parent = state
        .database
        .node(state.tenant_id, drive_id, parent_id)
        .await?;
    if parent.kind != "directory" {
        return Err(ApiError::conflict(
            "node.not_directory",
            "Children can only be listed for a directory",
        ));
    }
    let limit = validated_limit(page.limit)?;
    let cursor = page.cursor.as_deref().map(decode_cursor).transpose()?;
    let nodes = state
        .database
        .list_children(state.tenant_id, drive_id, parent_id)
        .await?;
    let mut visible = Vec::new();
    for node in nodes {
        if let Some(cursor) = &cursor
            && compare_node_cursor(&node, cursor) != Ordering::Greater
        {
            continue;
        }
        if authorize(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            node.id,
            Action::ReadMetadata,
        )
        .await
        .is_ok()
        {
            visible.push(node);
            if visible.len() > limit {
                break;
            }
        }
    }
    let next_cursor = if visible.len() > limit {
        visible.pop();
        visible.last().map(encode_cursor)
    } else {
        None
    };
    let response = Page {
        items: visible
            .into_iter()
            .map(NodeResponse::try_from)
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    };
    json_with_etag(StatusCode::OK, &response, node_etag(&parent))
}

async fn create_directory(
    State(state): State<AppState>,
    Path((drive_id, parent_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateDirectoryRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let parent_id = parse_uuid_v4(&parent_id)?;
    let name = NormalizedName::new(&request.name)
        .map_err(|error| ApiError::bad_request(error.code(), "The directory name is invalid"))?;
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        parent_id,
        Action::CreateChild,
    )
    .await?;
    let node = state
        .database
        .create_directory(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            parent_id,
            name.display(),
            name.comparison_key(),
            request.expected_parent_generation,
            generation_i64(grant.membership_generation)?,
            generation_i64(grant.drive_acl_generation)?,
            generation_i64(grant.namespace_generation)?,
            generation_i64(grant.resource_acl_generation)?,
        )
        .await?;
    json_with_etag(
        StatusCode::CREATED,
        &NodeResponse::try_from(node.clone())?,
        node_etag(&node),
    )
}

async fn get_collaboration_summary(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<CollaborationSummaryResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::WriteContent,
    )
    .await?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    let Some(room) = state
        .database
        .collaboration_room(state.tenant_id, drive_id, node_id)
        .await?
    else {
        return Ok(Json(CollaborationSummaryResponse {
            active: false,
            room_id: None,
            codec: None,
            room_epoch: None,
            durable_sequence: None,
            base_version_id: None,
            current_head_version_id: node.head_version_id,
            dirty_expires_at: None,
            warning_at: None,
            frozen: false,
        }));
    };
    Ok(Json(collaboration_summary_response(
        &room,
        node.head_version_id,
    )?))
}

async fn create_collaboration_grant(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateCollaborationGrantRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    if !state.config.collaboration.enabled {
        return Err(ApiError::not_found());
    }
    if matches!(request.transport, CollaborationTransport::Webtransport)
        && !state.config.collaboration.webtransport_enabled
    {
        return Err(ApiError::not_found());
    }
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let client_id = parse_uuid_v4(&request.client_id)?;
    let fingerprint = fingerprint(&(drive_id, node_id, &request))?;
    if let Some(response) = replay::<CollaborationGrantResponse>(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/collaboration-grants",
        key,
        &fingerprint,
    )
    .await?
    {
        let status = StatusCode::from_u16(response.0).map_err(|_| ApiError::internal())?;
        return Ok((status, Json(response.1)).into_response());
    }
    let read = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    let write = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::WriteContent,
    )
    .await?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    let base = node.head_version_id.ok_or_else(|| {
        ApiError::bad_request(
            "collaboration.head_required",
            "Markdown collaboration requires an immutable base version",
        )
    })?;
    let room = state
        .database
        .collaboration_get_or_create_room(
            state.tenant_id,
            drive_id,
            node_id,
            base,
            session.record.principal_id,
        )
        .await?;
    require_same_generations(read, write)?;
    let now = unix_time()?;
    let expires = now + 60;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ApiError::internal())?;
    let bootstrap_payload = state
        .database
        .payload_for_node(state.tenant_id, node_id, Some(base))
        .await?;
    let bootstrap_claims = CapabilityClaims {
        capability_id: Uuid::new_v4().to_string(),
        audience: CAPABILITY_AUDIENCE.into(),
        operation: CapabilityOperation::Download as i32,
        tenant_id: state.tenant_id.to_string(),
        principal_id: session.record.principal_id.to_string(),
        session_id: session.record.session_id.to_string(),
        resource_id: node_id.to_string(),
        upload_id: String::new(),
        payload_id: bootstrap_payload.payload_id.to_string(),
        part_number: 0,
        range_start: 0,
        range_end: u64::try_from(bootstrap_payload.size_bytes.saturating_sub(1)).unwrap_or(0),
        resource_acl_generation: write.resource_acl_generation,
        membership_generation: write.membership_generation,
        namespace_generation: write.namespace_generation,
        fencing_token: 0,
        nonce: random_nonce()?,
        issued_at_unix_seconds: now,
        expires_at_unix_seconds: expires,
        drive_acl_generation: write.drive_acl_generation,
        grant_id: Uuid::new_v4().to_string(),
    };
    let bootstrap_download_capability = sign_api_capability(&state, &bootstrap_claims)?;
    let grant_id = Uuid::new_v4();
    let mode = match request.presence_mode {
        CollaborationPresenceMode::Pseudonym => PresenceMode::Pseudonym,
        CollaborationPresenceMode::DisplayName => PresenceMode::DisplayName,
    };
    let presence_label = match request.presence_mode {
        CollaborationPresenceMode::Pseudonym => {
            let digest = blake3::hash(client_id.as_bytes());
            format!("Editor-{}", &digest.to_hex()[..8])
        }
        CollaborationPresenceMode::DisplayName => session.record.display_name.clone(),
    };
    let claims = CollaborationGrantClaims {
        grant_id: grant_id.to_string(),
        tenant_id: state.tenant_id.to_string(),
        room_id: room.room_id.to_string(),
        room_epoch: u64::try_from(room.epoch).map_err(|_| ApiError::internal())?,
        drive_id: drive_id.to_string(),
        node_id: node_id.to_string(),
        base_version_id: base.to_string(),
        principal_id: session.record.principal_id.to_string(),
        session_id: session.record.session_id.to_string(),
        client_id: client_id.to_string(),
        presence_mode: mode as i32,
        presence_label: presence_label.clone(),
        resource_acl_generation: write.resource_acl_generation,
        drive_acl_generation: write.drive_acl_generation,
        membership_generation: write.membership_generation,
        namespace_generation: write.namespace_generation,
        can_checkpoint: true,
        issued_at_unix_seconds: now,
        expires_at_unix_seconds: expires,
        nonce: nonce.to_vec(),
        bootstrap_download_capability,
    };
    let wire = sign_collaboration_grant(
        &claims,
        state
            .config
            .keys
            .api_collaboration_grant
            .as_ref()
            .ok_or_else(ApiError::internal)?
            .current_generation,
        state
            .collaboration_grant_signer
            .as_ref()
            .ok_or_else(ApiError::internal)?,
    )
    .map_err(|_| ApiError::internal())?;
    let digest = grant_digest(&wire);
    let grant = state
        .database
        .collaboration_create_join_grant(
            state.tenant_id,
            grant_id,
            room.room_id,
            room.epoch,
            &digest,
            session.record.principal_id,
            session.record.session_id,
            client_id,
            match request.presence_mode {
                CollaborationPresenceMode::Pseudonym => "pseudonym",
                CollaborationPresenceMode::DisplayName => "display_name",
            },
            &presence_label,
            generation_i64(write.resource_acl_generation)?,
            generation_i64(write.drive_acl_generation)?,
            generation_i64(read.membership_generation)?,
            generation_i64(read.namespace_generation)?,
            true,
        )
        .await?;
    let (transport, endpoint) = match request.transport {
        CollaborationTransport::Websocket => {
            let mut endpoint =
                Url::parse(&state.public_origin).map_err(|_| ApiError::internal())?;
            endpoint
                .set_scheme("wss")
                .map_err(|()| ApiError::internal())?;
            endpoint.set_path("/collaboration/v1/ws");
            ("websocket", endpoint)
        }
        CollaborationTransport::Webtransport => (
            "webtransport",
            state
                .config
                .collaboration
                .webtransport_endpoint
                .clone()
                .ok_or_else(ApiError::internal)?,
        ),
    };
    let response = CollaborationGrantResponse {
        grant_id: grant.id,
        authorization: wire,
        expires_at: postgres_timestamp(&grant.expires_at)?,
        codec: "yjs-v1".into(),
        protocol_version: 1,
        presence_label,
        room: collaboration_summary_response(&room, node.head_version_id)?,
        endpoints: vec![CollaborationEndpointResponse {
            transport: transport.into(),
            url: endpoint.to_string(),
        }],
    };
    let response = store_idempotent(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/collaboration-grants",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    let mut http = (StatusCode::CREATED, Json(response)).into_response();
    http.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(http)
}

async fn discard_collaboration(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let fingerprint = fingerprint(&(drive_id, node_id))?;
    if let Some(response) = replay::<()>(
        &state,
        &session,
        "DELETE /api/v1/drives/{drive_id}/nodes/{node_id}/collaboration",
        key,
        &fingerprint,
    )
    .await?
    {
        return StatusCode::from_u16(response.0).map_err(|_| ApiError::internal());
    }
    let delete_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::Delete,
    )
    .await?;
    let write_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::WriteContent,
    )
    .await?;
    require_same_generations(delete_grant, write_grant)?;
    let room = state
        .database
        .collaboration_room(state.tenant_id, drive_id, node_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    state
        .database
        .collaboration_discard(
            state.tenant_id,
            room.room_id,
            room.epoch,
            CollaborationAuthorizationContext {
                principal_id: session.record.principal_id,
                session_id: session.record.session_id,
                drive_id,
                node_id,
                generations: CollaborationAuthorizationGenerations {
                    membership: generation_i64(delete_grant.membership_generation)?,
                    drive_acl: generation_i64(delete_grant.drive_acl_generation)?,
                    namespace: generation_i64(delete_grant.namespace_generation)?,
                    resource_acl: generation_i64(delete_grant.resource_acl_generation)?,
                },
            },
        )
        .await?;
    store_idempotent(
        &state,
        &session,
        "DELETE /api/v1/drives/{drive_id}/nodes/{node_id}/collaboration",
        key,
        &fingerprint,
        StatusCode::NO_CONTENT,
        &(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_markdown_import_intent(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateMarkdownImportIntentRequest>,
) -> Result<(StatusCode, Json<MarkdownImportIntentResponse>), ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let version_id = parse_uuid_v4(&request.source_version_id)?;
    let name = NormalizedName::new(&request.target_name)
        .map_err(|error| ApiError::bad_request(error.code(), "The target file name is invalid"))?;
    let fingerprint = fingerprint(&(drive_id, node_id, version_id, &request))?;
    if let Some(response) = replay::<MarkdownImportIntentResponse>(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/markdown-import-intents",
        key,
        &fingerprint,
    )
    .await?
    {
        let status = StatusCode::from_u16(response.0).map_err(|_| ApiError::internal())?;
        return Ok((status, Json(response.1)));
    }
    let read = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    let source = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    let parent_id = source.parent_id.ok_or_else(ApiError::not_found)?;
    let create = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        parent_id,
        Action::CreateChild,
    )
    .await?;
    let intent = state
        .database
        .collaboration_create_import_intent(CollaborationImportIntentInput {
            tenant_id: state.tenant_id,
            drive_id,
            source_node_id: node_id,
            source_version_id: version_id,
            principal_id: session.record.principal_id,
            session_id: session.record.session_id,
            source_generations: CollaborationAuthorizationGenerations {
                membership: generation_i64(read.membership_generation)?,
                drive_acl: generation_i64(read.drive_acl_generation)?,
                namespace: generation_i64(read.namespace_generation)?,
                resource_acl: generation_i64(read.resource_acl_generation)?,
            },
            target_generations: CollaborationAuthorizationGenerations {
                membership: generation_i64(create.membership_generation)?,
                drive_acl: generation_i64(create.drive_acl_generation)?,
                namespace: generation_i64(create.namespace_generation)?,
                resource_acl: generation_i64(create.resource_acl_generation)?,
            },
            target_display_name: name.display(),
            target_name_key: name.comparison_key(),
        })
        .await?;
    let response = MarkdownImportIntentResponse {
        id: intent.id,
        source_drive_id: drive_id,
        source_node_id: node_id,
        source_version_id: version_id,
        target_parent_id: intent.target_parent_id,
        target_name: intent.target_display_name,
        target_media_type: "text/markdown".into(),
        expires_at: postgres_timestamp(&intent.expires_at)?,
    };
    let response = store_idempotent(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/markdown-import-intents",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

fn collaboration_summary_response(
    room: &filebelt_database::collaboration::CollaborationSummaryRecord,
    current_head_version_id: Option<Uuid>,
) -> Result<CollaborationSummaryResponse, ApiError> {
    Ok(CollaborationSummaryResponse {
        active: room.state == "active",
        room_id: Some(room.room_id),
        codec: Some("yjs-v1".into()),
        room_epoch: Some(room.epoch),
        durable_sequence: Some(room.durable_sequence),
        base_version_id: Some(room.base_version_id),
        current_head_version_id,
        dirty_expires_at: Some(postgres_timestamp(&room.expires_at)?),
        warning_at: Some(postgres_timestamp(&room.warning_at)?),
        frozen: room.state == "frozen",
    })
}

async fn begin_upload(
    State(state): State<AppState>,
    Path(drive_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<BeginUploadRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let parent_id = parse_uuid_v4(&request.parent_id)?;
    let node_id = request.node_id.as_deref().map(parse_uuid_v4).transpose()?;
    let expected_head = request
        .expected_head_version_id
        .as_deref()
        .map(parse_uuid_v4)
        .transpose()?;
    let collaboration_checkpoint_id = request
        .collaboration_checkpoint_id
        .as_deref()
        .map(parse_uuid_v4)
        .transpose()?;
    let import_intent_id = request
        .import_intent_id
        .as_deref()
        .map(parse_uuid_v4)
        .transpose()?;
    let declared_media_type = request.declared_media_type.as_deref();
    if declared_media_type == Some("text/markdown") && request.declared_size_bytes > 2_097_152
        || collaboration_checkpoint_id.is_some() && import_intent_id.is_some()
        || collaboration_checkpoint_id.is_some() && node_id.is_none()
        || import_intent_id.is_some() && node_id.is_some()
    {
        return Err(ApiError::bad_request(
            "upload.binding_invalid",
            "The upload media type or Markdown binding is invalid",
        ));
    }
    if (node_id.is_none()
        && (request.expected_parent_generation.is_none() || expected_head.is_some()))
        || (node_id.is_some() && expected_head.is_none())
    {
        return Err(ApiError::bad_request(
            "generation.expected_missing",
            "An expected parent generation or head version is required",
        ));
    }
    if request.declared_size_bytes > state.config.limits.max_file_bytes {
        return Err(ApiError::bad_request(
            "upload.too_large",
            "The declared file size exceeds the configured limit",
        ));
    }
    let name = NormalizedName::new(&request.name)
        .map_err(|error| ApiError::bad_request(error.code(), "The file name is invalid"))?;
    let resource_id = node_id.unwrap_or(parent_id);
    let action = if node_id.is_some() {
        Action::WriteContent
    } else {
        Action::CreateChild
    };
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        resource_id,
        action,
    )
    .await?;
    let parent = state
        .database
        .node(state.tenant_id, drive_id, parent_id)
        .await?;
    if parent.kind != "directory"
        || request
            .expected_parent_generation
            .is_some_and(|expected| expected <= 0 || expected != parent.namespace_generation)
    {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "generation.stale",
            "The parent directory generation is stale",
        ));
    }

    let fingerprint = fingerprint(&request)?;
    if let Some(response) = replay::<UploadAllocationResponse>(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/uploads",
        key,
        &fingerprint,
    )
    .await?
    {
        let status = StatusCode::from_u16(response.0).map_err(|_| ApiError::internal())?;
        return Ok((status, Json(response.1)).into_response());
    }
    let chunk_size = u64_to_i32(state.config.limits.chunk_size_bytes)?;
    let (layout, part_count) = upload_layout_and_part_count(
        request.declared_size_bytes,
        u64::from(chunk_size as u32),
        state.config.limits.whole_threshold_bytes,
    )?;
    if u32::try_from(part_count).map_err(|_| ApiError::internal())? > state.config.limits.max_parts
    {
        return Err(ApiError::bad_request(
            "upload.too_many_parts",
            "The upload requires too many parts",
        ));
    }
    let upload = state
        .database
        .begin_upload(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            parent_id,
            node_id,
            request.expected_parent_generation,
            expected_head,
            name.display(),
            name.comparison_key(),
            i64::try_from(request.declared_size_bytes).map_err(|_| ApiError::internal())?,
            chunk_size,
            part_count,
            layout,
            declared_media_type,
            collaboration_checkpoint_id,
            import_intent_id,
            i64::try_from(state.config.limits.upload_ttl_seconds)
                .map_err(|_| ApiError::internal())?,
            generation_i64(grant.membership_generation)?,
            generation_i64(grant.drive_acl_generation)?,
            generation_i64(grant.namespace_generation)?,
            generation_i64(grant.resource_acl_generation)?,
        )
        .await?;
    let response = UploadAllocationResponse::from(upload);
    let stored = store_idempotent(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/uploads",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(stored)).into_response())
}

async fn get_upload(
    State(state): State<AppState>,
    Path(upload_id): Path<String>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<UploadGrantResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let upload_id = parse_uuid_v4(&upload_id)?;
    let upload = state.database.upload(state.tenant_id, upload_id).await?;
    let resource_id = upload.node_id.unwrap_or(upload.parent_id);
    let action = if upload.node_id.is_some() {
        Action::WriteContent
    } else {
        Action::CreateChild
    };
    let grant = authorize_capability(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        upload.drive_id,
        resource_id,
        action,
    )
    .await?;
    if upload.owner_principal_id != session.record.principal_id || upload.state != "open" {
        return Err(ApiError::not_found());
    }
    let now = unix_time()?;
    let expires = now + MAX_CAPABILITY_LIFETIME_SECONDS;
    let limit = validated_limit(page.limit)?;
    let first_part = page
        .cursor
        .as_deref()
        .map(decode_part_cursor)
        .transpose()?
        .map_or(0, |part| part.saturating_add(1));
    if first_part < 0 || first_part > upload.part_count {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let limit_i32 = i32::try_from(limit).map_err(|_| ApiError::internal())?;
    let last_part_exclusive = first_part.saturating_add(limit_i32).min(upload.part_count);
    let mut parts = Vec::with_capacity(limit);
    for part in first_part..last_part_exclusive {
        let capability = issue_capability(
            &state,
            &session,
            &upload,
            resource_id,
            grant,
            CapabilityOperation::UploadPart,
            u64::try_from(part).map_err(|_| ApiError::internal())?,
            now,
            expires,
        )?;
        parts.push(ByteGrant {
            method: "PUT",
            path: format!("/io/v1/uploads/{upload_id}/parts/{part}"),
            authorization_scheme: "fbcap1",
            authorization: capability,
            expires_at: rfc3339(expires)?,
        });
    }
    let finalize = ByteGrant {
        method: "POST",
        path: format!("/io/v1/uploads/{upload_id}/finalize"),
        authorization_scheme: "fbcap1",
        authorization: issue_capability(
            &state,
            &session,
            &upload,
            resource_id,
            grant,
            CapabilityOperation::FinalizeUpload,
            0,
            now,
            expires,
        )?,
        expires_at: rfc3339(expires)?,
    };
    let next_cursor = (last_part_exclusive < upload.part_count)
        .then(|| encode_part_cursor(last_part_exclusive - 1));
    Ok(Json(UploadGrantResponse {
        upload: UploadAllocationResponse::from(upload),
        parts,
        next_cursor,
        finalize,
    }))
}

async fn commit_upload(
    State(state): State<AppState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CommitUploadRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let upload_id = parse_uuid_v4(&upload_id)?;
    let upload = state
        .database
        .upload_owned_by(state.tenant_id, upload_id, session.record.principal_id)
        .await?;
    if upload.fencing_token != request.expected_fencing_token {
        return Err(ApiError::conflict(
            "upload.fence_mismatch",
            "The upload fencing token does not match",
        ));
    }
    let resource_id = upload.node_id.unwrap_or(upload.parent_id);
    let action = if upload.node_id.is_some() {
        Action::CreateVersion
    } else {
        Action::CreateChild
    };
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        upload.drive_id,
        resource_id,
        action,
    )
    .await?;
    if upload.node_id.is_some() {
        let write_grant = authorize_session_bound(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            upload.drive_id,
            resource_id,
            Action::WriteContent,
        )
        .await?;
        require_same_generations(grant, write_grant)?;
    }
    let fingerprint = fingerprint(&request)?;
    if let Some(response) = replay::<CommitUploadResponse>(
        &state,
        &session,
        "POST /api/v1/uploads/{upload_id}/commit",
        key,
        &fingerprint,
    )
    .await?
    {
        let status = StatusCode::from_u16(response.0).map_err(|_| ApiError::internal())?;
        return Ok((status, Json(response.1)).into_response());
    }
    let (node_id, version_id) = state
        .database
        .commit_upload(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            upload_id,
            request.expected_fencing_token,
            generation_i64(grant.membership_generation)?,
            generation_i64(grant.drive_acl_generation)?,
            generation_i64(grant.namespace_generation)?,
            generation_i64(grant.resource_acl_generation)?,
        )
        .await?;
    let response = CommitUploadResponse {
        node_id,
        version_id,
    };
    let stored = store_idempotent(
        &state,
        &session,
        "POST /api/v1/uploads/{upload_id}/commit",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(stored)).into_response())
}

async fn create_download_grant(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<DownloadGrantRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let version_id = request
        .version_id
        .as_deref()
        .map(parse_uuid_v4)
        .transpose()?;
    let grant = authorize_capability(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    let payload = state
        .database
        .payload_for_node(state.tenant_id, node_id, version_id)
        .await?;
    if payload.drive_id != drive_id {
        return Err(ApiError::not_found());
    }
    let grant_id = Uuid::new_v4();
    let now = unix_time()?;
    let expires = now + MAX_CAPABILITY_LIFETIME_SECONDS;
    let claims = CapabilityClaims {
        capability_id: grant_id.to_string(),
        audience: CAPABILITY_AUDIENCE.into(),
        operation: CapabilityOperation::Download as i32,
        tenant_id: state.tenant_id.to_string(),
        principal_id: session.record.principal_id.to_string(),
        session_id: session.record.session_id.to_string(),
        resource_id: node_id.to_string(),
        upload_id: String::new(),
        payload_id: payload.payload_id.to_string(),
        part_number: 0,
        range_start: 0,
        range_end: u64::try_from(payload.size_bytes.saturating_sub(1)).unwrap_or(0),
        resource_acl_generation: grant.resource_acl_generation,
        membership_generation: grant.membership_generation,
        namespace_generation: grant.namespace_generation,
        fencing_token: 0,
        nonce: random_nonce()?,
        issued_at_unix_seconds: now,
        expires_at_unix_seconds: expires,
        drive_acl_generation: grant.drive_acl_generation,
        grant_id: grant_id.to_string(),
    };
    let capability = sign_api_capability(&state, &claims)?;
    let path = format!("/io/v1/downloads/{grant_id}");
    let body = DownloadGrantResponse {
        grant_id,
        method: "GET",
        path: path.clone(),
        authorization_scheme: "fbcap1",
        authorization: capability.clone(),
        expires_at: rfc3339(expires)?,
        size_bytes: payload.size_bytes,
    };
    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    let cookie = HeaderValue::from_str(&format!(
        "filebelt_capability={capability}; Path={path}; Max-Age={MAX_CAPABILITY_LIFETIME_SECONDS}; Secure; HttpOnly; SameSite=Lax"
    ))
    .map_err(|_| ApiError::internal())?;
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn list_versions(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<Page<VersionResponse>>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::ReadMetadata,
    )
    .await?;
    let limit = validated_limit(page.limit)?;
    let cursor = page
        .cursor
        .as_deref()
        .map(decode_version_cursor)
        .transpose()?;
    let mut versions = state
        .database
        .list_file_versions(state.tenant_id, drive_id, node_id)
        .await?;
    if let Some(cursor) = cursor {
        let position = versions
            .iter()
            .position(|version| version.id == cursor.id && version.ordinal == cursor.ordinal)
            .ok_or_else(|| {
                ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
            })?;
        versions = versions.split_off(position + 1);
    }
    let next_cursor = if versions.len() > limit {
        versions.truncate(limit);
        versions.last().map(encode_version_cursor)
    } else {
        None
    };
    Ok(Json(Page {
        items: versions
            .into_iter()
            .map(VersionResponse::try_from)
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    }))
}

async fn restore_version(
    State(state): State<AppState>,
    Path((drive_id, node_id, version_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(request): Json<RestoreVersionRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let version_id = parse_uuid_v4(&version_id)?;
    let expected_head_version_id = parse_uuid_v4(&request.expected_head_version_id)?;
    let create_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::CreateVersion,
    )
    .await?;
    let write_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::WriteContent,
    )
    .await?;
    require_same_generations(create_grant, write_grant)?;
    let fingerprint = fingerprint(&(drive_id, node_id, version_id, &request))?;
    if let Some(response) = replay::<VersionResponse>(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/versions/{version_id}/restore",
        key,
        &fingerprint,
    )
    .await?
    {
        let status = StatusCode::from_u16(response.0).map_err(|_| ApiError::internal())?;
        return Ok((status, Json(response.1)).into_response());
    }
    let restored = state
        .database
        .restore_file_version(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            node_id,
            version_id,
            Some(expected_head_version_id),
            generation_i64(create_grant.membership_generation)?,
            generation_i64(create_grant.drive_acl_generation)?,
            generation_i64(create_grant.namespace_generation)?,
            generation_i64(create_grant.resource_acl_generation)?,
        )
        .await?;
    let response = VersionResponse::try_from(restored)?;
    let stored = store_idempotent(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/versions/{version_id}/restore",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(stored)).into_response())
}

async fn list_shares(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Vec<DirectShareResponse>>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::Share,
    )
    .await?;
    let shares = state
        .database
        .list_direct_shares(state.tenant_id, drive_id, node_id)
        .await?;
    Ok(Json(
        shares
            .into_iter()
            .map(DirectShareResponse::try_from)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

async fn create_share(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateShareRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    if !state
        .database
        .descendant_share_admission_open(state.tenant_id)
        .await?
    {
        return Err(share_remediation_in_progress());
    }
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let (verified_email, preset, inheritance) = direct_share_parameters(&request)?;
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::Share,
    )
    .await?;
    for action in share_preset_delegated_actions(request.preset) {
        let delegated_grant = authorize_session_bound(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            node_id,
            *action,
        )
        .await?;
        require_same_generations(grant, delegated_grant)?;
    }
    let fingerprint = fingerprint(&(drive_id, node_id, &request))?;
    if let Some(response) = replay::<DirectShareResponse>(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/shares",
        key,
        &fingerprint,
    )
    .await?
    {
        let status = StatusCode::from_u16(response.0).map_err(|_| ApiError::internal())?;
        return Ok((status, Json(response.1)).into_response());
    }
    let share = state
        .database
        .create_direct_share(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            node_id,
            &verified_email,
            preset,
            inheritance,
            generation_i64(grant.membership_generation)?,
            generation_i64(grant.drive_acl_generation)?,
            generation_i64(grant.namespace_generation)?,
            generation_i64(grant.resource_acl_generation)?,
        )
        .await
        .map_err(|error| match error {
            DatabaseError::SecurityAdmissionBlocked => share_remediation_in_progress(),
            other => ApiError::from(other),
        })?;
    let response = DirectShareResponse::try_from(share)?;
    let stored = store_idempotent(
        &state,
        &session,
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/shares",
        key,
        &fingerprint,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(stored)).into_response())
}

fn share_remediation_in_progress() -> ApiError {
    ApiError::remediation_in_progress(
        "share.remediation_in_progress",
        "Direct sharing is unavailable until the security repair is activated",
    )
}

async fn revoke_share(
    State(state): State<AppState>,
    Path((drive_id, node_id, principal_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let principal_id = parse_uuid_v4(&principal_id)?;
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::Share,
    )
    .await?;
    state
        .database
        .revoke_direct_share(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            node_id,
            principal_id,
            generation_i64(grant.membership_generation)?,
            generation_i64(grant.drive_acl_generation)?,
            generation_i64(grant.namespace_generation)?,
            generation_i64(grant.resource_acl_generation)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_acl(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::ManageAcl,
    )
    .await?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    let entries = state
        .database
        .list_advanced_acl_entries(state.tenant_id, drive_id, node_id)
        .await?;
    json_with_etag(StatusCode::OK, &acl_collection(entries), node_etag(&node))
}

async fn replace_acl(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<ReplaceAclRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    require_acl_etag(&headers, &node_etag(&node))?;
    if request.entries.len() > Action::ALL.len() {
        return Err(ApiError::bad_request(
            "acl.entries_invalid",
            "An ACL replacement may contain at most one entry per action",
        ));
    }
    let manage_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ManageAcl,
    )
    .await?;
    let mut submitted_actions = BTreeSet::new();
    for entry in &request.entries {
        let action = parse_acl_action(&entry.action)?;
        if !submitted_actions.insert(action)
            || !matches!(entry.effect.as_str(), "allow" | "deny")
            || !matches!(
                entry.inheritance.as_str(),
                "self" | "descendants" | "self_and_descendants"
            )
        {
            return Err(ApiError::bad_request(
                "acl.entries_invalid",
                "ACL actions, effects, or inheritance values are invalid",
            ));
        }
    }
    let group_id = request
        .principal
        .group_id
        .as_deref()
        .map(parse_uuid_v4)
        .transpose()?;
    match request.principal.kind.as_str() {
        "user"
            if request.principal.verified_email.is_some()
                && request.principal.group_id.is_none() => {}
        "group"
            if request.principal.group_id.is_some()
                && request.principal.verified_email.is_none() => {}
        _ => {
            return Err(ApiError::bad_request(
                "acl.principal_invalid",
                "Select exactly one verified user or local group",
            ));
        }
    }
    let preflight = state
        .database
        .preflight_advanced_acl_replacement(
            state.tenant_id,
            drive_id,
            node_id,
            &request.principal.kind,
            request.principal.verified_email.as_deref(),
            group_id,
        )
        .await?;
    let covered_actions = advanced_acl_replacement_actions(&submitted_actions, &preflight);
    for action in &covered_actions {
        if *action != Action::ManageAcl {
            let delegated_grant = authorize_session_bound(
                &state.database,
                state.tenant_id,
                session.record.principal_id,
                session.record.session_id,
                drive_id,
                node_id,
                *action,
            )
            .await?;
            require_same_generations(manage_grant, delegated_grant)?;
        }
    }
    let entries = request
        .entries
        .iter()
        .map(|entry| AdvancedAclEntryInput {
            action: entry.action.as_str(),
            effect: entry.effect.as_str(),
            inheritance: entry.inheritance.as_str(),
        })
        .collect::<Vec<_>>();
    let replacement = state
        .database
        .replace_advanced_acl_entries(
            state.tenant_id,
            session.record.principal_id,
            session.record.session_id,
            drive_id,
            node_id,
            &request.principal.kind,
            request.principal.verified_email.as_deref(),
            group_id,
            preflight.target_principal_id,
            &entries,
            &covered_actions,
            generation_i64(manage_grant.membership_generation)?,
            generation_i64(manage_grant.drive_acl_generation)?,
            generation_i64(manage_grant.namespace_generation)?,
            generation_i64(manage_grant.resource_acl_generation)?,
        )
        .await;
    if matches!(replacement, Err(DatabaseError::StaleGeneration)) {
        return Err(ApiError::conflict(
            "acl.etag_stale",
            "The ACL changed while the replacement was being applied",
        ));
    }
    let (_, generation) = replacement.map_err(ApiError::from)?;
    let current = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    if current.acl_generation != generation {
        return Err(ApiError::internal());
    }
    let entries = state
        .database
        .list_advanced_acl_entries(state.tenant_id, drive_id, node_id)
        .await?;
    json_with_etag(
        StatusCode::OK,
        &acl_collection(entries),
        node_etag(&current),
    )
}

async fn trash_node(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<NamespaceMutationRequest>,
) -> Result<Response, ApiError> {
    namespace_mutation(&state, &headers, drive_id, node_id, request, true).await
}

async fn restore_node(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<NamespaceMutationRequest>,
) -> Result<Response, ApiError> {
    namespace_mutation(&state, &headers, drive_id, node_id, request, false).await
}

async fn namespace_mutation(
    state: &AppState,
    headers: &HeaderMap,
    drive_id: String,
    node_id: String,
    request: NamespaceMutationRequest,
    trash: bool,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(state, headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    if request.expected_namespace_generation <= 0 {
        return Err(ApiError::bad_request(
            "generation.expected_invalid",
            "The expected namespace generation must be positive",
        ));
    }
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        if trash {
            Action::Delete
        } else {
            Action::Restore
        },
    )
    .await?;
    let node = if trash {
        state
            .database
            .trash_node(
                state.tenant_id,
                session.record.principal_id,
                session.record.session_id,
                drive_id,
                node_id,
                request.expected_namespace_generation,
                generation_i64(grant.membership_generation)?,
                generation_i64(grant.drive_acl_generation)?,
                generation_i64(grant.namespace_generation)?,
                generation_i64(grant.resource_acl_generation)?,
            )
            .await?
    } else {
        state
            .database
            .restore_node(
                state.tenant_id,
                session.record.principal_id,
                session.record.session_id,
                drive_id,
                node_id,
                request.expected_namespace_generation,
                generation_i64(grant.membership_generation)?,
                generation_i64(grant.drive_acl_generation)?,
                generation_i64(grant.namespace_generation)?,
                generation_i64(grant.resource_acl_generation)?,
            )
            .await?
    };
    json_with_etag(
        StatusCode::OK,
        &NodeResponse::try_from(node.clone())?,
        node_etag(&node),
    )
}

async fn list_trash(
    State(state): State<AppState>,
    Path(drive_id): Path<String>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<Page<NodeResponse>>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let limit = validated_limit(page.limit)?;
    let cursor = page.cursor.as_deref().map(decode_cursor).transpose()?;
    let nodes = state
        .database
        .list_trashed_nodes(state.tenant_id, drive_id)
        .await?;
    let mut visible = Vec::new();
    for node in nodes {
        if let Some(cursor) = &cursor
            && compare_node_cursor(&node, cursor) != Ordering::Greater
        {
            continue;
        }
        if authorize(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            node.id,
            Action::ReadMetadata,
        )
        .await
        .is_ok()
        {
            visible.push(node);
            if visible.len() > limit {
                break;
            }
        }
    }
    let next_cursor = if visible.len() > limit {
        visible.pop();
        visible.last().map(encode_cursor)
    } else {
        None
    };
    Ok(Json(Page {
        items: visible
            .into_iter()
            .map(NodeResponse::try_from)
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    }))
}

async fn list_shared(
    State(state): State<AppState>,
    Query(page): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<Page<NodeResponse>>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let limit = validated_limit(page.limit)?;
    let cursor = page.cursor.as_deref().map(decode_cursor).transpose()?;
    let nodes = state
        .database
        .list_shared_nodes(state.tenant_id, session.record.principal_id)
        .await?;
    let mut visible = Vec::new();
    for node in nodes {
        if let Some(cursor) = &cursor
            && compare_node_cursor(&node, cursor) != Ordering::Greater
        {
            continue;
        }
        let (drive_id, resource_id, action) = shared_candidate_authorization(&node);
        if authorize(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            resource_id,
            action,
        )
        .await
        .is_ok()
        {
            visible.push(node);
            if visible.len() > limit {
                break;
            }
        }
    }
    let next_cursor = if visible.len() > limit {
        visible.pop();
        visible.last().map(encode_cursor)
    } else {
        None
    };
    Ok(Json(Page {
        items: visible
            .into_iter()
            .map(NodeResponse::try_from)
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    }))
}

#[allow(clippy::too_many_arguments)]
fn issue_capability(
    state: &AppState,
    session: &AuthenticatedSession,
    upload: &UploadRecord,
    resource_id: Uuid,
    grant: AuthorizationGrant,
    operation: CapabilityOperation,
    part_number: u64,
    issued_at: i64,
    expires_at: i64,
) -> Result<String, ApiError> {
    let (range_start, range_end) = upload_capability_range(upload, operation, part_number)?;
    let claims = CapabilityClaims {
        capability_id: Uuid::new_v4().to_string(),
        audience: CAPABILITY_AUDIENCE.into(),
        operation: operation as i32,
        tenant_id: state.tenant_id.to_string(),
        principal_id: session.record.principal_id.to_string(),
        session_id: session.record.session_id.to_string(),
        resource_id: resource_id.to_string(),
        upload_id: upload.upload_id.to_string(),
        payload_id: upload.payload_id.to_string(),
        part_number,
        range_start,
        range_end,
        resource_acl_generation: grant.resource_acl_generation,
        membership_generation: grant.membership_generation,
        namespace_generation: grant.namespace_generation,
        fencing_token: u64::try_from(upload.fencing_token).map_err(|_| ApiError::internal())?,
        nonce: random_nonce()?,
        issued_at_unix_seconds: issued_at,
        expires_at_unix_seconds: expires_at,
        drive_acl_generation: grant.drive_acl_generation,
        grant_id: Uuid::new_v4().to_string(),
    };
    sign_api_capability(state, &claims)
}

fn sign_api_capability(state: &AppState, claims: &CapabilityClaims) -> Result<String, ApiError> {
    let use_case = match CapabilityOperation::try_from(claims.operation) {
        Ok(CapabilityOperation::UploadPart) => ApiStorageCapabilityUse::UploadPart,
        Ok(CapabilityOperation::FinalizeUpload) => ApiStorageCapabilityUse::FinalizeUpload,
        Ok(CapabilityOperation::Download) => ApiStorageCapabilityUse::Download,
        _ => return Err(ApiError::internal()),
    };
    sign_api_storage_capability(
        claims,
        use_case,
        state.config.keys.api_storage.current_generation,
        &state.api_storage_signer,
    )
    .map_err(|_| ApiError::internal())
}

fn upload_capability_range(
    upload: &UploadRecord,
    operation: CapabilityOperation,
    part_number: u64,
) -> Result<(u64, u64), ApiError> {
    if operation != CapabilityOperation::UploadPart {
        return Ok((0, 0));
    }
    let declared_size =
        u64::try_from(upload.declared_size_bytes).map_err(|_| ApiError::internal())?;
    let chunk_size = u64::try_from(upload.chunk_size_bytes).map_err(|_| ApiError::internal())?;
    let part_count = u64::try_from(upload.part_count).map_err(|_| ApiError::internal())?;
    let part_size = upload_part_size(declared_size, chunk_size, part_count, part_number)?;
    Ok((0, part_size.saturating_sub(1)))
}

pub(crate) async fn replay<T: DeserializeOwned>(
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_idempotent<T: DeserializeOwned + Serialize>(
    state: &AppState,
    session: &AuthenticatedSession,
    route: &str,
    key: &str,
    fingerprint: &[u8; 32],
    status: StatusCode,
    body: &T,
) -> Result<T, ApiError> {
    let body_value = serde_json::to_value(body).map_err(|_| ApiError::internal())?;
    let stored = state
        .database
        .store_idempotency_response(
            state.tenant_id,
            session.record.principal_id,
            route,
            key,
            fingerprint,
            i32::from(status.as_u16()),
            &body_value,
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

pub(crate) fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
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

pub(crate) fn fingerprint<T: Serialize>(request: &T) -> Result<[u8; 32], ApiError> {
    let bytes = serde_json::to_vec(request).map_err(|_| ApiError::internal())?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn upload_layout_and_part_count(
    size: u64,
    chunk_size: u64,
    whole_threshold: u64,
) -> Result<(&'static str, i32), ApiError> {
    if size <= whole_threshold {
        return Ok(("whole", 1));
    }
    let parts = size
        .checked_add(chunk_size.checked_sub(1).ok_or_else(ApiError::internal)?)
        .ok_or_else(ApiError::internal)?
        / chunk_size;
    let parts = parts.max(1);
    let part_count = i32::try_from(parts).map_err(|_| {
        ApiError::bad_request(
            "upload.too_many_parts",
            "The upload requires too many parts",
        )
    })?;
    Ok(("chunked", part_count))
}

fn upload_part_size(
    declared_size: u64,
    chunk_size: u64,
    part_count: u64,
    part_number: u64,
) -> Result<u64, ApiError> {
    if part_count == 0 || part_number >= part_count || chunk_size == 0 {
        return Err(ApiError::internal());
    }
    if part_count == 1 {
        return Ok(declared_size);
    }
    let offset = part_number
        .checked_mul(chunk_size)
        .ok_or_else(ApiError::internal)?;
    let remaining = declared_size
        .checked_sub(offset)
        .ok_or_else(ApiError::internal)?;
    if part_number + 1 == part_count {
        Ok(remaining)
    } else if remaining >= chunk_size {
        Ok(chunk_size)
    } else {
        Err(ApiError::internal())
    }
}

fn u64_to_i32(value: u64) -> Result<i32, ApiError> {
    i32::try_from(value).map_err(|_| ApiError::internal())
}

fn generation_i64(value: u64) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::internal())
}

fn require_same_generations(
    first: AuthorizationGrant,
    second: AuthorizationGrant,
) -> Result<(), ApiError> {
    if first == second {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "authorization.generation_changed",
            "Authorization changed while the request was being evaluated",
        ))
    }
}

fn parse_acl_action(value: &str) -> Result<Action, ApiError> {
    Action::ALL
        .into_iter()
        .find(|action| action.as_str() == value)
        .ok_or_else(|| {
            ApiError::bad_request(
                "acl.action_invalid",
                "The ACL action is not part of the stable action vocabulary",
            )
        })
}

fn advanced_acl_replacement_actions(
    submitted_actions: &BTreeSet<Action>,
    preflight: &AdvancedAclReplacementPreflight,
) -> BTreeSet<Action> {
    let mut actions = preflight.actions.clone();
    actions.extend(submitted_actions.iter().copied());
    actions.insert(Action::ManageAcl);
    actions
}

fn require_acl_etag(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    if headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        != Some(expected)
    {
        return Err(ApiError::conflict(
            "acl.etag_stale",
            "The ACL changed before the replacement was applied",
        ));
    }
    Ok(())
}

fn acl_collection(entries: Vec<AdvancedAclEntryRecord>) -> AclCollectionResponse {
    AclCollectionResponse {
        supported_actions: Action::ALL.into_iter().map(Action::as_str).collect(),
        entries: entries
            .into_iter()
            .map(|entry| AclEntryResponse {
                principal_id: entry.principal_id,
                principal_kind: entry.principal_kind,
                display_name: entry.display_name,
                verified_email: entry.verified_email,
                action: entry.action,
                effect: entry.effect,
                inheritance: entry.inheritance,
                source: entry.source,
            })
            .collect(),
    }
}

fn direct_share_parameters(
    request: &CreateShareRequest,
) -> Result<(String, &'static str, &'static str), ApiError> {
    if !matches!(request.kind, ShareKind::Direct) {
        return Err(ApiError::bad_request(
            "share.kind_unsupported",
            "Phase 2 currently supports direct verified-email shares only",
        ));
    }
    let email = request
        .verified_email
        .as_deref()
        .map(str::trim)
        .filter(|email| {
            !email.is_empty()
                && email.len() <= 320
                && email.contains('@')
                && !email.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            ApiError::bad_request(
                "share.verified_email_invalid",
                "A valid verified email target is required",
            )
        })?;
    Ok((
        email.to_lowercase(),
        request.preset.as_str(),
        request.inheritance.as_str(),
    ))
}

fn share_preset_delegated_actions(preset: SharePreset) -> &'static [Action] {
    const VIEWER: &[Action] = &[
        Action::ReadMetadata,
        Action::ListChildren,
        Action::ReadContent,
        Action::UseExternalEditor,
    ];
    const CONTRIBUTOR: &[Action] = &[
        Action::ReadMetadata,
        Action::ListChildren,
        Action::ReadContent,
        Action::CreateChild,
        Action::WriteContent,
        Action::CreateVersion,
        Action::Rename,
        Action::Move,
        Action::Delete,
        Action::Restore,
        Action::SetAttributes,
        Action::UseExternalEditor,
        Action::Comment,
        Action::Review,
    ];
    const MANAGER: &[Action] = &[
        Action::ReadMetadata,
        Action::ListChildren,
        Action::ReadContent,
        Action::CreateChild,
        Action::WriteContent,
        Action::CreateVersion,
        Action::Rename,
        Action::Move,
        Action::Delete,
        Action::Restore,
        Action::SetAttributes,
        Action::Share,
        Action::ManageAcl,
        Action::UseExternalEditor,
        Action::Comment,
        Action::Review,
    ];
    match preset {
        SharePreset::Viewer => VIEWER,
        SharePreset::Contributor => CONTRIBUTOR,
        SharePreset::Manager => MANAGER,
    }
}

fn validated_limit(limit: usize) -> Result<usize, ApiError> {
    if (1..=200).contains(&limit) {
        Ok(limit)
    } else {
        Err(ApiError::bad_request(
            "pagination.limit_invalid",
            "The page limit must be between 1 and 200",
        ))
    }
}

const fn default_page_limit() -> usize {
    50
}

#[derive(Debug)]
struct NodeCursor {
    kind: String,
    name_key: String,
    id: Uuid,
}

#[derive(Debug)]
struct DriveCursor {
    kind: String,
    display_name: String,
    id: Uuid,
}

#[derive(Debug)]
struct VersionCursor {
    ordinal: i64,
    id: Uuid,
}

fn encode_drive_cursor(drive: &DriveRecord) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "{}\0{}\0{}",
        drive.kind, drive.display_name, drive.id
    ))
}

fn decode_drive_cursor(value: &str) -> Result<DriveCursor, ApiError> {
    let fields = decode_cursor_fields(value)?;
    Ok(DriveCursor {
        kind: fields.0,
        display_name: fields.1,
        id: fields.2,
    })
}

fn encode_version_cursor(version: &FileVersionRecord) -> String {
    URL_SAFE_NO_PAD.encode(format!("{}\0{}", version.ordinal, version.id))
}

fn decode_version_cursor(value: &str) -> Result<VersionCursor, ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let value = String::from_utf8(bytes).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let mut fields = value.split('\0');
    let ordinal = fields
        .next()
        .unwrap_or_default()
        .parse::<i64>()
        .ok()
        .filter(|ordinal| *ordinal > 0)
        .ok_or_else(|| {
            ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
        })?;
    let id = parse_uuid_v4(fields.next().unwrap_or_default())?;
    if fields.next().is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    Ok(VersionCursor { ordinal, id })
}

fn encode_cursor(node: &NodeRecord) -> String {
    URL_SAFE_NO_PAD.encode(format!("{}\0{}\0{}", node.kind, node.name_key, node.id))
}

fn decode_cursor(value: &str) -> Result<NodeCursor, ApiError> {
    let fields = decode_cursor_fields(value)?;
    let cursor = NodeCursor {
        kind: fields.0,
        name_key: fields.1,
        id: fields.2,
    };
    if !matches!(cursor.kind.as_str(), "file" | "directory") {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    Ok(cursor)
}

fn decode_cursor_fields(value: &str) -> Result<(String, String, Uuid), ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let value = String::from_utf8(bytes).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let mut fields = value.split('\0');
    let first = fields.next().unwrap_or_default().to_owned();
    let second = fields.next().unwrap_or_default().to_owned();
    let id = parse_uuid_v4(fields.next().unwrap_or_default())?;
    if fields.next().is_some() || first.is_empty() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    Ok((first, second, id))
}

fn encode_part_cursor(part: i32) -> String {
    URL_SAFE_NO_PAD.encode(part.to_string())
}

fn decode_part_cursor(value: &str) -> Result<i32, ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    let value = String::from_utf8(bytes).map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })?;
    value.parse::<i32>().map_err(|_| {
        ApiError::bad_request("pagination.cursor_invalid", "The page cursor is invalid")
    })
}

fn compare_node_cursor(node: &NodeRecord, cursor: &NodeCursor) -> Ordering {
    node.kind
        .cmp(&cursor.kind)
        .reverse()
        .then_with(|| node.name_key.cmp(&cursor.name_key))
        .then_with(|| node.id.cmp(&cursor.id))
}

fn shared_candidate_authorization(node: &NodeRecord) -> (Uuid, Uuid, Action) {
    (node.drive_id, node.id, Action::ReadMetadata)
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

fn random_nonce() -> Result<Vec<u8>, ApiError> {
    let mut nonce = vec![0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ApiError::internal())?;
    Ok(nonce)
}

fn unix_time() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ApiError::internal())
}

fn rfc3339(unix_seconds: i64) -> Result<String, ApiError> {
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    let z = days.checked_add(719_468).ok_or_else(ApiError::internal)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn node_etag(node: &NodeRecord) -> String {
    format!(
        "\"fb-node-{}-{}-{}\"",
        node.id, node.namespace_generation, node.acl_generation
    )
}

fn drive_etag(drive_id: Uuid, namespace_generation: i64, acl_generation: i64) -> String {
    format!("\"fb-drive-{drive_id}-{namespace_generation}-{acl_generation}\"")
}

fn json_with_etag<T: Serialize>(
    status: StatusCode,
    value: &T,
    etag: String,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

impl From<DriveRecord> for DriveResponse {
    fn from(value: DriveRecord) -> Self {
        Self {
            id: value.id,
            kind: value.kind,
            display_name: value.display_name,
            owner_display_name: value.owner_display_name,
            root_id: value.root_id,
            namespace_generation: value.namespace_generation,
            acl_generation: value.acl_generation,
            quota_bytes: value.quota_bytes,
            used_physical_bytes: value.used_physical_bytes,
            reserved_bytes: value.reserved_bytes,
        }
    }
}

impl TryFrom<NodeRecord> for NodeResponse {
    type Error = ApiError;

    fn try_from(value: NodeRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            drive_id: value.drive_id,
            parent_id: value.parent_id,
            kind: value.kind,
            display_name: value.display_name,
            head_version_id: value.head_version_id,
            namespace_generation: value.namespace_generation,
            acl_generation: value.acl_generation,
            trashed: value.trashed,
            updated_at: postgres_timestamp(&value.updated_at)?,
            size_bytes: value.size_bytes,
            version_ordinal: value.version_ordinal,
            head_media_type: value.head_media_type,
        })
    }
}

impl TryFrom<FileVersionRecord> for VersionResponse {
    type Error = ApiError;

    fn try_from(value: FileVersionRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            node_id: value.node_id,
            ordinal: value.ordinal,
            size_bytes: value.size_bytes,
            created_by: value.created_by,
            restored_from_version_id: value.restored_from_version_id,
            created_at: postgres_timestamp(&value.created_at)?,
            current: value.current,
            media_type: value
                .media_type
                .unwrap_or_else(|| "application/octet-stream".into()),
            provenance: VersionProvenanceResponse {
                origin: value.origin_kind,
                source_version_id: value.source_version_id,
                creator_display_name: value
                    .creator_display_name
                    .unwrap_or_else(|| value.created_by.to_string()),
                mcp_assisted: value.mcp_assisted,
            },
        })
    }
}

impl TryFrom<DirectShareRecord> for DirectShareResponse {
    type Error = ApiError;

    fn try_from(value: DirectShareRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: "direct".into(),
            principal_id: value.principal_id,
            display_name: value.display_name,
            verified_email: value.verified_email,
            preset: value.preset,
            inheritance: value.inheritance,
            created_at: postgres_timestamp(&value.created_at)?,
        })
    }
}

impl From<UploadRecord> for UploadAllocationResponse {
    fn from(value: UploadRecord) -> Self {
        Self {
            upload_id: value.upload_id,
            drive_id: value.drive_id,
            parent_id: value.parent_id,
            node_id: value.node_id,
            payload_id: value.payload_id,
            declared_size_bytes: value.declared_size_bytes,
            chunk_size_bytes: value.chunk_size_bytes,
            part_count: value.part_count,
            fencing_token: value.fencing_token,
            state: value.state,
            grants_url: format!("/api/v1/uploads/{}", value.upload_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        CreateShareRequest, ShareInheritance, ShareKind, SharePreset,
        advanced_acl_replacement_actions, decode_cursor, decode_part_cursor, decode_version_cursor,
        direct_share_parameters, encode_cursor, encode_part_cursor, parse_acl_action,
        require_same_generations, rfc3339, share_preset_delegated_actions,
        shared_candidate_authorization, upload_capability_range, upload_layout_and_part_count,
    };
    use crate::policy::AuthorizationGrant;
    use base64::Engine as _;
    use filebelt_database::{AdvancedAclReplacementPreflight, NodeRecord, UploadRecord};
    use filebelt_domain::Action;
    use filebelt_storage_protocol::CapabilityOperation;
    use uuid::Uuid;

    #[test]
    fn collaboration_grant_request_binds_client_and_presence() {
        let request: super::CreateCollaborationGrantRequest = serde_json::from_str(
            r#"{"transport":"websocket","client_id":"550e8400-e29b-41d4-a716-446655440000","presence_mode":"pseudonym"}"#,
        )
        .expect("valid collaboration grant request");
        assert_eq!(request.client_id, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn advanced_acl_uses_the_complete_stable_action_vocabulary() {
        for action in Action::ALL {
            assert_eq!(
                parse_acl_action(action.as_str()).expect("known action"),
                action
            );
        }
        assert!(parse_acl_action("read_content").is_err());

        let source = include_str!("resources.rs");
        let handler = source
            .split_once("async fn replace_acl")
            .expect("replace ACL handler exists")
            .1
            .split_once("async fn trash_node")
            .expect("trash handler follows replace ACL")
            .0;
        assert!(handler.contains("Action::ManageAcl"));
        assert!(handler.contains("require_acl_etag"));
        assert!(handler.contains("require_same_generations"));
        assert!(handler.contains("preflight_advanced_acl_replacement"));
    }

    #[test]
    fn advanced_acl_replacement_authorizes_deleted_actions_for_an_empty_submission() {
        let preflight = AdvancedAclReplacementPreflight {
            target_principal_id: Uuid::nil(),
            actions: [Action::ReadContent].into_iter().collect(),
        };
        let submitted_actions = BTreeSet::new();

        let actions = advanced_acl_replacement_actions(&submitted_actions, &preflight);

        assert_eq!(
            actions,
            [Action::ReadContent, Action::ManageAcl]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn advanced_acl_replacement_allows_an_empty_submission_without_existing_rows() {
        let preflight = AdvancedAclReplacementPreflight {
            target_principal_id: Uuid::nil(),
            actions: BTreeSet::new(),
        };

        let actions = advanced_acl_replacement_actions(&BTreeSet::new(), &preflight);

        assert_eq!(actions, [Action::ManageAcl].into_iter().collect());
    }

    #[test]
    fn markdown_import_intent_requires_a_new_sibling_name() {
        let request: super::CreateMarkdownImportIntentRequest = serde_json::from_str(
            r#"{"source_version_id":"550e8400-e29b-41d4-a716-446655440000","target_name":"imported.md"}"#,
        )
        .expect("valid sibling import request");
        assert_eq!(request.target_name, "imported.md");
    }

    #[test]
    fn markdown_control_plane_mutations_replay_idempotent_responses() {
        let source = include_str!("resources.rs");
        for handler in [
            "async fn create_collaboration_grant",
            "async fn discard_collaboration",
            "async fn create_markdown_import_intent",
        ] {
            let tail = source.split_once(handler).expect("handler exists").1;
            assert!(tail.contains("replay::<"));
            assert!(tail.contains("store_idempotent("));
        }
    }

    #[test]
    fn discard_requires_matching_delete_and_write_generations_at_the_database_fence() {
        let source = include_str!("resources.rs");
        let discard = source
            .split_once("async fn discard_collaboration")
            .expect("discard handler exists")
            .1
            .split_once("async fn create_markdown_import_intent")
            .expect("import intent follows discard")
            .0;
        for required in [
            "let delete_grant = authorize_session_bound(",
            "Action::Delete",
            "let write_grant = authorize_session_bound(",
            "Action::WriteContent",
            "require_same_generations(delete_grant, write_grant)?",
            "CollaborationAuthorizationContext",
            ".collaboration_discard(",
        ] {
            assert!(discard.contains(required), "missing {required}");
        }
    }

    #[test]
    fn upload_layout_respects_whole_threshold_and_chunk_boundaries() {
        assert_eq!(
            upload_layout_and_part_count(0, 16, 32).unwrap(),
            ("whole", 1)
        );
        assert_eq!(
            upload_layout_and_part_count(17, 16, 32).unwrap(),
            ("whole", 1)
        );
        assert_eq!(
            upload_layout_and_part_count(32, 16, 32).unwrap(),
            ("whole", 1)
        );
        assert_eq!(
            upload_layout_and_part_count(33, 16, 32).unwrap(),
            ("chunked", 3)
        );
        assert_eq!(
            upload_layout_and_part_count(17, 16, 8).unwrap(),
            ("chunked", 2)
        );
    }

    #[test]
    fn begin_upload_authorizes_before_parent_state_is_observed() {
        let source = include_str!("resources.rs");
        let begin_upload = source
            .split_once("async fn begin_upload")
            .expect("begin_upload exists")
            .1
            .split_once("async fn get_upload")
            .expect("get_upload follows begin_upload")
            .0;
        let authorization = begin_upload
            .find("authorize_session_bound(")
            .expect("session-bound authorization exists");
        let parent_lookup = begin_upload
            .find(".node(state.tenant_id, drive_id, parent_id)")
            .expect("parent lookup exists");
        assert!(authorization < parent_lookup);
    }

    #[test]
    fn begin_upload_does_not_accept_mcp_provenance() {
        let source = include_str!("resources.rs");
        let begin_upload = source
            .split_once("async fn begin_upload")
            .expect("begin upload exists")
            .1
            .split_once("async fn get_upload")
            .expect("get upload follows begin upload")
            .0;
        assert!(!begin_upload.contains("mcp_invocation_id"));
    }

    #[test]
    fn commit_upload_existence_hides_foreign_uploads_before_fence_checks() {
        let source = include_str!("resources.rs");
        let commit = source
            .split_once("async fn commit_upload")
            .expect("commit_upload exists")
            .1
            .split_once("async fn create_download_grant")
            .expect("download grant follows commit")
            .0;
        let owned_lookup = commit
            .find(".upload_owned_by(")
            .expect("owner-scoped upload lookup exists");
        let fence_check = commit
            .find("upload.fencing_token != request.expected_fencing_token")
            .expect("fence check exists");
        assert!(owned_lookup < fence_check);
    }

    #[test]
    fn upload_capability_range_matches_each_declared_part() {
        let upload = UploadRecord {
            tenant_id: Uuid::new_v4(),
            upload_id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            node_id: None,
            parent_id: Uuid::new_v4(),
            owner_principal_id: Uuid::new_v4(),
            payload_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
            payload_locator: Uuid::new_v4(),
            expected_head_version_id: None,
            target_display_name: "part.bin".into(),
            target_name_key: "part.bin".into(),
            declared_size_bytes: 33,
            chunk_size_bytes: 16,
            part_count: 3,
            fencing_token: 1,
            state: "allocated".into(),
            declared_media_type: None,
            collaboration_checkpoint_id: None,
            import_intent_id: None,
        };

        assert_eq!(
            upload_capability_range(&upload, CapabilityOperation::UploadPart, 0).unwrap(),
            (0, 15)
        );
        assert_eq!(
            upload_capability_range(&upload, CapabilityOperation::UploadPart, 1).unwrap(),
            (0, 15)
        );
        assert_eq!(
            upload_capability_range(&upload, CapabilityOperation::UploadPart, 2).unwrap(),
            (0, 0)
        );
        assert_eq!(
            upload_capability_range(&upload, CapabilityOperation::FinalizeUpload, 0).unwrap(),
            (0, 0)
        );

        let whole = UploadRecord {
            declared_size_bytes: 20,
            part_count: 1,
            ..upload
        };
        assert_eq!(
            upload_capability_range(&whole, CapabilityOperation::UploadPart, 0).unwrap(),
            (0, 19)
        );
    }

    #[test]
    fn cursor_round_trip_preserves_ordering_fields() {
        let node = NodeRecord {
            id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            parent_id: None,
            kind: "directory".into(),
            display_name: "Folder".into(),
            name_key: "folder".into(),
            head_version_id: None,
            namespace_generation: 1,
            acl_generation: 1,
            trashed: false,
            updated_at: "2026-01-01T00:00:00Z".into(),
            size_bytes: None,
            version_ordinal: None,
            head_media_type: None,
        };
        let cursor = decode_cursor(&encode_cursor(&node)).unwrap();
        assert_eq!(cursor.kind, node.kind);
        assert_eq!(cursor.name_key, node.name_key);
        assert_eq!(cursor.id, node.id);
    }

    #[test]
    fn shared_discovery_authorizes_the_candidate_not_its_ancestor() {
        let parent_id = Uuid::new_v4();
        let node = NodeRecord {
            id: Uuid::new_v4(),
            drive_id: Uuid::new_v4(),
            parent_id: Some(parent_id),
            kind: "file".into(),
            display_name: "Shared file".into(),
            name_key: "shared file".into(),
            head_version_id: Some(Uuid::new_v4()),
            namespace_generation: 1,
            acl_generation: 1,
            trashed: false,
            updated_at: "2026-08-06 12:30:00+00".into(),
            size_bytes: Some(1),
            version_ordinal: Some(1),
            head_media_type: None,
        };
        let target = shared_candidate_authorization(&node);
        assert_eq!(target, (node.drive_id, node.id, Action::ReadMetadata));
        assert_ne!(target.1, parent_id);
    }

    #[test]
    fn unix_epoch_formats_as_rfc3339_utc() {
        assert_eq!(rfc3339(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_753_353_030).unwrap(), "2025-07-24T10:30:30Z");
    }

    #[test]
    fn upload_part_cursor_round_trips() {
        assert_eq!(decode_part_cursor(&encode_part_cursor(199)).unwrap(), 199);
        assert!(decode_part_cursor("not-base64!").is_err());
    }

    #[test]
    fn version_cursor_requires_positive_ordinal_and_uuid_v4() {
        let id = Uuid::new_v4();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("7\0{id}"));
        let cursor = decode_version_cursor(&encoded).unwrap();
        assert_eq!(cursor.ordinal, 7);
        assert_eq!(cursor.id, id);
        let invalid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("0\0{id}"));
        assert!(decode_version_cursor(&invalid).is_err());
    }

    #[test]
    fn group_and_link_share_requests_are_explicitly_unsupported() {
        for kind in [ShareKind::Group, ShareKind::Link] {
            assert!(
                direct_share_parameters(&CreateShareRequest {
                    kind,
                    verified_email: Some("person@example.test".into()),
                    preset: SharePreset::Viewer,
                    inheritance: ShareInheritance::ThisResource,
                })
                .is_err()
            );
        }
        let direct = direct_share_parameters(&CreateShareRequest {
            kind: ShareKind::Direct,
            verified_email: Some(" Person@Example.TEST ".into()),
            preset: SharePreset::Contributor,
            inheritance: ShareInheritance::SelfAndDescendants,
        })
        .unwrap();
        assert_eq!(
            direct,
            (
                "person@example.test".into(),
                "contributor",
                "self_and_descendants"
            )
        );
    }

    #[test]
    fn share_presets_require_every_delegated_action_without_manage_drive() {
        let viewer = share_preset_delegated_actions(SharePreset::Viewer);
        assert_eq!(
            viewer,
            &[
                Action::ReadMetadata,
                Action::ListChildren,
                Action::ReadContent,
                Action::UseExternalEditor,
            ]
        );
        let contributor = share_preset_delegated_actions(SharePreset::Contributor);
        assert!(contributor.contains(&Action::CreateVersion));
        assert!(contributor.contains(&Action::Restore));
        assert!(contributor.contains(&Action::UseExternalEditor));
        assert!(contributor.contains(&Action::Comment));
        assert!(contributor.contains(&Action::Review));
        let manager = share_preset_delegated_actions(SharePreset::Manager);
        assert!(manager.contains(&Action::Share));
        assert!(manager.contains(&Action::ManageAcl));
        assert!(!manager.contains(&Action::ManageDrive));
    }

    #[test]
    fn dual_action_restore_rejects_generation_changes() {
        let grant = AuthorizationGrant {
            membership_generation: 1,
            drive_acl_generation: 2,
            namespace_generation: 3,
            resource_acl_generation: 4,
        };
        assert!(require_same_generations(grant, grant).is_ok());
        assert!(
            require_same_generations(
                grant,
                AuthorizationGrant {
                    resource_acl_generation: 5,
                    ..grant
                }
            )
            .is_err()
        );
    }
}

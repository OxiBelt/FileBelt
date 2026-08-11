// SPDX-License-Identifier: Apache-2.0

//! Authenticated per-principal MCP configuration and invocation mediation.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use aws_lc_rs::digest::{SHA256, digest};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use filebelt_collaboration_protocol::normalized_markdown_source_digest;
use filebelt_control_protocol::{Config, DeploymentMode};
use filebelt_database::DatabaseError;
use filebelt_database::mcp::{
    McpIdempotency, McpIdempotentWrite, McpRegistrationRecord, NewCapabilitySnapshot,
    NewMcpApprovalRule, NewMcpDataGrant, NewMcpInvocation, NewMcpManagedTemplate,
    NewMcpRegistration, NewMcpServiceGrant, NewMcpServicePrincipal, TemplateConfigurationUpdate,
};
use filebelt_domain::Action;
use filebelt_mcp_policy::{
    AuthenticationState, CapabilityState, QuarantineState, RegistrationPolicyState, ValidationState,
};
use filebelt_mcp_protocol::{
    AttachmentClaim, AttachmentDisclosure, AttachmentEncoding, AttachmentFieldClaim,
    DelegationClaims, InvocationFrameKind, InvocationRequest as BrokerInvocationRequest,
    MAX_FRAME_BYTES, McpOperation, McpPrimitive, decode_frames, sign_mcp_delegation,
};
use filebelt_storage_protocol::{
    ApiStorageCapabilityUse, CapabilityClaims, CapabilityOperation,
    MAX_CAPABILITY_LIFETIME_SECONDS, sign_api_storage_capability,
};
use prost::Message as _;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{AuthenticatedSession, authenticate, authenticate_mutation};
use crate::error::ApiError;
use crate::policy::{AuthorizationGrant, authorize, authorize_capability};

const INTERNAL_CONTENT_TYPE: &str = "application/vnd.filebelt.mcp.v1+protobuf";
const ARGUMENT_DIGEST_DOMAIN: &[u8] = b"filebelt.mcp.arguments.v1\0";
const INTENT_DIGEST_DOMAIN: &[u8] = b"filebelt.mcp.intent.v1\0";
const CURRENT_PROTOCOL: &str = "2026-07-28";
const FALLBACK_PROTOCOL: &str = "2025-11-25";
const STORAGE_CAPABILITY_AUDIENCE: &str = "filebelt-worker-io";
const MAX_BROKER_RESPONSE_BYTES: usize = MAX_FRAME_BYTES * 4;

pub(crate) struct McpApiState {
    broker: Client,
    broker_url: Url,
}

#[derive(Debug, Deserialize, Serialize)]
struct PageQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttachmentPolicy {
    allowed_mime_patterns: Vec<String>,
    allowed_encodings: Vec<String>,
    max_attachments: u8,
    max_item_bytes: u64,
    max_total_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationInput {
    display_name: String,
    #[serde(default)]
    description: String,
    transport: String,
    endpoint_uri: Option<String>,
    catalog_entry_id: Option<String>,
    trust_profile: String,
    attachment_policy: AttachmentPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeState {
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticCredential {
    kind: String,
    secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartOauthInput {
    return_path: String,
    issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OauthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityReviewInput {
    snapshot_id: Uuid,
    snapshot_fingerprint: String,
    decisions: Vec<CapabilityDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityDecision {
    capability_fingerprint: String,
    decision: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApproveIntentInput {
    scope: String,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateTemplateInput {
    display_name: String,
    #[serde(default)]
    description: String,
    transport: String,
    endpoint_uri: Option<String>,
    catalog_entry_id: Option<String>,
    trust_profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentInput {
    principal_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateServiceInput {
    display_name: String,
    spiffe_uri: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateServiceGrantInput {
    registration_id: Uuid,
    capability: CapabilityReference,
    application_id: String,
    argument_constraints: Value,
    mcp_data_grant_ids: Vec<Uuid>,
    max_invocations_per_hour: i64,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateBlockRuleInput {
    kind: String,
    value: String,
    reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateDataGrantInput {
    principal_id: Uuid,
    registration_id: Uuid,
    version_id: Uuid,
    actions: Vec<String>,
    expected_acl_generation: i64,
    expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InvocationRequest {
    application_id: String,
    registration_id: Uuid,
    capability: CapabilityReference,
    arguments: Value,
    #[serde(default)]
    semantic_input: Option<SemanticMarkdownInput>,
    attachments: Vec<AttachmentBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticMarkdownInput {
    format: String,
    node_id: Uuid,
    base_version_id: Uuid,
    markdown: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticMarkdownOutput {
    format: String,
    markdown: String,
}

#[derive(Clone, Copy, Debug)]
struct MarkdownSemanticProvenance {
    node_id: Uuid,
    base_version_id: Uuid,
    input_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityReference {
    kind: String,
    name: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttachmentBinding {
    drive_id: Uuid,
    node_id: Uuid,
    version_id: Uuid,
    fields: Vec<AttachmentFieldBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttachmentFieldBinding {
    source: String,
    target_json_pointer: String,
    encoding: String,
}

pub(crate) fn initialize(config: &Config) -> Result<Option<Arc<McpApiState>>> {
    if !config.mcp.enabled {
        return Ok(None);
    }
    let broker_url = config
        .mcp
        .broker
        .url
        .clone()
        .ok_or_else(|| anyhow!("MCP broker URL is absent"))?
        .join("internal/v1/mcp/invocations")
        .context("MCP broker invocation URL is invalid")?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(
            config.mcp.limits.connect_timeout_seconds,
        ));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let certificate = std::fs::read(
            config
                .mcp
                .broker
                .client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("MCP broker client certificate is absent"))?,
        )?;
        let private_key = std::fs::read(
            config
                .mcp
                .broker
                .client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("MCP broker client key is absent"))?,
        )?;
        let mut identity_pem = certificate;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&private_key);
        let identity =
            Identity::from_pem(&identity_pem).context("MCP broker client identity is invalid")?;
        let ca = std::fs::read(
            config
                .mcp
                .broker
                .server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("MCP broker CA is absent"))?,
        )?;
        let certificates = Certificate::from_pem_bundle(&ca).context("MCP broker CA is invalid")?;
        builder = builder.https_only(true).identity(identity);
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(Some(Arc::new(McpApiState {
        broker: builder
            .build()
            .context("cannot initialize MCP broker client")?,
        broker_url,
    })))
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/mcp/registrations",
            routing::get(list_registrations).post(create_registration),
        )
        .route(
            "/mcp/registrations/import",
            routing::post(import_registration),
        )
        .route(
            "/mcp/registrations/{registration_id}",
            routing::get(get_registration)
                .patch(update_registration)
                .delete(delete_registration),
        )
        .route(
            "/mcp/registrations/{registration_id}/export",
            routing::get(export_registration),
        )
        .route(
            "/mcp/registrations/{registration_id}/test",
            routing::post(test_registration),
        )
        .route(
            "/mcp/registrations/{registration_id}/discover",
            routing::post(discover_registration),
        )
        .route(
            "/mcp/registrations/{registration_id}/state",
            routing::post(change_registration_state),
        )
        .route(
            "/mcp/registrations/{registration_id}/credentials",
            routing::put(put_credential).delete(delete_credential),
        )
        .route(
            "/mcp/registrations/{registration_id}/oauth/start",
            routing::post(start_oauth),
        )
        .route("/mcp/oauth/callback", routing::get(complete_oauth))
        .route(
            "/mcp/registrations/{registration_id}/capability-review",
            routing::get(get_capability_review).put(put_capability_review),
        )
        .route("/mcp/approvals", routing::get(list_approvals))
        .route(
            "/mcp/approvals/{approval_id}",
            routing::delete(revoke_approval),
        )
        .route("/mcp/activity", routing::get(list_activity))
        .route("/mcp/invocation-intents", routing::post(create_intent))
        .route(
            "/mcp/invocation-intents/{intent_id}/approval",
            routing::post(approve_intent),
        )
        .route(
            "/mcp/invocation-intents/{intent_id}/stream",
            routing::post(stream_invocation),
        )
        .route(
            "/mcp/invocations/{invocation_id}",
            routing::delete(cancel_invocation),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/mcp-grants",
            routing::get(list_data_grants).post(create_data_grant),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/mcp-grants/{grant_id}",
            routing::delete(revoke_data_grant),
        )
        .route(
            "/admin/mcp/templates",
            routing::get(list_admin_templates).post(create_admin_template),
        )
        .route(
            "/admin/mcp/templates/{template_id}",
            routing::get(get_admin_template)
                .patch(update_admin_template)
                .delete(delete_admin_template),
        )
        .route(
            "/admin/mcp/templates/{template_id}/assignments/{principal_id}",
            routing::put(put_admin_assignment).delete(delete_admin_assignment),
        )
        .route(
            "/admin/mcp/service-identities",
            routing::get(list_admin_services).post(create_admin_service),
        )
        .route(
            "/admin/mcp/service-identities/{service_id}",
            routing::patch(update_admin_service).delete(delete_admin_service),
        )
        .route(
            "/admin/mcp/service-identities/{service_id}/invocation-grants",
            routing::get(list_admin_service_grants).post(create_admin_service_grant),
        )
        .route(
            "/admin/mcp/service-identities/{service_id}/invocation-grants/{service_grant_id}",
            routing::delete(revoke_admin_service_grant),
        )
        .route(
            "/admin/mcp/block-rules",
            routing::get(list_admin_block_rules).post(create_admin_block_rule),
        )
        .route(
            "/admin/mcp/block-rules/{block_rule_id}",
            routing::delete(delete_admin_block_rule),
        )
}

async fn list_registrations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    if !(1..=200).contains(&query.limit) || query.cursor.is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let items = state
        .database
        .mcp_list_registrations(state.tenant_id, session.record.principal_id, query.limit)
        .await?
        .iter()
        .map(registration_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

async fn create_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegistrationInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    validate_registration_input(&state, &input)?;
    let id = Uuid::new_v4();
    let policy = registration_policy(&input, "none", false);
    let record = state
        .database
        .mcp_create_registration(&NewMcpRegistration {
            tenant_id: state.tenant_id,
            id,
            owner_principal_id: session.record.principal_id,
            owner_kind: "user",
            source_kind: "personal",
            template_id: None,
            display_name: &input.display_name,
            description: &input.description,
            transport: database_transport(&input.transport)?,
            endpoint_uri: input.endpoint_uri.as_deref(),
            trust_profile: Some(&input.trust_profile),
            catalog_entry: input.catalog_entry_id.as_deref(),
            policy: &policy,
        })
        .await?;
    registration_response(StatusCode::CREATED, &record)
}

async fn import_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<Response, ApiError> {
    if value.get("format").and_then(Value::as_str) != Some("filebelt.mcp-registration.v1") {
        return Err(ApiError::bad_request(
            "mcp.import.invalid",
            "The MCP registration export is invalid",
        ));
    }
    let mut imported = value;
    imported
        .as_object_mut()
        .map(|object| object.remove("format"));
    let input: RegistrationInput = serde_json::from_value(imported).map_err(|_| {
        ApiError::bad_request(
            "mcp.import.invalid",
            "The MCP registration export is invalid",
        )
    })?;
    create_registration(State(state), headers, Json(input)).await
}

async fn get_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<Response, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let id = parse_uuid(&registration_id)?;
    let record = state
        .database
        .mcp_registration(state.tenant_id, session.record.principal_id, id)
        .await?;
    registration_response(StatusCode::OK, &record)
}

async fn export_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let record = state
        .database
        .mcp_registration(
            state.tenant_id,
            session.record.principal_id,
            parse_uuid(&registration_id)?,
        )
        .await?;
    Ok(Json(json!({
        "format": "filebelt.mcp-registration.v1",
        "display_name": record.display_name,
        "description": record.policy.get("description").and_then(Value::as_str).unwrap_or_default(),
        "transport": api_transport(&record.transport),
        "endpoint_uri": record.endpoint_uri,
        "catalog_entry_id": record.catalog_entry,
        "trust_profile": record.trust_profile.unwrap_or_else(|| "public".into()),
        "attachment_policy": record.policy.get("attachment_policy").cloned().unwrap_or_else(default_attachment_policy),
    })))
}

async fn update_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
    Json(value): Json<Value>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let current = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &current)?;
    if current.source_kind == "managed" {
        return Err(ApiError::forbidden(
            "mcp.registration.managed_locked",
            "Managed MCP configuration cannot be changed by its assignee",
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        ApiError::bad_request(
            "mcp.registration.invalid",
            "The MCP registration is invalid",
        )
    })?;
    if object.is_empty()
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "display_name"
                    | "description"
                    | "endpoint_uri"
                    | "trust_profile"
                    | "attachment_policy"
            )
        })
    {
        return Err(ApiError::bad_request(
            "mcp.registration.invalid",
            "The MCP registration is invalid",
        ));
    }
    let display_name = object
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or(&current.display_name)
        .to_owned();
    let endpoint_uri = object
        .get("endpoint_uri")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or(current.endpoint_uri.clone());
    let trust_profile = object
        .get("trust_profile")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or(current.trust_profile.clone());
    let mut policy = current.policy.clone();
    if let Some(description) = object.get("description") {
        policy["description"] = description.clone();
    }
    if let Some(attachment_policy) = object.get("attachment_policy") {
        policy["attachment_policy"] = attachment_policy.clone();
    }
    let candidate = RegistrationInput {
        display_name: display_name.clone(),
        description: policy
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        transport: api_transport(&current.transport).into(),
        endpoint_uri: endpoint_uri.clone(),
        catalog_entry_id: current.catalog_entry.clone(),
        trust_profile: trust_profile.clone().unwrap_or_else(|| "public".into()),
        attachment_policy: serde_json::from_value(
            policy
                .get("attachment_policy")
                .cloned()
                .unwrap_or_else(default_attachment_policy),
        )
        .map_err(|_| {
            ApiError::bad_request(
                "mcp.registration.invalid",
                "The MCP registration is invalid",
            )
        })?,
    };
    validate_registration_input(&state, &candidate)?;
    let arguments = serde_json::to_vec(&json!({
        "expected_revision": current.revision,
        "display_name": display_name,
        "description": candidate.description,
        "endpoint_uri": endpoint_uri,
        "trust_profile": trust_profile,
        "catalog_entry": current.catalog_entry,
        "policy": policy,
    }))
    .map_err(|_| ApiError::internal())?;
    call_broker(
        &state,
        &session.record,
        &current,
        McpOperation::RegistrationConfigure,
        McpPrimitive::Unspecified,
        "$registration_configure",
        "filebelt.settings.mcp",
        CURRENT_PROTOCOL,
        &arguments,
        None,
        &[0; 32],
        None,
        Vec::new(),
    )
    .await?;
    let updated = owned_registration(&state, session.record.principal_id, id).await?;
    registration_response(StatusCode::OK, &updated)
}

async fn delete_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let record = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &record)?;
    call_broker(
        &state,
        &session.record,
        &record,
        McpOperation::CredentialErase,
        McpPrimitive::Unspecified,
        "$credential_erase",
        "filebelt.settings.mcp",
        CURRENT_PROTOCOL,
        &serde_json::to_vec(&json!({"expected_revision": record.revision}))
            .map_err(|_| ApiError::internal())?,
        None,
        &[0; 32],
        None,
        Vec::new(),
    )
    .await?;
    let erased = owned_registration(&state, session.record.principal_id, id).await?;
    state
        .database
        .mcp_delete_registration(state.tenant_id, id, erased.revision, Uuid::new_v4())
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "id": id,
            "state": "erased",
            "destroy_after": rfc3339(unix_time()?),
        })),
    )
        .into_response())
}

async fn change_registration_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
    Json(input): Json<ChangeState>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let record = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &record)?;
    if input.action == "revoke" {
        state
            .database
            .mcp_revoke_registration(state.tenant_id, id, record.revision)
            .await?;
        let changed = owned_registration(&state, session.record.principal_id, id).await?;
        return registration_response(StatusCode::OK, &changed);
    }
    let mut policy = record.state;
    match input.action.as_str() {
        "enable" => policy.enabled = true,
        "disable" => policy.enabled = false,
        _ => {
            return Err(ApiError::bad_request(
                "mcp.state.invalid",
                "The MCP lifecycle action is invalid",
            ));
        }
    }
    let changed = state
        .database
        .mcp_update_registration_state(
            state.tenant_id,
            id,
            record.revision,
            policy,
            record.protocol_version.as_deref(),
        )
        .await?;
    registration_response(StatusCode::OK, &changed)
}

async fn put_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
    Json(input): Json<StaticCredential>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    if !matches!(input.kind.as_str(), "bearer" | "api_key")
        || input.secret.is_empty()
        || input.secret.len() > 8_192
    {
        return Err(ApiError::bad_request(
            "mcp.credential.invalid",
            "The MCP credential is invalid",
        ));
    }
    let id = parse_uuid(&registration_id)?;
    let record = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &record)?;
    let arguments = serde_json::to_vec(&json!({
        "kind": input.kind,
        "secret": input.secret,
        "expected_revision": record.revision,
    }))
    .map_err(|_| ApiError::internal())?;
    call_broker(
        &state,
        &session.record,
        &record,
        McpOperation::CredentialReplace,
        McpPrimitive::Unspecified,
        "$credential_replace",
        "filebelt.settings.mcp",
        CURRENT_PROTOCOL,
        &arguments,
        None,
        &[0; 32],
        None,
        Vec::new(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let record = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &record)?;
    call_broker(
        &state,
        &session.record,
        &record,
        McpOperation::CredentialErase,
        McpPrimitive::Unspecified,
        "$credential_erase",
        "filebelt.settings.mcp",
        CURRENT_PROTOCOL,
        &serde_json::to_vec(&json!({"expected_revision": record.revision}))
            .map_err(|_| ApiError::internal())?,
        None,
        &[0; 32],
        None,
        Vec::new(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_oauth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
    Json(input): Json<StartOauthInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    if !valid_mcp_return_path(&input.return_path) {
        return Err(ApiError::bad_request(
            "mcp.oauth.return_path_invalid",
            "The MCP OAuth return path is invalid",
        ));
    }
    let id = parse_uuid(&registration_id)?;
    let registration = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &registration)?;
    if registration.transport != "streamable_http" {
        return Err(ApiError::bad_request(
            "mcp.oauth.transport_invalid",
            "OAuth is only available for remote MCP registrations",
        ));
    }
    let issuer = select_oauth_issuer(&state, input.issuer.as_deref())?;
    let mut state_bytes = [0_u8; 32];
    let mut verifier_bytes = [0_u8; 32];
    getrandom::fill(&mut state_bytes).map_err(|_| ApiError::internal())?;
    getrandom::fill(&mut verifier_bytes).map_err(|_| ApiError::internal())?;
    let state_value = URL_SAFE_NO_PAD.encode(state_bytes);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()).as_ref());
    let state_digest = state.digest(b"filebelt.mcp.oauth-state.v1\0", state_value.as_bytes());
    let redirect_uri = state
        .config
        .public_origin
        .join(state.config.mcp.callback_path.trim_start_matches('/'))
        .map_err(|_| ApiError::internal())?;
    let arguments = serde_json::to_vec(&json!({
        "issuer": issuer,
        "state": state_value,
        "state_digest": hex(&state_digest),
        "verifier": verifier,
        "challenge": challenge,
        "redirect_uri": redirect_uri,
        "return_path": input.return_path,
        "attempt_id": Uuid::new_v4(),
    }))
    .map_err(|_| ApiError::internal())?;
    let result = call_broker(
        &state,
        &session.record,
        &registration,
        McpOperation::OauthBegin,
        McpPrimitive::Unspecified,
        "$oauth_begin",
        "filebelt.settings.mcp",
        CURRENT_PROTOCOL,
        &arguments,
        None,
        &[0; 32],
        None,
        Vec::new(),
    )
    .await?;
    let authorization_url = result
        .value
        .get("authorization_url")
        .and_then(Value::as_str)
        .and_then(|value| Url::parse(value).ok())
        .filter(|url| url.scheme() == "https" && url.host_str().is_some())
        .ok_or_else(ApiError::internal)?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "authorization_url": authorization_url,
            "expires_at": rfc3339(unix_time()?.saturating_add(600)),
        })),
    )
        .into_response())
}

async fn complete_oauth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OauthCallbackQuery>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate(&state, &headers).await?;
    let state_value = query.state.as_deref().ok_or_else(|| {
        ApiError::bad_request("mcp.oauth.state_invalid", "The MCP OAuth state is invalid")
    })?;
    if !(32..=256).contains(&state_value.len())
        || query
            .code
            .as_deref()
            .is_some_and(|value| value.len() > 4_096)
        || query
            .error
            .as_deref()
            .is_some_and(|value| value.len() > 256)
        || query
            .iss
            .as_deref()
            .is_some_and(|value| value.len() > 2_048)
        || (query.code.is_none() == query.error.is_none())
    {
        return Err(ApiError::bad_request(
            "mcp.oauth.callback_invalid",
            "The MCP OAuth callback is invalid",
        ));
    }
    let state_digest = state.digest(b"filebelt.mcp.oauth-state.v1\0", state_value.as_bytes());
    let registration_id = state
        .database
        .mcp_oauth_attempt_registration(state.tenant_id, session.record.session_id, &state_digest)
        .await?;
    let registration =
        owned_registration(&state, session.record.principal_id, registration_id).await?;
    let arguments = serde_json::to_vec(&json!({
        "state_digest": hex(&state_digest),
        "code": query.code,
        "iss": query.iss,
        "error": query.error,
    }))
    .map_err(|_| ApiError::internal())?;
    let result = call_broker(
        &state,
        &session.record,
        &registration,
        McpOperation::OauthComplete,
        McpPrimitive::Unspecified,
        "$oauth_complete",
        "filebelt.settings.mcp",
        CURRENT_PROTOCOL,
        &arguments,
        None,
        &[0; 32],
        None,
        Vec::new(),
    )
    .await?;
    let return_path = result
        .value
        .get("return_path")
        .and_then(Value::as_str)
        .filter(|value| valid_mcp_return_path(value))
        .ok_or_else(ApiError::internal)?;
    let location = HeaderValue::from_str(return_path).map_err(|_| ApiError::internal())?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

async fn test_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let record = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &record)?;
    let started = std::time::Instant::now();
    let (protocol, _result) = broker_probe(
        &state,
        &session.record,
        &record,
        McpOperation::Test,
        "$test",
    )
    .await?;
    let duration_ms = started.elapsed().as_millis().min(120_000) as u64;
    let authentication = if record.state.authentication == AuthenticationState::Required {
        AuthenticationState::Authorized
    } else {
        record.state.authentication
    };
    let changed = state
        .database
        .mcp_update_registration_state(
            state.tenant_id,
            id,
            record.revision,
            RegistrationPolicyState {
                validation: ValidationState::Valid,
                authentication,
                ..record.state
            },
            Some(&protocol),
        )
        .await?;
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "succeeded": true,
            "protocol_version": protocol,
            "authentication_state": authentication_state(changed.state.authentication),
            "duration_ms": duration_ms,
            "checked_at": rfc3339(unix_time()?),
            "problem_code": null,
        })),
    )
        .into_response();
    insert_etag(&mut response, &changed)?;
    Ok(response)
}

async fn discover_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let record = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &record)?;
    let (protocol, document) = broker_probe(
        &state,
        &session.record,
        &record,
        McpOperation::Discover,
        "$discover",
    )
    .await?;
    let canonical =
        filebelt_mcp_policy::canonical_json(&document).map_err(|_| ApiError::internal())?;
    if canonical.len() > state.config.mcp.limits.result_bytes as usize {
        return Err(ApiError::bad_request(
            "mcp.discovery.too_large",
            "The MCP capability document is too large",
        ));
    }
    let fingerprint = filebelt_mcp_policy::policy_json_digest(b"capability-snapshot", &document)
        .map_err(|_| ApiError::internal())?;
    let snapshot_id = Uuid::new_v4();
    state
        .database
        .mcp_store_capability_snapshot(&NewCapabilitySnapshot {
            tenant_id: state.tenant_id,
            id: snapshot_id,
            registration_id: id,
            credential_generation: record.credential_generation,
            fingerprint: &fingerprint,
            protocol_version: &protocol,
            document: &document,
        })
        .await?;
    let capabilities = normalize_capabilities(&document)?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "id": snapshot_id,
            "registration_id": id,
            "protocol_version": protocol,
            "fingerprint": hex(&fingerprint),
            "capabilities": capabilities,
            "created_at": rfc3339(unix_time()?),
        })),
    )
        .into_response())
}

async fn get_capability_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let id = parse_uuid(&registration_id)?;
    owned_registration(&state, session.record.principal_id, id).await?;
    capability_review_json(&state, id).await.map(Json)
}

async fn put_capability_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<String>,
    Json(input): Json<CapabilityReviewInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&registration_id)?;
    let registration = owned_registration(&state, session.record.principal_id, id).await?;
    require_revision(&headers, &registration)?;
    let snapshot = state
        .database
        .mcp_current_capability_snapshot(state.tenant_id, id)
        .await?;
    if snapshot.id != input.snapshot_id
        || snapshot.fingerprint.as_slice() != decode_hash(&input.snapshot_fingerprint)?
    {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "mcp.capability.snapshot_stale",
            "The MCP capability snapshot changed",
        ));
    }
    let capabilities = normalize_capabilities(&snapshot.document)?;
    if input.decisions.len() != capabilities.len() || input.decisions.is_empty() {
        return Err(ApiError::bad_request(
            "mcp.capability.review_incomplete",
            "Every current MCP capability must have one decision",
        ));
    }
    let expected = capabilities
        .iter()
        .filter_map(|value| value.get("fingerprint").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let supplied = input
        .decisions
        .iter()
        .map(|decision| decision.capability_fingerprint.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if expected != supplied
        || supplied.len() != input.decisions.len()
        || input
            .decisions
            .iter()
            .any(|decision| !matches!(decision.decision.as_str(), "approved" | "blocked"))
    {
        return Err(ApiError::bad_request(
            "mcp.capability.review_invalid",
            "The MCP capability review is invalid",
        ));
    }
    for decision in &input.decisions {
        let fingerprint = decode_hash(&decision.capability_fingerprint)?;
        state
            .database
            .mcp_review_capability(
                state.tenant_id,
                id,
                snapshot.id,
                &fingerprint,
                session.record.principal_id,
                if decision.decision == "approved" {
                    "approved"
                } else {
                    "denied"
                },
                &json!({}),
            )
            .await?;
    }
    let updated = state
        .database
        .mcp_update_registration_state(
            state.tenant_id,
            id,
            registration.revision,
            RegistrationPolicyState {
                capabilities: CapabilityState::Approved,
                enabled: false,
                ..registration.state
            },
            registration.protocol_version.as_deref(),
        )
        .await?;
    let mut response = (
        StatusCode::OK,
        Json(capability_review_json(&state, id).await?),
    )
        .into_response();
    insert_etag(&mut response, &updated)?;
    Ok(response)
}

async fn capability_review_json(
    state: &AppState,
    registration_id: Uuid,
) -> Result<Value, ApiError> {
    let snapshot = state
        .database
        .mcp_current_capability_snapshot(state.tenant_id, registration_id)
        .await?;
    let decisions = state
        .database
        .mcp_capability_reviews(state.tenant_id, registration_id)
        .await?
        .into_iter()
        .filter(|review| !review.revoked)
        .map(|review| {
            json!({
                "capability_fingerprint": hex(&review.capability_fingerprint),
                "decision": if review.decision == "approved" { "approved" } else { "blocked" },
            })
        })
        .collect::<Vec<_>>();
    let reviewed_at = state
        .database
        .mcp_capability_reviews(state.tenant_id, registration_id)
        .await?
        .into_iter()
        .filter(|review| !review.revoked)
        .map(|review| review.reviewed_at)
        .max();
    Ok(json!({
        "snapshot": {
            "id": snapshot.id,
            "registration_id": snapshot.registration_id,
            "protocol_version": snapshot.protocol_version,
            "fingerprint": hex(&snapshot.fingerprint),
            "capabilities": normalize_capabilities(&snapshot.document)?,
            "created_at": snapshot.discovered_at,
        },
        "decisions": decisions,
        "reviewed_at": reviewed_at,
    }))
}

async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    if !(1..=200).contains(&query.limit) || query.cursor.is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let items = state
        .database
        .mcp_approval_rules(state.tenant_id, session.record.principal_id, None)
        .await?
        .into_iter()
        .filter(|rule| !rule.revoked && !rule.consumed)
        .take(query.limit as usize)
        .map(|rule| {
            json!({
                "id": rule.id,
                "registration_id": rule.registration_id,
                "capability_fingerprint": hex(&rule.capability_fingerprint),
                "application_id": rule.application_id,
                "argument_digest": hex(&rule.argument_digest),
                "attachment_digest": hex(&rule.attachment_digest),
                "expires_at": rule.expires_at,
                "created_at": rule.created_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

async fn approve_intent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(intent_id): Path<String>,
    Json(input): Json<ApproveIntentInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    let idempotency_key = require_idempotency(&headers)?.to_owned();
    let intent_id = parse_uuid(&intent_id)?;
    let idempotency_fingerprint = mcp_idempotency_fingerprint(
        "POST /api/v1/mcp/invocation-intents/{intent_id}/approval",
        &json!({"intent_id":intent_id,"request":input}),
    )?;
    let intent = state
        .database
        .mcp_invocation_intent_for_approval(
            state.tenant_id,
            intent_id,
            session.record.principal_id,
            session.record.session_id,
        )
        .await?;
    let registration =
        owned_registration(&state, session.record.principal_id, intent.registration_id).await?;
    if !registration.state.enabled {
        return Err(ApiError::forbidden(
            "mcp.registration.disabled",
            "The MCP registration is disabled",
        ));
    }
    let capability_fingerprint: [u8; 32] = intent
        .capability_fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal())?;
    let argument_digest: [u8; 32] = intent
        .argument_digest
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal())?;
    let attachment_digest: [u8; 32] = intent
        .attachment_digest
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal())?;
    let capability = state
        .database
        .mcp_capability_by_fingerprint(
            state.tenant_id,
            intent.registration_id,
            &capability_fingerprint,
        )
        .await?;
    if capability.primitive != intent.primitive {
        return Err(ApiError::forbidden(
            "mcp.capability.changed",
            "The MCP capability changed after the invocation intent was created",
        ));
    }
    let reviewed = state
        .database
        .mcp_capability_reviews(state.tenant_id, intent.registration_id)
        .await?
        .into_iter()
        .any(|review| {
            !review.revoked
                && review.decision == "approved"
                && review.capability_fingerprint == capability_fingerprint
        });
    if !reviewed {
        return Err(ApiError::forbidden(
            "mcp.capability.not_reviewed",
            "The MCP capability is not approved",
        ));
    }
    let (single_use, lifetime, expires_at) =
        match (input.scope.as_str(), input.expires_at.as_deref()) {
            ("once", None) => {
                let lifetime = 300_i64;
                (
                    true,
                    lifetime,
                    rfc3339(unix_time()?.saturating_add(lifetime)),
                )
            }
            ("session", Some(expires_at))
                if session_approval_allowed(&intent.primitive, capability.read_only_hint) =>
            {
                let expires = parse_rfc3339_utc(expires_at)?;
                let lifetime = expires.saturating_sub(unix_time()?);
                if !(1..=3_600).contains(&lifetime) {
                    return Err(ApiError::bad_request(
                        "mcp.approval.expiry_invalid",
                        "Session MCP approvals may last at most one hour",
                    ));
                }
                (false, lifetime, expires_at.to_owned())
            }
            ("session", Some(_)) => {
                return Err(ApiError::forbidden(
                    "mcp.approval.scope_not_allowed",
                    "This MCP capability requires approval for every invocation",
                ));
            }
            _ => {
                return Err(ApiError::bad_request(
                    "mcp.approval.invalid",
                    "The MCP approval scope and expiry are invalid",
                ));
            }
        };
    let id = Uuid::new_v4();
    let response_body = json!({
        "id": id,
        "intent_id": intent_id,
        "scope": input.scope,
        "registration_id": intent.registration_id,
        "capability_fingerprint": hex(&capability_fingerprint),
        "application_id": intent.application_id,
        "argument_digest": hex(&argument_digest),
        "attachment_digest": hex(&attachment_digest),
        "expires_at": expires_at,
        "created_at": rfc3339(unix_time()?),
    });
    let outcome = state
        .database
        .mcp_create_approval_rule_idempotent(
            &NewMcpApprovalRule {
                tenant_id: state.tenant_id,
                id,
                registration_id: intent.registration_id,
                principal_id: session.record.principal_id,
                intent_id,
                session_id: Some(session.record.session_id),
                application_id: &intent.application_id,
                primitive: &intent.primitive,
                capability_name: &capability.name,
                capability_fingerprint: &capability_fingerprint,
                argument_digest: &argument_digest,
                attachment_digest: &attachment_digest,
                single_use,
                lifetime_seconds: lifetime,
            },
            &McpIdempotency {
                principal_id: session.record.principal_id,
                route: "POST /api/v1/mcp/invocation-intents/{intent_id}/approval",
                key: &idempotency_key,
                request_fingerprint: &idempotency_fingerprint,
                response_status: i32::from(StatusCode::CREATED.as_u16()),
                response_body: &response_body,
            },
        )
        .await?;
    mcp_idempotent_response(outcome, None)
}

fn session_approval_allowed(primitive: &str, read_only_hint: Option<bool>) -> bool {
    primitive != "tool_call" && read_only_hint == Some(true)
}

async fn revoke_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(approval_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    state
        .database
        .mcp_revoke_approval_rule(
            state.tenant_id,
            session.record.principal_id,
            parse_uuid(&approval_id)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    if !(1..=200).contains(&query.limit) || query.cursor.is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let items = state
        .database
        .mcp_activity(state.tenant_id, session.record.principal_id, query.limit)
        .await?
        .into_iter()
        .map(|item| json!({
            "id": item.id,
            "actor_kind": "user",
            "application_id": item.application_id,
            "registration_id": item.registration_id,
            "capability_fingerprint": hex(&item.capability_fingerprint),
            "attachment_version_ids": item.attachment_version_ids,
            "approval_id": item.approval_id,
            "request_bytes": item.request_bytes,
            "response_bytes": item.response_bytes,
            "duration_ms": item.duration_ms,
            "outcome": if item.state == "running" { "interrupted" } else { item.state.as_str() },
            "reason_code": item.reason_code,
            "created_at": item.created_at,
        }))
        .collect::<Vec<_>>();
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

async fn create_intent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InvocationRequest>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    validate_invocation_request(&state, &request)?;
    owned_registration(&state, session.record.principal_id, request.registration_id).await?;
    let request_value = serde_json::to_value(&request).map_err(|_| ApiError::internal())?;
    let canonical = filebelt_mcp_policy::canonical_json(&request_value).map_err(|_| {
        ApiError::bad_request("mcp.arguments.invalid", "The MCP arguments are invalid")
    })?;
    let digest = state.digest(INTENT_DIGEST_DOMAIN, &canonical);
    let capability_fingerprint = decode_hash(&request.capability.fingerprint)?;
    let capability = state
        .database
        .mcp_capability_by_fingerprint(
            state.tenant_id,
            request.registration_id,
            &capability_fingerprint,
        )
        .await?;
    let primitive = primitive_name(&request.capability.kind)?;
    if capability.primitive != primitive || capability.name != request.capability.name {
        return Err(ApiError::forbidden(
            "mcp.capability.changed",
            "The MCP capability is not in the current snapshot",
        ));
    }
    let argument_digest = invocation_argument_digest(&request)?;
    let attachment_value = serde_json::to_value(&request.attachments).map_err(|_| {
        ApiError::bad_request("mcp.attachments.invalid", "The MCP attachments are invalid")
    })?;
    let attachment_digest =
        filebelt_mcp_policy::policy_json_digest(b"attachments", &attachment_value).map_err(
            |_| ApiError::bad_request("mcp.attachments.invalid", "The MCP attachments are invalid"),
        )?;
    let id = Uuid::new_v4();
    state
        .database
        .mcp_create_invocation_intent(
            state.tenant_id,
            id,
            request.registration_id,
            session.record.principal_id,
            session.record.session_id,
            &request.application_id,
            primitive,
            &capability_fingerprint,
            &argument_digest,
            &attachment_digest,
            &digest,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "request_digest": hex(&digest),
            "expires_at": rfc3339(unix_time()?.saturating_add(300)),
            "approval_required": true,
        })),
    )
        .into_response())
}

async fn stream_invocation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(intent_id): Path<String>,
    Json(request): Json<InvocationRequest>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    validate_invocation_request(&state, &request)?;
    let invocation_id = parse_uuid(&intent_id)?;
    let request_value = serde_json::to_value(&request).map_err(|_| ApiError::internal())?;
    let canonical = filebelt_mcp_policy::canonical_json(&request_value).map_err(|_| {
        ApiError::bad_request("mcp.arguments.invalid", "The MCP arguments are invalid")
    })?;
    let intent_digest = state.digest(INTENT_DIGEST_DOMAIN, &canonical);
    let registration_id = state
        .database
        .mcp_consume_invocation_intent(
            state.tenant_id,
            invocation_id,
            session.record.principal_id,
            session.record.session_id,
            &request.application_id,
            &intent_digest,
        )
        .await?;
    if registration_id != request.registration_id {
        return Err(ApiError::forbidden(
            "mcp.intent.mismatch",
            "The MCP invocation intent does not match",
        ));
    }
    let registration =
        owned_registration(&state, session.record.principal_id, request.registration_id).await?;
    if !registration.state.enabled {
        return Err(ApiError::forbidden(
            "mcp.registration.disabled",
            "The MCP registration is disabled",
        ));
    }
    let capability_fingerprint = decode_hash(&request.capability.fingerprint)?;
    let approved = state
        .database
        .mcp_capability_reviews(state.tenant_id, request.registration_id)
        .await?
        .into_iter()
        .any(|review| {
            !review.revoked
                && review.decision == "approved"
                && review.capability_fingerprint == capability_fingerprint
        });
    if !approved {
        return Err(ApiError::forbidden(
            "mcp.capability.not_reviewed",
            "The MCP capability is not approved",
        ));
    }
    let attachment_claims =
        build_attachment_claims(&state, &session.record, &registration, &request.attachments)
            .await?;
    let semantic_provenance = validate_markdown_semantic_provenance(
        &state,
        &session.record,
        request.semantic_input.as_ref(),
    )
    .await?;
    let arguments = filebelt_mcp_policy::canonical_json(&request.arguments).map_err(|_| {
        ApiError::bad_request("mcp.arguments.invalid", "The MCP arguments are invalid")
    })?;
    let semantic_input = request
        .semantic_input
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| ApiError::internal())?;
    let argument_digest = invocation_argument_digest(&request)?;
    let attachment_value = serde_json::to_value(&request.attachments).map_err(|_| {
        ApiError::bad_request("mcp.attachments.invalid", "The MCP attachments are invalid")
    })?;
    let attachment_digest =
        filebelt_mcp_policy::policy_json_digest(b"attachments", &attachment_value).map_err(
            |_| ApiError::bad_request("mcp.attachments.invalid", "The MCP attachments are invalid"),
        )?;
    let primitive = primitive_name(&request.capability.kind)?;
    let approval_id = state
        .database
        .mcp_consume_matching_approval(
            state.tenant_id,
            request.registration_id,
            session.record.principal_id,
            Some(session.record.session_id),
            &request.application_id,
            primitive,
            &request.capability.name,
            &capability_fingerprint,
            &argument_digest,
            &attachment_digest,
        )
        .await
        .map_err(|_| {
            ApiError::forbidden(
                "mcp.approval.required",
                "An exact, active approval is required for this MCP invocation",
            )
        })?;
    let generations = state
        .database
        .mcp_revocation_generations(
            state.tenant_id,
            session.record.principal_id,
            request.registration_id,
        )
        .await?;
    state
        .database
        .mcp_start_invocation(&NewMcpInvocation {
            tenant_id: state.tenant_id,
            id: invocation_id,
            registration_id: request.registration_id,
            principal_id: session.record.principal_id,
            application_id: &request.application_id,
            primitive,
            capability_fingerprint: &capability_fingerprint,
            approval_id: Some(approval_id),
            registration_generation: generations.registration,
            authority_generation: generations.principal,
            admin_block_generation: generations.admin_block,
            request_bytes: arguments.len() as i64,
            semantic_node_id: semantic_provenance.map(|provenance| provenance.node_id),
            semantic_base_version_id: semantic_provenance
                .map(|provenance| provenance.base_version_id),
            semantic_input_digest: semantic_provenance
                .as_ref()
                .map(|provenance| &provenance.input_digest),
        })
        .await?;
    for (ordinal, claim) in attachment_claims.iter().enumerate() {
        state
            .database
            .mcp_record_invocation_attachment(
                state.tenant_id,
                invocation_id,
                i32::try_from(ordinal).map_err(|_| ApiError::internal())?,
                parse_uuid(&claim.version_id)?,
                claim
                    .fields
                    .iter()
                    .any(|field| field.disclosure == AttachmentDisclosure::Content as i32),
                claim
                    .fields
                    .iter()
                    .any(|field| field.disclosure == AttachmentDisclosure::Basename as i32),
                claim
                    .fields
                    .iter()
                    .any(|field| field.disclosure == AttachmentDisclosure::MediaType as i32),
                claim
                    .fields
                    .iter()
                    .any(|field| field.disclosure == AttachmentDisclosure::Size as i32),
                if claim
                    .fields
                    .iter()
                    .any(|field| field.disclosure == AttachmentDisclosure::Content as i32)
                {
                    i64::try_from(claim.size_bytes).map_err(|_| ApiError::internal())?
                } else {
                    0
                },
            )
            .await?;
    }
    let protocol = registration.protocol_version.as_deref().ok_or_else(|| {
        ApiError::forbidden(
            "mcp.protocol.missing",
            "The MCP protocol version is unavailable",
        )
    })?;
    let result = call_broker(
        &state,
        &session.record,
        &registration,
        McpOperation::Invoke,
        primitive_enum(&request.capability.kind)?,
        &request.capability.name,
        &request.application_id,
        protocol,
        &arguments,
        semantic_input.as_deref(),
        &capability_fingerprint,
        Some(invocation_id),
        attachment_claims,
    )
    .await;
    let active = state
        .database
        .mcp_invocation_is_active(state.tenant_id, session.record.principal_id, invocation_id)
        .await?;
    let (mut outcome, mut reason, mut result) = match (active, result) {
        (false, _) => (
            "cancelled",
            Some("mcp.cancelled_by_principal"),
            BrokerCallResult {
                value: json!({"error": "mcp.cancelled_by_principal"}),
                semantic: None,
            },
        ),
        (true, Ok(result)) => ("succeeded", None, result),
        (true, Err(_)) => (
            "failed",
            Some("mcp.broker.unavailable"),
            BrokerCallResult {
                value: json!({"error": "mcp.broker.unavailable"}),
                semantic: None,
            },
        ),
    };
    let semantic_output_digest = if outcome == "succeeded" {
        match result
            .semantic
            .as_ref()
            .map(validated_semantic_output_digest)
            .transpose()
        {
            Ok(digest) => digest,
            Err(_) => {
                outcome = "failed";
                reason = Some("mcp.broker.invalid_semantic");
                result = BrokerCallResult {
                    value: json!({"error": "mcp.broker.invalid_semantic"}),
                    semantic: None,
                };
                None
            }
        }
    } else {
        None
    };
    // A broker may return semantic data to a non-provenance MCP caller, but
    // only a request that supplied the immutable Markdown context may persist
    // an output digest as a collaboration provenance witness.
    let semantic_output_digest = semantic_provenance
        .is_some()
        .then_some(semantic_output_digest)
        .flatten();
    let result_bytes = serde_json::to_vec(&result.value).map_err(|_| ApiError::internal())?;
    if active {
        state
            .database
            .mcp_finish_invocation(
                state.tenant_id,
                invocation_id,
                outcome,
                result_bytes.len() as i64,
                reason,
                semantic_output_digest.as_ref(),
            )
            .await?;
    }
    let created_at = rfc3339(unix_time()?);
    let mut events = vec![
        json!({"event":"started","invocation_id":invocation_id,"sequence":0,"created_at":created_at}),
    ];
    if outcome == "succeeded" {
        events.push(json!({"event":"json","invocation_id":invocation_id,"sequence":1,"created_at":created_at,"json":result.value}));
        if let Some(semantic_output) = result.semantic {
            events.push(json!({"event":"semantic","invocation_id":invocation_id,"sequence":2,"created_at":created_at,"semantic_output":semantic_output}));
        }
    } else {
        events.push(json!({"event":"error","invocation_id":invocation_id,"sequence":1,"created_at":created_at,"problem_code":reason}));
    }
    events.push(json!({"event":"completed","invocation_id":invocation_id,"sequence":events.len(),"created_at":created_at}));
    let mut body = Vec::new();
    for event in events {
        serde_json::to_writer(&mut body, &event).map_err(|_| ApiError::internal())?;
        body.push(b'\n');
    }
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-ndjson"),
        )],
        body,
    )
        .into_response())
}

async fn cancel_invocation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invocation_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    state
        .database
        .mcp_cancel_invocation(
            state.tenant_id,
            session.record.principal_id,
            parse_uuid(&invocation_id)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_data_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((drive_id, node_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid(&drive_id)?;
    let node_id = parse_uuid(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::UseMcp,
    )
    .await?;
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
    let items = state
        .database
        .mcp_data_grants(
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            node_id,
        )
        .await?
        .into_iter()
        .filter(|grant| !grant.revoked)
        .map(data_grant_json)
        .collect::<Vec<_>>();
    json_response_with_etag(StatusCode::OK, json!(items), &mcp_node_etag(&node))
}

async fn create_data_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((drive_id, node_id)): Path<(String, String)>,
    Json(input): Json<CreateDataGrantInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    if !state
        .database
        .descendant_share_admission_open(state.tenant_id)
        .await?
    {
        return Err(data_grant_remediation_in_progress());
    }
    let idempotency_key = require_idempotency(&headers)?.to_owned();
    let drive_id = parse_uuid(&drive_id)?;
    let node_id = parse_uuid(&node_id)?;
    let idempotency_fingerprint = mcp_idempotency_fingerprint(
        "POST /api/v1/drives/{drive_id}/nodes/{node_id}/mcp-grants",
        &json!({
            "drive_id":drive_id,
            "node_id":node_id,
            "if_match":headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok()),
            "request":input,
        }),
    )?;
    if input.principal_id != session.record.principal_id {
        return Err(ApiError::forbidden(
            "mcp.data_grant.principal_invalid",
            "Personal MCP data grants must target the current principal",
        ));
    }
    let registration =
        owned_registration(&state, session.record.principal_id, input.registration_id).await?;
    if registration.state.revoked {
        return Err(ApiError::forbidden(
            "mcp.registration.revoked",
            "The MCP registration is revoked",
        ));
    }
    let mut actions = input.actions.clone();
    let action_count = actions.len();
    actions.sort();
    actions.dedup();
    if actions.len() != action_count
        || !actions.iter().any(|action| action == "use_mcp")
        || !actions.iter().any(|action| action == "read_metadata")
        || actions.iter().any(|action| {
            !matches!(
                action.as_str(),
                "use_mcp" | "read_metadata" | "read_content"
            )
        })
    {
        return Err(ApiError::bad_request(
            "mcp.data_grant.actions_invalid",
            "The MCP data-grant actions are invalid",
        ));
    }
    let use_mcp = authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::UseMcp,
    )
    .await?;
    let metadata = authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::ReadMetadata,
    )
    .await?;
    require_attachment_generations(use_mcp, metadata)?;
    if actions.iter().any(|action| action == "read_content") {
        let content = authorize(
            &state.database,
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            node_id,
            Action::ReadContent,
        )
        .await?;
        require_attachment_generations(use_mcp, content)?;
    }
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    require_etag(&headers, &mcp_node_etag(&node))?;
    if input.expected_acl_generation != node.acl_generation
        || node.acl_generation
            != i64::try_from(use_mcp.resource_acl_generation).map_err(|_| ApiError::internal())?
        || node.namespace_generation
            != i64::try_from(use_mcp.namespace_generation).map_err(|_| ApiError::internal())?
    {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "generation.stale",
            "The supplied generation is stale",
        ));
    }
    let expiry = parse_rfc3339_utc(&input.expires_at)?;
    let lifetime = expiry.saturating_sub(unix_time()?);
    if !(1..=2_592_000).contains(&lifetime) {
        return Err(ApiError::bad_request(
            "mcp.data_grant.expiry_invalid",
            "MCP data grants may last at most thirty days",
        ));
    }
    let id = Uuid::new_v4();
    let value = json!({
        "id": id,
        "principal_id": session.record.principal_id,
        "registration_id": input.registration_id,
        "drive_id": drive_id,
        "node_id": node_id,
        "version_id": input.version_id,
        "actions": actions,
        "acl_generation": node.acl_generation,
        "created_at": rfc3339(unix_time()?),
        "expires_at": input.expires_at,
    });
    let outcome = state
        .database
        .mcp_create_data_grant_idempotent(
            &NewMcpDataGrant {
                tenant_id: state.tenant_id,
                id,
                principal_id: session.record.principal_id,
                registration_id: input.registration_id,
                drive_id,
                resource_id: node_id,
                version_id: input.version_id,
                allow_metadata: true,
                allow_content: actions.iter().any(|action| action == "read_content"),
                drive_acl_generation: i64::try_from(use_mcp.drive_acl_generation)
                    .map_err(|_| ApiError::internal())?,
                acl_generation: node.acl_generation,
                namespace_generation: node.namespace_generation,
                created_by: session.record.principal_id,
                lifetime_seconds: lifetime,
            },
            &McpIdempotency {
                principal_id: session.record.principal_id,
                route: "POST /api/v1/drives/{drive_id}/nodes/{node_id}/mcp-grants",
                key: &idempotency_key,
                request_fingerprint: &idempotency_fingerprint,
                response_status: i32::from(StatusCode::CREATED.as_u16()),
                response_body: &value,
            },
        )
        .await
        .map_err(|error| match error {
            DatabaseError::SecurityAdmissionBlocked => data_grant_remediation_in_progress(),
            other => ApiError::from(other),
        })?;
    mcp_idempotent_response(outcome, Some(&mcp_node_etag(&node)))
}

fn data_grant_remediation_in_progress() -> ApiError {
    ApiError::remediation_in_progress(
        "mcp.data_grant.remediation_in_progress",
        "MCP data grants are unavailable until the security repair is activated",
    )
}

async fn revoke_data_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((drive_id, node_id, grant_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let drive_id = parse_uuid(&drive_id)?;
    let node_id = parse_uuid(&node_id)?;
    authorize(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        drive_id,
        node_id,
        Action::UseMcp,
    )
    .await?;
    let node = state
        .database
        .node(state.tenant_id, drive_id, node_id)
        .await?;
    require_etag(&headers, &mcp_node_etag(&node))?;
    state
        .database
        .mcp_revoke_data_grant(
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            node_id,
            parse_uuid(&grant_id)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_admin_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let session = require_admin_read(&state, &headers).await?;
    let _ = session;
    if !(1..=200).contains(&query.limit) || query.cursor.is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let records = state
        .database
        .mcp_managed_templates(state.tenant_id)
        .await?;
    let mut items = Vec::new();
    for record in records.iter().take(query.limit as usize) {
        let count = state
            .database
            .mcp_template_assignment_count(state.tenant_id, record.id)
            .await?;
        items.push(template_json(record, count));
    }
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

async fn create_admin_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateTemplateInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let policy = json!({"description": input.description});
    let record = state
        .database
        .mcp_create_managed_template(&NewMcpManagedTemplate {
            tenant_id: state.tenant_id,
            id: Uuid::new_v4(),
            display_name: &input.display_name,
            description: &input.description,
            transport: database_transport(&input.transport)?,
            endpoint_uri: input.endpoint_uri.as_deref(),
            trust_profile: Some(&input.trust_profile),
            catalog_entry: input.catalog_entry_id.as_deref(),
            policy: &policy,
            created_by: session.record.principal_id,
        })
        .await?;
    template_response(StatusCode::CREATED, &record, 0)
}

async fn get_admin_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Response, ApiError> {
    require_admin_read(&state, &headers).await?;
    let record = state
        .database
        .mcp_managed_template(state.tenant_id, parse_uuid(&template_id)?)
        .await?;
    let count = state
        .database
        .mcp_template_assignment_count(state.tenant_id, record.id)
        .await?;
    template_response(StatusCode::OK, &record, count)
}

async fn update_admin_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
    Json(value): Json<Value>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&template_id)?;
    let current = state
        .database
        .mcp_managed_template(state.tenant_id, id)
        .await?;
    require_etag(&headers, &template_etag(&current))?;
    let object = value.as_object().ok_or_else(|| {
        ApiError::bad_request("mcp.template.invalid", "The MCP template is invalid")
    })?;
    if object.is_empty() {
        return Err(ApiError::bad_request(
            "mcp.template.invalid",
            "The MCP template is invalid",
        ));
    }
    let display_name = object
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or(&current.display_name)
        .to_owned();
    let endpoint = object
        .get("endpoint_uri")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or(current.endpoint_uri.clone());
    let catalog = object
        .get("catalog_entry_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or(current.catalog_entry.clone());
    let trust = object
        .get("trust_profile")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or(current.trust_profile.clone());
    let enabled = object
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(current.enabled);
    let mut policy = current.policy.clone();
    if let Some(description) = object.get("description") {
        policy["description"] = description.clone();
    }
    let updated = state
        .database
        .mcp_update_managed_template(&TemplateConfigurationUpdate {
            tenant_id: state.tenant_id,
            template_id: id,
            expected_revision: current.revision,
            display_name: &display_name,
            description: policy
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            endpoint_uri: endpoint.as_deref(),
            trust_profile: trust.as_deref(),
            catalog_entry: catalog.as_deref(),
            policy: &policy,
            enabled,
        })
        .await?;
    let count = state
        .database
        .mcp_template_assignment_count(state.tenant_id, updated.id)
        .await?;
    template_response(StatusCode::OK, &updated, count)
}

async fn delete_admin_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&template_id)?;
    let current = state
        .database
        .mcp_managed_template(state.tenant_id, id)
        .await?;
    require_etag(&headers, &template_etag(&current))?;
    state
        .database
        .mcp_delete_managed_template(state.tenant_id, id, current.revision)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "id": id,
            "state": "erased",
            "destroy_after": rfc3339(unix_time()?),
        })),
    )
        .into_response())
}

async fn put_admin_assignment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((template_id, principal_id)): Path<(String, String)>,
    Json(input): Json<AssignmentInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let template_id = parse_uuid(&template_id)?;
    let principal_id = parse_uuid(&principal_id)?;
    let template = state
        .database
        .mcp_managed_template(state.tenant_id, template_id)
        .await?;
    require_etag(&headers, &template_etag(&template))?;
    state
        .database
        .mcp_assign_template(
            state.tenant_id,
            template_id,
            principal_id,
            &input.principal_kind,
            session.record.principal_id,
        )
        .await?;
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "template_id": template_id,
            "principal_id": principal_id,
            "principal_kind": input.principal_kind,
            "created_at": rfc3339(unix_time()?),
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&template_etag(&template)).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

async fn delete_admin_assignment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((template_id, principal_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let template_id = parse_uuid(&template_id)?;
    let template = state
        .database
        .mcp_managed_template(state.tenant_id, template_id)
        .await?;
    require_etag(&headers, &template_etag(&template))?;
    state
        .database
        .mcp_revoke_template_assignment(state.tenant_id, template_id, parse_uuid(&principal_id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_admin_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin_read(&state, &headers).await?;
    if !(1..=200).contains(&query.limit) || query.cursor.is_some() {
        return Err(ApiError::bad_request(
            "pagination.cursor_invalid",
            "The page cursor is invalid",
        ));
    }
    let items = state
        .database
        .mcp_service_principals(state.tenant_id)
        .await?
        .iter()
        .take(query.limit as usize)
        .map(service_json)
        .collect::<Vec<_>>();
    Ok(Json(json!({"items":items,"next_cursor":null})))
}

async fn create_admin_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateServiceInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    validate_spiffe(&state, &input.spiffe_uri)?;
    let service_id = Uuid::new_v4();
    let record = state
        .database
        .mcp_create_service_principal(&NewMcpServicePrincipal {
            tenant_id: state.tenant_id,
            service_id,
            principal_id: Uuid::new_v4(),
            display_name: &input.display_name,
            identity_binding_id: Uuid::new_v4(),
            spiffe_uri: &input.spiffe_uri,
            created_by: session.record.principal_id,
        })
        .await?;
    service_response(StatusCode::CREATED, &record)
}

async fn update_admin_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(service_id): Path<String>,
    Json(value): Json<Value>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&service_id)?;
    let current = state
        .database
        .mcp_service_principal(state.tenant_id, id)
        .await?;
    require_etag(&headers, &service_etag(&current))?;
    let display_name = value
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or(&current.display_name);
    let status = value
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or(&current.status);
    let mut updated = state
        .database
        .mcp_update_service_principal(state.tenant_id, id, display_name, status)
        .await?;
    if let Some(spiffe_uri) = value.get("spiffe_uri").and_then(Value::as_str) {
        validate_spiffe(&state, spiffe_uri)?;
        updated = state
            .database
            .mcp_replace_service_identity(state.tenant_id, id, Uuid::new_v4(), spiffe_uri)
            .await?;
    }
    service_response(StatusCode::OK, &updated)
}

async fn delete_admin_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(service_id): Path<String>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&service_id)?;
    let current = state
        .database
        .mcp_service_principal(state.tenant_id, id)
        .await?;
    require_etag(&headers, &service_etag(&current))?;
    state
        .database
        .mcp_delete_service_principal(state.tenant_id, id)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":id,"state":"erased","destroy_after":rfc3339(unix_time()?)})),
    )
        .into_response())
}

async fn list_admin_service_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(service_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_admin_read(&state, &headers).await?;
    let id = parse_uuid(&service_id)?;
    let grants = state
        .database
        .mcp_service_grants(state.tenant_id, id)
        .await?
        .iter()
        .filter(|grant| !grant.revoked)
        .map(service_grant_json)
        .collect::<Vec<_>>();
    Ok(Json(Value::Array(grants)))
}

async fn create_admin_service_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(service_id): Path<String>,
    Json(input): Json<CreateServiceGrantInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = require_admin_mutation(&state, &headers).await?;
    let idempotency_key = require_idempotency(&headers)?.to_owned();
    let service_id = parse_uuid(&service_id)?;
    let idempotency_fingerprint = mcp_idempotency_fingerprint(
        "POST /api/v1/admin/mcp/service-identities/{service_id}/invocation-grants",
        &json!({
            "service_id":service_id,
            "if_match":headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok()),
            "request":input,
        }),
    )?;
    let service = state
        .database
        .mcp_service_principal(state.tenant_id, service_id)
        .await?;
    require_etag(&headers, &service_etag(&service))?;
    if input.mcp_data_grant_ids.len() > 64 || !(1..=600).contains(&input.max_invocations_per_hour) {
        return Err(ApiError::bad_request(
            "mcp.service_grant.invalid",
            "The MCP service grant is invalid",
        ));
    }
    let lifetime = parse_rfc3339_utc(&input.expires_at)?.saturating_sub(unix_time()?);
    if !(1..=2_592_000).contains(&lifetime) {
        return Err(ApiError::bad_request(
            "mcp.service_grant.expiry_invalid",
            "MCP service grants may last at most thirty days",
        ));
    }
    let fingerprint = decode_hash(&input.capability.fingerprint)?;
    let constraints = json!({"argument_constraints":input.argument_constraints,"mcp_data_grant_ids":input.mcp_data_grant_ids});
    let quota = json!({"max_invocations_per_hour":input.max_invocations_per_hour});
    let id = Uuid::new_v4();
    let response_body = json!({
        "id":id,"service_id":service_id,"registration_id":input.registration_id,
        "capability":input.capability,"application_id":input.application_id,
        "argument_constraints":constraints["argument_constraints"],
        "mcp_data_grant_ids":constraints["mcp_data_grant_ids"],
        "max_invocations_per_hour":input.max_invocations_per_hour,
        "created_at":rfc3339(unix_time()?),"expires_at":input.expires_at,
    });
    let outcome = state
        .database
        .mcp_create_service_grant_idempotent(
            &NewMcpServiceGrant {
                tenant_id: state.tenant_id,
                id,
                service_id,
                expected_service_generation: service.revocation_generation,
                registration_id: input.registration_id,
                capability_fingerprint: &fingerprint,
                primitive: primitive_name(&input.capability.kind)?,
                capability_name: &input.capability.name,
                constraints: &constraints,
                application_id: &input.application_id,
                quota: &quota,
                data_grant_ids: &input.mcp_data_grant_ids,
                max_invocations_per_hour: input.max_invocations_per_hour as i32,
                created_by: session.record.principal_id,
                lifetime_seconds: lifetime,
            },
            &McpIdempotency {
                principal_id: session.record.principal_id,
                route: "POST /api/v1/admin/mcp/service-identities/{service_id}/invocation-grants",
                key: &idempotency_key,
                request_fingerprint: &idempotency_fingerprint,
                response_status: i32::from(StatusCode::CREATED.as_u16()),
                response_body: &response_body,
            },
        )
        .await?;
    mcp_idempotent_response(outcome, None)
}

async fn revoke_admin_service_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((service_id, grant_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let service_id = parse_uuid(&service_id)?;
    let service = state
        .database
        .mcp_service_principal(state.tenant_id, service_id)
        .await?;
    require_etag(&headers, &service_etag(&service))?;
    state
        .database
        .mcp_revoke_service_grant(state.tenant_id, service_id, parse_uuid(&grant_id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_admin_block_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin_read(&state, &headers).await?;
    Ok(Json(Value::Array(
        state
            .database
            .mcp_admin_block_rules(state.tenant_id)
            .await?
            .iter()
            .filter(|rule| rule.enabled)
            .map(block_rule_json)
            .collect(),
    )))
}

async fn create_admin_block_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateBlockRuleInput>,
) -> Result<Response, ApiError> {
    require_enabled(&state)?;
    let session = require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let rule = state
        .database
        .mcp_create_admin_block_rule(
            state.tenant_id,
            Uuid::new_v4(),
            &input.kind,
            &input.value,
            &input.reason,
            session.record.principal_id,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(block_rule_json(&rule))).into_response())
}

async fn delete_admin_block_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(block_rule_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    require_admin_mutation(&state, &headers).await?;
    require_idempotency(&headers)?;
    let id = parse_uuid(&block_rule_id)?;
    let revision = state
        .database
        .mcp_admin_block_rules(state.tenant_id)
        .await?
        .into_iter()
        .find(|rule| rule.id == id)
        .ok_or_else(ApiError::not_found)?
        .revision;
    state
        .database
        .mcp_delete_admin_block_rule(state.tenant_id, id, revision)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn broker_probe(
    state: &AppState,
    session: &filebelt_database::SessionRecord,
    registration: &McpRegistrationRecord,
    operation: McpOperation,
    capability_name: &str,
) -> Result<(String, Value), ApiError> {
    let protocols = if let Some(version) = &registration.protocol_version {
        vec![version.as_str()]
    } else {
        vec![CURRENT_PROTOCOL, FALLBACK_PROTOCOL]
    };
    let mut last_error = None;
    for protocol in protocols {
        match call_broker(
            state,
            session,
            registration,
            operation,
            McpPrimitive::Unspecified,
            capability_name,
            "filebelt.settings.mcp",
            protocol,
            &[],
            None,
            &[0; 32],
            None,
            Vec::new(),
        )
        .await
        {
            Ok(result) => return Ok((protocol.to_owned(), result.value)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(ApiError::internal))
}

#[allow(clippy::too_many_arguments)]
async fn call_broker(
    state: &AppState,
    session: &filebelt_database::SessionRecord,
    registration: &McpRegistrationRecord,
    operation: McpOperation,
    primitive: McpPrimitive,
    capability_name: &str,
    application_id: &str,
    protocol: &str,
    arguments: &[u8],
    semantic_input: Option<&[u8]>,
    capability_fingerprint: &[u8; 32],
    request_id: Option<Uuid>,
    attachments: Vec<AttachmentClaim>,
) -> Result<BrokerCallResult, ApiError> {
    let mcp = require_enabled(state)?;
    let generations = state
        .database
        .mcp_revocation_generations(state.tenant_id, session.principal_id, registration.id)
        .await?;
    let mut arguments_hasher = blake3::Hasher::new();
    arguments_hasher
        .update(ARGUMENT_DIGEST_DOMAIN)
        .update(&(arguments.len() as u64).to_be_bytes())
        .update(arguments);
    if let Some(semantic_input) = semantic_input {
        arguments_hasher
            .update(&(semantic_input.len() as u64).to_be_bytes())
            .update(semantic_input);
    } else {
        arguments_hasher.update(&0_u64.to_be_bytes());
    }
    let arguments_digest = arguments_hasher.finalize();
    let mut nonce = vec![0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ApiError::internal())?;
    let now = unix_time()?;
    let claims = DelegationClaims {
        capability_id: Uuid::new_v4().to_string(),
        audience: "filebelt-mcp-broker".into(),
        operation: operation as i32,
        tenant_id: state.tenant_id.to_string(),
        principal_id: session.principal_id.to_string(),
        session_id: session.session_id.to_string(),
        application_id: application_id.into(),
        registration_id: registration.id.to_string(),
        capability_fingerprint: capability_fingerprint.to_vec(),
        arguments_digest: arguments_digest.as_bytes().to_vec(),
        attachments,
        policy_generation: generations.registration as u64,
        membership_generation: generations.principal as u64,
        nonce,
        issued_at_unix_seconds: now,
        expires_at_unix_seconds: now.saturating_add(120),
        service_grant_id: String::new(),
    };
    let delegation = sign_mcp_delegation(
        &claims,
        state
            .config
            .keys
            .api_mcp_delegation
            .as_ref()
            .ok_or_else(ApiError::internal)?
            .current_generation,
        state
            .mcp_delegation_signer
            .as_ref()
            .ok_or_else(ApiError::internal)?,
    )
    .map_err(|_| ApiError::internal())?;
    let request = BrokerInvocationRequest {
        request_id: request_id.unwrap_or_else(Uuid::new_v4).to_string(),
        delegation,
        protocol_version: protocol.into(),
        primitive: primitive as i32,
        capability_name: capability_name.into(),
        arguments_json: arguments.to_vec(),
        deadline_unix_milliseconds: now
            .saturating_add(state.config.mcp.limits.absolute_timeout_seconds as i64)
            .saturating_mul(1_000),
        semantic_input_json: semantic_input.unwrap_or_default().to_vec(),
    };
    let response = mcp
        .broker
        .post(mcp.broker_url.clone())
        .header(header::CONTENT_TYPE, INTERNAL_CONTENT_TYPE)
        .header(header::ACCEPT, INTERNAL_CONTENT_TYPE)
        .timeout(Duration::from_secs(
            state.config.mcp.limits.absolute_timeout_seconds,
        ))
        .body(request.encode_to_vec())
        .send()
        .await
        .map_err(|_| mcp_unavailable())?;
    if !response.status().is_success() {
        return Err(mcp_unavailable());
    }
    let body = read_bounded_broker_body(response).await?;
    let frames = decode_frames(&body).map_err(|_| mcp_unavailable())?;
    let payload = frames
        .iter()
        .find(|frame| frame.kind == InvocationFrameKind::Json as i32)
        .ok_or_else(mcp_unavailable)?;
    let value = serde_json::from_slice(&payload.payload).map_err(|_| mcp_unavailable())?;
    let semantic = frames
        .iter()
        .find(|frame| frame.kind == InvocationFrameKind::Semantic as i32)
        .map(|frame| serde_json::from_slice(&frame.payload))
        .transpose()
        .map_err(|_| mcp_unavailable())?;
    Ok(BrokerCallResult { value, semantic })
}

struct BrokerCallResult {
    value: Value,
    semantic: Option<Value>,
}

async fn read_bounded_broker_body(mut response: reqwest::Response) -> Result<Vec<u8>, ApiError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BROKER_RESPONSE_BYTES as u64)
    {
        return Err(mcp_unavailable());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| mcp_unavailable())? {
        append_bounded_broker_chunk(&mut body, &chunk, MAX_BROKER_RESPONSE_BYTES)?;
    }
    Ok(body)
}

fn append_bounded_broker_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    maximum_bytes: usize,
) -> Result<(), ApiError> {
    if chunk.len() > maximum_bytes.saturating_sub(body.len()) {
        return Err(mcp_unavailable());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn validate_registration_input(
    state: &AppState,
    input: &RegistrationInput,
) -> Result<(), ApiError> {
    if input.display_name.is_empty()
        || input.display_name.len() > 120
        || input.description.len() > 1_000
        || !state
            .config
            .mcp
            .trust_profiles
            .contains_key(&input.trust_profile)
        || input.attachment_policy.max_attachments > 4
        || input.attachment_policy.max_item_bytes > 16_777_216
        || input.attachment_policy.max_total_bytes > 16_777_216
        || input.attachment_policy.max_item_bytes > input.attachment_policy.max_total_bytes
        || input.attachment_policy.allowed_mime_patterns.is_empty()
        || input.attachment_policy.allowed_mime_patterns.len() > 32
        || input
            .attachment_policy
            .allowed_mime_patterns
            .iter()
            .any(|value| !valid_mime_pattern(value))
        || input.attachment_policy.allowed_encodings.is_empty()
        || input.attachment_policy.allowed_encodings.len() > 2
        || input
            .attachment_policy
            .allowed_encodings
            .iter()
            .any(|value| !matches!(value.as_str(), "utf8" | "base64"))
    {
        return Err(ApiError::bad_request(
            "mcp.registration.invalid",
            "The MCP registration is invalid",
        ));
    }
    match input.transport.as_str() {
        "streamable_http" => {
            let endpoint = input
                .endpoint_uri
                .as_deref()
                .and_then(|value| Url::parse(value).ok())
                .ok_or_else(|| {
                    ApiError::bad_request("mcp.endpoint.invalid", "The MCP endpoint is invalid")
                })?;
            if endpoint.scheme() != "https"
                || endpoint.host_str().is_none()
                || endpoint.port_or_known_default() != Some(443)
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || input.catalog_entry_id.is_some()
            {
                return Err(ApiError::bad_request(
                    "mcp.endpoint.invalid",
                    "The MCP endpoint is invalid",
                ));
            }
        }
        "stdio_catalog" => {
            if input.endpoint_uri.is_some()
                || input.catalog_entry_id.as_deref().is_none_or(|value| {
                    value.is_empty()
                        || value.len() > 128
                        || !value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
            {
                return Err(ApiError::bad_request(
                    "mcp.catalog.invalid",
                    "The MCP catalog entry is invalid",
                ));
            }
        }
        _ => {
            return Err(ApiError::bad_request(
                "mcp.transport.invalid",
                "The MCP transport is invalid",
            ));
        }
    }
    Ok(())
}

fn valid_mcp_return_path(value: &str) -> bool {
    if value == "/settings/mcp" {
        return true;
    }
    value
        .strip_prefix("/settings/mcp/")
        .is_some_and(|value| parse_uuid(value).is_ok())
}

fn select_oauth_issuer(state: &AppState, requested: Option<&str>) -> Result<String, ApiError> {
    let configured = state
        .config
        .mcp
        .oauth_clients
        .values()
        .map(|client| client.issuer.as_str().trim_end_matches('/').to_owned())
        .collect::<Vec<_>>();
    let selected = match requested {
        Some(issuer) => {
            let parsed = Url::parse(issuer).map_err(|_| {
                ApiError::bad_request(
                    "mcp.oauth.issuer_invalid",
                    "The MCP OAuth issuer is invalid",
                )
            })?;
            parsed.as_str().trim_end_matches('/').to_owned()
        }
        None if configured.len() == 1 => configured[0].clone(),
        None => {
            return Err(ApiError::bad_request(
                "mcp.oauth.issuer_required",
                "An operator-configured MCP OAuth issuer is required",
            ));
        }
    };
    if !configured.iter().any(|issuer| issuer == &selected) {
        return Err(ApiError::forbidden(
            "mcp.oauth.issuer_not_configured",
            "The MCP OAuth issuer is not configured",
        ));
    }
    Ok(selected)
}

fn validate_invocation_request(
    state: &AppState,
    request: &InvocationRequest,
) -> Result<(), ApiError> {
    let canonical = filebelt_mcp_policy::canonical_json(&request.arguments).map_err(|_| {
        ApiError::bad_request("mcp.arguments.invalid", "The MCP arguments are invalid")
    })?;
    if request.application_id.is_empty()
        || request.application_id.len() > 128
        || request.capability.name.is_empty()
        || request.capability.name.len() > 256
        || !matches!(
            request.capability.kind.as_str(),
            "resource" | "prompt" | "tool"
        )
        || decode_hash(&request.capability.fingerprint).is_err()
        || canonical.len() > state.config.mcp.limits.message_bytes as usize
        || request.semantic_input.as_ref().is_some_and(|semantic| {
            semantic.format != "filebelt.markdown.semantic.v1"
                || semantic.markdown.len() > 2 * 1_024 * 1_024
                || semantic.markdown.contains('\0')
                || semantic.markdown.contains('\r')
        })
        || request.attachments.len() > 4
        || request.attachments.iter().any(|attachment| {
            attachment.fields.is_empty()
                || attachment.fields.len() > 4
                || attachment
                    .fields
                    .iter()
                    .any(|field| !valid_field_binding(field))
        })
    {
        return Err(ApiError::bad_request(
            "mcp.invocation.invalid",
            "The MCP invocation request is invalid",
        ));
    }
    Ok(())
}

async fn validate_markdown_semantic_provenance(
    state: &AppState,
    session: &filebelt_database::SessionRecord,
    semantic: Option<&SemanticMarkdownInput>,
) -> Result<Option<MarkdownSemanticProvenance>, ApiError> {
    let Some(semantic) = semantic else {
        return Ok(None);
    };
    let drive_id = state
        .database
        .mcp_markdown_context_drive(state.tenant_id, semantic.node_id, semantic.base_version_id)
        .await?;
    authorize(
        &state.database,
        state.tenant_id,
        session.principal_id,
        drive_id,
        semantic.node_id,
        Action::WriteContent,
    )
    .await?;
    Ok(Some(MarkdownSemanticProvenance {
        node_id: semantic.node_id,
        base_version_id: semantic.base_version_id,
        input_digest: normalized_markdown_source_digest(semantic.markdown.as_bytes()),
    }))
}

fn validated_semantic_output_digest(value: &Value) -> Result<[u8; 32], ApiError> {
    let semantic: SemanticMarkdownOutput =
        serde_json::from_value(value.clone()).map_err(|_| mcp_unavailable())?;
    if semantic.format != "filebelt.markdown.semantic.v1"
        || semantic.markdown.len() > 2 * 1_024 * 1_024
        || semantic.markdown.contains('\0')
        || semantic.markdown.contains('\r')
    {
        return Err(mcp_unavailable());
    }
    Ok(normalized_markdown_source_digest(
        semantic.markdown.as_bytes(),
    ))
}

fn invocation_argument_digest(request: &InvocationRequest) -> Result<[u8; 32], ApiError> {
    if request.semantic_input.is_none() {
        return filebelt_mcp_policy::policy_json_digest(b"arguments", &request.arguments).map_err(
            |_| ApiError::bad_request("mcp.arguments.invalid", "The MCP arguments are invalid"),
        );
    }
    filebelt_mcp_policy::policy_json_digest(
        b"arguments-and-semantic-input",
        &json!({
            "arguments": request.arguments,
            "semantic_input": request.semantic_input,
        }),
    )
    .map_err(|_| ApiError::bad_request("mcp.arguments.invalid", "The MCP arguments are invalid"))
}

async fn build_attachment_claims(
    state: &AppState,
    session: &filebelt_database::SessionRecord,
    registration: &McpRegistrationRecord,
    attachments: &[AttachmentBinding],
) -> Result<Vec<AttachmentClaim>, ApiError> {
    let policy: AttachmentPolicy = serde_json::from_value(
        registration
            .policy
            .get("attachment_policy")
            .cloned()
            .unwrap_or_else(default_attachment_policy),
    )
    .map_err(|_| ApiError::internal())?;
    if attachments.len() > usize::from(policy.max_attachments) {
        return Err(ApiError::bad_request(
            "mcp.attachments.limit_exceeded",
            "The MCP attachment count exceeds the registration policy",
        ));
    }
    let mut claims = Vec::with_capacity(attachments.len());
    let mut total_bytes = 0_u64;
    let mut targets = HashSet::new();
    for attachment in attachments {
        let needs_content = attachment
            .fields
            .iter()
            .any(|field| field.source == "content");
        let needs_metadata = attachment
            .fields
            .iter()
            .any(|field| field.source != "content");
        if attachment
            .fields
            .iter()
            .any(|field| !targets.insert(field.target_json_pointer.clone()))
        {
            return Err(ApiError::bad_request(
                "mcp.attachments.target_conflict",
                "Each MCP attachment target must be unique",
            ));
        }
        let use_mcp = authorize_capability(
            &state.database,
            state.tenant_id,
            session.principal_id,
            session.session_id,
            attachment.drive_id,
            attachment.node_id,
            Action::UseMcp,
        )
        .await?;
        let metadata_grant = if needs_metadata {
            Some(
                authorize_capability(
                    &state.database,
                    state.tenant_id,
                    session.principal_id,
                    session.session_id,
                    attachment.drive_id,
                    attachment.node_id,
                    Action::ReadMetadata,
                )
                .await?,
            )
        } else {
            None
        };
        let content_grant = if needs_content {
            Some(
                authorize_capability(
                    &state.database,
                    state.tenant_id,
                    session.principal_id,
                    session.session_id,
                    attachment.drive_id,
                    attachment.node_id,
                    Action::ReadContent,
                )
                .await?,
            )
        } else {
            None
        };
        for grant in [metadata_grant, content_grant].into_iter().flatten() {
            require_attachment_generations(use_mcp, grant)?;
        }
        let mut selected = None;
        for grant in state
            .database
            .mcp_data_grants(
                state.tenant_id,
                session.principal_id,
                attachment.drive_id,
                attachment.node_id,
            )
            .await?
            .into_iter()
            .filter(|grant| {
                !grant.revoked
                    && grant.registration_id == registration.id
                    && grant.version_id == attachment.version_id
                    && (!needs_content || grant.allow_content)
                    && (!needs_metadata || grant.allow_metadata)
            })
        {
            let Ok(snapshot) = state
                .database
                .mcp_authority_snapshot(
                    state.tenant_id,
                    session.principal_id,
                    registration.id,
                    grant.id,
                )
                .await
            else {
                continue;
            };
            if snapshot.principal_generation
                == i64::try_from(use_mcp.membership_generation).map_err(|_| ApiError::internal())?
                && snapshot.registration_generation == registration.revocation_generation
                && snapshot.acl_generation
                    == i64::try_from(use_mcp.resource_acl_generation)
                        .map_err(|_| ApiError::internal())?
                && snapshot.namespace_generation
                    == i64::try_from(use_mcp.namespace_generation)
                        .map_err(|_| ApiError::internal())?
            {
                selected = Some(grant);
                break;
            }
        }
        let data_grant = selected.ok_or_else(|| {
            ApiError::forbidden(
                "mcp.attachment.grant_required",
                "An exact active MCP data grant is required for this attachment",
            )
        })?;
        let payload = state
            .database
            .payload_for_node(
                state.tenant_id,
                attachment.node_id,
                Some(attachment.version_id),
            )
            .await?;
        if payload.drive_id != attachment.drive_id || payload.size_bytes < 0 {
            return Err(ApiError::not_found());
        }
        let size_bytes = u64::try_from(payload.size_bytes).map_err(|_| ApiError::internal())?;
        total_bytes = total_bytes
            .checked_add(size_bytes)
            .ok_or_else(ApiError::internal)?;
        if size_bytes > policy.max_item_bytes
            || size_bytes > state.config.mcp.limits.attachment_hard_bytes
            || total_bytes > policy.max_total_bytes
            || total_bytes > state.config.mcp.limits.attachment_bytes
        {
            return Err(ApiError::bad_request(
                "mcp.attachments.limit_exceeded",
                "The MCP attachment bytes exceed the registration policy",
            ));
        }
        let metadata = state
            .database
            .mcp_attachment_metadata(
                state.tenant_id,
                attachment.drive_id,
                attachment.node_id,
                attachment.version_id,
            )
            .await?;
        if !policy
            .allowed_mime_patterns
            .iter()
            .any(|pattern| mime_matches(pattern, &metadata.media_type))
        {
            return Err(ApiError::forbidden(
                "mcp.attachment.media_type_denied",
                "The MCP attachment media type is not allowed",
            ));
        }
        let fields = attachment
            .fields
            .iter()
            .map(|field| attachment_field_claim(field, &policy))
            .collect::<Result<Vec<_>, _>>()?;
        let capability_id = Uuid::new_v4();
        let now = unix_time()?;
        let capability = sign_api_storage_capability(
            &CapabilityClaims {
                capability_id: capability_id.to_string(),
                audience: STORAGE_CAPABILITY_AUDIENCE.into(),
                operation: CapabilityOperation::Download as i32,
                tenant_id: state.tenant_id.to_string(),
                principal_id: session.principal_id.to_string(),
                session_id: session.session_id.to_string(),
                resource_id: attachment.node_id.to_string(),
                upload_id: String::new(),
                payload_id: payload.payload_id.to_string(),
                part_number: 0,
                range_start: 0,
                range_end: size_bytes.saturating_sub(1),
                resource_acl_generation: use_mcp.resource_acl_generation,
                membership_generation: use_mcp.membership_generation,
                namespace_generation: use_mcp.namespace_generation,
                fencing_token: 0,
                nonce: attachment_nonce()?,
                issued_at_unix_seconds: now,
                expires_at_unix_seconds: now.saturating_add(MAX_CAPABILITY_LIFETIME_SECONDS),
                drive_acl_generation: use_mcp.drive_acl_generation,
                grant_id: capability_id.to_string(),
            },
            ApiStorageCapabilityUse::Download,
            state.config.keys.api_storage.current_generation,
            &state.api_storage_signer,
        )
        .map_err(|_| ApiError::internal())?;
        claims.push(AttachmentClaim {
            drive_id: attachment.drive_id.to_string(),
            node_id: attachment.node_id.to_string(),
            version_id: attachment.version_id.to_string(),
            data_grant_id: data_grant.id.to_string(),
            fields,
            maximum_raw_bytes: policy.max_item_bytes,
            drive_acl_generation: use_mcp.drive_acl_generation,
            resource_acl_generation: use_mcp.resource_acl_generation,
            membership_generation: use_mcp.membership_generation,
            namespace_generation: use_mcp.namespace_generation,
            download_path: format!("/io/v1/downloads/{capability_id}"),
            authorization: capability,
            basename: metadata.basename,
            media_type: metadata.media_type,
            size_bytes,
        });
    }
    Ok(claims)
}

fn attachment_field_claim(
    field: &AttachmentFieldBinding,
    policy: &AttachmentPolicy,
) -> Result<AttachmentFieldClaim, ApiError> {
    let (disclosure, encoding) = match (field.source.as_str(), field.encoding.as_str()) {
        ("content", "utf8") => (AttachmentDisclosure::Content, AttachmentEncoding::Utf8),
        ("content", "base64") => (AttachmentDisclosure::Content, AttachmentEncoding::Base64),
        ("basename", "native" | "utf8") => {
            (AttachmentDisclosure::Basename, AttachmentEncoding::Utf8)
        }
        ("basename", "base64") => (AttachmentDisclosure::Basename, AttachmentEncoding::Base64),
        ("mime_type", "native" | "utf8") => {
            (AttachmentDisclosure::MediaType, AttachmentEncoding::Utf8)
        }
        ("mime_type", "base64") => (AttachmentDisclosure::MediaType, AttachmentEncoding::Base64),
        ("size_bytes", "native") => (AttachmentDisclosure::Size, AttachmentEncoding::Decimal),
        _ => {
            return Err(ApiError::bad_request(
                "mcp.attachments.encoding_invalid",
                "The MCP attachment encoding is invalid for the selected disclosure",
            ));
        }
    };
    let policy_encoding = match encoding {
        AttachmentEncoding::Base64 => "base64",
        AttachmentEncoding::Utf8 | AttachmentEncoding::Decimal => "utf8",
        AttachmentEncoding::Unspecified => "",
    };
    if !policy
        .allowed_encodings
        .iter()
        .any(|allowed| allowed == policy_encoding)
    {
        return Err(ApiError::forbidden(
            "mcp.attachment.encoding_denied",
            "The MCP attachment encoding is not allowed",
        ));
    }
    Ok(AttachmentFieldClaim {
        disclosure: disclosure as i32,
        target_json_pointer: field.target_json_pointer.clone(),
        encoding: encoding as i32,
    })
}

fn require_attachment_generations(
    expected: AuthorizationGrant,
    actual: AuthorizationGrant,
) -> Result<(), ApiError> {
    if expected != actual {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "generation.stale",
            "The attachment authorization generations changed",
        ));
    }
    Ok(())
}

fn attachment_nonce() -> Result<Vec<u8>, ApiError> {
    let mut nonce = vec![0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ApiError::internal())?;
    Ok(nonce)
}

fn mime_matches(pattern: &str, media_type: &str) -> bool {
    pattern == media_type
        || pattern
            .strip_suffix("/*")
            .is_some_and(|prefix| media_type.starts_with(&format!("{prefix}/")))
}

fn valid_field_binding(field: &AttachmentFieldBinding) -> bool {
    matches!(
        field.source.as_str(),
        "content" | "basename" | "mime_type" | "size_bytes"
    ) && matches!(field.encoding.as_str(), "native" | "utf8" | "base64")
        && !matches!(
            (field.source.as_str(), field.encoding.as_str()),
            ("content", "native")
        )
        && (field.source != "size_bytes" || field.encoding == "native")
        && field.target_json_pointer.len() <= 512
        && field.target_json_pointer.starts_with('/')
        && !field.target_json_pointer.split('/').skip(1).any(|token| {
            let bytes = token.as_bytes();
            bytes.iter().enumerate().any(|(index, byte)| {
                *byte == b'~'
                    && bytes
                        .get(index + 1)
                        .is_none_or(|next| !matches!(*next, b'0' | b'1'))
            })
        })
}

fn valid_mime_pattern(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    valid_mime_token(kind) && (subtype == "*" || valid_mime_token(subtype))
}

fn valid_mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn registration_policy(
    input: &RegistrationInput,
    credential_kind: &str,
    credential_present: bool,
) -> Value {
    json!({
        "description": input.description,
        "attachment_policy": input.attachment_policy,
        "credential_kind": credential_kind,
        "credential_present": credential_present,
    })
}

async fn require_admin_read(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let session = authenticate(state, headers).await?;
    if !session.record.tenant_admin || !session.record.reauthenticated_recently {
        return Err(ApiError::forbidden(
            "admin.reauthentication_required",
            "Recent tenant administrator authentication is required",
        ));
    }
    Ok(session)
}

async fn require_admin_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let session = authenticate_mutation(state, headers).await?;
    if !session.record.tenant_admin || !session.record.reauthenticated_recently {
        return Err(ApiError::forbidden(
            "admin.reauthentication_required",
            "Recent tenant administrator authentication is required",
        ));
    }
    Ok(session)
}

fn template_json(
    record: &filebelt_database::mcp::McpManagedTemplateRecord,
    assignment_count: i64,
) -> Value {
    json!({
        "id": record.id,
        "display_name": record.display_name,
        "description": record.description,
        "transport": api_transport(&record.transport),
        "endpoint_uri": record.endpoint_uri,
        "catalog_entry_id": record.catalog_entry,
        "trust_profile": record.trust_profile.as_deref().unwrap_or("public"),
        "enabled": record.enabled,
        "assignment_count": assignment_count,
        "etag": template_etag(record),
        "generation": record.revision,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    })
}

fn template_response(
    status: StatusCode,
    record: &filebelt_database::mcp::McpManagedTemplateRecord,
    assignment_count: i64,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(template_json(record, assignment_count))).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&template_etag(record)).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

fn template_etag(record: &filebelt_database::mcp::McpManagedTemplateRecord) -> String {
    format!("\"fb-mcp-template-{}-{}\"", record.id, record.revision)
}

fn service_json(record: &filebelt_database::mcp::McpServicePrincipalRecord) -> Value {
    json!({
        "id": record.service_id,
        "display_name": record.display_name,
        "spiffe_uri": record.spiffe_uri,
        "state": if record.status == "active" { "active" } else { "suspended" },
        "etag": service_etag(record),
        "generation": record.revocation_generation,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    })
}

fn service_response(
    status: StatusCode,
    record: &filebelt_database::mcp::McpServicePrincipalRecord,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(service_json(record))).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&service_etag(record)).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

fn service_etag(record: &filebelt_database::mcp::McpServicePrincipalRecord) -> String {
    format!(
        "\"fb-mcp-service-{}-{}\"",
        record.service_id, record.revocation_generation
    )
}

fn service_grant_json(record: &filebelt_database::mcp::McpServiceGrantRecord) -> Value {
    let kind = match record.primitive.as_str() {
        "resource_read" => "resource",
        "prompt_get" => "prompt",
        _ => "tool",
    };
    json!({
        "id": record.id,
        "service_id": record.service_id,
        "registration_id": record.registration_id,
        "capability": {
            "kind": kind,
            "name": record.capability_name,
            "fingerprint": hex(&record.capability_fingerprint),
        },
        "application_id": record.application_id,
        "argument_constraints": record.constraints,
        "mcp_data_grant_ids": record.data_grant_ids,
        "max_invocations_per_hour": record.max_invocations_per_hour,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
    })
}

fn block_rule_json(record: &filebelt_database::mcp::McpAdminBlockRuleRecord) -> Value {
    json!({
        "id": record.id,
        "kind": record.scope,
        "value": record.matcher,
        "reason": record.reason_code,
        "created_at": record.created_at,
    })
}

fn require_etag(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    if headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        != Some(expected)
    {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "generation.stale",
            "The supplied generation is stale",
        ));
    }
    Ok(())
}

fn validate_spiffe(state: &AppState, value: &str) -> Result<(), ApiError> {
    let uri = Url::parse(value)
        .map_err(|_| ApiError::bad_request("mcp.spiffe.invalid", "The SPIFFE URI is invalid"))?;
    if uri.scheme() != "spiffe"
        || uri.host_str().is_none_or(|host| {
            !state
                .config
                .mcp
                .service_trust_domains
                .iter()
                .any(|domain| domain == host)
        })
        || uri.path() == "/"
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        return Err(ApiError::bad_request(
            "mcp.spiffe.invalid",
            "The SPIFFE URI is invalid",
        ));
    }
    Ok(())
}

fn registration_json(record: &McpRegistrationRecord) -> Result<Value, ApiError> {
    Ok(json!({
        "id": record.id,
        "etag": registration_etag(record),
        "ownership": if record.source_kind == "personal" { "personal" } else if record.owner_kind == "service" { "managed_service" } else { "managed_user" },
        "managed_template_id": record.template_id,
        "display_name": record.display_name,
        "description": record.policy.get("description").and_then(Value::as_str).unwrap_or_default(),
        "transport": api_transport(&record.transport),
        "endpoint_uri": record.endpoint_uri,
        "catalog_entry_id": record.catalog_entry,
        "trust_profile": record.trust_profile.as_deref().unwrap_or("public"),
        "protocol_version": record.protocol_version.as_deref().unwrap_or(CURRENT_PROTOCOL),
        "lifecycle_state": if record.state.revoked { "deleted" } else if record.state.enabled { "enabled" } else { "disabled" },
        "validation_state": validation_state(record.state.validation),
        "authentication_state": authentication_state(record.state.authentication),
        "capability_state": capability_state(record.state.capabilities),
        "quarantine_state": if record.state.quarantine == QuarantineState::Clear { "clear" } else { "quarantined" },
        "credential_kind": record.credential_kind,
        "credential_present": record.credential_kind != "none",
        "managed_locked": record.source_kind == "managed",
        "attachment_policy": record.policy.get("attachment_policy").cloned().unwrap_or_else(default_attachment_policy),
        "capability_snapshot_id": null,
        "generation": record.revision,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }))
}

fn registration_response(
    status: StatusCode,
    record: &McpRegistrationRecord,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(registration_json(record)?)).into_response();
    insert_etag(&mut response, record)?;
    Ok(response)
}

fn insert_etag(response: &mut Response, record: &McpRegistrationRecord) -> Result<(), ApiError> {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&registration_etag(record)).map_err(|_| ApiError::internal())?,
    );
    Ok(())
}

fn require_revision(headers: &HeaderMap, record: &McpRegistrationRecord) -> Result<(), ApiError> {
    if headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        != Some(registration_etag(record).as_str())
    {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "generation.stale",
            "The supplied generation is stale",
        ));
    }
    Ok(())
}

fn registration_etag(record: &McpRegistrationRecord) -> String {
    format!("\"fb-mcp-{}-{}\"", record.id, record.revision)
}

fn mcp_node_etag(node: &filebelt_database::NodeRecord) -> String {
    format!(
        "\"fb-node-{}-{}-{}\"",
        node.id, node.namespace_generation, node.acl_generation
    )
}

fn json_response_with_etag(
    status: StatusCode,
    value: Value,
    etag: &str,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

fn data_grant_json(grant: filebelt_database::mcp::McpDataGrantRecord) -> Value {
    let mut actions = vec!["use_mcp", "read_metadata"];
    if grant.allow_content {
        actions.push("read_content");
    }
    json!({
        "id": grant.id,
        "principal_id": grant.principal_id,
        "registration_id": grant.registration_id,
        "drive_id": grant.drive_id,
        "node_id": grant.resource_id,
        "version_id": grant.version_id,
        "actions": actions,
        "acl_generation": grant.acl_generation,
        "created_at": grant.created_at,
        "expires_at": grant.expires_at,
    })
}

async fn owned_registration(
    state: &AppState,
    principal: Uuid,
    id: Uuid,
) -> Result<McpRegistrationRecord, ApiError> {
    state
        .database
        .mcp_registration(state.tenant_id, principal, id)
        .await
        .map_err(Into::into)
}

fn require_enabled(state: &AppState) -> Result<&McpApiState, ApiError> {
    state
        .mcp
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "mcp.disabled", "MCP is not enabled"))
}

fn mcp_idempotency_fingerprint(route: &str, request: &Value) -> Result<[u8; 32], ApiError> {
    filebelt_mcp_policy::policy_json_digest(
        b"filebelt.mcp.idempotency.v1",
        &json!({"route":route,"request":request}),
    )
    .map_err(|_| ApiError::internal())
}

fn mcp_idempotent_response(
    outcome: McpIdempotentWrite,
    etag: Option<&str>,
) -> Result<Response, ApiError> {
    let record = match outcome {
        McpIdempotentWrite::Created(record) | McpIdempotentWrite::Replayed(record) => record,
        McpIdempotentWrite::KeyReused => {
            return Err(ApiError::conflict(
                "idempotency.key_reused",
                "The idempotency key was used for a different request",
            ));
        }
    };
    let status = u16::try_from(record.response_status)
        .ok()
        .and_then(|status| StatusCode::from_u16(status).ok())
        .ok_or_else(ApiError::internal)?;
    let mut response = (status, Json(record.response_body)).into_response();
    if let Some(etag) = etag {
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(etag).map_err(|_| ApiError::internal())?,
        );
    }
    Ok(response)
}

fn require_idempotency(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or_else(|| {
            ApiError::bad_request(
                "idempotency.key_invalid",
                "The idempotency key is missing or invalid",
            )
        })
}

fn normalize_capabilities(document: &Value) -> Result<Vec<Value>, ApiError> {
    let mut output = Vec::new();
    for (kind, list, key) in [
        ("tool", document.get("tools"), "tools"),
        ("resource", document.get("resources"), "resources"),
        ("prompt", document.get("prompts"), "prompts"),
    ] {
        let values = list
            .and_then(|value| value.get(key))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ApiError::bad_request(
                    "mcp.discovery.invalid",
                    "The MCP capability document is invalid",
                )
            })?;
        for value in values {
            output.push(json!({
                "kind": kind,
                "name": value.get("name").and_then(Value::as_str).unwrap_or_default(),
                "title": value.get("title"),
                "description": value.get("description"),
            "fingerprint": hex(&filebelt_mcp_policy::policy_json_digest(b"capability", value).map_err(|_| ApiError::internal())?),
                "read_only_hint": value.pointer("/annotations/readOnlyHint"),
                "risk": if kind == "tool" { "elevated" } else { "low" },
                "state": "new",
                "input_schema": value.get("inputSchema").cloned().unwrap_or_else(|| json!({})),
                "output_schema": value.get("outputSchema"),
            }));
        }
    }
    Ok(output)
}

fn default_attachment_policy() -> Value {
    json!({
        "allowed_mime_patterns": ["text/plain", "application/json"],
        "allowed_encodings": ["utf8", "base64"],
        "max_attachments": 4,
        "max_item_bytes": 1_048_576,
        "max_total_bytes": 4_194_304,
    })
}

fn database_transport(value: &str) -> Result<&'static str, ApiError> {
    match value {
        "streamable_http" => Ok("streamable_http"),
        "stdio_catalog" => Ok("stdio_catalog"),
        _ => Err(ApiError::bad_request(
            "mcp.transport.invalid",
            "The MCP transport is invalid",
        )),
    }
}

fn api_transport(value: &str) -> &str {
    value
}

fn validation_state(value: ValidationState) -> &'static str {
    match value {
        ValidationState::NeverTested => "untested",
        ValidationState::Valid => "valid",
        ValidationState::Invalid => "invalid",
    }
}

fn authentication_state(value: AuthenticationState) -> &'static str {
    match value {
        AuthenticationState::NoneRequired => "not_required",
        AuthenticationState::Required => "missing",
        AuthenticationState::Authorized => "ready",
        AuthenticationState::Failed => "expired",
    }
}

fn capability_state(value: CapabilityState) -> &'static str {
    match value {
        CapabilityState::Undiscovered => "undiscovered",
        CapabilityState::PendingReview => "review_required",
        CapabilityState::Approved => "reviewed",
        CapabilityState::Drifted => "changed",
    }
}

fn primitive_name(kind: &str) -> Result<&'static str, ApiError> {
    match kind {
        "resource" => Ok("resource_read"),
        "prompt" => Ok("prompt_get"),
        "tool" => Ok("tool_call"),
        _ => Err(ApiError::bad_request(
            "mcp.primitive.invalid",
            "The MCP primitive is invalid",
        )),
    }
}

fn primitive_enum(kind: &str) -> Result<McpPrimitive, ApiError> {
    match kind {
        "resource" => Ok(McpPrimitive::Resource),
        "prompt" => Ok(McpPrimitive::Prompt),
        "tool" => Ok(McpPrimitive::Tool),
        _ => Err(ApiError::bad_request(
            "mcp.primitive.invalid",
            "The MCP primitive is invalid",
        )),
    }
}

fn decode_hash(value: &str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64 {
        return Err(ApiError::bad_request(
            "mcp.fingerprint.invalid",
            "The MCP fingerprint is invalid",
        ));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, ApiError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ApiError::bad_request(
            "mcp.fingerprint.invalid",
            "The MCP fingerprint is invalid",
        )),
    }
}

fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
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

fn unix_time() -> Result<i64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_secs()
        .try_into()
        .map_err(|_| ApiError::internal())
}

fn rfc3339(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    let z = days + 719_468;
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
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

fn parse_rfc3339_utc(value: &str) -> Result<i64, ApiError> {
    if value.len() != 20
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.as_bytes().get(19) != Some(&b'Z')
    {
        return Err(ApiError::bad_request(
            "time.invalid",
            "The timestamp is invalid",
        ));
    }
    let number = |range: std::ops::Range<usize>| -> Result<i64, ApiError> {
        value
            .get(range)
            .and_then(|part| part.parse().ok())
            .ok_or_else(|| ApiError::bad_request("time.invalid", "The timestamp is invalid"))
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(ApiError::bad_request(
            "time.invalid",
            "The timestamp is invalid",
        ));
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let timestamp = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| ApiError::bad_request("time.invalid", "The timestamp is invalid"))?;
    if rfc3339(timestamp) != value {
        return Err(ApiError::bad_request(
            "time.invalid",
            "The timestamp is invalid",
        ));
    }
    Ok(timestamp)
}

fn mcp_unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "mcp.broker.unavailable",
        "The MCP broker is unavailable",
    )
}

const fn default_limit() -> i64 {
    50
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_strict_lowercase_hex() {
        assert_eq!(decode_hash(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(decode_hash(&"AB".repeat(32)).is_err());
        assert!(decode_hash("00").is_err());
    }

    #[test]
    fn json_pointer_bindings_reject_ambiguous_tildes() {
        let mut field = AttachmentFieldBinding {
            source: "content".into(),
            target_json_pointer: "/input/file~1body".into(),
            encoding: "base64".into(),
        };
        assert!(valid_field_binding(&field));
        field.target_json_pointer = "/input/file~2body".into();
        assert!(!valid_field_binding(&field));
    }

    #[test]
    fn attachment_media_patterns_are_bounded_tokens() {
        assert!(valid_mime_pattern("text/plain"));
        assert!(valid_mime_pattern("application/*"));
        assert!(mime_matches("text/*", "text/markdown"));
        assert!(!valid_mime_pattern("*/*"));
        assert!(!valid_mime_pattern("text/plain; charset=utf-8"));
    }

    #[test]
    fn attachment_generation_comparison_rejects_drive_only_staleness() {
        let expected = AuthorizationGrant {
            membership_generation: 7,
            drive_acl_generation: 11,
            namespace_generation: 13,
            resource_acl_generation: 17,
        };
        assert!(require_attachment_generations(expected, expected).is_ok());
        assert!(
            require_attachment_generations(
                expected,
                AuthorizationGrant {
                    drive_acl_generation: 12,
                    ..expected
                },
            )
            .is_err()
        );
    }

    #[test]
    fn tool_calls_never_receive_reusable_session_approval() {
        assert!(!session_approval_allowed("tool_call", Some(true)));
        assert!(!session_approval_allowed("tool_call", Some(false)));
        assert!(session_approval_allowed("resource_read", Some(true)));
        assert!(!session_approval_allowed("resource_read", None));
    }

    #[test]
    fn broker_body_limit_rejects_before_extending_the_aggregate() {
        let mut body = vec![0_u8; 7];
        append_bounded_broker_chunk(&mut body, &[1], 8).unwrap();
        assert_eq!(body.len(), 8);
        assert!(append_bounded_broker_chunk(&mut body, &[2], 8).is_err());
        assert_eq!(body.len(), 8);
    }

    #[test]
    fn semantic_input_is_bound_into_the_approval_digest() {
        let base = InvocationRequest {
            application_id: "filebelt.markdown".into(),
            registration_id: Uuid::new_v4(),
            capability: CapabilityReference {
                kind: "tool".into(),
                name: "rewrite".into(),
                fingerprint: "ab".repeat(32),
            },
            arguments: json!({"selection_start": 0, "selection_end": 3}),
            semantic_input: None,
            attachments: Vec::new(),
        };
        let mut first = base.clone();
        first.semantic_input = Some(SemanticMarkdownInput {
            format: "filebelt.markdown.semantic.v1".into(),
            node_id: Uuid::new_v4(),
            base_version_id: Uuid::new_v4(),
            markdown: "one".into(),
        });
        let mut second = first.clone();
        second.semantic_input.as_mut().unwrap().markdown = "two".into();

        assert_ne!(
            invocation_argument_digest(&base).unwrap(),
            invocation_argument_digest(&first).unwrap()
        );
        assert_ne!(
            invocation_argument_digest(&first).unwrap(),
            invocation_argument_digest(&second).unwrap()
        );
    }

    #[test]
    fn semantic_output_digest_requires_normalized_output_shape() {
        let expected = normalized_markdown_source_digest(b"# Proposed\n");
        assert_eq!(
            validated_semantic_output_digest(&json!({
                "format": "filebelt.markdown.semantic.v1",
                "markdown": "# Proposed\n",
            }))
            .unwrap(),
            expected
        );
        assert!(
            validated_semantic_output_digest(&json!({
                "format": "filebelt.markdown.semantic.v1",
                "node_id": Uuid::new_v4(),
                "markdown": "# Proposed\n",
            }))
            .is_err()
        );
        assert!(
            validated_semantic_output_digest(&json!({
                "format": "filebelt.markdown.semantic.v1",
                "markdown": "# Proposed\r\n",
            }))
            .is_err()
        );
    }
}

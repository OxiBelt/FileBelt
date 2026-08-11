// SPDX-License-Identifier: Apache-2.0

//! Self-service mount policy, credential, device, and session management.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, Router, routing};
use filebelt_control_protocol::{Config, DeploymentMode};
use filebelt_database::mount::{
    MountCredentialRecord, MountDeviceRecord, MountPolicyRecord, MountSessionSummary,
    NfsExportRecord, NfsExportState, NfsFeatureState, NfsFeatureStateRecord, NfsPosixGroupRecord,
    NfsPrincipalMapping, UpsertNfsPrincipalMappingInput,
};
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{AuthenticatedSession, authenticate, authenticate_mutation};
use crate::error::ApiError;

pub(crate) struct MountApiState {
    management: Client,
    credential_url: Url,
}

#[derive(Debug, Serialize)]
struct MountOverview {
    policies: Vec<MountPolicyRecord>,
    credentials: Vec<MountCredentialRecord>,
    devices: Vec<MountDeviceRecord>,
    sessions: Vec<MountSessionSummary>,
    drives: Vec<MountDrive>,
}

#[derive(Debug, Serialize)]
struct MountDrive {
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
#[serde(deny_unknown_fields)]
struct PolicyInput {
    enabled: bool,
    read_only: bool,
    allowed_drive_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateCredentialInput {
    protocol: String,
    read_only: bool,
    allowed_drive_ids: Vec<Uuid>,
    bound_device_id: Option<Uuid>,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct InternalCreateCredentialRequest<'a> {
    principal_id: Uuid,
    protocol: &'a str,
    read_only: bool,
    allowed_drive_ids: &'a [Uuid],
    bound_device_id: Option<Uuid>,
    expires_at: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateCredentialResponse {
    credential_id: Uuid,
    protocol: String,
    username: String,
    password: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NfsMappingInput {
    principal_id: Uuid,
    kerberos_principal: String,
    projected_uid: i64,
    projected_gid: i64,
    allowed_drive_ids: Vec<Uuid>,
    expected_generation: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NfsFeatureTransitionInput {
    target_state: String,
    expected_generation: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NfsExportRegistrationInput {
    drive_id: Uuid,
    export_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NfsExportStageInput {
    target_state: String,
    expected_generation: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NfsPosixGroupRegistrationInput {
    group_id: Uuid,
    posix_name: String,
    projected_gid: i64,
}

#[derive(Debug, Serialize)]
struct NfsAdminOverview {
    feature: NfsFeatureResponse,
    exports: Vec<NfsExportResponse>,
    posix_groups: Vec<NfsPosixGroupResponse>,
    mappings: Vec<NfsMappingResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
struct NfsFeatureResponse {
    state: String,
    generation: i64,
    desired_manifest_generation: i64,
    applied_manifest_generation: i64,
    manifest_applied: bool,
    applied_gateway_id: Option<String>,
    applied_gateway_epoch: Option<i64>,
    restore_generation: i64,
}

impl From<NfsFeatureStateRecord> for NfsFeatureResponse {
    fn from(record: NfsFeatureStateRecord) -> Self {
        let manifest_applied = record.applied_manifest_generation > 0
            && record.applied_manifest_generation == record.manifest_generation;
        Self {
            state: record.state.as_str().to_owned(),
            generation: record.generation,
            desired_manifest_generation: record.manifest_generation,
            applied_manifest_generation: record.applied_manifest_generation,
            manifest_applied,
            applied_gateway_id: record.applied_gateway_id,
            applied_gateway_epoch: record.applied_gateway_epoch,
            restore_generation: record.restore_generation,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct NfsExportResponse {
    drive_id: Uuid,
    export_id: i64,
    export_path: String,
    desired_state: String,
    applied_state: String,
    desired_generation: i64,
    applied_generation: i64,
    in_sync: bool,
}

impl From<NfsExportRecord> for NfsExportResponse {
    fn from(record: NfsExportRecord) -> Self {
        let in_sync = record.desired_state == record.applied_state
            && record.desired_generation == record.applied_generation;
        Self {
            drive_id: record.drive_id,
            export_id: record.export_id,
            export_path: record.export_path,
            desired_state: record.desired_state.as_str().to_owned(),
            applied_state: record.applied_state.as_str().to_owned(),
            desired_generation: record.desired_generation,
            applied_generation: record.applied_generation,
            in_sync,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct NfsPosixGroupResponse {
    group_id: Uuid,
    posix_name: String,
    projected_gid: i64,
}

impl From<NfsPosixGroupRecord> for NfsPosixGroupResponse {
    fn from(record: NfsPosixGroupRecord) -> Self {
        Self {
            group_id: record.group_id,
            posix_name: record.posix_name,
            projected_gid: record.projected_gid,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct NfsMappingResponse {
    kerberos_principal: String,
    principal_id: Uuid,
    credential_id: Uuid,
    projected_uid: i64,
    projected_gid: i64,
    generation: i64,
}

impl From<NfsPrincipalMapping> for NfsMappingResponse {
    fn from(record: NfsPrincipalMapping) -> Self {
        Self {
            kerberos_principal: record.kerberos_principal,
            principal_id: record.principal_id,
            credential_id: record.credential_id,
            projected_uid: record.projected_uid,
            projected_gid: record.projected_gid,
            generation: record.generation,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationQuery {
    expected_generation: i64,
}

pub(crate) fn initialize(config: &Config) -> Result<Option<Arc<MountApiState>>> {
    if !config.mounts.any_protocol_enabled() {
        return Ok(None);
    }
    let credential_url = config
        .mounts
        .management_url
        .clone()
        .ok_or_else(|| anyhow!("VFS management URL is absent"))?
        .join("internal/v1/mount/credentials")
        .context("VFS credential management URL is invalid")?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let mut identity_pem = std::fs::read(
            config
                .mounts
                .management_client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("VFS management client certificate is absent"))?,
        )?;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&std::fs::read(
            config
                .mounts
                .management_client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("VFS management client key is absent"))?,
        )?);
        let identity =
            Identity::from_pem(&identity_pem).context("VFS management identity is invalid")?;
        let ca = std::fs::read(
            config
                .mounts
                .management_server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("VFS management CA is absent"))?,
        )?;
        let certificates =
            Certificate::from_pem_bundle(&ca).context("VFS management CA is invalid")?;
        builder = builder.https_only(true).identity(identity);
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(Some(Arc::new(MountApiState {
        management: builder
            .build()
            .context("cannot initialize VFS management client")?,
        credential_url,
    })))
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/mounts", routing::get(get_overview))
        .route("/mounts/policies/{protocol}", routing::put(put_policy))
        .route("/mounts/credentials", routing::post(create_credential))
        .route(
            "/mounts/credentials/{credential_id}",
            routing::delete(revoke_credential),
        )
        .route("/admin/mounts/nfs", routing::get(get_nfs_overview))
        .route(
            "/admin/mounts/nfs/feature",
            routing::put(transition_nfs_feature),
        )
        .route(
            "/admin/mounts/nfs/exports",
            routing::post(register_nfs_export),
        )
        .route(
            "/admin/mounts/nfs/exports/{drive_id}",
            routing::put(stage_nfs_export),
        )
        .route(
            "/admin/mounts/nfs/posix-groups",
            routing::post(register_nfs_posix_group),
        )
        .route(
            "/admin/mounts/nfs/mappings",
            routing::get(list_nfs_mappings).post(upsert_nfs_mapping),
        )
        .route(
            "/admin/mounts/nfs/mappings/{credential_id}",
            routing::delete(revoke_nfs_mapping),
        )
}

async fn get_nfs_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NfsAdminOverview>, ApiError> {
    require_nfs_admin(&state, &headers, false).await?;
    let (feature, exports, posix_groups, mappings) = tokio::try_join!(
        state.database.nfs_feature_state(state.tenant_id),
        state.database.list_nfs_exports(state.tenant_id),
        state.database.list_nfs_posix_groups(state.tenant_id),
        state.database.list_nfs_principal_mappings(state.tenant_id),
    )?;
    Ok(Json(NfsAdminOverview {
        feature: feature.into(),
        exports: exports.into_iter().map(Into::into).collect(),
        posix_groups: posix_groups.into_iter().map(Into::into).collect(),
        mappings: mappings.into_iter().map(Into::into).collect(),
    }))
}

async fn transition_nfs_feature(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NfsFeatureTransitionInput>,
) -> Result<Json<NfsFeatureResponse>, ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    let target = parse_nfs_feature_state(&input.target_state)?;
    require_positive_generation(input.expected_generation)?;
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&input)?;
    const ROUTE: &str = "PUT /api/v1/admin/mounts/nfs/feature";
    if let Some((status, feature)) =
        crate::resources::replay::<NfsFeatureResponse>(&state, &session, ROUTE, key, &fingerprint)
            .await?
    {
        ensure_replay_status(status, StatusCode::OK)?;
        return Ok(Json(feature));
    }
    let feature = state
        .database
        .transition_nfs_feature_state(
            state.tenant_id,
            session.record.principal_id,
            input.expected_generation,
            target,
        )
        .await?
        .into();
    let feature = crate::resources::store_idempotent(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
        StatusCode::OK,
        &feature,
    )
    .await?;
    Ok(Json(feature))
}

async fn register_nfs_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NfsExportRegistrationInput>,
) -> Result<(StatusCode, Json<NfsExportResponse>), ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    if input.export_id <= 0 {
        return Err(ApiError::bad_request(
            "mount.nfs.export_invalid",
            "The NFS export request is invalid",
        ));
    }
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&input)?;
    const ROUTE: &str = "POST /api/v1/admin/mounts/nfs/exports";
    if let Some((status, export)) =
        crate::resources::replay::<NfsExportResponse>(&state, &session, ROUTE, key, &fingerprint)
            .await?
    {
        return Ok((
            StatusCode::from_u16(status).map_err(|_| ApiError::internal())?,
            Json(export),
        ));
    }
    validate_drive_selection(&state, &session, &[input.drive_id]).await?;
    let export = state
        .database
        .register_nfs_export(
            state.tenant_id,
            session.record.principal_id,
            input.drive_id,
            input.export_id,
        )
        .await?
        .into();
    let export = crate::resources::store_idempotent(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
        StatusCode::CREATED,
        &export,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(export)))
}

async fn stage_nfs_export(
    State(state): State<AppState>,
    Path(drive_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<NfsExportStageInput>,
) -> Result<Json<NfsExportResponse>, ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    let target = parse_nfs_export_state(&input.target_state)?;
    require_positive_generation(input.expected_generation)?;
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&(drive_id, &input))?;
    const ROUTE: &str = "PUT /api/v1/admin/mounts/nfs/exports/{drive_id}";
    if let Some((status, export)) =
        crate::resources::replay::<NfsExportResponse>(&state, &session, ROUTE, key, &fingerprint)
            .await?
    {
        ensure_replay_status(status, StatusCode::OK)?;
        return Ok(Json(export));
    }
    validate_drive_selection(&state, &session, &[drive_id]).await?;
    let export = state
        .database
        .stage_nfs_export(
            state.tenant_id,
            session.record.principal_id,
            drive_id,
            input.expected_generation,
            target,
        )
        .await?
        .into();
    let export = crate::resources::store_idempotent(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
        StatusCode::OK,
        &export,
    )
    .await?;
    Ok(Json(export))
}

async fn register_nfs_posix_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NfsPosixGroupRegistrationInput>,
) -> Result<(StatusCode, Json<NfsPosixGroupResponse>), ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    validate_nfs_posix_group(&input.posix_name, input.projected_gid)?;
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&input)?;
    const ROUTE: &str = "POST /api/v1/admin/mounts/nfs/posix-groups";
    if let Some((status, group)) = crate::resources::replay::<NfsPosixGroupResponse>(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
    )
    .await?
    {
        return Ok((
            StatusCode::from_u16(status).map_err(|_| ApiError::internal())?,
            Json(group),
        ));
    }
    let group = state
        .database
        .register_nfs_posix_group(
            state.tenant_id,
            session.record.principal_id,
            input.group_id,
            &input.posix_name,
            input.projected_gid,
        )
        .await?
        .into();
    let group = crate::resources::store_idempotent(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
        StatusCode::CREATED,
        &group,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(group)))
}

async fn list_nfs_mappings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NfsMappingResponse>>, ApiError> {
    require_nfs_admin(&state, &headers, false).await?;
    Ok(Json(
        state
            .database
            .list_nfs_principal_mappings(state.tenant_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

async fn upsert_nfs_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NfsMappingInput>,
) -> Result<(StatusCode, Json<NfsMappingResponse>), ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    validate_nfs_kerberos_principal(&input.kerberos_principal, configured_nfs_realm(&state)?)?;
    validate_nfs_mapping_input(&input)?;
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&input)?;
    const ROUTE: &str = "POST /api/v1/admin/mounts/nfs/mappings";
    if let Some((status, mapping)) =
        crate::resources::replay::<NfsMappingResponse>(&state, &session, ROUTE, key, &fingerprint)
            .await?
    {
        return Ok((
            StatusCode::from_u16(status).map_err(|_| ApiError::internal())?,
            Json(mapping),
        ));
    }
    validate_drive_selection(&state, &session, &input.allowed_drive_ids).await?;
    let created = input.expected_generation.is_none();
    let mapping: NfsMappingResponse = state
        .database
        .upsert_nfs_principal_mapping(&UpsertNfsPrincipalMappingInput {
            tenant_id: state.tenant_id,
            actor_principal_id: session.record.principal_id,
            principal_id: input.principal_id,
            kerberos_principal: &input.kerberos_principal,
            projected_uid: input.projected_uid,
            projected_gid: input.projected_gid,
            allowed_drive_ids: &input.allowed_drive_ids,
            expected_generation: input.expected_generation,
        })
        .await?
        .into();
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mapping = crate::resources::store_idempotent(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
        status,
        &mapping,
    )
    .await?;
    Ok((status, Json(mapping)))
}

async fn revoke_nfs_mapping(
    State(state): State<AppState>,
    Path(credential_id): Path<Uuid>,
    Query(query): Query<GenerationQuery>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    require_positive_generation(query.expected_generation)?;
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&(credential_id, query.expected_generation))?;
    const ROUTE: &str = "DELETE /api/v1/admin/mounts/nfs/mappings/{credential_id}";
    if let Some((status, ())) =
        crate::resources::replay::<()>(&state, &session, ROUTE, key, &fingerprint).await?
    {
        return StatusCode::from_u16(status).map_err(|_| ApiError::internal());
    }
    state
        .database
        .revoke_nfs_principal_mapping(
            state.tenant_id,
            session.record.principal_id,
            credential_id,
            query.expected_generation,
        )
        .await?;
    crate::resources::store_idempotent(
        &state,
        &session,
        ROUTE,
        key,
        &fingerprint,
        StatusCode::NO_CONTENT,
        &(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_nfs_admin(
    state: &AppState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<AuthenticatedSession, ApiError> {
    if !state.config.mounts.nfs.enabled {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mount.nfs.disabled",
            "NFS administration is not enabled for this deployment",
        ));
    }
    configured_nfs_realm(state)?;
    let session = if mutation {
        authenticate_mutation(state, headers).await?
    } else {
        authenticate(state, headers).await?
    };
    if !session.record.tenant_admin || !session.record.reauthenticated_recently {
        return Err(ApiError::forbidden(
            "admin.reauthentication_required",
            "Recent tenant administrator authentication is required",
        ));
    }
    Ok(session)
}

fn configured_nfs_realm(state: &AppState) -> Result<&str, ApiError> {
    state
        .config
        .mounts
        .nfs
        .realm
        .as_deref()
        .filter(|realm| !realm.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "mount.nfs.configuration_invalid",
                "NFS administration is not configured for this deployment",
            )
        })
}

fn parse_nfs_feature_state(value: &str) -> Result<NfsFeatureState, ApiError> {
    match value {
        "disabled" => Ok(NfsFeatureState::Disabled),
        "preflight" => Ok(NfsFeatureState::Preflight),
        "active" => Ok(NfsFeatureState::Active),
        "draining" => Ok(NfsFeatureState::Draining),
        _ => Err(ApiError::bad_request(
            "mount.nfs.feature_state_invalid",
            "The NFS feature target state is invalid",
        )),
    }
}

fn parse_nfs_export_state(value: &str) -> Result<NfsExportState, ApiError> {
    match value {
        "disabled" => Ok(NfsExportState::Disabled),
        "active" => Ok(NfsExportState::Active),
        "draining" => Ok(NfsExportState::Draining),
        _ => Err(ApiError::bad_request(
            "mount.nfs.export_state_invalid",
            "The NFS export target state is invalid",
        )),
    }
}

fn require_positive_generation(generation: i64) -> Result<(), ApiError> {
    if generation <= 0 {
        return Err(ApiError::bad_request(
            "mount.nfs.generation_invalid",
            "The NFS generation precondition is invalid",
        ));
    }
    Ok(())
}

fn ensure_replay_status(actual: u16, expected: StatusCode) -> Result<(), ApiError> {
    if actual != expected.as_u16() {
        return Err(ApiError::internal());
    }
    Ok(())
}

fn validate_nfs_mapping_input(input: &NfsMappingInput) -> Result<(), ApiError> {
    if !valid_nfs_projected_id(input.projected_uid)
        || !valid_nfs_projected_id(input.projected_gid)
        || input.allowed_drive_ids.is_empty()
        || input.allowed_drive_ids.len() > 256
        || input
            .allowed_drive_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != input.allowed_drive_ids.len()
        || input.expected_generation.is_some_and(|value| value <= 0)
    {
        return Err(ApiError::bad_request(
            "mount.nfs.mapping_invalid",
            "The NFS mapping request is invalid",
        ));
    }
    Ok(())
}

fn validate_nfs_kerberos_principal(principal: &str, realm: &str) -> Result<(), ApiError> {
    let invalid = || {
        ApiError::bad_request(
            "mount.nfs.kerberos_principal_invalid",
            "The Kerberos principal must be an unescaped user in the configured realm",
        )
    };
    if principal.is_empty()
        || principal.len() > 512
        || principal
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '/' | '\\'))
    {
        return Err(invalid());
    }
    let Some((user, actual_realm)) = principal.split_once('@') else {
        return Err(invalid());
    };
    if user.is_empty()
        || user.eq_ignore_ascii_case("root")
        || actual_realm != realm
        || actual_realm.contains('@')
        || !valid_nfs_posix_name(&user.to_ascii_lowercase())
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_nfs_posix_group(posix_name: &str, projected_gid: i64) -> Result<(), ApiError> {
    if !valid_nfs_posix_name(posix_name) || !valid_nfs_projected_id(projected_gid) {
        return Err(ApiError::bad_request(
            "mount.nfs.posix_group_invalid",
            "The NFS POSIX group request is invalid",
        ));
    }
    Ok(())
}

fn valid_nfs_projected_id(value: i64) -> bool {
    const MAX_PROJECTED_ID: i64 = 4_294_967_294;
    const NOBODY_PROJECTED_ID: i64 = 65_534;
    (1..=MAX_PROJECTED_ID).contains(&value) && value != NOBODY_PROJECTED_ID
}

fn valid_nfs_posix_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=255).contains(&bytes.len())
        && matches!(bytes[0], b'a'..=b'z' | b'_')
        && bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

async fn get_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MountOverview>, ApiError> {
    require_enabled(&state)?;
    let session = authenticate(&state, &headers).await?;
    let principal_id = session.record.principal_id;
    let (policies, credentials, devices, sessions, drives) = tokio::try_join!(
        state
            .database
            .list_mount_policies(state.tenant_id, principal_id),
        state
            .database
            .list_mount_credentials(state.tenant_id, principal_id),
        state
            .database
            .list_mount_devices(state.tenant_id, principal_id),
        state
            .database
            .list_mount_sessions(state.tenant_id, principal_id),
        state.database.list_drives(state.tenant_id, principal_id),
    )?;
    Ok(Json(MountOverview {
        policies,
        credentials,
        devices,
        sessions,
        drives: drives
            .into_iter()
            .map(|drive| MountDrive {
                id: drive.id,
                kind: drive.kind,
                display_name: drive.display_name,
                owner_display_name: drive.owner_display_name,
                root_id: drive.root_id,
                namespace_generation: drive.namespace_generation,
                acl_generation: drive.acl_generation,
                quota_bytes: drive.quota_bytes,
                used_physical_bytes: drive.used_physical_bytes,
                reserved_bytes: drive.reserved_bytes,
            })
            .collect(),
    }))
}

async fn put_policy(
    State(state): State<AppState>,
    Path(protocol): Path<String>,
    headers: HeaderMap,
    Json(input): Json<PolicyInput>,
) -> Result<Json<MountPolicyRecord>, ApiError> {
    require_enabled(&state)?;
    let session = authenticate_mutation(&state, &headers).await?;
    validate_protocol(&state.config, &protocol)?;
    require_read_only(input.read_only)?;
    validate_drive_selection(&state, &session, &input.allowed_drive_ids).await?;
    if input.enabled && input.allowed_drive_ids.is_empty() {
        return Err(ApiError::bad_request(
            "mount.drive_selection_required",
            "An enabled mount policy must select at least one accessible drive",
        ));
    }
    Ok(Json(
        state
            .database
            .upsert_mount_policy(
                state.tenant_id,
                session.record.principal_id,
                &protocol,
                input.enabled,
                input.read_only,
                &input.allowed_drive_ids,
            )
            .await?,
    ))
}

async fn create_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateCredentialInput>,
) -> Result<(StatusCode, Json<CreateCredentialResponse>), ApiError> {
    let mounts = require_enabled(&state)?;
    let session = require_recent_mutation(&state, &headers).await?;
    validate_protocol(&state.config, &input.protocol)?;
    require_read_only(input.read_only)?;
    validate_drive_selection(&state, &session, &input.allowed_drive_ids).await?;
    if input.allowed_drive_ids.is_empty() {
        return Err(ApiError::bad_request(
            "mount.drive_selection_required",
            "A mount credential must select at least one accessible drive",
        ));
    }
    let response = mounts
        .management
        .post(mounts.credential_url.clone())
        .json(&InternalCreateCredentialRequest {
            principal_id: session.record.principal_id,
            protocol: &input.protocol,
            read_only: input.read_only,
            allowed_drive_ids: &input.allowed_drive_ids,
            bound_device_id: input.bound_device_id,
            expires_at: &input.expires_at,
        })
        .send()
        .await
        .map_err(|_| unavailable())?;
    match response.status() {
        StatusCode::CREATED => {
            let created = response
                .json::<CreateCredentialResponse>()
                .await
                .map_err(|_| unavailable())?;
            Ok((StatusCode::CREATED, Json(created)))
        }
        StatusCode::BAD_REQUEST => Err(ApiError::bad_request(
            "mount.credential_invalid",
            "The mount credential request is invalid",
        )),
        StatusCode::CONFLICT => Err(ApiError::conflict(
            "mount.policy_conflict",
            "The mount policy or device binding rejected this credential",
        )),
        _ => Err(unavailable()),
    }
}

async fn revoke_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let session = require_recent_mutation(&state, &headers).await?;
    state
        .database
        .revoke_mount_credential(
            state.tenant_id,
            session.record.principal_id,
            credential_id,
            "user_revoked",
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn require_enabled(state: &AppState) -> Result<&Arc<MountApiState>, ApiError> {
    state.mounts.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mount.disabled",
            "Mount access is not enabled for this deployment",
        )
    })
}

async fn require_recent_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let session = authenticate_mutation(state, headers).await?;
    if !session.record.reauthenticated_recently {
        return Err(ApiError::forbidden(
            "mount.reauthentication_required",
            "Recent OIDC authentication is required for mount credentials",
        ));
    }
    Ok(session)
}

fn validate_protocol(config: &Config, protocol: &str) -> Result<(), ApiError> {
    match protocol {
        "smb" if config.mounts.smb.enabled => Ok(()),
        "ftps" if config.mounts.ftp_ftps.enabled => Ok(()),
        "smb" | "ftps" => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mount.protocol_disabled",
            "The requested mount protocol is not enabled for this deployment",
        )),
        _ => Err(ApiError::bad_request(
            "mount.protocol_invalid",
            "The mount protocol must be smb or ftps",
        )),
    }
}

fn require_read_only(read_only: bool) -> Result<(), ApiError> {
    if !read_only {
        return Err(ApiError::bad_request(
            "mount.write_not_supported",
            "Mount gateways are read-only in this release",
        ));
    }
    Ok(())
}

async fn validate_drive_selection(
    state: &AppState,
    session: &AuthenticatedSession,
    selected: &[Uuid],
) -> Result<(), ApiError> {
    if selected.len() > 256
        || selected.iter().copied().collect::<HashSet<_>>().len() != selected.len()
    {
        return Err(ApiError::bad_request(
            "mount.drive_selection_invalid",
            "The mount drive selection is invalid",
        ));
    }
    let accessible = state
        .database
        .list_drives(state.tenant_id, session.record.principal_id)
        .await?
        .into_iter()
        .map(|drive| drive.id)
        .collect::<HashSet<_>>();
    if !selected.iter().all(|drive| accessible.contains(drive)) {
        return Err(ApiError::forbidden(
            "mount.drive_selection_denied",
            "The mount drive selection contains an inaccessible drive",
        ));
    }
    Ok(())
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "mount.management_unavailable",
        "Mount credential management is temporarily unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfs_kerberos_mapping_accepts_only_users_in_the_exact_realm() {
        for valid in [
            "alice@EXAMPLE.TEST",
            "Alice_1@EXAMPLE.TEST",
            "_sync@EXAMPLE.TEST",
        ] {
            assert!(
                validate_nfs_kerberos_principal(valid, "EXAMPLE.TEST").is_ok(),
                "expected {valid} to be accepted"
            );
        }
        for invalid in [
            "root@EXAMPLE.TEST",
            "ROOT@EXAMPLE.TEST",
            "nfs/server.example.test@EXAMPLE.TEST",
            "alice/admin@EXAMPLE.TEST",
            "alice\\@EXAMPLE.TEST",
            "alice@OTHER.TEST",
            "alice@example.test",
            "alice@@EXAMPLE.TEST",
            "alice @EXAMPLE.TEST",
            "alice",
            "9alice@EXAMPLE.TEST",
        ] {
            assert!(
                validate_nfs_kerberos_principal(invalid, "EXAMPLE.TEST").is_err(),
                "expected {invalid} to be rejected"
            );
        }
    }

    #[test]
    fn nfs_mapping_validation_bounds_ids_generations_and_unique_drives() {
        let drive_id = Uuid::new_v4();
        let mut input = NfsMappingInput {
            principal_id: Uuid::new_v4(),
            kerberos_principal: "alice@EXAMPLE.TEST".to_owned(),
            projected_uid: 1000,
            projected_gid: 1000,
            allowed_drive_ids: vec![drive_id],
            expected_generation: Some(1),
        };
        assert!(validate_nfs_mapping_input(&input).is_ok());
        input.allowed_drive_ids.push(drive_id);
        assert!(validate_nfs_mapping_input(&input).is_err());
        input.allowed_drive_ids = Vec::new();
        assert!(validate_nfs_mapping_input(&input).is_err());
        input.allowed_drive_ids = vec![Uuid::new_v4()];
        input.expected_generation = Some(0);
        assert!(validate_nfs_mapping_input(&input).is_err());
        input.expected_generation = None;
        input.projected_uid = 65_534;
        assert!(validate_nfs_mapping_input(&input).is_err());
    }

    #[test]
    fn nfs_overview_distinguishes_desired_and_applied_state() {
        let pending: NfsFeatureResponse = NfsFeatureStateRecord {
            state: NfsFeatureState::Preflight,
            generation: 2,
            manifest_generation: 4,
            applied_manifest_generation: 3,
            applied_manifest_digest: Some([7; 32]),
            applied_gateway_id: Some("gateway-1".to_owned()),
            applied_gateway_epoch: Some(2),
            restore_generation: 1,
        }
        .into();
        assert_eq!(pending.state, "preflight");
        assert_eq!(pending.desired_manifest_generation, 4);
        assert_eq!(pending.applied_manifest_generation, 3);
        assert!(!pending.manifest_applied);

        let export: NfsExportResponse = NfsExportRecord {
            drive_id: Uuid::new_v4(),
            export_id: 1,
            export_path: "/exports/1".to_owned(),
            desired_state: NfsExportState::Draining,
            applied_state: NfsExportState::Active,
            desired_generation: 3,
            applied_generation: 2,
        }
        .into();
        assert_eq!(export.desired_state, "draining");
        assert_eq!(export.applied_state, "active");
        assert!(!export.in_sync);
    }

    #[test]
    fn nfs_mutations_are_idempotent_and_gateway_reconciliation_is_not_exposed() {
        let source = include_str!("mounts.rs");
        for route in [
            ".route(\"/admin/mounts/nfs\", routing::get(get_nfs_overview))",
            "\"/admin/mounts/nfs/feature\"",
            "\"/admin/mounts/nfs/exports\"",
            "\"/admin/mounts/nfs/exports/{drive_id}\"",
            "\"/admin/mounts/nfs/posix-groups\"",
            "\"/admin/mounts/nfs/mappings\"",
        ] {
            assert!(source.contains(route), "missing route {route}");
        }
        for (handler, next_handler) in [
            (
                "async fn transition_nfs_feature",
                "async fn register_nfs_export",
            ),
            ("async fn register_nfs_export", "async fn stage_nfs_export"),
            (
                "async fn stage_nfs_export",
                "async fn register_nfs_posix_group",
            ),
            (
                "async fn register_nfs_posix_group",
                "async fn list_nfs_mappings",
            ),
            ("async fn upsert_nfs_mapping", "async fn revoke_nfs_mapping"),
            ("async fn revoke_nfs_mapping", "async fn require_nfs_admin"),
        ] {
            let handler_source = source
                .split_once(handler)
                .expect("NFS mutation handler exists")
                .1
                .split_once(next_handler)
                .expect("next NFS handler exists")
                .0;
            assert!(handler_source.contains("idempotency_key(&headers)"));
            assert!(handler_source.contains("replay::<"));
            assert!(handler_source.contains("store_idempotent("));
        }
        let reconciliation_method = ["reconcile", "nfs", "export", "manifest("].join("_");
        assert!(!source.contains(&reconciliation_method));
        let retired_gate = ["phase8", "is", "active("].join("_");
        assert!(!source.contains(&retired_gate));
    }
}

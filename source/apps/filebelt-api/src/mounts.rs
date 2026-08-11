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
        .route(
            "/admin/mounts/nfs/mappings",
            routing::get(list_nfs_mappings).post(upsert_nfs_mapping),
        )
        .route(
            "/admin/mounts/nfs/mappings/{credential_id}",
            routing::delete(revoke_nfs_mapping),
        )
}

async fn list_nfs_mappings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NfsPrincipalMapping>>, ApiError> {
    require_nfs_admin(&state, &headers, false).await?;
    Ok(Json(
        state
            .database
            .list_nfs_principal_mappings(state.tenant_id)
            .await?,
    ))
}

async fn upsert_nfs_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NfsMappingInput>,
) -> Result<(StatusCode, Json<NfsPrincipalMapping>), ApiError> {
    let session = require_nfs_admin(&state, &headers, true).await?;
    let key = crate::resources::idempotency_key(&headers)?;
    let fingerprint = crate::resources::fingerprint(&input)?;
    const ROUTE: &str = "POST /api/v1/admin/mounts/nfs/mappings";
    if let Some((status, mapping)) =
        crate::resources::replay::<NfsPrincipalMapping>(&state, &session, ROUTE, key, &fingerprint)
            .await?
    {
        return Ok((
            StatusCode::from_u16(status).map_err(|_| ApiError::internal())?,
            Json(mapping),
        ));
    }
    if input.allowed_drive_ids.len() > 256
        || input
            .allowed_drive_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != input.allowed_drive_ids.len()
    {
        return Err(ApiError::bad_request(
            "mount.nfs.mapping_invalid",
            "The NFS mapping drive selection is invalid",
        ));
    }
    let created = input.expected_generation.is_none();
    let mapping = state
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
        .await?;
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
    let active = state.database.phase8_is_active(state.tenant_id).await?;
    if !active {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "phase8.inactive",
            "Phase 8 admission is not active",
        ));
    }
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

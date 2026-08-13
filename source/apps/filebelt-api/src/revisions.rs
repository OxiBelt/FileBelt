// SPDX-License-Identifier: Apache-2.0

//! Public text-history comparison facade.
//!
//! Browser requests stop here.  The API evaluates READ_CONTENT, persists its
//! session-bound authorization generations, and forwards only that fence to
//! the internal revision coordinator.  It never learns the Git adapter
//! address or protocol.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, Router, routing};
use filebelt_control_protocol::{Config, DeploymentMode};
use filebelt_domain::Action;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::authenticate;
use crate::error::ApiError;
use crate::policy::authorize_session_bound;

const MAX_COORDINATOR_RESPONSE_BYTES: u64 = 8 * 1024 * 1024 + 65_536;

pub(crate) struct RevisionApiState {
    client: Client,
    compare_url: Url,
}

pub(crate) fn initialize(config: &Config) -> Result<Option<Arc<RevisionApiState>>> {
    if !config.revisions.enabled {
        return Ok(None);
    }
    let compare_url = config
        .revisions
        .url
        .clone()
        .ok_or_else(|| anyhow!("revision service URL is absent"))?
        .join("internal/v1/revision/compare")
        .context("revision comparison URL is invalid")?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(6));
    if config.deployment.mode == DeploymentMode::Kubernetes {
        let certificate = std::fs::read(
            config
                .revisions
                .client_certificate_chain_file
                .as_ref()
                .ok_or_else(|| anyhow!("revision client certificate is absent"))?,
        )?;
        let private_key = std::fs::read(
            config
                .revisions
                .client_private_key_file
                .as_ref()
                .ok_or_else(|| anyhow!("revision client key is absent"))?,
        )?;
        let mut identity_pem = certificate;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&private_key);
        let identity =
            Identity::from_pem(&identity_pem).context("revision client identity is invalid")?;
        let ca = std::fs::read(
            config
                .revisions
                .server_ca_file
                .as_ref()
                .ok_or_else(|| anyhow!("revision service CA is absent"))?,
        )?;
        let certificates =
            Certificate::from_pem_bundle(&ca).context("revision service CA is invalid")?;
        builder = builder
            .https_only(true)
            .tls_built_in_root_certs(false)
            .identity(identity);
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(Some(Arc::new(RevisionApiState {
        client: builder
            .build()
            .context("cannot initialize revision client")?,
        compare_url,
    })))
}

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/drives/{drive_id}/nodes/{node_id}/versions/{base_version_id}/compare/{target_version_id}",
        routing::get(compare_versions),
    )
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparisonResponse {
    algorithm: String,
    context_lines: u8,
    base_version_id: Uuid,
    target_version_id: Uuid,
    base_final_newline: bool,
    target_final_newline: bool,
    hunks: Vec<DiffHunk>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiffHunk {
    base_start: u64,
    base_lines: u64,
    target_start: u64,
    target_lines: u64,
    lines: Vec<DiffLine>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiffLine {
    kind: String,
    base_line: Option<u64>,
    target_line: Option<u64>,
    text: String,
}

async fn compare_versions(
    State(state): State<AppState>,
    Path((drive_id, node_id, base_version_id, target_version_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
) -> Result<Json<ComparisonResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid(&drive_id)?;
    let node_id = parse_uuid(&node_id)?;
    let base_version_id = parse_uuid(&base_version_id)?;
    let target_version_id = parse_uuid(&target_version_id)?;
    let grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    let revision = state.revisions.as_ref().ok_or_else(unavailable)?;
    let mut response = revision
        .client
        .post(revision.compare_url.clone())
        .json(&CompareCommand {
            tenant_id: state.tenant_id,
            user_id: session.record.user_id,
            principal_id: session.record.principal_id,
            session_id: session.record.session_id,
            drive_id,
            node_id,
            base_version_id,
            target_version_id,
            membership_generation: i64::try_from(grant.membership_generation)
                .map_err(|_| ApiError::internal())?,
            drive_acl_generation: i64::try_from(grant.drive_acl_generation)
                .map_err(|_| ApiError::internal())?,
            namespace_generation: i64::try_from(grant.namespace_generation)
                .map_err(|_| ApiError::internal())?,
            resource_acl_generation: i64::try_from(grant.resource_acl_generation)
                .map_err(|_| ApiError::internal())?,
        })
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "revision coordinator request failed");
            unavailable()
        })?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_COORDINATOR_RESPONSE_BYTES)
    {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "revision.limit_exceeded",
            "The comparison exceeds its atomic size limit",
        ));
    }
    let status = response.status();
    match status {
        StatusCode::OK => {
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
                let next = bytes
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(unavailable)?;
                if u64::try_from(next).map_err(|_| unavailable())? > MAX_COORDINATOR_RESPONSE_BYTES
                {
                    return Err(ApiError::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "revision.limit_exceeded",
                        "The comparison exceeds its atomic size limit",
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            let comparison =
                serde_json::from_slice::<ComparisonResponse>(&bytes).map_err(|_| unavailable())?;
            if comparison.algorithm != "git-histogram-v1"
                || comparison.context_lines != 3
                || comparison.base_version_id != base_version_id
                || comparison.target_version_id != target_version_id
            {
                return Err(unavailable());
            }
            Ok(Json(comparison))
        }
        StatusCode::PAYLOAD_TOO_LARGE => Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "revision.limit_exceeded",
            "The comparison exceeds its atomic size limit",
        )),
        StatusCode::TOO_MANY_REQUESTS => Err(ApiError::admission_limited(
            "revision.admission_limited",
            "Text revision comparison is temporarily at capacity",
        )),
        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => Err(ApiError::not_found()),
        _ => Err(unavailable()),
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    let uuid = Uuid::parse_str(value).map_err(|_| ApiError::not_found())?;
    if uuid.get_version_num() != 4 {
        return Err(ApiError::not_found());
    }
    Ok(uuid)
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "revision.unavailable",
        "Text revision comparison is temporarily unavailable",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn comparison_path_is_the_public_openapi_path() {
        let route = "/drives/{drive_id}/nodes/{node_id}/versions/{base_version_id}/compare/{target_version_id}";
        assert!(route.contains("versions/{base_version_id}/compare/{target_version_id}"));
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Compatibility-state HTTP surface for directory-level Git repositories.
//!
//! Every endpoint is compatibility-disabled.  The API has no runtime grant to
//! create or activate a repository, and read handlers remain unavailable until
//! the PostgreSQL repository store provides root-scoped repository and
//! deterministic ref-list methods.  Handlers must not introduce local SQL or
//! infer a repository from a mutation result.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Json, Router, routing};
use filebelt_database::repository::RepositoryObjectFormat;
use filebelt_domain::Action;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::{authenticate, authenticate_mutation};
use crate::error::ApiError;
use crate::policy::{authorize, authorize_session_bound};
use crate::resources::{fingerprint, idempotency_key, parse_uuid_v4, require_same_generations};

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/drives/{drive_id}/nodes/{node_id}/repository",
            routing::post(create_repository).get(get_repository),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/repository/refs",
            routing::get(list_repository_refs),
        )
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateRepositoryRequest {
    object_format: String,
}

async fn create_repository(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateRepositoryRequest>,
) -> Result<Response, ApiError> {
    let session = authenticate_mutation(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let object_format = parse_object_format(&request.object_format)?;
    let request_fingerprint = fingerprint(&(drive_id, node_id, &request))?;

    let manage_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ManageRepository,
    )
    .await?;
    let attributes_grant = authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::SetAttributes,
    )
    .await?;
    require_same_generations(manage_grant, attributes_grant)?;

    let _ = (key, object_format, request_fingerprint);
    repository_write_unavailable()
}

async fn get_repository(
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
        Action::ReadRepository,
    )
    .await?;
    repository_read_unavailable()
}

async fn list_repository_refs(
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
        Action::ReadRepository,
    )
    .await?;
    repository_read_unavailable()
}

/// Fails closed until `Database` exposes both of these handler-facing
/// operations, each tenant- and root-scoped: `managed_repository_by_root` and
/// `list_managed_repository_refs` with a deterministic opaque cursor.
///
/// Keeping this seam avoids a partial repository lookup that could disclose a
/// repository or ref to a caller who was authorized only for another root.
fn repository_read_unavailable() -> Result<Response, ApiError> {
    Err(ApiError::remediation_in_progress(
        "repository.compatibility_disabled",
        "Directory Git repository reads are not activated",
    ))
}

/// The request's idempotency key and fingerprint are parsed before this fence,
/// so enabling the operation later cannot weaken its request contract.  The
/// API deliberately does not persist an idempotency result for a disabled
/// operation.
fn repository_write_unavailable() -> Result<Response, ApiError> {
    Err(ApiError::remediation_in_progress(
        "repository.compatibility_disabled",
        "Directory Git repository creation is not activated",
    ))
}

fn parse_object_format(value: &str) -> Result<RepositoryObjectFormat, ApiError> {
    match value {
        "sha1" => Ok(RepositoryObjectFormat::Sha1),
        "sha256" => Ok(RepositoryObjectFormat::Sha256),
        _ => Err(ApiError::bad_request(
            "repository.object_format_invalid",
            "The repository object format must be sha1 or sha256",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_object_format;
    use filebelt_database::repository::RepositoryObjectFormat;

    #[test]
    fn repository_object_formats_are_explicit() {
        assert_eq!(
            parse_object_format("sha1").unwrap(),
            RepositoryObjectFormat::Sha1
        );
        assert_eq!(
            parse_object_format("sha256").unwrap(),
            RepositoryObjectFormat::Sha256
        );
        assert!(parse_object_format("sha512").is_err());
    }

    #[test]
    fn repository_handlers_authorize_before_observing_repository_state() {
        let source = include_str!("repositories.rs");
        let create = source
            .split_once("async fn create_repository")
            .expect("create handler exists")
            .1
            .split_once("async fn get_repository")
            .expect("get handler follows create")
            .0;
        for required in [
            "authenticate_mutation(&state, &headers)",
            "idempotency_key(&headers)",
            "Action::ManageRepository",
            "Action::SetAttributes",
            "require_same_generations(manage_grant, attributes_grant)?",
            "repository_write_unavailable()",
        ] {
            assert!(create.contains(required), "missing {required}");
        }
        let authorization = create
            .find("Action::ManageRepository")
            .expect("manage authorization exists");
        let unavailable = create
            .find("repository_write_unavailable()")
            .expect("compatibility seam exists");
        assert!(authorization < unavailable);

        for handler in ["async fn get_repository", "async fn list_repository_refs"] {
            let tail = source.split_once(handler).expect("read handler exists").1;
            let authorization = tail
                .find("Action::ReadRepository")
                .expect("repository read authorization exists");
            let unavailable = tail
                .find("repository_read_unavailable()")
                .expect("compatibility seam exists");
            assert!(authorization < unavailable);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Media-preview admission and status. Derivative bytes remain behind the
//! scoped I/O boundary and this API never accepts FFmpeg options or paths.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, Router, routing};
use filebelt_database::media::{AdmitMediaPreviewInput, MediaPreviewRecord};
use filebelt_domain::Action;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{authenticate, authenticate_mutation};
use crate::error::ApiError;
use crate::policy::authorize_session_bound;

const IDEMPOTENCY_HEADER: &str = "idempotency-key";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateMediaPreviewRequest {
    source_version_id: String,
    video_codecs: Vec<MediaVideoCodec>,
    audio_codec: MediaAudioCodec,
    explicit_user_confirmation: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MediaVideoCodec {
    Av1,
    Vp9,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MediaAudioCodec {
    Opus,
}

#[derive(Debug, Serialize)]
struct MediaPreviewResponse {
    id: Uuid,
    drive_id: Uuid,
    node_id: Uuid,
    source_version_id: Uuid,
    state: &'static str,
    attempt_count: i32,
    job_epoch: i64,
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/drives/{drive_id}/nodes/{node_id}/media-previews",
            routing::post(create_preview),
        )
        .route(
            "/drives/{drive_id}/nodes/{node_id}/media-previews/{preview_id}",
            routing::get(get_preview).delete(cancel_preview),
        )
}

async fn create_preview(
    State(state): State<AppState>,
    Path((drive_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<CreateMediaPreviewRequest>,
) -> Result<(StatusCode, Json<MediaPreviewResponse>), ApiError> {
    require_media(&state).await?;
    let session = authenticate_mutation(&state, &headers).await?;
    let idempotency_key = headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| {
            ApiError::bad_request(
                "idempotency.required",
                "A valid Idempotency-Key header is required",
            )
        })?;
    if !request.explicit_user_confirmation
        || request.video_codecs.is_empty()
        || request.video_codecs.len() > 2
    {
        return Err(ApiError::bad_request(
            "media.confirmation_required",
            "Media transcoding requires explicit confirmation and an admitted browser codec",
        ));
    }
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let source_version_id = parse_uuid_v4(&request.source_version_id)?;
    authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::Transcode,
    )
    .await?;
    let versions = state
        .database
        .list_file_versions(state.tenant_id, drive_id, node_id)
        .await?;
    if !versions
        .iter()
        .any(|version| version.id == source_version_id)
    {
        return Err(ApiError::not_found());
    }
    let codec = if request
        .video_codecs
        .iter()
        .any(|codec| matches!(codec, MediaVideoCodec::Av1))
    {
        "av1-opus-segmented-v1"
    } else {
        "vp9-opus-segmented-v1"
    };
    let profile_digest = *blake3::hash(codec.as_bytes()).as_bytes();
    let image = state
        .config
        .media
        .transcoder_image
        .as_deref()
        .ok_or_else(ApiError::internal)?;
    let build_identity = *blake3::hash(image.as_bytes()).as_bytes();
    let fingerprint =
        *blake3::hash(&serde_json::to_vec(&request).map_err(|_| ApiError::internal())?).as_bytes();
    let mut cache_material = Vec::with_capacity(16 + 32 + 32);
    cache_material.extend_from_slice(source_version_id.as_bytes());
    cache_material.extend_from_slice(&profile_digest);
    cache_material.extend_from_slice(&build_identity);
    let cache_key = state.digest(b"filebelt-media-cache-v1\0", &cache_material);
    let preview = state
        .database
        .admit_media_preview(AdmitMediaPreviewInput {
            tenant_id: state.tenant_id,
            preview_id: Uuid::new_v4(),
            drive_id,
            node_id,
            source_version_id,
            requester_principal_id: session.record.principal_id,
            requester_session_id: session.record.session_id,
            idempotency_key,
            request_fingerprint: &fingerprint,
            cache_key: &cache_key,
            profile_id: codec,
            profile_digest: &profile_digest,
            transcoder_build_identity: &build_identity,
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(response(preview))))
}

async fn get_preview(
    State(state): State<AppState>,
    Path((drive_id, node_id, preview_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<MediaPreviewResponse>, ApiError> {
    require_media(&state).await?;
    let session = authenticate(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let preview_id = parse_uuid_v4(&preview_id)?;
    authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::ReadContent,
    )
    .await?;
    let preview = state
        .database
        .media_preview(state.tenant_id, preview_id)
        .await?;
    if preview.drive_id != drive_id || preview.node_id != node_id {
        return Err(ApiError::not_found());
    }
    Ok(Json(response(preview)))
}

async fn cancel_preview(
    State(state): State<AppState>,
    Path((drive_id, node_id, preview_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<MediaPreviewResponse>, ApiError> {
    require_media(&state).await?;
    let session = authenticate_mutation(&state, &headers).await?;
    let drive_id = parse_uuid_v4(&drive_id)?;
    let node_id = parse_uuid_v4(&node_id)?;
    let preview_id = parse_uuid_v4(&preview_id)?;
    authorize_session_bound(
        &state.database,
        state.tenant_id,
        session.record.principal_id,
        session.record.session_id,
        drive_id,
        node_id,
        Action::Transcode,
    )
    .await?;
    let current = state
        .database
        .media_preview(state.tenant_id, preview_id)
        .await?;
    if current.drive_id != drive_id || current.node_id != node_id {
        return Err(ApiError::not_found());
    }
    Ok(Json(response(
        state
            .database
            .cancel_media_preview(state.tenant_id, preview_id)
            .await?,
    )))
}

async fn require_media(state: &AppState) -> Result<(), ApiError> {
    if !state.config.media.enabled {
        return Err(ApiError::not_found());
    }
    if !state.database.phase8_is_active(state.tenant_id).await? {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "phase8.inactive",
            "Phase 8 admission is not active",
        ));
    }
    Ok(())
}

fn response(preview: MediaPreviewRecord) -> MediaPreviewResponse {
    MediaPreviewResponse {
        id: preview.id,
        drive_id: preview.drive_id,
        node_id: preview.node_id,
        source_version_id: preview.source_version_id,
        state: preview.state.as_str(),
        attempt_count: preview.attempt_count,
        job_epoch: preview.job_epoch,
    }
}

fn parse_uuid_v4(value: &str) -> Result<Uuid, ApiError> {
    let parsed = value
        .parse::<Uuid>()
        .map_err(|_| ApiError::bad_request("id.invalid_syntax", "The identifier is invalid"))?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
        return Err(ApiError::bad_request(
            "id.invalid_syntax",
            "The identifier is invalid",
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_request_is_closed_to_approved_codecs_and_confirmation() {
        let request: CreateMediaPreviewRequest = serde_json::from_str(
            r#"{"source_version_id":"00000000-0000-4000-8000-000000000001","video_codecs":["vp9"],"audio_codec":"opus","explicit_user_confirmation":true}"#,
        )
        .expect("closed media request");
        assert!(request.explicit_user_confirmation);
        assert!(matches!(request.video_codecs[0], MediaVideoCodec::Vp9));
        assert!(serde_json::from_str::<CreateMediaPreviewRequest>(
            r#"{"source_version_id":"x","video_codecs":["h264"],"audio_codec":"aac","explicit_user_confirmation":true}"#,
        )
        .is_err());
    }
}

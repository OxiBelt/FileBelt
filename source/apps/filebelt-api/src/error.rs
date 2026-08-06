// SPDX-License-Identifier: Apache-2.0

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use filebelt_database::DatabaseError;
use serde::Serialize;

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    title: &'static str,
}

#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    kind: String,
    title: &'a str,
    status: u16,
    code: &'a str,
}

impl ApiError {
    pub(crate) const fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        Self {
            status,
            code,
            title,
        }
    }

    pub(crate) const fn bad_request(code: &'static str, title: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, title)
    }

    pub(crate) const fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "session.invalid",
            "Authentication is required",
        )
    }

    pub(crate) const fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "resource.not_found",
            "The requested resource was not found",
        )
    }

    pub(crate) const fn forbidden(code: &'static str, title: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, title)
    }

    pub(crate) const fn conflict(code: &'static str, title: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code, title)
    }

    pub(crate) const fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server.internal",
            "The request could not be completed",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(Problem {
                kind: format!("https://filebelt.dev/problems/{}", self.code),
                title: self.title,
                status: self.status.as_u16(),
                code: self.code,
            }),
        )
            .into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

impl From<DatabaseError> for ApiError {
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::NotFound => Self::not_found(),
            DatabaseError::Conflict => Self::conflict(
                "request.conflict",
                "The request conflicts with current state",
            ),
            DatabaseError::QuotaExceeded => Self::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "quota.exceeded",
                "The drive quota is exhausted",
            ),
            DatabaseError::StorageUnavailable => Self::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "storage.unavailable",
                "Storage is unavailable for new reservations",
            ),
            DatabaseError::AdmissionLimited => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "request.admission_limited",
                "The service is temporarily at its request admission limit",
            ),
            DatabaseError::StaleGeneration => Self::new(
                StatusCode::PRECONDITION_FAILED,
                "generation.stale",
                "The supplied generation is stale",
            ),
            DatabaseError::Sql(_)
            | DatabaseError::Migration(_)
            | DatabaseError::InvalidPersistedValue => Self::internal(),
        }
    }
}

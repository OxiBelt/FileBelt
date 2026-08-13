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
    retry_after_seconds: Option<u32>,
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
            retry_after_seconds: None,
        }
    }

    pub(crate) const fn remediation_in_progress(code: &'static str, title: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            title,
            retry_after_seconds: Some(60),
        }
    }

    pub(crate) const fn admission_limited(code: &'static str, title: &'static str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
            title,
            retry_after_seconds: Some(5),
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
        if let Some(seconds) = self.retry_after_seconds {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&seconds.to_string())
                    .expect("a positive integer is a valid Retry-After header"),
            );
        }
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
            DatabaseError::SecurityAdmissionBlocked => Self::remediation_in_progress(
                "security.remediation_in_progress",
                "Security repair must complete before this authority can be created",
            ),
            DatabaseError::Sql(_)
            | DatabaseError::Migration(_)
            | DatabaseError::InvalidPersistedValue => Self::internal(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remediation_errors_are_retryable_problem_responses() {
        let response = ApiError::remediation_in_progress(
            "share.remediation_in_progress",
            "remediation in progress",
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/problem+json"))
        );
    }

    #[test]
    fn admission_errors_use_the_fixed_retry_hint() {
        let response = ApiError::admission_limited(
            "revision.admission_limited",
            "comparison admission limited",
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("5"))
        );
    }
}
